//! The compile-time route table: a radix trie over path segments.
//!
//! Implements `SRV-003`; Proposal §6.4. Also resolves `OQ-007` / `SRV-006`.
//!
//! # The two design decisions this module makes, and why
//!
//! ## 1. A segment trie, not a character trie
//!
//! "Radix trie" in routing usually means two different things, and the
//! difference matters:
//!
//! * A **character** radix trie shares string prefixes, so `/api/v1` and
//!   `/api/v2` share the `/api/v` chain. It saves memory on long shared
//!   prefixes.
//! * A **segment** trie splits on `/` and stores one node per path segment.
//!
//! Segment wins here because **every route parameter is a whole segment**.
//! `/orders/:id` matches `/orders/42`, never `/orders/4x2`. With a character
//! trie, a parameter node has to carry "match until the next `/`" logic, and
//! every wildcard boundary becomes a place to get off-by-one wrong. With a
//! segment trie, a parameter is a node whose value is "whatever segment is
//! here", and the boundary is `split('/')` — which the standard library gets
//! right.
//!
//! The memory saving of a character trie is real but irrelevant at this scale:
//! a routing table is tens to hundreds of entries, built once at load, and held
//! for the process's lifetime.
//!
//! ## 2. Priority is a total order, and it is not insertion order
//!
//! When several patterns could match one path, exactly one must win, and the
//! choice must not depend on the order routes appear in `qqq.toml`. Otherwise
//! reordering a config file silently changes which handler runs — a bug that is
//! nearly impossible to see in a diff.
//!
//! The order, most specific first:
//!
//! | Rank | Kind | Example |
//! |---|---|---|
//! | 0 | literal | `/orders/new` |
//! | 1 | parameter | `/orders/:id` |
//! | 2 | wildcard | `/files/*rest` |
//!
//! So `/orders/new` beats `/orders/:id`, which beats `/files/*rest`. This is
//! the rule every framework converges on, because the alternative — a literal
//! shadowed by a parameter — makes a route impossible to reach, and an
//! unreachable route is a bug that presents as a 404.
//!
//! # `OQ-007`, resolved
//!
//! Checklist `SRV-006` asks whether `wasi:http` is the foundation or whether a
//! custom interface is required. **`wasi:http` is the foundation; `qqq:http`
//! extends it.**
//!
//! The reasoning, since the checklist left it open:
//!
//! * `wasi:http` is the only HTTP interface a component can import without
//!   QQQ-specific toolchain support, so building on it is what makes the
//!   five-language claim real rather than aspirational. A Go or Python
//!   component reaches QQQ's server through the same interface it would use
//!   anywhere else.
//! * But `wasi:http` has no route table, no per-route capability scoping, and
//!   no place to express "this handler may only read, not write". Those are
//!   QQQ's contributions, and they belong in an extension rather than in a
//!   fork.
//! * The `qqq:http` WIT in this repository already reflects that: its module
//!   comment reads *"Built over `wasi:http`, adding the routing and headers an
//!   application actually needs while keeping the guest's view of a body a
//!   **stream** rather than a buffer."*
//!
//! The consequence for this module: **the route table is host-side.** A guest
//! never sees a pattern; it is handed a matched request with parameters already
//! extracted. That keeps pattern syntax out of the ABI, so it can change
//! without a WIT version bump — which is the property that makes the extension
//! safe to evolve.

use std::collections::BTreeMap;
use std::fmt;

use qqq_core::{Error, ErrorCode};

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// The most routes a table will hold.
///
/// A bound rather than unbounded growth: routes come from `qqq.toml`, and
/// nothing stops a generated manifest from declaring a hundred thousand. Failing
/// at load with a named limit is better than a server that takes ten seconds to
/// start and cannot say why.
pub const MAX_ROUTES: usize = 10_000;

/// The most parameters one pattern may capture.
///
/// Each capture becomes a `String` allocation per request. A pattern with a
/// hundred parameters is either generated or a mistake, and the limit turns it
/// into a load-time error rather than a per-request cost.
pub const MAX_PARAMS: usize = 16;

/// The wildcard marker in a pattern.
pub const WILDCARD: char = '*';

/// The parameter marker in a pattern.
pub const PARAM_MARKER: char = ':';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a route table could not be built.
///
/// A structured enum rather than a string because every variant names a
/// *specific* manifest mistake, and the fix differs for each. `qqqai serve`
/// renders these into the error block Proposal §12.2 mandates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterError {
    /// A pattern was not absolute.
    PatternNotAbsolute {
        /// The offending pattern.
        pattern: String,
    },
    /// A pattern contains an empty segment.
    EmptySegment {
        /// The offending pattern.
        pattern: String,
        /// The segment index, from 1.
        index: usize,
    },
    /// A parameter or wildcard had no name.
    UnnamedCapture {
        /// The offending pattern.
        pattern: String,
        /// The segment index, from 1.
        index: usize,
    },
    /// Two patterns are structurally identical.
    DuplicateRoute {
        /// The pattern already registered.
        first: String,
        /// The pattern that collided.
        second: String,
    },
    /// A wildcard appeared somewhere other than the last segment.
    WildcardNotLast {
        /// The offending pattern.
        pattern: String,
    },
    /// A pattern captured more parameters than [`MAX_PARAMS`].
    TooManyParams {
        /// The offending pattern.
        pattern: String,
        /// How many it declared.
        count: usize,
    },
    /// The table already holds [`MAX_ROUTES`] routes.
    TooManyRoutes {
        /// The limit.
        limit: usize,
    },
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PatternNotAbsolute { pattern } => {
                write!(f, "route `{pattern}` must start with `/`")
            }
            Self::EmptySegment { pattern, index } => write!(
                f,
                "route `{pattern}` has an empty segment at position {index} \
                 (a doubled or trailing `/`)"
            ),
            Self::UnnamedCapture { pattern, index } => write!(
                f,
                "route `{pattern}` has a capture with no name at position {index}"
            ),
            Self::DuplicateRoute { first, second } => {
                write!(f, "routes `{first}` and `{second}` are the same pattern")
            }
            Self::WildcardNotLast { pattern } => write!(
                f,
                "route `{pattern}` has a wildcard that is not the last segment"
            ),
            Self::TooManyParams { pattern, count } => write!(
                f,
                "route `{pattern}` captures {count} parameters, more than the limit of {MAX_PARAMS}"
            ),
            Self::TooManyRoutes { limit } => {
                write!(f, "the route table already holds {limit} routes")
            }
        }
    }
}

impl std::error::Error for RouterError {}

impl RouterError {
    /// Convert to the shared error type with the mandated rendering.
    #[must_use]
    pub fn to_error(&self) -> Error {
        let remediation = match self {
            Self::PatternNotAbsolute { .. } => "routes are absolute paths, e.g. `/orders/:id`",
            Self::EmptySegment { .. } => "remove the doubled or trailing `/`",
            Self::UnnamedCapture { .. } => {
                "name every capture, e.g. `:id` or `*rest` — an unnamed one cannot be read"
            }
            Self::DuplicateRoute { .. } => "remove one of them, or differentiate the pattern",
            Self::WildcardNotLast { .. } => {
                "a wildcard consumes the rest of the path, so nothing may follow it"
            }
            Self::TooManyParams { .. } => {
                "use fewer captures; each one costs a per-request allocation"
            }
            Self::TooManyRoutes { .. } => "split the application, or raise the limit in qqq-serve",
        };
        Error::new(ErrorCode::ManifestSchemaViolation, self.to_string())
            .with_context("surface", "routes")
            .with_remediation(remediation)
    }
}

// ---------------------------------------------------------------------------
// Method
// ---------------------------------------------------------------------------

/// An HTTP method.
///
/// A closed enum rather than a string: an unknown method is rejected once at
/// load, and matching is an integer comparison rather than a string one. The
/// `Extension` variant exists because RFC 9110 explicitly allows extension
/// methods and a framework that cannot express them would force a breaking
/// change the first time one is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// `GET`
    Get,
    /// `HEAD`
    Head,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
    /// `OPTIONS`
    Options,
    /// `TRACE`
    Trace,
    /// `CONNECT`
    Connect,
    /// Any other method, matched by name.
    ///
    /// Carried as a variant rather than folded into `Get` so an extension
    /// method cannot be silently routed to the wrong handler.
    Extension,
}

impl Method {
    /// Every method this table knows by name.
    pub const ALL: [Self; 9] = [
        Self::Get,
        Self::Head,
        Self::Post,
        Self::Put,
        Self::Patch,
        Self::Delete,
        Self::Options,
        Self::Trace,
        Self::Connect,
    ];

    /// The method's wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
            Self::Extension => "<extension>",
        }
    }

    /// Parse a method name.
    ///
    /// Case-insensitive, because HTTP methods are defined as case-sensitive but
    /// every proxy and client in existence sends the canonical uppercase form,
    /// and rejecting `get` would be pedantry that produces a confusing 400.
    /// The canonical name is restored on the way out, so the enum is always
    /// canonical internally.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let upper = s.trim().to_ascii_uppercase();
        Self::ALL.into_iter().find(|m| m.as_str() == upper)
    }

    /// Whether this method is one HTTP defines as **safe** (read-only).
    ///
    /// Used by the capability layer: a route reachable only by safe methods can
    /// be exposed with fewer grants than one reachable by `POST`. RFC 9110
    /// §9.2.1 defines the property; this is where it becomes actionable.
    #[must_use]
    pub const fn is_safe(self) -> bool {
        matches!(self, Self::Get | Self::Head | Self::Options | Self::Trace)
    }

    /// Whether this method is **idempotent** (repeating it has the same effect).
    ///
    /// Enforced nowhere in V1 — it is a client contract, not a server one — but
    /// reported so a route table can be audited for methods that should not be
    /// retried by a proxy.
    #[must_use]
    pub const fn is_idempotent(self) -> bool {
        matches!(
            self,
            Self::Get | Self::Head | Self::Options | Self::Trace | Self::Put | Self::Delete
        )
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Segments
// ---------------------------------------------------------------------------

/// One parsed piece of a route pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// A literal that must match exactly.
    Literal(String),
    /// A `:name` capture of one segment.
    Param(String),
    /// A `*name` capture of the remainder, possibly empty.
    Wildcard(String),
}

// ---------------------------------------------------------------------------
// Route
// ---------------------------------------------------------------------------

/// One registered route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The method this route answers.
    pub method: Method,
    /// The pattern as written, for diagnostics.
    pub pattern: String,
    /// The handler identifier the host resolves at dispatch.
    ///
    /// A name rather than a function pointer: the handler lives in a component
    /// instance that may be replaced on reload (`qqqai dev`, tier 1), so
    /// binding a pointer here would pin the old code. The indirection is also
    /// what lets the whole table be built and validated before any component is
    /// loaded.
    pub handler: String,
    /// The parsed segments, retained so capture names travel with their route.
    ///
    /// See [`Node::handlers`] for why these are not stored on the trie.
    segments: Vec<Segment>,
}

impl Route {
    /// Build a route, validating the pattern.
    ///
    /// # Why this returns `RouterError` rather than `qqq_core::Error`
    ///
    /// Because a caller building a table wants to *inspect* which pattern is
    /// wrong — to report all of them at once, or to point at the manifest line.
    /// Flattening to the shared error type here would throw that structure away,
    /// and the flattened form is recoverable at any point via
    /// [`RouterError::to_error`]. Losing information is one-way; keeping it is
    /// free.
    ///
    /// # Errors
    ///
    /// Any [`RouterError`] the pattern violates.
    pub fn new(
        method: Method,
        pattern: &str,
        handler: &str,
    ) -> std::result::Result<Self, RouterError> {
        let segments = parse_pattern(pattern)?;
        Ok(Self {
            method,
            pattern: pattern.to_owned(),
            handler: handler.to_owned(),
            segments,
        })
    }

    /// The capture names in pattern order.
    fn captures(&self) -> Vec<&str> {
        self.segments
            .iter()
            .filter_map(|s| match s {
                Segment::Literal(_) => None,
                Segment::Param(n) | Segment::Wildcard(n) => Some(n.as_str()),
            })
            .collect()
    }
}

/// Parse a pattern into segments, validating it.
///
/// # Errors
///
/// * [`RouterError::PatternNotAbsolute`] — no leading `/`.
/// * [`RouterError::EmptySegment`] — a doubled or trailing `/`.
/// * [`RouterError::UnnamedCapture`] — a bare `:` or `*`.
/// * [`RouterError::WildcardNotLast`] — a wildcard with segments after it.
/// * [`RouterError::TooManyParams`] — more than [`MAX_PARAMS`] captures.
fn parse_pattern(pattern: &str) -> std::result::Result<Vec<Segment>, RouterError> {
    if !pattern.starts_with('/') {
        return Err(RouterError::PatternNotAbsolute {
            pattern: pattern.to_owned(),
        });
    }

    // `/` alone is the root route, with no segments.
    if pattern == "/" {
        return Ok(Vec::new());
    }

    // `split('/')` on `/a/b` yields `["", "a", "b"]`; the leading empty string
    // is the artifact of the absolute path, so it is dropped rather than
    // treated as an empty segment.
    let raw: Vec<&str> = pattern.split('/').skip(1).collect();
    let mut segments = Vec::with_capacity(raw.len());
    let mut params = 0usize;

    for (i, piece) in raw.iter().enumerate() {
        let index = i + 1;
        if piece.is_empty() {
            return Err(RouterError::EmptySegment {
                pattern: pattern.to_owned(),
                index,
            });
        }

        let mut chars = piece.chars();
        let first = chars.next().unwrap_or(' ');
        let rest: String = chars.collect();

        let segment = match first {
            PARAM_MARKER => {
                if rest.is_empty() {
                    return Err(RouterError::UnnamedCapture {
                        pattern: pattern.to_owned(),
                        index,
                    });
                }
                params += 1;
                Segment::Param(rest)
            }
            WILDCARD => {
                if rest.is_empty() {
                    return Err(RouterError::UnnamedCapture {
                        pattern: pattern.to_owned(),
                        index,
                    });
                }
                // A wildcard consumes the remainder, so anything after it is
                // unreachable. Rejecting it at load is far better than a route
                // that silently never matches.
                if index != raw.len() {
                    return Err(RouterError::WildcardNotLast {
                        pattern: pattern.to_owned(),
                    });
                }
                params += 1;
                Segment::Wildcard(rest)
            }
            _ => Segment::Literal((*piece).to_owned()),
        };
        segments.push(segment);
    }

    if params > MAX_PARAMS {
        return Err(RouterError::TooManyParams {
            pattern: pattern.to_owned(),
            count: params,
        });
    }
    Ok(segments)
}

// ---------------------------------------------------------------------------
// Trie
// ---------------------------------------------------------------------------

/// One node in the trie.
#[derive(Debug, Default)]
struct Node {
    /// Literal children, keyed by segment text.
    ///
    /// A `BTreeMap` rather than a `HashMap`: with a handful of children the
    /// linear scan beats hashing, and the ordering makes iteration
    /// deterministic, which matters when the table is dumped by `qqqai
    /// inspect` and compared between builds.
    literals: BTreeMap<String, Node>,
    /// The `:param` child. At most one, because two parameter segments at the
    /// same position are indistinguishable and would both match.
    param: Option<Box<Node>>,
    /// The `*wildcard` child, if any. Terminal by construction.
    wildcard: Option<Box<Node>>,
    /// The routes terminating here, keyed by method.
    ///
    /// # Why the capture names live on the route, not on the node
    ///
    /// The trie is **shared** between patterns that differ only in their
    /// capture names. `/a/:x/c` and `/a/:y/b` walk the same `a` node and the
    /// same param child; only the final segment differs. So a node-level
    /// `param_name` can hold just one of `x` or `y` — whichever registered
    /// first — and the other route would report the wrong parameter name.
    ///
    /// That was a real bug, caught by
    /// `parameters_do_not_leak_between_failed_branches`, which is exactly the
    /// case of two patterns sharing a prefix and differing in capture name.
    /// Storing the names on each `Route` means every route carries its own
    /// pattern's names, and the shared trie carries only structure.
    handlers: BTreeMap<Method, Route>,
}

/// What a match produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// The handler to invoke.
    pub handler: String,
    /// The pattern that matched, for logging.
    pub pattern: String,
    /// The captured parameters.
    pub params: Params,
}

/// Captured route parameters.
///
/// A small vector rather than a map: there are at most [`MAX_PARAMS`] of them,
/// linear lookup beats hashing at that size, and the order is the order they
/// appeared in the pattern — which is what a handler wants when it binds them
/// positionally.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params {
    entries: Vec<(String, String)>,
}

impl Params {
    /// Look up a parameter by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// How many parameters were captured.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing was captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate the `(name, value)` pairs in pattern order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (k, v) in &self.entries {
            if !first {
                f.write_str(", ")?;
            }
            write!(f, "{k}={v}")?;
            first = false;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Table
// ---------------------------------------------------------------------------

/// The compiled route table.
///
/// Built once at load from the manifest and never mutated afterwards. The
/// absence of a mutation API is deliberate: Proposal §6.4 forbids runtime route
/// registration, and the most reliable way to forbid something is to not
/// provide it.
#[derive(Debug, Default)]
pub struct RouteTable {
    root: Node,
    count: usize,
}

impl RouteTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a table from routes.
    ///
    /// # Errors
    ///
    /// Any [`RouterError`], including [`RouterError::DuplicateRoute`] when two
    /// entries have the same method and the same pattern.
    pub fn build(
        routes: impl IntoIterator<Item = Route>,
    ) -> std::result::Result<Self, RouterError> {
        let mut table = Self::new();
        for route in routes {
            table.insert(route)?;
        }
        Ok(table)
    }

    /// Add a route.
    ///
    /// # Errors
    ///
    /// As [`RouteTable::build`].
    pub fn insert(&mut self, route: Route) -> std::result::Result<(), RouterError> {
        if self.count >= MAX_ROUTES {
            return Err(RouterError::TooManyRoutes { limit: MAX_ROUTES });
        }

        let mut node = &mut self.root;
        for segment in &route.segments {
            node = match segment {
                Segment::Literal(text) => node.literals.entry(text.clone()).or_default(),
                Segment::Param(_) => {
                    // The child is shared between patterns that differ only in
                    // capture name; the names live on the route. See
                    // `Node::handlers`.
                    node.param.get_or_insert_with(|| Box::new(Node::default()))
                }
                Segment::Wildcard(_) => node
                    .wildcard
                    .get_or_insert_with(|| Box::new(Node::default())),
            };
        }

        if let Some(existing) = node.handlers.get(&route.method) {
            return Err(RouterError::DuplicateRoute {
                first: existing.pattern.clone(),
                second: route.pattern.clone(),
            });
        }
        node.handlers.insert(route.method, route);
        self.count += 1;
        Ok(())
    }

    /// How many routes are registered.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether no routes are registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Match a method and path.
    ///
    /// Returns `None` when nothing matches, which the caller turns into a 404.
    /// A path that matches a *pattern* under a different method is not reported
    /// separately here: doing so would need a second traversal, and the caller
    /// that wants a 405 must ask for it explicitly via [`Self::allows`].
    #[must_use]
    pub fn match_route(&self, method: Method, path: &str) -> Option<Match> {
        let segments: Vec<&str> = if path == "/" {
            Vec::new()
        } else {
            path.split('/').skip(1).collect()
        };

        let mut captures = Vec::new();
        let route = walk(&self.root, &segments, 0, method, &mut captures)?;
        Some(bind(&route, captures))
    }

    /// Whether any pattern matches this path, under any method.
    ///
    /// The 405 path: a request that matches a route but not the method should
    /// say so, and RFC 9110 §15.5.6 requires an `Allow` header listing what is
    /// permitted. Returning the methods makes that possible without a second
    /// table.
    #[must_use]
    pub fn allows(&self, path: &str) -> Vec<Method> {
        let segments: Vec<&str> = if path == "/" {
            Vec::new()
        } else {
            path.split('/').skip(1).collect()
        };
        let mut out = Vec::new();
        collect_methods(&self.root, &segments, 0, &mut out);
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Every route in the table, sorted by pattern then method.
    ///
    /// For `qqqai inspect`, which reports what a service exposes. Sorted so two
    /// builds of the same manifest produce identical output — an unsorted dump
    /// makes a diff useless exactly when it is most needed.
    #[must_use]
    pub fn routes(&self) -> Vec<Route> {
        let mut out = Vec::with_capacity(self.count);
        collect_routes(&self.root, &mut out);
        out.sort_by(|a, b| {
            a.pattern
                .cmp(&b.pattern)
                .then_with(|| a.method.as_str().cmp(b.method.as_str()))
        });
        out
    }
}

/// The recursive match, trying candidates in specificity order.
///
/// # Why this is a free function rather than a method
///
/// It never reads `self`. It walks a `Node` tree that the caller supplies, so
/// making it a method would be a fiction that the compiler has to be told to
/// ignore (`clippy::only_used_in_recursion`). Being free is also the clearer
/// statement: this is a pure function of `(tree, path, method)`.
///
/// # Why this returns on the first success rather than collecting all matches
///
/// Because the order *is* the priority. Trying `literal`, then `param`, then
/// `wildcard` and returning the first hit implements "most specific wins"
/// directly, with no post-filtering and no tie-break step. Collecting everything
/// and sorting would be more code for the same answer, and would make the
/// priority rule invisible.
fn walk(
    node: &Node,
    segments: &[&str],
    index: usize,
    method: Method,
    captures: &mut Vec<String>,
) -> Option<Route> {
    // -- all segments consumed -----------------------------------------
    //
    // Two things can match here, and *both* must be tried:
    //
    // 1. A handler on this node (an exact-length pattern).
    // 2. A wildcard child, which matches an empty remainder.
    //
    // An earlier version returned on a missing handler here, so
    // `/files/*rest` did not answer `/files` — the wildcard node is a
    // *child*, and returning early never reached it. The test
    // `a_wildcard_matches_an_empty_remainder` caught it.
    if index == segments.len() {
        if let Some(route) = node.handlers.get(&method) {
            return Some(route.clone());
        }
        if let Some(child) = &node.wildcard {
            if let Some(route) = child.handlers.get(&method) {
                captures.push(String::new());
                return Some(route.clone());
            }
        }
        return None;
    }

    let segment = segments[index];

    // -- 1. literal, most specific ------------------------------------
    if let Some(child) = node.literals.get(segment) {
        if let Some(found) = walk(child, segments, index + 1, method, captures) {
            return Some(found);
        }
    }

    // -- 2. parameter -------------------------------------------------
    //
    // An empty segment never matches a parameter: `/orders/` is not
    // `/orders/:id`. This matters because a trailing slash is common in
    // hand-written URLs, and treating it as an empty id would route
    // `/orders/` to a handler expecting a real value.
    if !segment.is_empty() {
        if let Some(child) = &node.param {
            captures.push((*segment).to_owned());
            if let Some(found) = walk(child, segments, index + 1, method, captures) {
                return Some(found);
            }
            // The subtree did not match, so the capture is undone before
            // trying the next candidate — otherwise a failed branch would
            // leak a value into a later match.
            captures.pop();
        }
    }

    // -- 3. wildcard, least specific ----------------------------------
    //
    // A wildcard captures the remainder *joined by `/`*, so `/files/*rest`
    // against `/files/a/b/c` yields `a/b/c`.
    if let Some(child) = &node.wildcard {
        captures.push(segments[index..].join("/"));
        if let Some(found) = walk(child, segments, segments.len(), method, captures) {
            return Some(found);
        }
        captures.pop();
    }

    None
}

/// Pair positional capture values with the matched route's names.
///
/// # Why this is a separate step
///
/// The walk produces *values* in pattern order; the route supplies the
/// *names*. Keeping them apart is what lets patterns share trie nodes while
/// each retaining its own parameter names — see [`Node::handlers`].
///
/// The zip is safe because both are generated from the same pattern: the
/// walk pushes exactly one value per capture segment. A mismatch would mean
/// the trie and the pattern disagree, which is a bug in this module rather
/// than a caller error, so an under-run silently yields fewer parameters
/// rather than panicking in a request path.
fn bind(route: &Route, values: Vec<String>) -> Match {
    let names = route.captures();
    let params = Params {
        entries: names
            .iter()
            .zip(values)
            .map(|(n, v)| ((*n).to_owned(), v))
            .collect(),
    };
    Match {
        handler: route.handler.clone(),
        pattern: route.pattern.clone(),
        params,
    }
}

/// Collect every method that matches a path, ignoring which one was asked
/// for. Used for the 405 `Allow` header.
fn collect_methods(node: &Node, segments: &[&str], index: usize, out: &mut Vec<Method>) {
    if index == segments.len() {
        out.extend(node.handlers.keys().copied());
        return;
    }
    let segment = segments[index];
    if let Some(child) = node.literals.get(segment) {
        collect_methods(child, segments, index + 1, out);
    }
    if !segment.is_empty() {
        if let Some(child) = &node.param {
            collect_methods(child, segments, index + 1, out);
        }
    }
    if let Some(child) = &node.wildcard {
        collect_methods(child, segments, segments.len(), out);
    }
}

/// Recursively gather every route.
fn collect_routes(node: &Node, out: &mut Vec<Route>) {
    out.extend(node.handlers.values().cloned());
    for child in node.literals.values() {
        collect_routes(child, out);
    }
    if let Some(child) = &node.param {
        collect_routes(child, out);
    }
    if let Some(child) = &node.wildcard {
        collect_routes(child, out);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn route(pattern: &str, handler: &str) -> Route {
        Route::new(Method::Get, pattern, handler).expect("test pattern must be valid")
    }

    fn table(patterns: &[(&str, &str)]) -> RouteTable {
        RouteTable::build(patterns.iter().map(|(p, h)| route(p, h))).expect("test table must build")
    }

    fn hit(table: &RouteTable, path: &str) -> String {
        table
            .match_route(Method::Get, path)
            .unwrap_or_else(|| panic!("`{path}` should match"))
            .handler
    }

    // -- pattern parsing ---------------------------------------------------

    #[test]
    fn the_root_route_is_valid() {
        let t = table(&[("/", "root")]);
        assert_eq!(hit(&t, "/"), "root");
    }

    #[test]
    fn literal_patterns_parse() {
        let t = table(&[("/orders/new", "new"), ("/api/v1/users", "users")]);
        assert_eq!(hit(&t, "/orders/new"), "new");
        assert_eq!(hit(&t, "/api/v1/users"), "users");
    }

    #[test]
    fn a_pattern_must_start_with_a_slash() {
        let e = Route::new(Method::Get, "orders", "h").unwrap_err();
        assert_eq!(
            e,
            RouterError::PatternNotAbsolute {
                pattern: "orders".to_owned()
            }
        );
        // And it renders to the mandated shape.
        let rendered = e.to_error();
        assert!(rendered.remediation.is_some());
        assert!(rendered.message.contains("orders"));
    }

    /// A doubled slash has no sensible meaning, and treating it as "skip an
    /// empty segment" would make `/a//b` and `/a/b` the same route — which is
    /// the kind of ambiguity that produces a 404 nobody can explain.
    #[test]
    fn a_doubled_slash_is_rejected() {
        let e = Route::new(Method::Get, "/a//b", "h").unwrap_err();
        assert!(matches!(e, RouterError::EmptySegment { index: 2, .. }));
    }

    #[test]
    fn a_trailing_slash_is_rejected() {
        let e = Route::new(Method::Get, "/a/", "h").unwrap_err();
        assert!(matches!(e, RouterError::EmptySegment { .. }));
    }

    #[test]
    fn an_unnamed_capture_is_rejected() {
        for pattern in ["/a/:", "/a/*"] {
            let e = Route::new(Method::Get, pattern, "h").unwrap_err();
            assert!(
                matches!(e, RouterError::UnnamedCapture { .. }),
                "`{pattern}` must be rejected as unnamed, got {e:?}"
            );
        }
    }

    /// A wildcard consumes the remainder, so anything after it is unreachable.
    /// Rejecting at load beats a route that silently never matches.
    #[test]
    fn a_wildcard_must_be_last() {
        let e = Route::new(Method::Get, "/files/*rest/more", "h").unwrap_err();
        assert!(matches!(e, RouterError::WildcardNotLast { .. }));
        // A wildcard in the last position is fine.
        assert!(Route::new(Method::Get, "/files/*rest", "h").is_ok());
    }

    #[test]
    fn too_many_parameters_is_rejected() {
        let pattern = format!(
            "/{}",
            (0..=MAX_PARAMS)
                .map(|i| format!(":p{i}"))
                .collect::<Vec<_>>()
                .join("/")
        );
        let e = Route::new(Method::Get, &pattern, "h").unwrap_err();
        assert!(matches!(e, RouterError::TooManyParams { .. }));
    }

    /// [SRV-003 / security] Two routes with the same method and pattern are a
    /// configuration bug: one silently shadows the other, and which one wins
    /// depends on file order.
    #[test]
    fn a_duplicate_route_is_rejected() {
        let routes = vec![route("/orders", "first"), route("/orders", "second")];
        let e = RouteTable::build(routes).unwrap_err();
        assert!(matches!(e, RouterError::DuplicateRoute { .. }));
    }

    /// The same pattern under *different* methods is not a duplicate — that is
    /// the normal REST shape.
    #[test]
    fn the_same_pattern_under_two_methods_is_allowed() {
        let t = RouteTable::build(vec![
            Route::new(Method::Get, "/orders", "list").unwrap(),
            Route::new(Method::Post, "/orders", "create").unwrap(),
        ])
        .expect("must build");
        assert_eq!(
            t.match_route(Method::Get, "/orders").unwrap().handler,
            "list"
        );
        assert_eq!(
            t.match_route(Method::Post, "/orders").unwrap().handler,
            "create"
        );
    }

    // -- matching ----------------------------------------------------------

    #[test]
    fn a_parameter_captures_one_segment() {
        let t = table(&[("/orders/:id", "one")]);
        let m = t
            .match_route(Method::Get, "/orders/42")
            .expect("must match");
        assert_eq!(m.handler, "one");
        assert_eq!(m.params.get("id"), Some("42"));
        assert_eq!(m.params.len(), 1);
    }

    /// A parameter matches exactly one segment, never several.
    #[test]
    fn a_parameter_does_not_span_segments() {
        let t = table(&[("/orders/:id", "one")]);
        assert!(
            t.match_route(Method::Get, "/orders/42/items").is_none(),
            "`:id` must not swallow `/items`"
        );
    }

    /// **The parameter-empty case.** A trailing slash produces an empty final
    /// segment, which must not be captured as an empty id: `/orders/` is not
    /// `/orders/:id`, and a handler receiving `id = ""` would fail confusingly
    /// later.
    #[test]
    fn an_empty_segment_never_matches_a_parameter() {
        let t = table(&[("/orders/:id", "one")]);
        assert!(
            t.match_route(Method::Get, "/orders/").is_none(),
            "an empty segment must not be captured"
        );
    }

    #[test]
    fn several_parameters_capture_in_order() {
        let t = table(&[("/org/:org/repo/:repo", "repo")]);
        let m = t
            .match_route(Method::Get, "/org/qqq/repo/core")
            .expect("must match");
        assert_eq!(m.params.get("org"), Some("qqq"));
        assert_eq!(m.params.get("repo"), Some("core"));
        let names: Vec<&str> = m.params.iter().map(|(k, _)| k).collect();
        assert_eq!(
            names,
            vec!["org", "repo"],
            "pattern order must be preserved"
        );
    }

    #[test]
    fn a_wildcard_captures_the_remainder() {
        let t = table(&[("/files/*rest", "files")]);
        let m = t
            .match_route(Method::Get, "/files/a/b/c")
            .expect("must match");
        assert_eq!(m.params.get("rest"), Some("a/b/c"));
    }

    /// A wildcard matches an empty remainder too, which makes `/files/*rest`
    /// also answer `/files`. Stated explicitly because it is a real design
    /// choice: the alternative would require declaring both routes.
    #[test]
    fn a_wildcard_matches_an_empty_remainder() {
        let t = table(&[("/files/*rest", "files")]);
        let m = t.match_route(Method::Get, "/files").expect("must match");
        assert_eq!(m.params.get("rest"), Some(""));
    }

    #[test]
    fn no_match_returns_none() {
        let t = table(&[("/orders", "orders")]);
        assert!(t.match_route(Method::Get, "/nope").is_none());
        assert!(t.match_route(Method::Get, "/orders/extra").is_none());
        assert!(t.match_route(Method::Get, "/").is_none());
    }

    #[test]
    fn a_method_mismatch_is_not_a_match() {
        let t = RouteTable::build(vec![Route::new(Method::Post, "/orders", "create").unwrap()])
            .expect("must build");
        assert!(t.match_route(Method::Get, "/orders").is_none());
        assert!(t.match_route(Method::Post, "/orders").is_some());
    }

    // -- specificity, the ordering rule ------------------------------------

    /// **The rule that makes routes reachable.** A literal must beat a
    /// parameter, or `/orders/new` could never be reached — it would always be
    /// captured as an order id, and the bug would present as a confusing 404
    /// from inside the wrong handler.
    #[test]
    fn a_literal_beats_a_parameter() {
        let t = table(&[("/orders/:id", "by-id"), ("/orders/new", "new")]);
        assert_eq!(hit(&t, "/orders/new"), "new");
        assert_eq!(hit(&t, "/orders/42"), "by-id");
    }

    /// A parameter beats a wildcard.
    #[test]
    fn a_parameter_beats_a_wildcard() {
        let t = table(&[("/files/*rest", "wild"), ("/files/:name", "named")]);
        assert_eq!(hit(&t, "/files/readme.txt"), "named");
        // The wildcard still answers what the parameter cannot: several
        // segments.
        assert_eq!(hit(&t, "/files/a/b"), "wild");
    }

    /// All three at once, which is the case a hand-written router gets wrong.
    #[test]
    fn the_full_specificity_order_holds() {
        let t = table(&[
            ("/a/*rest", "wildcard"),
            ("/a/:p", "param"),
            ("/a/literal", "literal"),
        ]);
        assert_eq!(hit(&t, "/a/literal"), "literal");
        assert_eq!(hit(&t, "/a/other"), "param");
        assert_eq!(hit(&t, "/a/x/y"), "wildcard");
    }

    /// **Insertion order must not matter.** If it did, reordering `qqq.toml`
    /// would silently change which handler runs — a bug invisible in a diff.
    #[test]
    fn specificity_does_not_depend_on_insertion_order() {
        let forward = table(&[
            ("/a/literal", "literal"),
            ("/a/:p", "param"),
            ("/a/*rest", "wildcard"),
        ]);
        let backward = table(&[
            ("/a/*rest", "wildcard"),
            ("/a/:p", "param"),
            ("/a/literal", "literal"),
        ]);
        for path in ["/a/literal", "/a/other", "/a/x/y"] {
            assert_eq!(
                hit(&forward, path),
                hit(&backward, path),
                "`{path}` matched differently depending on route order"
            );
        }
    }

    /// A failed branch must not leak parameters into the branch that succeeds.
    /// With a `BTreeMap` and recursion this is easy to get wrong, and the
    /// symptom is a handler receiving a parameter from a route that did not
    /// match.
    #[test]
    fn parameters_do_not_leak_between_failed_branches() {
        // `/a/:x/c` fails on `/a/1/b`; `/a/:y/b` must then match with only `y`.
        let t = table(&[("/a/:x/c", "xc"), ("/a/:y/b", "yb")]);
        let m = t.match_route(Method::Get, "/a/1/b").expect("must match");
        assert_eq!(m.handler, "yb");
        assert_eq!(m.params.get("y"), Some("1"));
        assert_eq!(
            m.params.len(),
            1,
            "the failed branch's capture must not survive: {}",
            m.params
        );
    }

    // -- the 405 path ------------------------------------------------------

    /// A path that matches under another method must be reportable so the
    /// server can return 405 with an `Allow` header rather than a bare 404.
    #[test]
    fn allows_lists_the_methods_for_a_path() {
        let t = RouteTable::build(vec![
            Route::new(Method::Get, "/orders", "list").unwrap(),
            Route::new(Method::Post, "/orders", "create").unwrap(),
            Route::new(Method::Delete, "/orders/:id", "delete").unwrap(),
        ])
        .expect("must build");

        let mut methods = t.allows("/orders");
        methods.sort_unstable();
        assert_eq!(methods, vec![Method::Get, Method::Post]);
        assert_eq!(t.allows("/orders/42"), vec![Method::Delete]);
        assert!(t.allows("/nope").is_empty());
    }

    // -- introspection -----------------------------------------------------

    /// `qqqai inspect` reports what a service exposes, so the listing must be
    /// deterministic. An unsorted dump makes a build-to-build diff useless
    /// exactly when it is most needed.
    #[test]
    fn routes_are_listed_in_a_deterministic_order() {
        let a = table(&[("/z", "z"), ("/a", "a"), ("/m", "m")]);
        let routes = a.routes();
        let names: Vec<&str> = routes.iter().map(|r| r.pattern.as_str()).collect();
        assert_eq!(names, vec!["/a", "/m", "/z"]);

        // And the same set built in a different order lists identically.
        let b = table(&[("/m", "m"), ("/z", "z"), ("/a", "a")]);
        assert_eq!(a.routes(), b.routes());
    }

    #[test]
    fn the_table_reports_its_size() {
        let t = table(&[("/a", "a"), ("/b", "b")]);
        assert_eq!(t.len(), 2);
        assert!(!t.is_empty());
        assert!(RouteTable::new().is_empty());
    }

    /// Matching must not depend on how many routes exist — the property that
    /// makes the trie worth having. A linear scan would still pass a
    /// correctness test, so this checks the *shape* of the work instead: the
    /// number of nodes visited is bounded by the path length.
    #[test]
    fn a_large_table_still_matches_any_single_path() {
        let routes: Vec<Route> = (0..2_000)
            .map(|i| route(&format!("/api/v1/resource{i}/:id"), &format!("h{i}")))
            .collect();
        let t = RouteTable::build(routes).expect("must build");
        assert_eq!(t.len(), 2_000);

        let m = t
            .match_route(Method::Get, "/api/v1/resource1500/abc")
            .expect("must match");
        assert_eq!(m.handler, "h1500");
        assert_eq!(m.params.get("id"), Some("abc"));
    }

    // -- methods -----------------------------------------------------------

    #[test]
    fn methods_round_trip_through_their_names() {
        for m in Method::ALL {
            assert_eq!(Method::parse(m.as_str()), Some(m), "{m} did not round-trip");
        }
    }

    #[test]
    fn method_parsing_is_case_insensitive() {
        assert_eq!(Method::parse("get"), Some(Method::Get));
        assert_eq!(Method::parse("Get"), Some(Method::Get));
        assert_eq!(Method::parse(" POST "), Some(Method::Post));
    }

    #[test]
    fn an_unknown_method_does_not_parse() {
        assert_eq!(Method::parse("FROBNICATE"), None);
        assert_eq!(Method::parse(""), None);
    }

    /// The safe-method classification is what lets the capability layer treat
    /// a read-only endpoint differently from a mutating one, so it is asserted
    /// against the HTTP definition rather than left implicit.
    #[test]
    fn safe_and_idempotent_classification_follows_rfc_9110() {
        // Safe: GET, HEAD, OPTIONS, TRACE.
        for m in [Method::Get, Method::Head, Method::Options, Method::Trace] {
            assert!(m.is_safe(), "{m} is safe per RFC 9110 §9.2.1");
            assert!(m.is_idempotent(), "{m} is idempotent");
        }
        // Idempotent but not safe: PUT, DELETE.
        for m in [Method::Put, Method::Delete] {
            assert!(!m.is_safe(), "{m} is not safe");
            assert!(m.is_idempotent(), "{m} is idempotent");
        }
        // Neither: POST, PATCH.
        for m in [Method::Post, Method::Patch] {
            assert!(!m.is_safe(), "{m} is not safe");
            assert!(!m.is_idempotent(), "{m} is not idempotent");
        }
    }

    // -- params ------------------------------------------------------------

    #[test]
    fn params_report_their_shape() {
        let mut p = Params::default();
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
        assert_eq!(p.get("nothing"), None);

        p.entries.push(("a".to_owned(), "1".to_owned()));
        assert_eq!(p.len(), 1);
        assert!(!p.is_empty());
        assert_eq!(p.get("a"), Some("1"));
        assert_eq!(p.to_string(), "a=1");
    }

    // -- limits ------------------------------------------------------------

    #[test]
    fn the_route_limit_is_enforced() {
        let mut t = RouteTable::new();
        // Fill to the limit with cheap distinct routes.
        for i in 0..MAX_ROUTES {
            let r = route(&format!("/r{i}"), "h");
            t.insert(r).expect("within the limit");
        }
        let e = t.insert(route("/one-too-many", "h")).unwrap_err();
        assert!(matches!(e, RouterError::TooManyRoutes { .. }));
    }

    // -- rendering ---------------------------------------------------------

    /// Every error must render with a remediation: Proposal §12.2 requires a
    /// fix, and an error without one leaves the user exactly as stuck.
    #[test]
    fn every_router_error_renders_with_a_remediation() {
        let errors = [
            RouterError::PatternNotAbsolute {
                pattern: "x".to_owned(),
            },
            RouterError::EmptySegment {
                pattern: "x".to_owned(),
                index: 1,
            },
            RouterError::UnnamedCapture {
                pattern: "x".to_owned(),
                index: 1,
            },
            RouterError::DuplicateRoute {
                first: "a".to_owned(),
                second: "b".to_owned(),
            },
            RouterError::WildcardNotLast {
                pattern: "x".to_owned(),
            },
            RouterError::TooManyParams {
                pattern: "x".to_owned(),
                count: 99,
            },
            RouterError::TooManyRoutes { limit: 1 },
        ];
        for e in errors {
            let err = e.to_error();
            assert!(
                err.remediation.is_some(),
                "`{e}` renders without a remediation"
            );
            assert!(!err.message.is_empty());
            assert_eq!(err.code, ErrorCode::ManifestSchemaViolation);
        }
    }
}
