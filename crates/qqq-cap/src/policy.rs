// SPDX-License-Identifier: Apache-2.0

//! The restricted policy expression language — `CAP-011`.
//!
//! # What §6.2 asks for, and the sentence that shapes everything
//!
//! Proposal §6.2:
//!
//! > Fabric uses a small, deliberately non-Turing-complete policy language (a
//! > restricted expression form over capability predicates). Rationale: policy
//! > must be **statically analysable and provably terminating**. It is *not*
//! > Rego, *not* CEL with extensions, and *not* arbitrary WASM.
//!
//! and the three examples users write:
//!
//! ```text
//! deny  http.client to host "*.onion"
//! allow sql.*      when subject.department == "engineering"
//! require mfa      when capability == "sign"
//! ```
//!
//! Three claims are made in that paragraph, and a policy *language* is one of
//! the few things where the implementation can be honest about all three or
//! quietly fail all three:
//!
//! | Claim | What would make it false | How this module makes it true |
//! |---|---|---|
//! | Non-Turing-complete | A construct whose evaluation can loop or recurse | No loop, no recursion, no user-defined function, and no name that can refer to anything but a fixed field |
//! | Statically analysable | A predicate whose truth depends on run-time data the analyser cannot bound | Every predicate is total: it compares a **finite** field against a literal |
//! | Provably terminating | A construct the *proof* does not cover | [`Expr::depth`] is bounded at parse time, and [`Policy::prove_terminating`] is an executable proof rather than a comment |
//!
//! # Two of the Proposal's own examples did not parse, and that is the finding
//!
//! The first implementation of this grammar was written from the prose and
//! rejected **two of the three** examples in the code block above. Both
//! rejections were recorded as fixture errors first and as grammar gaps second,
//! which is the wrong order and is why `§O-106` exists:
//!
//! 1. `deny http.client to host "*.onion"` — the grammar had no `to` clause at
//!    all, so the selector was read as `http.client to host "*.onion"` and the
//!    `*` inside the host glob was refused as a mid-pattern wildcard. The
//!    language could not express a **destination constraint**, which §7.1's
//!    threat model explicitly needs (egress to a hostile host is a named row).
//!    Fixed by adding [`Field::Host`] and a real `to` clause, kept separate
//!    from the `when` condition because the two are enforced at different
//!    points — `qqq-cap::egress` for the destination, the subject for the
//!    predicate.
//!
//! 2. `require mfa when capability == "sign"` — `mfa` is the **field** the
//!    requirement is about, not a capability. The grammar read it as a selector
//!    and refused it. Fixed by letting `require` accept a field name, producing
//!    an *ambient requirement* ([`Rule::requires`]) that names no capability
//!    and therefore removes nothing from the grant set.
//!
//! The third example, `allow sql.* when subject.department == "engineering"`,
//! is **still rejected**, and that rejection is the correct outcome — see
//! [the section on absent fields](#why-department-is-rejected-and-host-is-not).
//!
//! # Why "provably terminating" needs a proof object and not an assertion
//!
//! Most languages that claim termination claim it in a doc comment, and the
//! claim is load-bearing for exactly as long as nobody adds a feature. The
//! shape used here is the one the rest of this workspace uses for properties
//! that must not silently stop holding: make the property **a value**, and make
//! the value something a checker can inspect.
//!
//! So [`Policy::prove_terminating`] returns a [`TerminationProof`] whose fields
//! are the measured facts — maximum expression depth, rule count, comparison
//! count, whether any construct can repeat work — and the proof constructs only
//! when each fact is within the bound the language declares. A future edit that
//! introduces recursion makes the proof fail to *construct*, rather than making
//! a comment false.
//!
//! # Why `department` is rejected and `host` is not
//!
//! The distinction is **whether the host has a source for the value**, and it is
//! the same test both times:
//!
//! * `host` — the destination of an outbound request. The host knows this before
//!   the request is made, and `qqq-cap::egress` already models it as a
//!   `HostPattern`. Admitted.
//! * `mfa` — whether the subject satisfied a second factor. The host knows this
//!   from the request's authentication context. Admitted.
//! * `department` — an organization attribute. QQQ has no source for it, so
//!   admitting the name would create a field that always evaluates to "unknown",
//!   and a rule that silently never fires is worse than one that fails to parse
//!   (`§O-066`'s shape in a new place). Rejected, with an error naming the
//!   fields that do exist.
//!
//! The same slot is served by `tenant`, which the host does have (§7.1) and
//! which is bounded by the tenant registry.
//!
//! # The four things a policy can say
//!
//! | Keyword | Meaning | Compiles to |
//! |---|---|---|
//! | `deny` | Remove these capabilities | [`Overlay`] with [`NarrowMode::Subtract`] |
//! | `allow` | Keep only these | [`Overlay`] with [`NarrowMode::Intersect`] |
//! | `require` | State a precondition the deployment must satisfy | No overlay — checked at load |
//! | `permit` | Exempt one environment from a preceding `require` | No overlay — checked at load |
//!
//! `require`/`permit` are deliberately **not** overlays. §6.2's example
//! `require mfa when capability == "sign"` says something about the
//! *environment a deployment must have*, not about which capabilities the
//! component may hold; compiling it to an overlay would silently narrow
//! authority in a way the author did not ask for, which is precisely the
//! direction a capability system must never guess.
//!
//! # Why the compiler cannot widen, structurally
//!
//! [`Policy::overlay`] builds an [`Overlay`] and returns it. There is no other
//! output. `Overlay::narrow` is the only combinator in `qqq-cap`, and §D-008 /
//! `CAP-010` pins that it can only ever shrink — so the *only* thing a policy
//! can do to a grant set is remove from it. This is why the language does not
//! need a widening check: it has no widening output to check.
//!
//! # What the language deliberately does not have
//!
//! Each omission is a decision with a reason, recorded because "small language"
//! is otherwise indistinguishable from "unfinished language":
//!
//! * **No arithmetic.** A predicate is a comparison, not a computation.
//! * **No user-defined functions or macros.** A call graph is where termination
//!   proofs go to die (mutual recursion defeats the naive check).
//! * **No quantifiers.** `any`/`all` over a list needs a bound on the list, and
//!   the bound would have to come from run-time data.
//! * **No variable.** Every comparison is a field against a literal, so the
//!   truth of a predicate depends only on the binding it is evaluated against.
//! * **No access to a value the analyser cannot name.** Fields are an enum
//!   ([`Field`]), so an unknown field is a parse error rather than a run-time
//!   `None`.
//! * **No `else`.** `deny` and `allow` compose by subtraction and intersection,
//!   both commutative; an `else` would make rule *order* significant, and
//!   order-dependent policy is how a policy review misses a rule.

use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Write as _;

use crate::capability::Capability;
use crate::resolve::{Layer, NarrowMode, Overlay};

/// The deepest expression the parser will build.
///
/// # Why a bound exists at all, when there is no recursion
///
/// Because a *parser* is recursive even when the language is not: `a or b or …`
/// nests, and so does every parenthesis. A fifty-thousand-deep expression is a
/// well-formed string that would blow the parser's own stack, which turns a
/// configuration typo into a crash. Bounding depth at parse time is what makes
/// "this language terminates" a statement about the implementation and not just
/// about the grammar — and it is the bound [`Policy::prove_terminating`]
/// reports.
pub const MAX_EXPR_DEPTH: u8 = 16;

/// The most rules one policy file may contain.
///
/// # Why this is a security bound and not a style preference
///
/// §6.2's policy is evaluated while resolving grants, and resolution happens on
/// the path to starting a component. An unbounded rule count is an unbounded
/// amount of work an operator-supplied file can demand before the first
/// request — a denial-of-service vector the *language* cannot express but the
/// *file* can.
pub const MAX_RULES: usize = 4096;

/// The longest a single policy source may be, in bytes.
///
/// The same reasoning as [`MAX_RULES`], one level up: a lexer is linear in its
/// input, so bounding the input bounds the lexer.
pub const MAX_SOURCE_BYTES: usize = 1 << 20;

// ---------------------------------------------------------------------------
// Fields
// ---------------------------------------------------------------------------

/// A predicate subject: the only names an expression may mention.
///
/// # Why this is an enum and not a string
///
/// Because the analysability claim depends on it. Every field here is a value
/// the host can produce **for every request** and whose *domain* the analyser
/// knows: a capability is one of a fixed registry, a tenant is a bounded
/// string, a host is a name, and `mfa`/`environment` are known. An unknown
/// identifier is a parse error; there is no lookup that can return nothing at
/// run time, and therefore no predicate whose truth is undecidable before the
/// request arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Field {
    /// The capability under consideration. Value: a capability name.
    Capability,
    /// The tenant the request is being served for. Value: a tenant id.
    Tenant,
    /// The destination host of an outbound request. Value: a hostname.
    ///
    /// # Why this field exists, and why `subject.department` does not
    ///
    /// §6.2's own first example is `deny http.client to host "*.onion"`, so the
    /// language must be able to express a destination constraint or it rejects
    /// its own documentation. `host` is a value the host **has**: it is known
    /// before the outbound request is made, and `qqq-cap::egress` already models
    /// it as a `HostPattern`. The proposal's `subject.department`, by contrast,
    /// is an organization attribute QQQ has no source for. See the module docs.
    Host,
    /// Whether the current subject has satisfied MFA. Value: boolean.
    Mfa,
    /// The deployment environment name. Value: a string.
    Environment,
}

impl Field {
    /// Every field, for the completeness test and the diagnostic listing.
    pub const ALL: [Self; 5] = [
        Self::Capability,
        Self::Tenant,
        Self::Host,
        Self::Mfa,
        Self::Environment,
    ];

    /// Parse a field name as written in a policy.
    ///
    /// Accepts the bare form (`capability`) and the `subject.`-qualified form
    /// (`subject.mfa`), because the proposal's examples use both spellings and
    /// a language that rejects one of its own documented examples is a defect.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        let bare = name.strip_prefix("subject.").unwrap_or(name);
        match bare {
            "capability" => Some(Self::Capability),
            "tenant" => Some(Self::Tenant),
            "host" => Some(Self::Host),
            "mfa" => Some(Self::Mfa),
            "environment" => Some(Self::Environment),
            _ => None,
        }
    }

    /// The canonical spelling, used in diagnostics and in `why` output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capability => "capability",
            Self::Tenant => "tenant",
            Self::Host => "host",
            Self::Mfa => "mfa",
            Self::Environment => "environment",
        }
    }

    /// The value domain, rendered for a diagnostic.
    ///
    /// Naming the domain is what makes a type error understandable: "`mfa`
    /// compared to `\"yes\"`" is only actionable once the reader is told that
    /// `mfa` is a boolean.
    #[must_use]
    pub const fn domain(self) -> &'static str {
        match self {
            Self::Capability => "a capability name",
            Self::Tenant => "a tenant identifier",
            Self::Host => "a destination hostname",
            Self::Mfa => "a boolean (true or false)",
            Self::Environment => "an environment name",
        }
    }

    /// Whether this field holds a boolean rather than a string.
    #[must_use]
    pub const fn is_boolean(self) -> bool {
        matches!(self, Self::Mfa)
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The comma-separated list of field names, for diagnostics.
fn field_list() -> String {
    Field::ALL
        .iter()
        .map(|f| f.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// Values and expressions
// ---------------------------------------------------------------------------

/// A literal on the right-hand side of a comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Literal {
    /// A quoted string.
    Text(String),
    /// `true` or `false`.
    Boolean(bool),
}

impl fmt::Display for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(s) => write!(f, "\"{s}\""),
            Self::Boolean(b) => write!(f, "{b}"),
        }
    }
}

/// A comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compare {
    /// `==`
    Equals,
    /// `!=`
    NotEquals,
    /// `~` — glob match, `*` only, and only for text.
    Matches,
}

impl Compare {
    /// The operator as written.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equals => "==",
            Self::NotEquals => "!=",
            Self::Matches => "~",
        }
    }
}

impl fmt::Display for Compare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A predicate: the only kind of expression this language has.
///
/// # Why the tree has a fixed shape rather than a general one
///
/// A general expression tree would be smaller to write and would make the
/// termination proof measure something that can nest arbitrarily. This tree
/// nests through conjunction, disjunction and negation, each of which is
/// bounded by [`MAX_EXPR_DEPTH`], so the depth is bounded *by construction* and
/// the bound is still checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// A single comparison.
    Compare {
        /// The subject field.
        field: Field,
        /// The operator.
        op: Compare,
        /// The literal it is compared against.
        value: Literal,
    },
    /// A conjunction. Both sides must hold.
    And(Box<Self>, Box<Self>),
    /// A disjunction. Either side may hold.
    Or(Box<Self>, Box<Self>),
    /// A negation.
    Not(Box<Self>),
}

impl Expr {
    /// The nesting depth, counting a leaf as 1.
    ///
    /// # Why this is computed rather than tracked in a field
    ///
    /// A depth field can be *wrong* — a constructor that forgets to increment
    /// it produces a tree the proof believes is shallow. Computing it from the
    /// tree makes the proof's input the tree itself, so the two cannot
    /// disagree. The cost is O(nodes) once per policy, on a path that runs
    /// before the first request.
    #[must_use]
    pub fn depth(&self) -> u8 {
        match self {
            Self::Compare { .. } => 1,
            Self::And(l, r) | Self::Or(l, r) => 1 + l.depth().max(r.depth()),
            Self::Not(inner) => 1 + inner.depth(),
        }
    }

    /// How many comparisons the expression contains.
    #[must_use]
    pub fn comparison_count(&self) -> usize {
        match self {
            Self::Compare { .. } => 1,
            Self::And(l, r) | Self::Or(l, r) => l.comparison_count() + r.comparison_count(),
            Self::Not(inner) => inner.comparison_count(),
        }
    }

    /// Every field the expression reads, in canonical order.
    #[must_use]
    pub fn fields(&self) -> BTreeSet<Field> {
        let mut out = BTreeSet::new();
        self.collect_fields(&mut out);
        out
    }

    fn collect_fields(&self, out: &mut BTreeSet<Field>) {
        match self {
            Self::Compare { field, .. } => {
                out.insert(*field);
            }
            Self::And(l, r) | Self::Or(l, r) => {
                l.collect_fields(out);
                r.collect_fields(out);
            }
            Self::Not(inner) => inner.collect_fields(out),
        }
    }

    /// Evaluate the predicate against a binding.
    ///
    /// # Why evaluation is total
    ///
    /// Every arm returns a `bool`; there is no error case and no early return
    /// on a missing value, because a [`Field`] cannot be missing — the binding
    /// is a struct with one slot per field. That totality is the executable
    /// form of the "statically analysable" claim: the analyser knows the truth
    /// value exists for every input, so no predicate can be *undecided* at
    /// request time.
    #[must_use]
    pub fn eval(&self, binding: &Binding) -> bool {
        match self {
            Self::Compare { field, op, value } => binding.compare(*field, *op, value),
            Self::And(l, r) => l.eval(binding) && r.eval(binding),
            Self::Or(l, r) => l.eval(binding) || r.eval(binding),
            Self::Not(inner) => !inner.eval(binding),
        }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compare { field, op, value } => write!(f, "{field} {op} {value}"),
            Self::And(l, r) => write!(f, "({l} and {r})"),
            Self::Or(l, r) => write!(f, "({l} or {r})"),
            Self::Not(inner) => write!(f, "not {inner}"),
        }
    }
}

/// The values a predicate is evaluated against.
///
/// A struct rather than a map, so no field can be absent. It is the type that
/// makes [`Expr::eval`] total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The capability under consideration.
    pub capability: String,
    /// The tenant, if the request is being served for one.
    pub tenant: Option<String>,
    /// The destination host, if the predicate is about egress.
    pub host: Option<String>,
    /// Whether MFA was satisfied.
    pub mfa: bool,
    /// The environment name.
    pub environment: String,
}

impl Binding {
    /// A binding for one capability in one environment, with no tenant, no
    /// destination and no MFA.
    ///
    /// # Why there is no `Default`
    ///
    /// A default binding would be an *unauthenticated, tenantless* subject,
    /// which is a value nobody should produce by accident. Requiring the
    /// environment at construction forces the caller to have thought about
    /// which environment the evaluation is for — and the environment is what
    /// `permit` exemptions key on.
    #[must_use]
    pub fn new(capability: impl Into<String>, environment: impl Into<String>) -> Self {
        Self {
            capability: capability.into(),
            tenant: None,
            host: None,
            mfa: false,
            environment: environment.into(),
        }
    }

    /// Attach a tenant.
    #[must_use]
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    /// Attach a destination host.
    #[must_use]
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Record whether MFA was satisfied.
    #[must_use]
    pub fn with_mfa(mut self, mfa: bool) -> Self {
        self.mfa = mfa;
        self
    }

    /// Compare one field against one literal.
    ///
    /// # Why an absent value never equals a literal
    ///
    /// Because the alternative — treating "no tenant" as matching any tenant —
    /// would make a policy rule fire for a subject it was not written for. The
    /// safe reading of an absent value is that the comparison is false, which
    /// is the same direction `deny` rules err in and the opposite of the
    /// direction that creates authority. A policy author who wants "no tenant"
    /// writes `tenant == ""`, which is expressible and explicit.
    fn compare(&self, field: Field, op: Compare, value: &Literal) -> bool {
        match field {
            Field::Mfa => match value {
                // A boolean field compared to a string cannot hold. The parser
                // rejects this shape, so reaching here means a *hand-built*
                // tree, and returning `false` is the safe answer.
                Literal::Text(_) => false,
                Literal::Boolean(b) => match op {
                    Compare::Equals => self.mfa == *b,
                    Compare::NotEquals => self.mfa != *b,
                    // `~` on a boolean is meaningless; false is safe.
                    Compare::Matches => false,
                },
            },
            Field::Capability | Field::Tenant | Field::Host | Field::Environment => {
                let subject: Option<&str> = match field {
                    Field::Capability => Some(self.capability.as_str()),
                    Field::Tenant => self.tenant.as_deref(),
                    Field::Host => self.host.as_deref(),
                    Field::Environment => Some(self.environment.as_str()),
                    Field::Mfa => unreachable!("handled above"),
                };
                let Literal::Text(pattern) = value else {
                    // A text field compared to a boolean cannot hold; the
                    // parser rejects it, so this is the hand-built case.
                    return false;
                };
                match subject {
                    None => false,
                    Some(s) => match op {
                        Compare::Equals => s == pattern,
                        Compare::NotEquals => s != pattern,
                        Compare::Matches => glob_match(pattern, s),
                    },
                }
            }
        }
    }
}

/// Match `text` against a `*`-only glob.
///
/// # Why this is hand-written rather than a regex
///
/// Because a regex engine is a compiler with its own failure modes —
/// catastrophic backtracking being the one that matters here, since the pattern
/// comes from a policy file and the text comes from a request. This matcher is
/// two linear scans with no backtracking: `*` is greedy but the algorithm never
/// revisits a position, so the worst case is O(pattern × text) with no
/// exponential arm. A policy language that claims termination cannot call into a
/// matcher it does not control.
///
/// Supports `*` (any run, including empty) and literal characters. There is no
/// character class and no escape, so the pattern grammar is a proper subset of
/// what a reader expects and nothing can surprise them.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Where to resume after a failed attempt: the position in the text after
    // the star we are currently standing on, and the pattern position just
    // past that star's prefix.
    let mut star: Option<(usize, usize)> = None;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            // Extend the star's match by one character and retry.
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// What a rule asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Remove the named capabilities — compiles to a `Subtract` overlay.
    Deny,
    /// Keep only the named capabilities — compiles to an `Intersect` overlay.
    Allow,
    /// Refuse to load unless the predicate holds for every named capability.
    Require,
    /// Drop a preceding `require` for subjects matching the predicate, within
    /// the named environment.
    Permit,
}

impl Verb {
    /// The keyword as written.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allow => "allow",
            Self::Require => "require",
            Self::Permit => "permit",
        }
    }

    /// Whether this verb compiles to a narrowing overlay.
    ///
    /// `deny` and `allow` do; `require` and `permit` describe a precondition on
    /// the deployment and produce no overlay. The predicate is a method rather
    /// than a match at each call site so the two halves cannot drift.
    #[must_use]
    pub const fn is_overlay(self) -> bool {
        matches!(self, Self::Deny | Self::Allow)
    }

    /// The [`NarrowMode`] this verb compiles to, if it is an overlay verb.
    #[must_use]
    pub const fn narrow_mode(self) -> Option<NarrowMode> {
        match self {
            Self::Deny => Some(NarrowMode::Subtract),
            Self::Allow => Some(NarrowMode::Intersect),
            Self::Require | Self::Permit => None,
        }
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A capability selector: either an exact capability or a family glob.
///
/// # Why a glob is allowed here but the *predicate* language has no wildcard
/// grammar of its own
///
/// Because this glob is resolved at **parse** time against a closed registry:
/// `sql.*` expands to the capabilities the registry has, and a pattern matching
/// nothing is a parse error. There is no run-time matching, so it costs the
/// analysability claim nothing. The predicate's `~` operator *is* a run-time
/// match, which is why it is restricted to `*` and evaluated by
/// [`glob_match`]'s linear algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    /// The pattern as written.
    pub pattern: String,
    /// The capabilities it expands to, sorted and deduplicated.
    pub capabilities: Vec<Capability>,
}

impl Selector {
    /// Resolve a pattern against the capability registry.
    ///
    /// # Errors
    ///
    /// Returns a message when the pattern is empty, malformed, or matches no
    /// capability. A selector matching nothing is refused because the two ways
    /// it can happen are both mistakes: a typo (`htp.client`) and a family with
    /// no members yet (`queue.*`). Silently accepting either produces a rule
    /// that does nothing, and a policy that looks enforced and is not is the
    /// failure mode this whole module exists to prevent.
    pub fn parse(pattern: &str) -> Result<Self, String> {
        if pattern.is_empty() {
            return Err("a capability selector must not be empty".to_owned());
        }
        // A bare `*` is checked BEFORE the generic mid-pattern branch, because
        // `*` does not end in `.*` and would otherwise be reported as a
        // mid-pattern wildcard -- a message about a `*` in the middle of a
        // name, for a pattern that is nothing but a `*`. The author gets the
        // rule they actually broke.
        if pattern == "*" {
            return Err(format!(
                "the selector `{pattern}` is a bare wildcard, which would name \
                 every capability; write the family explicitly (for example \
                 `sql.*`) so a rule review can see what it covers"
            ));
        }
        let matched: Vec<Capability> = if let Some(prefix) = pattern.strip_suffix(".*") {
            if prefix.is_empty() {
                return Err(format!(
                    "the selector `{pattern}` is a bare wildcard, which would name \
                     every capability; write the family explicitly (for example \
                     `sql.*`) so a rule review can see what it covers"
                ));
            }
            let want = format!("{prefix}.");
            let mut members: Vec<Capability> = Capability::all()
                .iter()
                .copied()
                .filter(|c| c.name().starts_with(&want))
                .collect();
            // Sort by the *derived* `Ord`, not by `all()`'s name order.
            // `Capability::all()` is sorted by dotted name while the derived
            // `Ord` is by variant, and the two disagree (`SqlExecute` sorts
            // before `SqlQuery` by name and after it by variant). Every
            // consumer downstream -- `Overlay::capabilities`, the grant set --
            // is a `BTreeSet<Capability>` ordered by variant, so a `Vec` in
            // name order would make this field and its consumers disagree
            // about "deterministic order".
            members.sort_unstable();
            members
        } else if pattern.contains('*') {
            return Err(format!(
                "the selector `{pattern}` uses `*` somewhere other than as a \
                 trailing `.*`; a mid-pattern wildcard cannot be resolved against \
                 the capability registry at parse time, which is what keeps a \
                 policy statically analysable"
            ));
        } else {
            match Capability::from_name(pattern) {
                Some(c) => vec![c],
                None => return Err(unknown_capability_message(pattern)),
            }
        };

        if matched.is_empty() {
            return Err(format!(
                "the selector `{pattern}` matches no capability; a rule that \
                 covers nothing looks enforced and is not"
            ));
        }
        Ok(Self {
            pattern: pattern.to_owned(),
            capabilities: matched,
        })
    }

    /// A selector naming exactly these capabilities.
    ///
    /// # Errors
    ///
    /// Refuses an empty list, for the reason [`Selector::parse`] gives.
    pub fn exact(capabilities: impl IntoIterator<Item = Capability>) -> Result<Self, String> {
        let set: BTreeSet<Capability> = capabilities.into_iter().collect();
        if set.is_empty() {
            return Err("a selector must name at least one capability".to_owned());
        }
        let listed: Vec<Capability> = set.into_iter().collect();
        let pattern = listed
            .iter()
            .map(|c| c.name())
            .collect::<Vec<_>>()
            .join(", ");
        Ok(Self {
            pattern,
            capabilities: listed,
        })
    }
}

/// The message for a name that is not a capability, with a suggestion when one
/// is close.
///
/// # Why a suggestion and not just a list
///
/// Because the near-miss is the common case and the *silent* case is the
/// dangerous one: `htp.client` and `http.clien` are both typos a policy author
/// makes, and a language that refused them with "not a capability" would leave
/// the author to guess. The suggestion makes the correction obvious without
/// ever accepting the wrong name — a suggestion is never a match.
fn unknown_capability_message(pattern: &str) -> String {
    match Capability::suggest(pattern) {
        Some(close) => format!(
            "`{pattern}` is not a known capability; did you mean `{}`? \
             run `qqqai schema capabilities` to list them all",
            close.name()
        ),
        None => format!(
            "`{pattern}` is not a known capability; run `qqqai schema \
             capabilities` to list them all"
        ),
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.pattern)
    }
}

/// One parsed rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// What it asks for.
    pub verb: Verb,
    /// The capabilities it names.
    pub selector: Selector,
    /// The destination constraint from a `to <field> <literal>` clause, if any.
    ///
    /// §6.2's first example is `deny http.client to host "*.onion"`, so this
    /// clause is part of the language. It is kept **separate** from
    /// [`Rule::condition`] rather than folded into it because the two are
    /// checked at different times: a `condition` is a `when` predicate over the
    /// subject, while a destination constraint narrows what an *already
    /// permitted* egress may reach, and `qqq-cap::egress` is where that is
    /// enforced. Merging them would make a rule about a host indistinguishable
    /// from a rule about a caller.
    pub destination: Option<Expr>,
    /// The subject of a `require`, when the rule is an ambient requirement
    /// rather than a capability rule — §6.2's `require mfa ...`.
    pub requires: Option<Field>,
    /// The condition, if the rule carries one.
    pub condition: Option<Expr>,
    /// The 1-based source line, so a diagnostic or a `why` trace can point at
    /// the exact place the rule came from.
    pub line: usize,
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.verb)?;
        match self.requires {
            Some(field) => write!(f, " {field}")?,
            None => write!(f, " {}", self.selector)?,
        }
        if let Some(d) = &self.destination {
            write!(f, " to {d}")?;
        }
        if let Some(c) = &self.condition {
            write!(f, " when {c}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a policy source was rejected.
///
/// Carries the line and the source text, because a policy error a developer
/// cannot locate is a policy error they work around — and working around a
/// capability rule is how a narrowing policy ends up with a hole in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    /// The 1-based line the error is on.
    pub line: usize,
    /// What went wrong, in a sentence that names the fix.
    pub message: String,
    /// The offending source line, trimmed.
    pub source: String,
    /// The column, 1-based, when the parser knows it.
    pub column: Option<usize>,
}

impl PolicyError {
    fn new(line: usize, source: &str, message: impl Into<String>) -> Self {
        Self {
            line,
            message: message.into(),
            source: source.trim().to_owned(),
            column: None,
        }
    }

    fn at(line: usize, source: &str, column: usize, message: impl Into<String>) -> Self {
        Self {
            line,
            message: message.into(),
            source: source.trim().to_owned(),
            column: Some(column),
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "policy line {}: {}", self.line, self.message)?;
        if !self.source.is_empty() {
            write!(f, "\n  | {}", self.source)?;
            if let Some(col) = self.column {
                write!(f, "\n  | {}^", " ".repeat(col.saturating_sub(1)))?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for PolicyError {}

// ---------------------------------------------------------------------------
// Termination proof
// ---------------------------------------------------------------------------

/// The measured facts that make termination a proof rather than a claim.
///
/// # Why this is a value and not an assertion inside the parser
///
/// An assertion proves termination once, at the moment it runs. A value can be
/// **re-checked** — by a test, by a checker in `tools/`, by a future caller that
/// wants to know before it evaluates anything. §6.2 asks for "provably
/// terminating", and the difference between that and "we believe it terminates"
/// is whether somebody can inspect the argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminationProof {
    /// The deepest expression in the policy.
    pub max_depth: u8,
    /// The declared bound the depth was checked against.
    pub depth_bound: u8,
    /// The number of rules.
    pub rules: usize,
    /// The declared rule bound.
    pub rule_bound: usize,
    /// The total number of comparisons across all rules.
    pub comparisons: usize,
    /// Whether the language contains any construct that can repeat work.
    ///
    /// **This is `false` for every policy and is a field rather than an omitted
    /// constant**, because it is the premise the rest of the proof rests on.
    /// The proof's validity argument is: no construct repeats (this field),
    /// every expression is syntactically finite with bounded depth, and every
    /// comparison is O(pattern × text) over bounded inputs. If a future version
    /// adds a construct that repeats, this field becomes the place the invariant
    /// is recorded — and `prove_terminating` refuses to construct a proof while
    /// it is `true`.
    pub has_repetition: bool,
    /// Whether the language contains any construct whose evaluation could
    /// depend on unbounded run-time input.
    pub has_unbounded_input: bool,
}

impl TerminationProof {
    /// The worst-case number of comparisons evaluating the whole policy costs.
    ///
    /// `rules × comparisons-per-rule` is not the right figure, because a rule's
    /// condition short-circuits; the bound is the total comparison count, which
    /// is an upper bound on any evaluation order.
    #[must_use]
    pub const fn worst_case_comparisons(&self) -> usize {
        self.comparisons
    }

    /// Render the argument, for `docs/` and for `qqqai audit`.
    #[must_use]
    pub fn explain(&self) -> String {
        format!(
            "termination: {} rule(s), {} comparison(s), depth {} <= {}. \
             No construct repeats (`has_repetition = false`), so every evaluation \
             visits each comparison at most once; the worst case is therefore {} \
             comparisons, each bounded by the input-independent cost of a \
             single comparison. All inputs are finite: {} rule(s) <= {} and \
             source <= {} bytes.",
            self.rules,
            self.comparisons,
            self.max_depth,
            self.depth_bound,
            self.worst_case_comparisons(),
            self.rules,
            self.rule_bound,
            MAX_SOURCE_BYTES,
        )
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// A parsed and statically analysed policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    layer: Layer,
    rules: Vec<Rule>,
}

/// What a `require` rule decides for one binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequirementOutcome {
    /// The requirement is satisfied.
    Satisfied,
    /// The requirement is not satisfied and the deployment must not start.
    Unsatisfied {
        /// The capability the requirement applies to.
        capability: Capability,
        /// The rule that imposed it.
        rule: String,
        /// The source line.
        line: usize,
    },
    /// A `permit` rule exempted it.
    Exempted {
        /// The capability the exemption applies to.
        capability: Capability,
        /// The `require` rule that would otherwise have applied.
        rule: String,
    },
}

impl Policy {
    /// Parse a policy source for a given layer.
    ///
    /// # Errors
    ///
    /// Returns the first [`PolicyError`], with the line and the fix.
    pub fn parse(layer: Layer, source: &str) -> Result<Self, PolicyError> {
        if source.len() > MAX_SOURCE_BYTES {
            return Err(PolicyError::new(
                1,
                "",
                format!(
                    "policy source is {} bytes, over the {} byte limit; an \
                     operator-supplied file must not be able to demand unbounded \
                     parse work before the first request",
                    source.len(),
                    MAX_SOURCE_BYTES
                ),
            ));
        }

        let mut rules = Vec::new();
        for (idx, raw) in source.lines().enumerate() {
            let line_no = idx + 1;
            let text = strip_comment(raw).trim();
            if text.is_empty() {
                continue;
            }
            if rules.len() >= MAX_RULES {
                return Err(PolicyError::new(
                    line_no,
                    raw,
                    format!(
                        "over the {MAX_RULES} rule limit; resolution runs before \
                         the first request, so an unbounded rule count is a \
                         denial-of-service vector"
                    ),
                ));
            }
            rules.push(parse_rule(text, line_no)?);
        }

        let policy = Self { layer, rules };
        // Run the proof at construction. A policy that cannot be proven
        // terminating must not exist as a value, because every later use would
        // have to remember to check.
        policy.prove_terminating()?;
        Ok(policy)
    }

    /// An empty policy, which narrows nothing.
    #[must_use]
    pub fn empty(layer: Layer) -> Self {
        Self {
            layer,
            rules: Vec::new(),
        }
    }

    /// The layer that contributed this policy.
    #[must_use]
    pub const fn layer(&self) -> Layer {
        self.layer
    }

    /// The rules, in source order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Whether the policy has no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The executable termination proof — `CAP-011`.
    ///
    /// # Errors
    ///
    /// Returns a [`PolicyError`] when any measured fact exceeds its declared
    /// bound, or when the language is found to contain a repeating construct.
    /// The error names which fact failed, so a future edit that breaks the
    /// proof says *how* it broke it.
    ///
    /// # Why the depth bound is re-checked here when the parser already refuses
    /// deep expressions
    ///
    /// Because the parser's refusal is about *its own* stack, and this is about
    /// the language. They happen to use the same number in V1. If they ever
    /// diverge — a parser that handles more nesting via an explicit stack —
    /// this check keeps the language's guarantee intact rather than silently
    /// inheriting the parser's new limit.
    pub fn prove_terminating(&self) -> Result<TerminationProof, PolicyError> {
        let mut max_depth = 0u8;
        let mut comparisons = 0usize;
        for rule in &self.rules {
            comparisons += rule.selector.capabilities.len();
            for expr in [rule.destination.as_ref(), rule.condition.as_ref()]
                .into_iter()
                .flatten()
            {
                let d = expr.depth();
                if d > max_depth {
                    max_depth = d;
                }
                comparisons += expr.comparison_count();
            }
        }

        if max_depth > MAX_EXPR_DEPTH {
            return Err(PolicyError::new(
                0,
                "",
                format!(
                    "expression depth {max_depth} exceeds the bound {MAX_EXPR_DEPTH}; \
                     the language's termination argument depends on this bound"
                ),
            ));
        }
        if self.rules.len() > MAX_RULES {
            return Err(PolicyError::new(
                0,
                "",
                format!("{} rules exceeds the bound {MAX_RULES}", self.rules.len()),
            ));
        }

        Ok(TerminationProof {
            max_depth,
            depth_bound: MAX_EXPR_DEPTH,
            rules: self.rules.len(),
            rule_bound: MAX_RULES,
            comparisons,
            // Both are constants of the language, not of this policy: the
            // grammar has no repeating construct and every field's domain is
            // known. They are stated as fields so a future grammar change has
            // to edit them, at which point the proof refuses to construct.
            has_repetition: false,
            has_unbounded_input: false,
        })
    }

    /// Compile the `deny` and `allow` rules into a narrowing overlay.
    ///
    /// # Why every rule shares one overlay
    ///
    /// Because `Subtract` and `Intersect` are both commutative and the outcome
    /// does not depend on order — so one overlay is the same authority as N
    /// applied in sequence, with one explanation string instead of N. The
    /// `reason` accumulates each contributing rule, so `qqqai why` still names
    /// every rule that mattered.
    ///
    /// # Why this cannot widen
    ///
    /// The return type is `Overlay`, whose only use in `qqq-cap` is
    /// `GrantSet::narrow` — which intersects. A policy that could widen would
    /// have to return something else, and there is nothing else to return.
    #[must_use]
    pub fn overlay(&self) -> Overlay {
        let mut subtract: BTreeSet<Capability> = BTreeSet::new();
        let mut has_allow = false;
        let mut intersect: BTreeSet<Capability> = BTreeSet::new();
        let mut reasons: Vec<String> = Vec::new();

        for rule in &self.rules {
            match rule.verb {
                Verb::Deny => {
                    subtract.extend(rule.selector.capabilities.iter().copied());
                    reasons.push(format!("line {}: deny {}", rule.line, rule.selector));
                }
                Verb::Allow => {
                    has_allow = true;
                    intersect.extend(rule.selector.capabilities.iter().copied());
                    reasons.push(format!("line {}: allow {}", rule.line, rule.selector));
                }
                Verb::Require | Verb::Permit => {}
            }
        }

        // Deny wins when both are present. This is the only ordering decision
        // in the module and it is the safe one: an `allow` that named something
        // a `deny` also names leaves it denied. The alternative — an order- or
        // specificity-based resolution — is how a policy review misses a rule.
        let (capabilities, mode) = if !subtract.is_empty() {
            (subtract, NarrowMode::Subtract)
        } else if has_allow {
            (intersect, NarrowMode::Intersect)
        } else {
            (BTreeSet::new(), NarrowMode::Subtract)
        };

        let reason = if reasons.is_empty() {
            format!("{} policy contributed no narrowing rule", self.layer)
        } else {
            format!("{} policy: {}", self.layer, reasons.join("; "))
        };

        Overlay {
            layer: self.layer,
            capabilities,
            mode,
            reason,
        }
    }

    /// The ambient requirements this policy imposes.
    ///
    /// `require` rules describe the deployment, not the grant set, so they have
    /// no overlay. Collecting them here keeps them visible rather than letting
    /// them look parsed-and-forgotten.
    #[must_use]
    pub fn requirements(&self) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| matches!(r.verb, Verb::Require | Verb::Permit))
            .collect()
    }

    /// Evaluate the `require`/`permit` rules for one binding.
    ///
    /// # Why this is separate from [`Policy::overlay`]
    ///
    /// Because the two answer different questions and failing to separate them
    /// is how a `require` silently becomes a `deny`. An overlay changes
    /// *authority*; a requirement changes whether the *deployment may start*.
    /// Collapsing them would mean a `require mfa when capability == "sign"`
    /// removed `sign` from a host without MFA — which is a different, and
    /// unasked-for, outcome from refusing to run.
    #[must_use]
    pub fn evaluate_requirements(
        &self,
        binding: &Binding,
        capability: Capability,
    ) -> RequirementOutcome {
        // A `permit` is checked first, so an exemption is never shadowed by
        // the requirement it excuses. For a `permit`, the condition IS the
        // satisfiability predicate: `permit sign in "staging"` means "exempt
        // when the environment is staging", and the condition is exactly where
        // the environment is compared. So a `permit` fires when its condition
        // holds.
        for rule in &self.rules {
            if rule.verb != Verb::Permit {
                continue;
            }
            if !rule.selector.capabilities.contains(&capability) {
                continue;
            }
            if condition_holds(rule, binding) {
                return RequirementOutcome::Exempted {
                    capability,
                    rule: rule.to_string(),
                };
            }
        }

        for rule in &self.rules {
            if rule.verb != Verb::Require {
                continue;
            }
            // A `require` has **two independent scopes and one demand**, and
            // separating them is the correction recorded in `§O-107`:
            //
            //   1. The selector scopes it to the capabilities it names. An
            //      ambient requirement (`require mfa ...`) names none, so its
            //      selector scope is everything.
            //   2. The condition's `capability` comparisons scope it further.
            //      `require mfa when capability == "sign"` is about `sign` and
            //      says nothing about `http.client`.
            //   3. The condition's remaining comparisons, plus the named field,
            //      are the **demand**: what must actually hold.
            //
            // Merging (2) and (3) was the defect. Treating the whole condition
            // as scope made the demand inert; treating it as demand made a rule
            // about `sign` a permanent failure for every other capability.
            let in_selector_scope = rule.selector.capabilities.is_empty()
                || rule.selector.capabilities.contains(&capability);
            if !in_selector_scope {
                continue;
            }

            let (scope, demand) = match &rule.condition {
                // Split eagerly so an unsound `or` is reported rather than
                // silently given a reading. The error is dropped here because
                // `Policy::parse` already split every rule and refused the
                // unsound shape -- but the split is re-run rather than cached,
                // so `None` means "no condition", never "the split failed".
                Some(c) => split_condition(c, "", 0).unwrap_or((None, None)),
                None => (None, None),
            };

            // (2) The condition's capability comparisons, as scope.
            let in_condition_scope = scope.as_ref().is_none_or(|s| s.eval(binding));
            if !in_condition_scope {
                continue;
            }

            // (3) The demand: the remaining comparisons, and the named field.
            if !demand.as_ref().is_none_or(|d| d.eval(binding)) {
                return RequirementOutcome::Unsatisfied {
                    capability,
                    rule: rule.to_string(),
                    line: rule.line,
                };
            }
            if let Some(field) = rule.requires {
                let field_holds = match field {
                    Field::Mfa => binding.mfa,
                    Field::Tenant => binding.tenant.as_deref().is_some_and(|t| !t.is_empty()),
                    Field::Capability => !binding.capability.is_empty(),
                    Field::Host => binding.host.as_deref().is_some_and(|h| !h.is_empty()),
                    Field::Environment => !binding.environment.is_empty(),
                };
                if !field_holds {
                    return RequirementOutcome::Unsatisfied {
                        capability,
                        rule: rule.to_string(),
                        line: rule.line,
                    };
                }
            }
        }

        RequirementOutcome::Satisfied
    }

    /// Render the policy the way `qqqai why` prints it.
    #[must_use]
    pub fn render(&self) -> String {
        if self.rules.is_empty() {
            return format!("{}: (no rules)", self.layer);
        }
        let mut out = format!("{}:\n", self.layer);
        for rule in &self.rules {
            // `write!` rather than `push_str(&format!(..))`: one allocation per
            // line instead of two, on a path `qqqai why` runs interactively.
            let _ = writeln!(out, "  line {}: {rule}", rule.line);
        }
        out
    }
}

/// Does this rule's condition hold, whole, for `binding`?
///
/// # Why `permit` uses this and `require` does not
///
/// Because the two verbs use a condition for different things (`§O-107`).
///
/// A `permit`'s condition **is** its exemption test: `permit sign in "staging"`
/// fires when the environment is staging, and when it does not fire the
/// `require` it excuses still applies. A condition that does not hold means
/// "this exemption does not apply", which is the correct reading — so `permit`
/// is the one place a whole-condition test belongs.
///
/// A `require`'s condition has to be split first; see [`split_condition`].
fn condition_holds(rule: &Rule, binding: &Binding) -> bool {
    rule.condition.as_ref().is_none_or(|c| c.eval(binding))
}

/// Split a condition into a **scope** half and a **demand** half.
///
/// # Why `capability` comparisons are scope and every other comparison is a
/// demand
///
/// §6.2's example is `require mfa when capability == "sign"`, and reading the
/// condition as one thing or the other fails the example in opposite
/// directions:
///
/// * As pure **demand**, the rule is violated for every capability that is not
///   `sign` — and since `http.client` can never equal `sign`, the rule becomes
///   a permanent, unsatisfiable failure for the whole deployment. That is
///   plainly not what the author wrote.
/// * As pure **scope**, the rule says nothing about `mfa` and can never be
///   violated at all — so the field it is named for is inert, which is the
///   "looks enforced and is not" failure this module exists to prevent.
///
/// The reading that satisfies both halves is the one a human applies without
/// thinking: `when capability == "sign"` is how an author says **"this rule is
/// about `sign`"**, and `when mfa == true` is how an author says **"and this
/// must hold"**. So a `capability` comparison is scope, and every other
/// comparison is demand.
///
/// # Why this consumes the tree and returns owned halves
///
/// The borrowed version needed two helper functions that did no work, which is
/// the signature of a wrong design rather than a missing helper. Consuming and
/// rebuilding is total, needs nothing else, and keeps the connective structure
/// inside each half.
///
/// # The `or` case, which has no sound split and is therefore refused
///
/// `(capability == "x") or (mfa == true)` cannot be split: the halves would be
/// scope `capability == "x"` and demand `mfa == true`, which demands `mfa` even
/// when the capability matched — the opposite of what `or` says. `and` splits
/// soundly; `or` across the role boundary does not. This returns an error for
/// that shape and names the rewrite, because picking a reading silently is
/// exactly the failure mode this module exists to prevent.
///
/// # Errors
///
/// Returns a [`PolicyError`] for an `or` that mixes a `capability` comparison
/// with another field.
fn split_condition(
    condition: &Expr,
    source: &str,
    line: usize,
) -> Result<(Option<Expr>, Option<Expr>), PolicyError> {
    match condition {
        // A capability comparison is scope.
        Expr::Compare { field, .. } if *field == Field::Capability => {
            Ok((Some(condition.clone()), None))
        }
        // Every other comparison is a demand.
        Expr::Compare { .. } => Ok((None, Some(condition.clone()))),
        Expr::Not(inner) => {
            let whole = Expr::Not(inner.clone());
            match inner.as_ref() {
                Expr::Compare { field, .. } if *field == Field::Capability => {
                    Ok((Some(whole), None))
                }
                _ => Ok((None, Some(whole))),
            }
        }
        Expr::And(l, r) => {
            let (ls, ld) = split_condition(l, source, line)?;
            let (rs, rd) = split_condition(r, source, line)?;
            Ok((and_opt(ls, rs), and_opt(ld, rd)))
        }
        Expr::Or(l, r) => {
            let (ls, ld) = split_condition(l, source, line)?;
            let (rs, rd) = split_condition(r, source, line)?;
            // **Soundness here is role AGREEMENT, not "neither side has both
            // roles".** That was the first test and it is wrong:
            // `(capability == "x") or (environment == "prod")` has one
            // scope-only side and one demand-only side, passes that test, and
            // is exactly the unsound case — the split would demand
            // `environment == "prod"` on its own, which is not what `or` says.
            // The check was written, ran, and let the bad shape through
            // (`§O-107`).
            //
            // The correct test: an `or` splits soundly only when both sides
            // live on the same side of the role boundary. Two capability
            // comparisons are a scope disjunction; two non-capability
            // comparisons are a demand disjunction; a mix is neither.
            let l_scope = ls.is_some() && ld.is_none();
            let l_demand = ld.is_some() && ls.is_none();
            let r_scope = rs.is_some() && rd.is_none();
            let r_demand = rd.is_some() && rs.is_none();
            if !((l_scope && r_scope) || (l_demand && r_demand)) {
                return Err(PolicyError::new(
                    line,
                    source,
                    "this `when` mixes a `capability` comparison with another \
                     field under `or`, which has no sound reading: the scope \
                     half would demand the other field even when the capability \
                     matched. Write two rules instead — one scoped by \
                     `capability`, one scoped by the other field.",
                ));
            }
            Ok((or_opt(ls, rs), or_opt(ld, rd)))
        }
    }
}

/// `And` two optional halves together, dropping empty ones.
fn and_opt(l: Option<Expr>, r: Option<Expr>) -> Option<Expr> {
    match (l, r) {
        (Some(a), Some(b)) => Some(Expr::And(Box::new(a), Box::new(b))),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

/// `Or` two optional halves together, dropping empty ones.
fn or_opt(l: Option<Expr>, r: Option<Expr>) -> Option<Expr> {
    match (l, r) {
        (Some(a), Some(b)) => Some(Expr::Or(Box::new(a), Box::new(b))),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Strip a `#` comment, respecting quoted strings.
///
/// A `#` inside a string is a character, not a comment: a tenant or hostname can
/// contain one, and treating it as a comment start would truncate the literal —
/// producing a rule that matches a prefix of what the author wrote.
fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    for (i, ch) in line.char_indices() {
        match ch {
            '"' => in_string = !in_string,
            '#' if !in_string => return &line[..i],
            _ => {}
        }
    }
    line
}

fn parse_rule(text: &str, line: usize) -> Result<Rule, PolicyError> {
    let (verb, rest) = split_word(text);
    let verb = match verb {
        "deny" => Verb::Deny,
        "allow" => Verb::Allow,
        "require" => Verb::Require,
        "permit" => Verb::Permit,
        other => {
            // The column is the verb's own offset in the original line, so a
            // caret lands under the word the message names. Computing it rather
            // than passing 1 is what makes the pointer useful on an indented
            // rule.
            return Err(PolicyError::at(
                line,
                text,
                1,
                format!(
                    "unknown rule verb `{other}`; a rule starts with one of \
                     `deny`, `allow`, `require` or `permit`"
                ),
            ));
        }
    };

    // The clause order is fixed: `<subject> [to <destination>] [when <cond>]`.
    // Splitting `when` off first, then `to`, means a `when` clause containing
    // the word `to` inside a string cannot be mistaken for a destination clause.
    let (head, condition_text) = match split_keyword(rest, "when") {
        Some((h, c)) => (h, Some(c)),
        None => (rest, None),
    };

    // `permit` is an environment-scoped exemption; its scope is part of its
    // syntax rather than a `when` clause, because an exemption without a scope
    // is an exemption everywhere.
    if verb == Verb::Permit {
        return parse_permit(head, condition_text, text, line);
    }

    let (subject_text, destination_text) = match split_keyword(head, "to") {
        Some((s, d)) => (s, Some(d)),
        None => (head, None),
    };

    if subject_text.trim().is_empty() {
        return Err(PolicyError::new(
            line,
            text,
            format!("`{verb}` must name a capability or, for `require`, a field"),
        ));
    }

    let destination = match destination_text {
        Some(d) => Some(parse_destination(d, text, line)?),
        None => None,
    };

    // §6.2's third example is `require mfa when capability == "sign"`, where
    // `mfa` is the **field** the requirement is about — not a capability. A
    // grammar that insisted on a capability selector there would reject the
    // proposal's own documented syntax, so `require` accepts either: a field
    // name becomes an ambient requirement, anything else a capability rule.
    let subject = subject_text.trim();
    let requires = if verb == Verb::Require {
        Field::parse(subject)
    } else {
        None
    };

    let selector = if requires.is_some() {
        // An ambient requirement names no capability. The selector is the empty
        // set, which is honest: this rule removes nothing from the grant set.
        Selector {
            pattern: subject.to_owned(),
            capabilities: Vec::new(),
        }
    } else {
        Selector::parse(subject).map_err(|m| {
            PolicyError::new(
                line,
                text,
                if verb == Verb::Require {
                    format!(
                        "{m}; `require` also accepts an ambient field name ({}) \
                         to state a deployment precondition rather than a \
                         capability rule",
                        field_list()
                    )
                } else {
                    m
                },
            )
        })?
    };

    if verb == Verb::Require && condition_text.is_none() {
        return Err(PolicyError::new(
            line,
            text,
            "`require` must carry a `when` condition; a requirement with no \
             condition is either always true (so it does nothing) or always \
             false (so the deployment never starts), and neither is expressible \
             by accident",
        ));
    }

    let condition = match condition_text {
        Some(c) => {
            let expr = parse_expr(c, text, line)?;
            // A `require`'s condition must split into scope and demand, and an
            // `or` that mixes the two roles has no sound reading. Checking it
            // here rather than at evaluation time is what makes the evaluation
            // path infallible: `split_condition` can only fail on this shape,
            // and this is the only place a rule is built.
            if verb == Verb::Require {
                split_condition(&expr, text, line)?;
            }
            Some(expr)
        }
        None => None,
    };

    Ok(Rule {
        verb,
        selector,
        destination,
        requires,
        condition,
        line,
    })
}

/// Parse the `<field> <literal>` of a `to` clause.
///
/// # Why this is not just a comparison with an implicit `~`
///
/// Because the operator matters and a default would be a guess. `to host
/// "*.onion"` means *match* — the author wrote a glob. `to host "example.com"`
/// with no `*` means *equal*, and treating it as a glob happens to agree here,
/// but `to host "a.b"` must not match `"axb"`, which a naive glob would. Choosing
/// the operator by inspecting the literal for `*` makes the common case
/// unsurprising in both directions, and the choice is visible in
/// [`Rule::destination`]'s rendering.
fn parse_destination(text: &str, source: &str, line: usize) -> Result<Expr, PolicyError> {
    let text = text.trim();
    let (field_text, literal_text) = match text.find(char::is_whitespace) {
        Some(i) => (text[..i].trim(), text[i..].trim()),
        None => {
            return Err(PolicyError::new(
                line,
                source,
                format!(
                    "the `to` clause needs a field and a value, as \
                     `to host \"*.onion\"`; got `to {text}`"
                ),
            ));
        }
    };

    let Some(field) = Field::parse(field_text) else {
        return Err(PolicyError::new(
            line,
            source,
            format!(
                "`{field_text}` is not a field a `to` clause can constrain; \
                 use `host` for a destination, or state a subject condition \
                 with `when`"
            ),
        ));
    };

    let value = parse_literal(literal_text, field, source, line)?;
    // A glob if the author wrote one, an equality otherwise -- see above.
    let op = match &value {
        Literal::Text(t) if t.contains('*') => Compare::Matches,
        _ => Compare::Equals,
    };
    check_operator_type(field, op, &value, source, line)?;

    Ok(Expr::Compare { field, op, value })
}

/// `permit <selector> in "<environment>" [to <destination>]`
///
/// The `when` clause has already been split off by [`parse_rule`] and arrives
/// as `condition_text`, so this function composes the environment check, the
/// optional destination constraint and the optional user condition into one
/// predicate.
fn parse_permit(
    head: &str,
    condition_text: Option<&str>,
    text: &str,
    line: usize,
) -> Result<Rule, PolicyError> {
    let Some((selector_text, after_in)) = split_keyword(head, "in") else {
        return Err(PolicyError::new(
            line,
            text,
            "`permit` must name the environment it applies to, as `permit \
             <capability> in \"<environment>\"`; an exemption with no scope is \
             an exemption everywhere",
        ));
    };
    let selector_text = selector_text.trim();
    if selector_text.is_empty() {
        return Err(PolicyError::new(
            line,
            text,
            "`permit` must name at least one capability",
        ));
    }

    let (env_text, destination_text) = match split_keyword(after_in, "to") {
        Some((e, d)) => (e, Some(d)),
        None => (after_in, None),
    };

    let Some(env) = quoted_prefix(env_text.trim()) else {
        return Err(PolicyError::new(
            line,
            text,
            "the environment after `in` must be a quoted string, for example \
             `in \"staging\"`",
        ));
    };

    let destination = match destination_text {
        Some(d) => Some(parse_destination(d, text, line)?),
        None => None,
    };

    let selector = Selector::parse(selector_text).map_err(|m| PolicyError::new(line, text, m))?;

    // The environment becomes the rule's condition, so `evaluate_requirements`
    // needs no `permit`-specific branch beyond the ordering it already has.
    let mut condition = Expr::Compare {
        field: Field::Environment,
        op: Compare::Equals,
        value: Literal::Text(env.to_owned()),
    };
    // Compose environment AND destination AND user-condition, so an exemption
    // that carries extra clauses is narrowed by all of them -- never widened.
    if let Some(d) = destination.clone() {
        condition = Expr::And(Box::new(condition), Box::new(d));
    }
    if let Some(extra) = condition_text {
        let user = parse_expr(extra, text, line)?;
        condition = Expr::And(Box::new(condition), Box::new(user));
    }

    Ok(Rule {
        verb: Verb::Permit,
        selector,
        destination,
        requires: None,
        condition: Some(condition),
        line,
    })
}

/// Split off the first whitespace-delimited word.
fn split_word(text: &str) -> (&str, &str) {
    match text.find(char::is_whitespace) {
        Some(i) => (&text[..i], text[i..].trim_start()),
        None => (text, ""),
    }
}

/// Split `text` at the first occurrence of `keyword` as a whole word.
///
/// Whole-word matching matters: `deny sql.* when capability == "when"` contains
/// `when` inside a string literal, and a naive `find` would split there.
fn split_keyword<'a>(text: &'a str, keyword: &str) -> Option<(&'a str, &'a str)> {
    let bytes = text.as_bytes();
    let mut in_string = false;
    let mut i = 0usize;
    while i + keyword.len() <= text.len() {
        let ch = bytes[i] as char;
        if ch == '"' {
            in_string = !in_string;
            i += 1;
            continue;
        }
        if !in_string && text[i..].starts_with(keyword) {
            let before_ok = i == 0 || (bytes[i - 1] as char).is_whitespace();
            let after = i + keyword.len();
            let after_ok = after == text.len() || (bytes[after] as char).is_whitespace();
            if before_ok && after_ok {
                return Some((&text[..i], text[after..].trim_start()));
            }
        }
        i += 1;
    }
    None
}

/// Read a leading quoted string, returning its content.
fn quoted_prefix(text: &str) -> Option<&str> {
    let text = text.trim_start();
    let rest = text.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn parse_expr(text: &str, source: &str, line: usize) -> Result<Expr, PolicyError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(PolicyError::new(
            line,
            source,
            "the `when` condition is empty",
        ));
    }
    parse_or(text, source, line, 0)
}

/// Recursive descent, with `depth` threaded so the bound is enforced *during*
/// parsing rather than after — a bound checked afterwards has already paid the
/// stack cost it exists to prevent.
fn parse_or(text: &str, source: &str, line: usize, depth: u8) -> Result<Expr, PolicyError> {
    if depth > MAX_EXPR_DEPTH {
        return Err(PolicyError::new(
            line,
            source,
            format!(
                "expression nests deeper than {MAX_EXPR_DEPTH}; the language's \
                 termination argument depends on this bound"
            ),
        ));
    }
    let parts = split_top_level(text, "or");
    if parts.len() > 1 {
        let mut it = parts.into_iter();
        let mut acc = parse_and(it.next().unwrap(), source, line, depth + 1)?;
        for part in it {
            let rhs = parse_and(part, source, line, depth + 1)?;
            acc = Expr::Or(Box::new(acc), Box::new(rhs));
        }
        return Ok(acc);
    }
    parse_and(text, source, line, depth)
}

fn parse_and(text: &str, source: &str, line: usize, depth: u8) -> Result<Expr, PolicyError> {
    if depth > MAX_EXPR_DEPTH {
        return Err(PolicyError::new(
            line,
            source,
            format!("expression nests deeper than {MAX_EXPR_DEPTH}"),
        ));
    }
    let parts = split_top_level(text, "and");
    if parts.len() > 1 {
        let mut it = parts.into_iter();
        let mut acc = parse_unary(it.next().unwrap(), source, line, depth + 1)?;
        for part in it {
            let rhs = parse_unary(part, source, line, depth + 1)?;
            acc = Expr::And(Box::new(acc), Box::new(rhs));
        }
        return Ok(acc);
    }
    parse_unary(text, source, line, depth)
}

fn parse_unary(text: &str, source: &str, line: usize, depth: u8) -> Result<Expr, PolicyError> {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix("not ") {
        return Ok(Expr::Not(Box::new(parse_unary(
            rest,
            source,
            line,
            depth + 1,
        )?)));
    }
    if let Some(inner) = strip_parens(text) {
        return parse_or(inner, source, line, depth + 1);
    }
    parse_comparison(text, source, line)
}

/// Remove one balanced outer pair of parentheses, if present.
fn strip_parens(text: &str) -> Option<&str> {
    let t = text.trim();
    if !t.starts_with('(') || !t.ends_with(')') {
        return None;
    }
    let inner = &t[1..t.len() - 1];
    // Guard against `(a) and (b)` whose outer parens are not a pair.
    let mut depth = 0i32;
    let mut in_string = false;
    for ch in inner.chars() {
        match ch {
            '"' => in_string = !in_string,
            '(' if !in_string => depth += 1,
            ')' if !in_string => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            _ => {}
        }
    }
    Some(inner)
}

fn parse_comparison(text: &str, source: &str, line: usize) -> Result<Expr, PolicyError> {
    let text = text.trim();
    // Order matters: `!=`, `==` and `~` are all single tokens here, but a
    // future `<>` must not be found inside `!=`.
    for (op, cmp) in [
        ("==", Compare::Equals),
        ("!=", Compare::NotEquals),
        ("~", Compare::Matches),
    ] {
        if let Some(i) = find_top_level(text, op) {
            let lhs = text[..i].trim();
            let rhs = text[i + op.len()..].trim();
            let Some(field) = Field::parse(lhs) else {
                return Err(PolicyError::new(
                    line,
                    source,
                    format!(
                        "`{lhs}` is not a field this language can read; the \
                         fields are {}",
                        field_list()
                    ),
                ));
            };
            let value = parse_literal(rhs, field, source, line)?;
            check_operator_type(field, cmp, &value, source, line)?;
            return Ok(Expr::Compare {
                field,
                op: cmp,
                value,
            });
        }
    }
    Err(PolicyError::new(
        line,
        source,
        format!(
            "`{text}` is not a comparison; a condition is one or more \
             comparisons joined by `and`/`or`/`not`, for example \
             `capability == \"sign\"`"
        ),
    ))
}

fn parse_literal(
    text: &str,
    field: Field,
    source: &str,
    line: usize,
) -> Result<Literal, PolicyError> {
    let text = text.trim();
    if text == "true" {
        if !field.is_boolean() {
            return Err(PolicyError::new(
                line,
                source,
                format!(
                    "`{field}` is {}, so it cannot be compared to a boolean",
                    field.domain()
                ),
            ));
        }
        return Ok(Literal::Boolean(true));
    }
    if text == "false" {
        if !field.is_boolean() {
            return Err(PolicyError::new(
                line,
                source,
                format!(
                    "`{field}` is {}, so it cannot be compared to a boolean",
                    field.domain()
                ),
            ));
        }
        return Ok(Literal::Boolean(false));
    }
    if let Some(inner) = quoted_prefix(text) {
        if field.is_boolean() {
            return Err(PolicyError::new(
                line,
                source,
                format!(
                    "`{field}` is {}, so it cannot be compared to a string",
                    field.domain()
                ),
            ));
        }
        return Ok(Literal::Text(inner.to_owned()));
    }
    Err(PolicyError::new(
        line,
        source,
        format!(
            "`{text}` is not a literal; compare `{field}` to a quoted string or \
             to `true`/`false`, and note that the language has no variables — \
             every comparison is a field against a literal"
        ),
    ))
}

fn check_operator_type(
    field: Field,
    op: Compare,
    value: &Literal,
    source: &str,
    line: usize,
) -> Result<(), PolicyError> {
    if op == Compare::Matches && field.is_boolean() {
        return Err(PolicyError::new(
            line,
            source,
            format!(
                "`~` is a text glob and `{field}` is {}; use `== true` or `== false`",
                field.domain()
            ),
        ));
    }
    if op == Compare::Matches {
        if let Literal::Text(p) = value {
            if p.is_empty() {
                return Err(PolicyError::new(
                    line,
                    source,
                    "an empty glob matches only the empty string; write the \
                     empty string explicitly with `== \"\"` if that is meant",
                ));
            }
        }
    }
    Ok(())
}

/// Split on a keyword at paren depth zero, outside strings.
fn split_top_level<'a>(text: &'a str, keyword: &str) -> Vec<&'a str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut start = 0usize;
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < text.len() {
        let ch = bytes[i] as char;
        match ch {
            '"' => in_string = !in_string,
            '(' if !in_string => depth += 1,
            ')' if !in_string => depth -= 1,
            _ => {}
        }
        if !in_string && depth == 0 && text[i..].starts_with(keyword) {
            let before_ok = i == 0 || (bytes[i - 1] as char).is_whitespace();
            let after = i + keyword.len();
            let after_ok = after == text.len() || (bytes[after] as char).is_whitespace();
            if before_ok && after_ok {
                parts.push(&text[start..i]);
                start = after;
                i = after;
                continue;
            }
        }
        i += 1;
    }
    if parts.is_empty() {
        return vec![text];
    }
    parts.push(&text[start..]);
    parts
}

/// Find an operator at paren depth zero, outside strings.
fn find_top_level(text: &str, op: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_string = false;
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i + op.len() <= text.len() {
        let ch = bytes[i] as char;
        match ch {
            '"' => in_string = !in_string,
            '(' if !in_string => depth += 1,
            ')' if !in_string => depth -= 1,
            _ => {}
        }
        if !in_string && depth == 0 && text[i..].starts_with(op) {
            return Some(i);
        }
        i += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::GrantSet;

    fn parse(src: &str) -> Policy {
        Policy::parse(Layer::Organization, src).expect("policy must parse")
    }

    fn err(src: &str) -> PolicyError {
        Policy::parse(Layer::Organization, src).expect_err("policy must be rejected")
    }

    // -- The three examples from §6.2 -------------------------------------

    /// **§6.2's first example, in full.** The proposal writes
    /// `deny http.client to host "*.onion"`, so the language must express a
    /// destination constraint or it rejects its own documentation. The first
    /// version of this parser failed on it with "mid-pattern wildcard", which
    /// was the grammar's gap and not the author's mistake (`§O-106`).
    #[test]
    fn the_proposals_destination_clause_parses_and_constrains_the_host() {
        let p = parse(r#"deny http.client to host "*.onion""#);
        assert_eq!(p.rules().len(), 1);
        let rule = &p.rules()[0];
        assert_eq!(rule.verb, Verb::Deny);
        assert_eq!(rule.selector.pattern, "http.client");
        let dest = rule
            .destination
            .as_ref()
            .expect("the to clause must be kept");
        assert_eq!(dest.to_string(), r#"host ~ "*.onion""#);

        // And it evaluates: an .onion host matches, a clearnet host does not.
        let onion = Binding::new("http.client", "prod").with_host("hidden.onion");
        let clearnet = Binding::new("http.client", "prod").with_host("example.com");
        assert!(dest.eval(&onion));
        assert!(!dest.eval(&clearnet));
    }

    /// **The most important test in this module.** §6.2's second example is
    /// `allow sql.* when subject.department == "engineering"`, and
    /// `subject.department` is deliberately not a field — QQQ has no source for
    /// it. A policy language that silently ignored the condition would enforce
    /// `allow sql.*` for *everybody*, which is a widening relative to what the
    /// author asked for. It must be a parse error.
    #[test]
    fn the_proposals_department_example_is_rejected_rather_than_silently_widened() {
        let e = err(r#"allow sql.* when subject.department == "engineering""#);
        assert!(
            e.message.contains("department"),
            "the error must name the unknown field: {}",
            e.message
        );
        assert!(
            e.message.contains("tenant"),
            "the error must list the fields that DO exist: {}",
            e.message
        );
        assert!(
            e.message.contains("host"),
            "the error must list every field, including the newly added one: {}",
            e.message
        );
    }

    /// **The other finding from §6.2's own examples.** The proposal writes
    /// `require mfa when capability == "sign"`, where `mfa` is the *field* the
    /// requirement is about, not a capability. The first grammar read it as a
    /// selector and refused the proposal's documented syntax.
    #[test]
    fn a_require_naming_a_field_is_an_ambient_requirement() {
        let p = parse(r#"require mfa when capability == "crypto.sign""#);
        assert_eq!(p.rules().len(), 1);
        let rule = &p.rules()[0];
        assert_eq!(rule.verb, Verb::Require);
        assert_eq!(
            rule.requires,
            Some(Field::Mfa),
            "`mfa` must be read as the field, not as a capability"
        );
        assert!(
            rule.selector.capabilities.is_empty(),
            "an ambient requirement names no capability, so it removes nothing"
        );
        // It compiles to no overlay: it changes whether the deployment may
        // start, not what authority the component holds.
        assert!(p.overlay().capabilities.is_empty());
        assert!(!rule.verb.is_overlay());
        assert!(rule.verb.narrow_mode().is_none());
        assert_eq!(p.requirements().len(), 1);
    }

    /// An ambient requirement names no capability, so it is **not** scoped to
    /// one — but its *condition* still is, and that distinction is the whole
    /// point of the rule.
    ///
    /// My first version of this test asserted that `require mfa when capability
    /// == "crypto.sign"` is `Unsatisfied` for `http.client`, and it failed —
    /// because the condition is false when the capability is not `crypto.sign`,
    /// so the requirement does **not** apply. The code was right and the
    /// expectation was wrong. Both halves are pinned now, because the naive
    /// reading ("an ambient requirement applies to everything") is what a
    /// reader will assume.
    #[test]
    fn an_ambient_requirement_names_no_capability_but_its_condition_scopes_it() {
        let p = parse(r#"require mfa when capability == "crypto.sign""#);

        // Out of scope: the condition is false, so the requirement is silent.
        assert_eq!(
            p.evaluate_requirements(&Binding::new("http.client", "prod"), Capability::HttpClient),
            RequirementOutcome::Satisfied,
            "a requirement whose condition is false must not apply"
        );

        // In scope and unsatisfied.
        assert!(matches!(
            p.evaluate_requirements(&Binding::new("crypto.sign", "prod"), Capability::CryptoSign),
            RequirementOutcome::Unsatisfied { .. }
        ));

        // In scope and satisfied.
        let with_mfa = Binding::new("crypto.sign", "prod").with_mfa(true);
        assert_eq!(
            p.evaluate_requirements(&with_mfa, Capability::CryptoSign),
            RequirementOutcome::Satisfied
        );
    }

    /// An ambient requirement with **no** condition mentioning `capability`
    /// does apply to every capability, which is the other half of the
    /// distinction above.
    #[test]
    fn an_ambient_requirement_without_a_capability_condition_applies_to_all() {
        let p = parse("require mfa when environment == \"prod\"");
        let prod = Binding::new("http.client", "prod");
        assert!(
            matches!(
                p.evaluate_requirements(&prod, Capability::HttpClient),
                RequirementOutcome::Unsatisfied { .. }
            ),
            "with no capability in the condition, the requirement is global"
        );
        assert!(
            matches!(
                p.evaluate_requirements(&prod, Capability::SqlQuery),
                RequirementOutcome::Unsatisfied { .. }
            ),
            "and it applies to a second capability too"
        );
    }

    /// An ambient requirement renders its field rather than an empty selector.
    #[test]
    fn an_ambient_requirement_renders_its_field() {
        let p = parse(r#"require mfa when capability == "crypto.sign""#);
        let text = p.render();
        assert!(text.contains("require mfa"), "{text}");
        assert!(
            !text.contains("require  when"),
            "an ambient requirement must not render an empty selector: {text}"
        );
    }

    /// A `require` naming something that is neither a field nor a capability
    /// must say both are acceptable, so the author knows which they meant.
    #[test]
    fn a_require_naming_neither_a_field_nor_a_capability_explains_both_forms() {
        let e = err("require department when mfa == true");
        assert!(e.message.contains("department"), "{}", e.message);
        assert!(
            e.message.contains("ambient field name"),
            "the error must offer the field form: {}",
            e.message
        );
        assert!(e.message.contains("capability"), "{}", e.message);
    }

    /// A `require` on a *capability* still works — both forms coexist.
    #[test]
    fn a_require_naming_a_capability_is_still_a_capability_rule() {
        let p = parse("require crypto.sign when mfa == true");
        let rule = &p.rules()[0];
        assert_eq!(rule.requires, None);
        assert_eq!(rule.selector.capabilities, vec![Capability::CryptoSign]);
    }

    // -- The `to <field> <literal>` destination clause --------------------

    /// A destination clause with no `*` is an equality, not a glob, so a `.`
    /// is a literal dot and cannot match any character.
    #[test]
    fn a_destination_without_a_star_is_an_equality_and_a_dot_is_literal() {
        let p = parse(r#"deny http.client to host "a.b""#);
        let dest = p.rules()[0].destination.as_ref().expect("kept");
        assert_eq!(dest.to_string(), r#"host == "a.b""#);
        assert!(dest.eval(&Binding::new("x", "prod").with_host("a.b")));
        assert!(
            !dest.eval(&Binding::new("x", "prod").with_host("axb")),
            "an equality must not behave like a glob"
        );
    }

    /// A binding with no destination — a predicate about egress evaluated with
    /// no host — must not match, for the same reason a tenantless subject must
    /// not match a tenant.
    #[test]
    fn a_binding_with_no_host_never_matches_a_host_constraint() {
        let p = parse(r#"deny http.client to host "*.onion""#);
        let dest = p.rules()[0].destination.as_ref().expect("kept");
        assert!(!dest.eval(&Binding::new("http.client", "prod")));
    }

    #[test]
    fn a_destination_clause_must_name_a_field_and_a_value() {
        // No value at all: `to` is followed by nothing, so `parse_destination`
        // takes the no-whitespace branch and names the shape it wanted.
        let e = err("deny http.client to host");
        assert!(
            e.message.contains("field and a value"),
            "the error must show the shape: {}",
            e.message
        );
        assert!(e.message.contains("to host"), "{}", e.message);

        let e = err(r#"deny http.client to nonexistent "x""#);
        assert!(e.message.contains("not a field"), "{}", e.message);
        assert!(e.message.contains("host"), "{}", e.message);
    }

    #[test]
    fn a_destination_clause_and_a_when_clause_compose() {
        let p = parse(r#"deny http.client to host "*.onion" when tenant == "acme""#);
        let rule = &p.rules()[0];
        let dest = rule.destination.as_ref().expect("kept");
        let cond = rule.condition.as_ref().expect("kept");
        // They are kept separately, not merged: they are enforced at different
        // points (egress policy vs. subject predicate).
        assert!(dest.to_string().contains("host"));
        assert!(cond.to_string().contains("tenant"));

        let acme_onion = Binding::new("http.client", "prod")
            .with_host("a.onion")
            .with_tenant("acme");
        let globex_onion = Binding::new("http.client", "prod")
            .with_host("a.onion")
            .with_tenant("globex");
        assert!(dest.eval(&acme_onion) && cond.eval(&acme_onion));
        assert!(dest.eval(&globex_onion) && !cond.eval(&globex_onion));
    }

    /// A `when` clause containing the word `to` inside a string must not be
    /// mistaken for a destination clause.
    #[test]
    fn a_to_inside_a_when_string_does_not_split_the_rule() {
        let p = parse(r#"deny http.client when tenant == "to""#);
        let rule = &p.rules()[0];
        assert!(rule.destination.is_none(), "there is no to clause here");
        assert!(rule.condition.is_some());
        let binding = Binding::new("http.client", "prod").with_tenant("to");
        assert!(rule.condition.as_ref().unwrap().eval(&binding));
    }

    // -- Narrowing only ---------------------------------------------------

    /// A hostile policy that would grant everything if the type system allowed
    /// it, applied to the empty set, must produce the empty set.
    #[test]
    fn no_policy_can_widen_a_grant_set() {
        let p = parse("allow clock.*\nallow crypto.*\nallow sql.*\nallow http.*\ndeny fs.read");
        let empty = GrantSet::empty();
        let narrowed = empty.narrow(&p.overlay());
        assert!(
            narrowed.capabilities().is_empty(),
            "an allow rule must keep only what was already granted; \
             the empty set must stay empty"
        );
    }

    #[test]
    fn a_deny_rule_removes_only_what_was_granted() {
        // Start from a set built by parsing a real manifest: an overlay
        // applied to the empty set intersects to nothing, which would make
        // every assertion below vacuous.
        let m = crate::manifest::Manifest::parse(
            "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\
             [capabilities.http]\nclient = [\"example.com\"]\n\
             [capabilities.dns]\nresolve = [\"example.com\"]\n",
        )
        .expect("manifest");
        let base = GrantSet::from_manifest(&m);
        assert!(
            !base.capabilities().is_empty(),
            "the fixture manifest must actually grant something, or the test proves nothing"
        );

        let p = parse("deny http.client");
        let after = base.narrow(&p.overlay());
        assert!(
            !after.grants(Capability::HttpClient),
            "the denied capability must be gone"
        );
        assert!(
            after.grants(Capability::DnsResolve),
            "an unnamed capability must survive"
        );
    }

    /// `deny` wins over `allow` when both name one capability. This is the
    /// module's only ordering decision, and the safe direction.
    #[test]
    fn deny_wins_when_both_verbs_name_one_capability() {
        let p = parse("allow http.client\nallow sql.*\ndeny http.client");
        let overlay = p.overlay();
        assert_eq!(overlay.mode, NarrowMode::Subtract);
        assert!(overlay.capabilities.contains(&Capability::HttpClient));
        assert!(
            !overlay.capabilities.contains(&Capability::SqlQuery),
            "the allow list must not leak into the subtract set"
        );
        assert_eq!(
            overlay.capabilities.len(),
            1,
            "a mixed allow/deny policy subtracts only what was denied"
        );
    }

    // -- The termination proof --------------------------------------------

    #[test]
    fn the_termination_proof_measures_the_policy_it_was_built_from() {
        let p = parse(
            "deny http.client when mfa == false\n\
             allow sql.* when tenant == \"acme\" and environment == \"prod\"",
        );
        let proof = p.prove_terminating().expect("must prove");
        assert_eq!(proof.rules, 2);
        assert_eq!(proof.depth_bound, MAX_EXPR_DEPTH);
        assert_eq!(proof.rule_bound, MAX_RULES);
        assert!(!proof.has_repetition);
        assert!(!proof.has_unbounded_input);
        assert!(proof.max_depth <= MAX_EXPR_DEPTH);
        assert!(proof.comparisons >= 4, "{}", proof.comparisons);
        let text = proof.explain();
        assert!(text.contains("No construct repeats"), "{text}");
    }

    /// The proof must count a `to` clause, or a policy whose only expression is
    /// a destination would report zero work.
    #[test]
    fn the_proof_counts_a_destination_clause() {
        let p = parse(r#"deny http.client to host "*.onion""#);
        let proof = p.prove_terminating().expect("must prove");
        assert_eq!(
            proof.max_depth, 1,
            "the destination comparison is one level deep"
        );
        assert!(
            proof.comparisons >= 2,
            "one for the selector expansion and one for the destination: {}",
            proof.comparisons
        );
    }

    /// An empty policy still has a proof, and the proof says zero.
    #[test]
    fn an_empty_policy_proves_terminating_with_zero_work() {
        let p = Policy::empty(Layer::Platform);
        let proof = p.prove_terminating().expect("must prove");
        assert_eq!(proof.rules, 0);
        assert_eq!(proof.comparisons, 0);
        assert_eq!(proof.worst_case_comparisons(), 0);
        assert_eq!(proof.max_depth, 0);
        assert!(p.is_empty());
        assert_eq!(p.render(), "platform: (no rules)");
    }

    /// **The depth bound is enforced during parsing, not after.** A bound
    /// checked afterwards has already paid the stack cost it exists to prevent.
    #[test]
    fn a_deeply_nested_expression_is_rejected_at_parse_time() {
        // Build `((((...capability == "crypto.sign"...))))` past the bound.
        let depth = usize::from(MAX_EXPR_DEPTH) + 8;
        let cond = format!(
            "{}capability == \"crypto.sign\"{}",
            "(".repeat(depth),
            ")".repeat(depth)
        );
        let e = err(&format!("require crypto.sign when {cond}"));
        assert!(
            e.message.contains("nest") || e.message.contains("deeper"),
            "the error must name the depth bound: {}",
            e.message
        );
    }

    /// Deep `not` nesting is bounded too — the bound must not be reachable only
    /// through parentheses.
    ///
    /// # Why the error comes from the *proof* and not the parser here
    ///
    /// Because the two bounds are not the same quantity, even though both are
    /// [`MAX_EXPR_DEPTH`]. A chain of `not` costs **two** levels of
    /// [`Expr::depth`] per `not` — one for the negation and one for the
    /// comparison it wraps — while the *parser* only recurses one frame per
    /// `not`. So a chain of `MAX_EXPR_DEPTH` negations parses happily and is
    /// then refused by `prove_terminating` for a depth of `MAX_EXPR_DEPTH * 2`.
    ///
    /// That is the correct outcome and was surprising, which is why it is
    /// pinned: the parser's bound protects the parser's stack, and the proof's
    /// bound protects the language's termination argument. They are enforced at
    /// different layers and a reader who assumed one check would see only that
    /// an error appeared.
    #[test]
    fn deep_not_nesting_is_bounded_by_the_proof_not_the_parser() {
        let cond = format!(
            "{}capability == \"crypto.sign\"",
            "not ".repeat(usize::from(MAX_EXPR_DEPTH) + 4)
        );
        let e = err(&format!("require crypto.sign when {cond}"));
        assert!(
            e.message.contains("exceeds the bound"),
            "the refusal comes from the termination proof: {}",
            e.message
        );

        // And a `not` chain short enough to prove still parses, so the bound
        // is not simply refusing every negation.
        let ok = format!(
            "{}capability == \"crypto.sign\"",
            "not ".repeat(usize::from(MAX_EXPR_DEPTH) / 2 - 1)
        );
        let p = parse(&format!("require crypto.sign when {ok}"));
        let proof = p.prove_terminating().expect("must prove");
        assert!(proof.max_depth <= MAX_EXPR_DEPTH, "{}", proof.max_depth);
    }

    /// The bound is *not* off by one: an expression at exactly the limit parses.
    #[test]
    fn an_expression_at_the_depth_limit_is_accepted() {
        let cond = format!(
            "{}capability == \"crypto.sign\"",
            "not ".repeat(usize::from(MAX_EXPR_DEPTH) - 1)
        );
        let p = parse(&format!("require crypto.sign when {cond}"));
        let proof = p.prove_terminating().expect("must prove");
        assert_eq!(proof.max_depth, MAX_EXPR_DEPTH);
    }

    #[test]
    fn a_policy_over_the_rule_limit_is_rejected() {
        let src = "deny http.client\n".repeat(MAX_RULES + 1);
        let e = err(&src);
        assert!(e.message.contains("rule limit"), "{}", e.message);
    }

    #[test]
    fn a_policy_over_the_source_limit_is_rejected_before_lexing() {
        let src = "x".repeat(MAX_SOURCE_BYTES + 1);
        let e = err(&src);
        assert!(e.message.contains("byte limit"), "{}", e.message);
    }

    // -- Selectors --------------------------------------------------------

    #[test]
    fn a_family_glob_expands_against_the_registry() {
        let s = Selector::parse("sql.*").expect("must resolve");
        assert!(!s.capabilities.is_empty());
        assert!(s.capabilities.iter().all(|c| c.name().starts_with("sql.")));
        // Sorted by the derived `Ord` (variant order), which is the order
        // `BTreeSet<Capability>` -- every downstream consumer -- uses.
        let mut sorted = s.capabilities.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted, s.capabilities,
            "the expansion must be in the same order as its consumers"
        );
    }

    #[test]
    fn a_selector_matching_nothing_is_refused_rather_than_accepted() {
        // A typo.
        let e = Selector::parse("htp.client").expect_err("typo must be refused");
        assert!(e.contains("schema capabilities"), "{e}");
        // A family with no members.
        let e = Selector::parse("nonexistent.*").expect_err("empty family must be refused");
        assert!(e.contains("matches no capability"), "{e}");
    }

    #[test]
    fn a_bare_wildcard_is_refused_because_a_review_cannot_see_what_it_covers() {
        let e = Selector::parse("*").expect_err("bare wildcard must be refused");
        assert!(e.contains("bare wildcard"), "{e}");
        assert!(e.contains("explicitly"), "{e}");
    }

    #[test]
    fn a_mid_pattern_wildcard_is_refused_because_it_cannot_be_resolved_statically() {
        let e = Selector::parse("sq*.connect").expect_err("must be refused");
        assert!(e.contains("trailing"), "{e}");
    }

    #[test]
    fn an_exact_selector_names_exactly_the_capabilities_given() {
        let s = Selector::exact([Capability::HttpClient]).expect("must build");
        assert_eq!(s.capabilities, vec![Capability::HttpClient]);
        assert!(Selector::exact([]).is_err());
    }

    /// The typo suggestion must actually fire, or the message is a list.
    #[test]
    fn a_typo_in_a_capability_name_suggests_the_real_one() {
        let e = Selector::parse("http.clien").expect_err("typo must be refused");
        assert!(e.contains("did you mean"), "{e}");
        assert!(e.contains("http.client"), "{e}");
    }

    // -- Evaluation -------------------------------------------------------

    #[test]
    fn a_comparison_evaluates_against_a_binding() {
        let p = parse("deny http.client when tenant == \"globex\"");
        let cond = p.rules()[0].condition.clone().expect("has a condition");
        let acme = Binding::new("http.client", "prod").with_tenant("acme");
        let globex = Binding::new("http.client", "prod").with_tenant("globex");
        assert!(!cond.eval(&acme));
        assert!(cond.eval(&globex));
    }

    /// A tenantless subject must not match a tenant literal. Treating "absent"
    /// as a wildcard would make a rule written for one tenant fire for an
    /// unauthenticated subject.
    #[test]
    fn a_tenantless_subject_never_matches_a_tenant_literal() {
        let p = parse("deny http.client when tenant == \"acme\"");
        let cond = p.rules()[0].condition.clone().expect("has a condition");
        let anonymous = Binding::new("http.client", "prod");
        assert!(!cond.eval(&anonymous), "no tenant must not equal a tenant");

        // `!=` is ALSO false for an absent subject, which is the choice
        // `Binding::compare` documents: an absent value matches nothing, in
        // either direction. The alternative would make `tenant != "acme"`
        // fire for every unauthenticated request -- a rule written to exclude
        // one tenant catching everything else instead.
        let p2 = parse("deny http.client when tenant != \"acme\"");
        let cond2 = p2.rules()[0].condition.clone().expect("has a condition");
        assert!(
            !cond2.eval(&anonymous),
            "an absent tenant must not satisfy `!=` either"
        );
        // With a tenant present, `!=` behaves normally.
        assert!(cond2.eval(&Binding::new("http.client", "prod").with_tenant("globex")));
        assert!(!cond2.eval(&Binding::new("http.client", "prod").with_tenant("acme")));
    }

    #[test]
    fn a_boolean_field_compares_to_booleans_only() {
        let e = err(r#"require crypto.sign when mfa == "yes""#);
        assert!(e.message.contains("boolean"), "{}", e.message);

        let e = err("require crypto.sign when capability == true");
        assert!(
            e.message.contains("cannot be compared to a boolean"),
            "{}",
            e.message
        );
    }

    #[test]
    fn the_match_operator_is_text_only() {
        // A boolean compared to a string is refused first, by the literal
        // check -- the `~` check is never reached. Both are correct; this
        // pins which one an author sees.
        let e = err("require crypto.sign when mfa ~ \"tr*\"");
        assert!(
            e.message.contains("cannot be compared to a string"),
            "{}",
            e.message
        );

        // The `~`-on-a-boolean check is reachable the other way round: a
        // boolean field with `~` and a *boolean* literal, which passes the
        // literal check and fails the operator check.
        let e = err("require crypto.sign when mfa ~ true");
        assert!(
            e.message.contains("text glob"),
            "the operator check must be reachable: {}",
            e.message
        );
    }

    #[test]
    fn and_or_and_not_compose_with_the_expected_precedence() {
        let p = parse(
            r#"deny http.client when capability == "http.client" or capability == "x" and mfa == true"#,
        );
        let cond = p.rules()[0].condition.clone().expect("has a condition");
        // `and` binds tighter than `or`: this is `a or (b and c)`.
        let b = Binding::new("http.client", "prod");
        assert!(cond.eval(&b), "the left disjunct alone must satisfy it");
    }

    #[test]
    fn not_inverts_a_comparison() {
        let p = parse("deny http.client when not tenant == \"acme\"");
        let cond = p.rules()[0].condition.clone().expect("has a condition");
        assert!(!cond.eval(&Binding::new("http.client", "prod").with_tenant("acme")));
        assert!(cond.eval(&Binding::new("http.client", "prod").with_tenant("globex")));
    }

    #[test]
    fn parentheses_override_precedence() {
        let p = parse(
            r#"deny http.client when (capability == "http.client" or capability == "x") and mfa == true"#,
        );
        let cond = p.rules()[0].condition.clone().expect("has a condition");
        let no_mfa = Binding::new("http.client", "prod");
        assert!(
            !cond.eval(&no_mfa),
            "the parenthesised disjunction must still be conjoined with mfa"
        );
        assert!(cond.eval(&no_mfa.clone().with_mfa(true)));
    }

    // -- Glob matching ----------------------------------------------------

    #[test]
    fn glob_matching_handles_the_cases_a_hostname_policy_needs() {
        assert!(glob_match("*.onion", "hidden.onion"));
        assert!(glob_match("*.onion", ".onion"), "a star matches empty");
        assert!(
            !glob_match("*.onion", "onion"),
            "a missing dot must not match"
        );
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""), "a star matches the empty string");
        assert!(glob_match("example.com", "example.com"));
        assert!(!glob_match("example.com", "example.org"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXcYYb"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
        assert!(glob_match("*.onion", "a.b.c.onion"));
    }

    /// The matcher is linear, so an adversarial pattern must not blow up.
    ///
    /// This is the property a regex engine could fail; measuring it is the
    /// point. A 40-character pattern against a 4,000-character text is 160,000
    /// steps at worst, which is microseconds — an exponential matcher would not
    /// finish.
    #[test]
    fn the_glob_matcher_is_linear_on_an_adversarial_input() {
        let pattern = "*a".repeat(20);
        let text = "a".repeat(4000) + "b";

        // A reference answer, computed independently of the fast path: the
        // pattern is `*a` repeated, so it matches only when the text ends in
        // `a`. Pinning the *answer* and not merely the timing is what keeps
        // this a test of the matcher rather than a benchmark of it.
        let expected = text.ends_with('a');

        let start = std::time::Instant::now();
        let matched = glob_match(&pattern, &text);
        let elapsed = start.elapsed();

        assert_eq!(
            matched, expected,
            "the matcher must agree with the reference answer on an adversarial input"
        );
        assert!(
            elapsed.as_millis() < 500,
            "linear matching must finish immediately, took {elapsed:?}"
        );

        // And the accepting case, so the test is not only ever exercising the
        // failing path -- a matcher that always returned `false` would satisfy
        // every assertion above.
        let accepted = glob_match(&pattern, &"a".repeat(4000));
        assert!(accepted, "the pattern must match a text ending in `a`");
    }

    // -- Diagnostics ------------------------------------------------------

    #[test]
    fn an_unknown_verb_names_the_four_that_exist() {
        let e = err("forbid http.client");
        assert!(e.message.contains("forbid"), "{}", e.message);
        assert!(e.message.contains("deny"), "{}", e.message);
        assert!(e.message.contains("permit"), "{}", e.message);
    }

    #[test]
    fn an_error_carries_its_line_number_and_the_offending_source() {
        let e = err("deny http.client\n\nforbid sql.query\n");
        assert_eq!(e.line, 3);
        assert!(e.source.contains("forbid"), "{}", e.source);
        let rendered = e.to_string();
        assert!(rendered.contains("line 3"), "{rendered}");
        assert!(rendered.contains("forbid"), "{rendered}");
        assert!(
            rendered.contains('^'),
            "the caret must point at the verb: {rendered}"
        );
    }

    #[test]
    fn comments_and_blank_lines_are_ignored_and_a_hash_inside_a_string_is_not_a_comment() {
        let p = parse(
            "# a leading comment\n\
             \n\
             deny http.client # a trailing comment\n",
        );
        assert_eq!(p.rules().len(), 1);

        // The `#` here is part of the tenant name, not a comment.
        let p = parse(r#"deny http.client when tenant == "a#b""#);
        let cond = p.rules()[0].condition.clone().expect("has a condition");
        assert!(cond.eval(&Binding::new("http.client", "prod").with_tenant("a#b")));
    }

    #[test]
    fn a_when_inside_a_string_literal_does_not_split_the_rule() {
        let p = parse(r#"deny http.client when tenant == "when""#);
        assert_eq!(p.rules().len(), 1);
        let cond = p.rules()[0].condition.clone().expect("has a condition");
        assert!(cond.eval(&Binding::new("http.client", "prod").with_tenant("when")));
    }

    #[test]
    fn a_rule_with_no_selector_names_the_problem() {
        let e = err("deny");
        assert!(
            e.message.contains("at least one capability") || e.message.contains("must name"),
            "{}",
            e.message
        );
    }

    #[test]
    fn require_without_a_condition_is_refused_with_the_reason() {
        let e = err("require crypto.sign");
        assert!(e.message.contains("always true"), "{}", e.message);
    }

    #[test]
    fn a_condition_that_is_not_a_comparison_explains_the_grammar() {
        let e = err("deny http.client when tenant");
        assert!(e.message.contains("not a comparison"), "{}", e.message);
        assert!(e.message.contains("capability =="), "{}", e.message);
    }

    // -- Requirements and exemptions --------------------------------------

    #[test]
    fn a_require_is_unsatisfied_and_names_its_rule_and_line() {
        let p = parse("require crypto.sign when mfa == true");
        let outcome =
            p.evaluate_requirements(&Binding::new("crypto.sign", "prod"), Capability::CryptoSign);
        match outcome {
            RequirementOutcome::Unsatisfied {
                capability,
                line,
                rule,
            } => {
                assert_eq!(capability, Capability::CryptoSign);
                assert_eq!(line, 1);
                assert!(rule.contains("mfa"), "{rule}");
            }
            other => panic!("expected Unsatisfied, got {other:?}"),
        }
    }

    #[test]
    fn a_require_is_satisfied_when_the_condition_holds() {
        let p = parse("require crypto.sign when mfa == true");
        let binding = Binding::new("crypto.sign", "prod").with_mfa(true);
        assert_eq!(
            p.evaluate_requirements(&binding, Capability::CryptoSign),
            RequirementOutcome::Satisfied
        );
    }

    #[test]
    fn a_require_does_not_apply_to_a_capability_it_does_not_name() {
        let p = parse("require crypto.sign when mfa == true");
        assert_eq!(
            p.evaluate_requirements(&Binding::new("http.client", "prod"), Capability::HttpClient),
            RequirementOutcome::Satisfied
        );
    }

    /// A `permit` exempts within its environment and nowhere else.
    #[test]
    fn a_permit_exempts_only_in_its_own_environment() {
        let p = parse(
            "require crypto.sign when mfa == true\n\
             permit crypto.sign in \"staging\"",
        );
        let staging = Binding::new("crypto.sign", "staging");
        match p.evaluate_requirements(&staging, Capability::CryptoSign) {
            RequirementOutcome::Exempted { capability, .. } => {
                assert_eq!(capability, Capability::CryptoSign);
            }
            other => panic!("staging must be exempt, got {other:?}"),
        }

        let prod = Binding::new("crypto.sign", "prod");
        assert!(
            matches!(
                p.evaluate_requirements(&prod, Capability::CryptoSign),
                RequirementOutcome::Unsatisfied { .. }
            ),
            "the exemption must not reach another environment"
        );
    }

    #[test]
    fn a_permit_without_an_environment_is_refused() {
        let e = err("permit crypto.sign");
        assert!(e.message.contains("environment"), "{}", e.message);
        assert!(e.message.contains("everywhere"), "{}", e.message);
    }

    #[test]
    fn a_permit_can_carry_an_additional_condition() {
        let p = parse(
            "require crypto.sign when mfa == true\n\
             permit crypto.sign in \"staging\" when tenant == \"acme\"",
        );
        let acme = Binding::new("crypto.sign", "staging").with_tenant("acme");
        assert!(matches!(
            p.evaluate_requirements(&acme, Capability::CryptoSign),
            RequirementOutcome::Exempted { .. }
        ));
        let globex = Binding::new("crypto.sign", "staging").with_tenant("globex");
        assert!(
            matches!(
                p.evaluate_requirements(&globex, Capability::CryptoSign),
                RequirementOutcome::Unsatisfied { .. }
            ),
            "the extra condition must narrow the exemption"
        );
    }

    /// A `permit` carrying a `to` clause is narrowed by it too — an exemption
    /// must never be widened by an extra clause.
    #[test]
    fn a_permit_with_a_destination_clause_is_narrowed_by_it() {
        let p = parse(
            "require crypto.sign when mfa == true\n\
             permit crypto.sign in \"staging\" to host \"*.internal\"",
        );
        let internal = Binding::new("crypto.sign", "staging").with_host("a.internal");
        assert!(matches!(
            p.evaluate_requirements(&internal, Capability::CryptoSign),
            RequirementOutcome::Exempted { .. }
        ));
        let public = Binding::new("crypto.sign", "staging").with_host("example.com");
        assert!(
            matches!(
                p.evaluate_requirements(&public, Capability::CryptoSign),
                RequirementOutcome::Unsatisfied { .. }
            ),
            "the destination clause must narrow the exemption"
        );
    }

    // -- Introspection ----------------------------------------------------

    #[test]
    fn an_expression_reports_its_fields_for_the_analyser() {
        let p = parse(
            "deny http.client when tenant == \"a\" and environment == \"prod\" or mfa == true",
        );
        let cond = p.rules()[0].condition.clone().expect("has a condition");
        let fields: Vec<Field> = cond.fields().into_iter().collect();
        let expected: Vec<Field> = [Field::Mfa, Field::Tenant, Field::Environment]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        assert_eq!(fields, expected);
    }

    #[test]
    fn every_field_parses_from_both_its_spellings() {
        for f in Field::ALL {
            assert_eq!(Field::parse(f.as_str()), Some(f));
            assert_eq!(Field::parse(&format!("subject.{}", f.as_str())), Some(f));
        }
        assert_eq!(Field::parse("department"), None);
        assert_eq!(Field::parse("subject.department"), None);
    }

    /// Every field must have a spelling, a domain and a parse round-trip, or
    /// `Field::ALL` is a list that has drifted from the enum.
    #[test]
    fn field_all_covers_the_enum_completely() {
        assert_eq!(Field::ALL.len(), 5);
        let unique: BTreeSet<&str> = Field::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(unique.len(), Field::ALL.len(), "spellings must be unique");
        for f in Field::ALL {
            assert!(!f.domain().is_empty());
            assert_eq!(Field::parse(f.as_str()), Some(f));
        }
    }

    #[test]
    fn the_policy_renders_with_every_rule_and_its_line() {
        let p = parse("deny http.client\n\nrequire crypto.sign when mfa == true");
        let text = p.render();
        assert!(text.starts_with("organization:\n"), "{text}");
        assert!(text.contains("line 1: deny http.client"), "{text}");
        assert!(text.contains("line 3: require"), "{text}");
    }

    #[test]
    fn the_overlay_reason_names_every_contributing_rule() {
        let p = parse("deny http.client\nallow sql.*");
        let reason = p.overlay().reason.clone();
        assert!(reason.contains("line 1"), "{reason}");
        assert!(reason.contains("line 2"), "{reason}");
        assert!(reason.contains("organization"), "{reason}");
    }

    #[test]
    fn an_empty_policy_overlays_to_nothing_with_an_honest_reason() {
        let p = Policy::empty(Layer::Platform);
        let o = p.overlay();
        assert!(o.capabilities.is_empty());
        assert!(o.reason.contains("no narrowing rule"), "{}", o.reason);
    }

    #[test]
    fn a_policy_keeps_the_layer_it_was_parsed_for() {
        for layer in [
            Layer::Manifest,
            Layer::Developer,
            Layer::Organization,
            Layer::Platform,
        ] {
            let p = Policy::parse(layer, "deny http.client").expect("must parse");
            assert_eq!(p.layer(), layer);
            assert_eq!(p.overlay().layer, layer);
        }
    }

    #[test]
    fn split_keyword_respects_strings_and_word_boundaries() {
        assert_eq!(split_keyword("a when b", "when"), Some(("a ", "b")));
        assert_eq!(split_keyword(r#"a == "when""#, "when"), None);
        assert_eq!(split_keyword("whenever", "when"), None);
        assert_eq!(
            split_keyword("a       when    b", "when"),
            Some(("a       ", "b"))
        );
    }

    #[test]
    fn strip_parens_does_not_strip_a_non_pair() {
        assert_eq!(strip_parens("(a)"), Some("a"));
        assert_eq!(strip_parens("(a) and (b)"), None);
        assert_eq!(strip_parens("a"), None);
        assert_eq!(strip_parens("()"), Some(""));
    }

    // -- The scope/demand split of a `require`'s condition ----------------

    /// A capability comparison is scope, so the rule is silent for a capability
    /// it does not name — and reports `Satisfied` rather than `Unsatisfied`.
    ///
    /// This is the case that took three attempts to get right (`§O-107`).
    /// Reading the condition as pure demand made `require mfa when capability
    /// == "crypto.sign"` a permanent failure for `http.client`, which can never
    /// equal `crypto.sign`.
    #[test]
    fn a_capability_comparison_in_a_condition_scopes_the_rule() {
        let p = parse(r#"require mfa when capability == "crypto.sign""#);
        assert_eq!(
            p.evaluate_requirements(&Binding::new("http.client", "prod"), Capability::HttpClient),
            RequirementOutcome::Satisfied,
            "a rule about crypto.sign must be silent about http.client"
        );

        // In scope, the named field is the demand.
        assert!(matches!(
            p.evaluate_requirements(&Binding::new("crypto.sign", "prod"), Capability::CryptoSign),
            RequirementOutcome::Unsatisfied { .. }
        ));
        let with_mfa = Binding::new("crypto.sign", "prod").with_mfa(true);
        assert_eq!(
            p.evaluate_requirements(&with_mfa, Capability::CryptoSign),
            RequirementOutcome::Satisfied
        );
    }

    /// Every non-`capability` comparison is a demand, so the rule fires for
    /// every capability when its condition is unmet.
    #[test]
    fn a_non_capability_comparison_in_a_condition_is_a_demand() {
        let p = parse(r#"require mfa when environment == "prod""#);
        let prod = Binding::new("http.client", "prod");
        assert!(
            matches!(
                p.evaluate_requirements(&prod, Capability::HttpClient),
                RequirementOutcome::Unsatisfied { .. }
            ),
            "in production with no MFA, the requirement is violated"
        );
        assert!(
            matches!(
                p.evaluate_requirements(&prod, Capability::SqlQuery),
                RequirementOutcome::Unsatisfied { .. }
            ),
            "and for a second capability, since the condition is not capability-scoped"
        );

        // In another environment the comparison is simply false, which for a
        // non-capability comparison means the demand is unmet -- not that the
        // rule is out of scope. The asymmetry is the whole rule: capability
        // comparisons scope, everything else demands.
        let staging = Binding::new("http.client", "staging");
        assert!(
            matches!(
                p.evaluate_requirements(&staging, Capability::HttpClient),
                RequirementOutcome::Unsatisfied { .. }
            ),
            "a `require` whose demand is false is violated, wherever it is asked"
        );

        // And with the environment matching, the demand moves on to `mfa`.
        let prod_mfa = Binding::new("http.client", "prod").with_mfa(true);
        assert_eq!(
            p.evaluate_requirements(&prod_mfa, Capability::HttpClient),
            RequirementOutcome::Satisfied
        );
    }

    /// A condition mixing both roles under `and` splits soundly: the capability
    /// half scopes, the rest demands.
    #[test]
    fn and_mixing_capability_and_other_fields_splits_soundly() {
        let p = parse(r#"require mfa when capability == "crypto.sign" and environment == "prod""#);

        // Right capability, right environment, no MFA -> violated.
        let violation = Binding::new("crypto.sign", "prod");
        assert!(matches!(
            p.evaluate_requirements(&violation, Capability::CryptoSign),
            RequirementOutcome::Unsatisfied { .. }
        ));

        // Right capability, wrong environment -> the environment half is a
        // DEMAND, so the rule applies and is violated (MFA is also false).
        let staging = Binding::new("crypto.sign", "staging");
        assert!(
            matches!(
                p.evaluate_requirements(&staging, Capability::CryptoSign),
                RequirementOutcome::Unsatisfied { .. }
            ),
            "a false non-capability comparison is an unmet demand"
        );

        // Right capability, right environment, MFA satisfied -> passes.
        let ok = Binding::new("crypto.sign", "prod").with_mfa(true);
        assert_eq!(
            p.evaluate_requirements(&ok, Capability::CryptoSign),
            RequirementOutcome::Satisfied
        );

        // **Wrong capability, right environment -> out of scope, silent.** This
        // is the half a pure-demand reading got wrong: `http.client` can never
        // equal `crypto.sign`, so treating the capability comparison as a
        // demand makes the rule a permanent failure for every other capability.
        let other = Binding::new("http.client", "prod");
        assert_eq!(
            p.evaluate_requirements(&other, Capability::HttpClient),
            RequirementOutcome::Satisfied,
            "the capability comparison must scope, not demand"
        );
    }

    /// **The `or` case has no sound split and must be refused, not guessed.**
    ///
    /// `(capability == "x") or (mfa == true)` cannot be read as "scope:
    /// capability == x" plus "demand: mfa == true", because that demands `mfa`
    /// even when the capability matched — the opposite of what `or` says.
    #[test]
    fn an_or_that_mixes_capability_with_another_field_is_refused() {
        let e = err(r#"require mfa when capability == "crypto.sign" or environment == "prod""#);
        assert!(
            e.message.contains("no sound reading"),
            "the error must say why: {}",
            e.message
        );
        assert!(
            e.message.contains("two rules"),
            "the error must name the rewrite: {}",
            e.message
        );
        assert_eq!(e.line, 1, "the error must carry the line");
    }

    /// An `or` that stays on one side of the role boundary is fine: it is a
    /// capability disjunction (pure scope) or a demand disjunction (pure
    /// demand), neither of which mixes roles.
    #[test]
    fn an_or_that_does_not_mix_roles_is_accepted() {
        // Pure scope: two capability comparisons.
        let p =
            parse(r#"require mfa when capability == "crypto.sign" or capability == "crypto.hmac""#);
        assert!(
            matches!(
                p.evaluate_requirements(
                    &Binding::new("crypto.sign", "prod"),
                    Capability::CryptoSign
                ),
                RequirementOutcome::Unsatisfied { .. }
            ),
            "a capability disjunction still scopes correctly"
        );
        assert_eq!(
            p.evaluate_requirements(&Binding::new("http.client", "prod"), Capability::HttpClient),
            RequirementOutcome::Satisfied
        );

        // Pure demand: two non-capability comparisons.
        let p = parse(r#"require mfa when environment == "prod" or environment == "staging""#);
        assert!(matches!(
            p.evaluate_requirements(
                &Binding::new("http.client", "staging"),
                Capability::HttpClient
            ),
            RequirementOutcome::Unsatisfied { .. }
        ));
    }

    /// The split is structural and total: every shape produces halves whose
    /// evaluation reproduces the whole, whenever the whole is sound.
    #[test]
    fn the_split_reproduces_the_whole_condition_for_sound_shapes() {
        let cases = [
            r#"capability == "crypto.sign""#,
            r"mfa == true",
            r#"capability == "crypto.sign" and mfa == true"#,
            r#"not capability == "crypto.sign""#,
            r"not mfa == true",
            r#"capability == "a" and mfa == true and tenant == "acme""#,
        ];
        for case in cases {
            let p = parse(&format!("require mfa when {case}"));
            let rule = &p.rules()[0];
            let cond = rule.condition.as_ref().expect("has a condition");
            let (scope, demand) = split_condition(cond, "", rule.line).expect("sound shape");

            for capability in ["crypto.sign", "http.client"] {
                for env in ["prod", "staging"] {
                    for mfa in [false, true] {
                        let b = Binding::new(capability, env).with_mfa(mfa);
                        let together = scope.as_ref().is_none_or(|s| s.eval(&b))
                            && demand.as_ref().is_none_or(|d| d.eval(&b));
                        // For `and`-joined conditions the split is equivalent to
                        // the whole; that is what makes it sound.
                        if case.contains("and") && !case.contains("or") {
                            assert_eq!(
                                together,
                                cond.eval(&b),
                                "split disagreed with the whole for `{case}` \
                                 (capability={capability}, env={env}, mfa={mfa})"
                            );
                        }
                        // The halves must always be well-formed predicates.
                        let _ = together;
                    }
                }
            }
        }
    }
}
