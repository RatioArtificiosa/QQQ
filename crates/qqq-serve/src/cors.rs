// SPDX-License-Identifier: Apache-2.0

//! Cross-Origin Resource Sharing: the policy and the response headers.
//!
//! Implements Checklist `SRV-019` — *"Implement CORS configuration with safe
//! defaults"* — against Proposal §5.3's manifest stanza:
//!
//! ```toml
//! [server.cors]
//! allow_origins = ["https://app.example.com"]
//! ```
//!
//! # "Safe defaults" is the whole item, so it is the first thing stated
//!
//! The default is **no CORS at all**: no `Access-Control-Allow-Origin` header is sent
//! for any request, and a cross-origin browser request therefore fails. That is not a
//! conservative reading of the item — it is what the specification requires. CORS is a
//! *relaxation* of the browser's same-origin policy, and a runtime that relaxes it by
//! default has made every QQQ application cross-origin-readable without its author
//! asking. The three shapes that look like defaults and are all wrong:
//!
//! | Tempting default | What it does |
//! |---|---|
//! | `Access-Control-Allow-Origin: *` | makes every response readable by every site |
//! | reflecting the request's `Origin` | identical to `*` for simple requests, and *worse* than `*` when combined with credentials, because it is a wildcard that looks like a decision |
//! | allowing `null` | `null` is sent by sandboxed iframes, `file://` pages and some redirects — the origins an attacker can most easily obtain |
//!
//! So `Cors::none()` is the default, and `allow_origins` must name origins explicitly.
//! An empty `allow_origins` is *also* `none`, not "allow everything" — the vacuity
//! failure this project refuses everywhere else (`check_toolchain.py`'s "found no
//! pin", `check_scope_table.py`'s empty table). A configuration that lists nothing
//! allows nothing.
//!
//! # Why origin matching is an exact string comparison
//!
//! The `Origin` header is `scheme://host[:port]` and browsers serialize it
//! canonically, so an exact match on the serialized form is both correct and the only
//! form that cannot be fooled. The tempting alternatives are all exploitable:
//!
//! - **Suffix matching** on `example.com` accepts `evil-example.com` and
//!   `example.com.evil.net`. This is the classic CORS bypass, and it is why
//!   [`Origin::parse`] validates the shape rather than trusting the string.
//! - **Case-insensitive host matching** is required by the URL standard (`EXAMPLE.com`
//!   is `example.com`), so the *host* is lowercased — but the *scheme* is also
//!   lowercased and the port is kept, so `https://example.com` and
//!   `http://example.com` remain different, which is the point of the scheme being
//!   there.
//! - **A wildcard in the middle** (`https://*.example.com`) is a real requirement for
//!   some deployments and is deliberately **not** implemented in V1: a wildcard
//!   subdomain matcher is a substring matcher with extra steps unless it is written
//!   against the URL standard's label rules, and a half-correct one is worse than none.
//!   [`Cors::from_manifest`] rejects such an entry instead of accepting it and matching
//!   too much.
//!
//! # Why `Vary: Origin` is not optional
//!
//! The `Access-Control-Allow-Origin` value depends on the request's `Origin` header,
//! which makes the response **not** cacheable as a single entity. Without `Vary:
//! Origin` a shared cache will store the response for one origin and serve it to
//! another, handing that origin a grant it was never given. The header is emitted
//! whenever the output can differ by origin, including on a *denial* — a denial is
//! also origin-dependent, and caching one would deny an origin that should be allowed.
//!
//! # Preflight, and why the answer is a separate type
//!
//! An `OPTIONS` request with `Access-Control-Request-Method` is a *preflight*: the
//! browser asks permission before sending the real request. The response to it carries
//! no body and a different header set, and the two are easy to conflate — a
//! preflight answered with the actual response's headers would advertise methods the
//! route will not accept. [`Cors::preflight`] and [`Cors::simple`] are separate
//! functions returning a [`Decision`] that says *granted* or *denied*, so a caller
//! cannot accidentally treat a denial as an empty grant.

use std::collections::BTreeSet;

/// An `Origin` header value, validated and canonically serialized.
///
/// The type exists so the comparison in [`Cors::is_allowed`] is between two values
/// that have both been normalized the same way. A `String` comparison would silently
/// miss `https://EXAMPLE.com` vs `https://example.com`, which the URL standard says
/// are the same origin — and a "fix" for that by lowercasing both sides at the
/// comparison site is how a scheme like `HTTPS` stops being distinct from `https`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin(String);

impl Origin {
    /// Parse and canonicalize an `Origin` header value.
    ///
    /// Accepts `scheme://host[:port]`, lowercasing the scheme and host and leaving the
    /// port as written.
    ///
    /// # Errors
    ///
    /// Returns [`CorsError::BadOrigin`] for anything else — including the literal
    /// `null`, which is a *valid* `Origin` value that this type refuses to treat as a
    /// matchable origin. See [`Origin::is_null`] for the honest handling of that case.
    pub fn parse(value: &str) -> Result<Self, CorsError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(CorsError::BadOrigin("the value is empty".to_owned()));
        }
        if value.eq_ignore_ascii_case("null") {
            return Err(CorsError::BadOrigin(
                "`null` is a valid Origin header but never a matchable origin: it is \
                 sent by sandboxed iframes and `file://` pages"
                    .to_owned(),
            ));
        }
        let (scheme, rest) = value
            .split_once("://")
            .ok_or_else(|| CorsError::BadOrigin(format!("`{value}` has no scheme")))?;
        if rest.is_empty() {
            return Err(CorsError::BadOrigin(format!("`{value}` has no host")));
        }
        let scheme = scheme.to_ascii_lowercase();

        // Split the authority into host and port. A bare IPv6 literal is bracketed, so
        // a colon is the port separator only when what follows it is all digits — which
        // excludes every colon inside `[...]`, since those are followed by hex.
        let (host, port) = match rest.rfind(':') {
            Some(i) if rest[i + 1..].chars().all(|c| c.is_ascii_digit()) => {
                (&rest[..i], Some(&rest[i + 1..]))
            }
            _ => (rest, None),
        };
        if host.is_empty() {
            return Err(CorsError::BadOrigin(format!("`{value}` has no host")));
        }
        // A path, query or fragment in an Origin is a malformed header: the value is an
        // origin, not a URL. Accepting one would mean matching a prefix of a URL, which
        // is the substring bug in a different costume.
        if host.contains('/') || host.contains('?') || host.contains('#') {
            return Err(CorsError::BadOrigin(format!(
                "`{value}` carries a path, query or fragment; an Origin is not a URL"
            )));
        }

        let mut out = String::with_capacity(value.len());
        out.push_str(&scheme);
        out.push_str("://");
        out.push_str(&host.to_ascii_lowercase());
        if let Some(port) = port {
            out.push(':');
            out.push_str(port);
        }
        Ok(Self(out))
    }

    /// Whether the header read `null`.
    ///
    /// Provided so a caller can distinguish "no origin" from "an origin that cannot be
    /// matched" in a log or an error message. It is never a match: `null` is what a
    /// sandboxed iframe sends, so treating it as an origin would grant exactly the
    /// callers least able to be trusted.
    #[must_use]
    pub fn is_null(value: &str) -> bool {
        value.trim().eq_ignore_ascii_case("null")
    }

    /// The canonical serialization.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A CORS policy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Cors {
    /// The origins allowed to read responses. Empty means no CORS at all.
    allowed: BTreeSet<Origin>,
    /// Whether `Access-Control-Allow-Credentials: true` is sent.
    credentials: bool,
    /// Methods advertised on a preflight. Empty means the allowed set is derived from
    /// the request, which is the safer default.
    methods: BTreeSet<String>,
    /// Headers the client may send on the real request.
    allowed_headers: BTreeSet<String>,
    /// Headers the browser may expose to script.
    exposed_headers: BTreeSet<String>,
    /// How long a preflight may be cached.
    max_age: Option<u64>,
}

/// Why a CORS configuration could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorsError {
    /// An origin value is not a valid origin.
    BadOrigin(String),
    /// The configuration asks for something that cannot be expressed safely.
    Unsupported(String),
}

impl std::fmt::Display for CorsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadOrigin(detail) => write!(f, "invalid origin: {detail}"),
            Self::Unsupported(detail) => write!(f, "unsupported CORS configuration: {detail}"),
        }
    }
}

impl std::error::Error for CorsError {}

/// What the policy decided about one request.
///
/// A separate type rather than an empty header list, because **denied and granted are
/// different facts**. A caller that received "no headers" could not tell a denial from
/// a policy that had nothing to add, and an access log that recorded the two the same
/// way would be unable to answer "was this request refused by CORS?".
///
/// A denial carries its own header list, which is usually `Vary: Origin` — a denial is
/// origin-dependent, so a cache must not treat it as one entity. Carrying the headers
/// on the variant rather than synthesizing them in an accessor is what lets
/// [`Decision::headers`] return a slice with no allocation and no static-string
/// special case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The exchange is allowed; these headers go on the response.
    Granted(Vec<(&'static str, String)>),
    /// The request was refused. The response is still sent — CORS is enforced by the
    /// **browser**, not the server, so a denial means the browser will not expose the
    /// response to script.
    Denied {
        /// Why it was refused.
        reason: Reason,
        /// Headers the refusal still needs, normally `Vary: Origin`.
        headers: Vec<(&'static str, String)>,
    },
}

/// Why a CORS request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// No origins are configured.
    NoPolicy,
    /// The origin is not in the allow-list.
    OriginNotAllowed(String),
    /// The `Origin` header is absent, so this is not a CORS request.
    NotACorsRequest,
    /// The origin is the literal `null`.
    NullOrigin,
    /// A preflight asked for a method the policy does not allow.
    MethodNotAllowed(String),
    /// A preflight asked for a header the policy does not allow.
    HeaderNotAllowed(String),
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPolicy => f.write_str("no allowed origins are configured"),
            Self::OriginNotAllowed(o) => write!(f, "origin `{o}` is not allowed"),
            Self::NotACorsRequest => f.write_str("the request carries no Origin header"),
            Self::NullOrigin => f.write_str("the `null` origin is never allowed"),
            Self::MethodNotAllowed(m) => write!(f, "method `{m}` is not allowed"),
            Self::HeaderNotAllowed(h) => write!(f, "header `{h}` is not allowed"),
        }
    }
}

impl Decision {
    /// Whether the decision grants access.
    #[must_use]
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted(_))
    }

    /// Why the request was refused, when it was.
    #[must_use]
    pub fn reason(&self) -> Option<&Reason> {
        match self {
            Self::Granted(_) => None,
            Self::Denied { reason, .. } => Some(reason),
        }
    }

    /// The headers to apply, which are empty for a denial that needs none.
    ///
    /// `Vary: Origin` is present even on a denial — see the module docs — so this
    /// method is the one a caller should use rather than matching on the variant.
    ///
    /// Returns a slice borrowed from the variant: no allocation, and no second place
    /// that has to know which headers a denial carries.
    #[must_use]
    pub fn headers(&self) -> &[(&'static str, String)] {
        match self {
            Self::Granted(h) => h,
            Self::Denied { headers, .. } => headers,
        }
    }
}

/// The headers a denial carries.
///
/// A denial is origin-dependent, so a shared cache must not store it as one entity and
/// serve it to an origin that should have been granted. The one exception is
/// [`Reason::NotACorsRequest`]: a request with no `Origin` at all is not
/// origin-dependent, so emitting `Vary` would fragment the cache for no reason.
fn denial_headers(reason: &Reason) -> Vec<(&'static str, String)> {
    match reason {
        Reason::NotACorsRequest => Vec::new(),
        _ => vec![("Vary", "Origin".to_owned())],
    }
}

/// A denial, with the headers it needs.
fn deny(reason: Reason) -> Decision {
    let headers = denial_headers(&reason);
    Decision::Denied { reason, headers }
}

impl Cors {
    /// A policy that allows nothing: the default, and the only safe one.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Build from a manifest's `[server.cors] allow_origins`.
    ///
    /// Takes `impl AsRef<[S]>` rather than `&[S]` so a caller can pass an array
    /// literal — which is what a manifest's fixed origin list becomes — without writing
    /// `&` at every call site. The conversion is free for both `&[S]` and `[S; N]`.
    ///
    /// # Errors
    ///
    /// Returns [`CorsError`] for an origin that is not a valid origin, and for a
    /// wildcard host, which V1 refuses rather than matching too broadly.
    pub fn from_manifest<S, L>(allow_origins: L) -> Result<Self, CorsError>
    where
        S: AsRef<str>,
        L: AsRef<[S]>,
    {
        let mut cors = Self::none();
        for raw in allow_origins.as_ref() {
            let raw = raw.as_ref().trim();
            // A bare `*` is the configuration an author writes when they mean "allow
            // everything". Refusing it with a message that says so is better than
            // accepting it, because `*` next to `allow_credentials` is a combination
            // browsers reject outright — so accepting it would produce a policy that
            // silently does nothing.
            if raw == "*" {
                return Err(CorsError::Unsupported(
                    "`*` is not accepted: name the origins explicitly. A wildcard would \
                     make every QQQ application readable by every site, and combined \
                     with credentials browsers reject it outright, so it would not even \
                     work"
                        .to_owned(),
                ));
            }
            if raw.contains('*') {
                return Err(CorsError::Unsupported(format!(
                    "`{raw}` contains a wildcard: V1 has no subdomain wildcard, because a \
                     partial matcher is a substring matcher and this is the classic CORS \
                     bypass"
                )));
            }
            cors.allowed.insert(Origin::parse(raw)?);
        }
        Ok(cors)
    }

    /// Send `Access-Control-Allow-Credentials: true`.
    ///
    /// Note what this does **not** do: it does not permit `*`. The allow-list is still
    /// enforced, because a wildcard with credentials is both rejected by browsers and
    /// meaningless as a policy.
    #[must_use]
    pub fn with_credentials(mut self) -> Self {
        self.credentials = true;
        self
    }

    /// Advertise specific methods on a preflight.
    #[must_use]
    pub fn with_methods<I, S>(mut self, methods: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.methods = methods
            .into_iter()
            .map(|m| m.as_ref().to_ascii_uppercase())
            .collect();
        self
    }

    /// Allow specific request headers on the real request.
    #[must_use]
    pub fn with_allowed_headers<I, S>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.allowed_headers = headers
            .into_iter()
            .map(|h| h.as_ref().to_ascii_lowercase())
            .collect();
        self
    }

    /// Expose specific response headers to script.
    #[must_use]
    pub fn with_exposed_headers<I, S>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.exposed_headers = headers
            .into_iter()
            .map(|h| h.as_ref().to_ascii_lowercase())
            .collect();
        self
    }

    /// Cache a preflight for `seconds`.
    #[must_use]
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// How many origins are allowed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    /// Whether nothing is allowed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    /// The decision for a request, given its `Origin` header.
    ///
    /// `origin` is the raw header value, or `None` when the header is absent — a
    /// same-origin request from a browser sends no `Origin` at all on a `GET`, and a
    /// non-browser client never does.
    #[must_use]
    pub fn simple(&self, origin: Option<&str>) -> Decision {
        let Some(raw) = origin else {
            return deny(Reason::NotACorsRequest);
        };
        if self.allowed.is_empty() {
            return deny(Reason::NoPolicy);
        }
        if Origin::is_null(raw) {
            return deny(Reason::NullOrigin);
        }
        let Ok(parsed) = Origin::parse(raw) else {
            return deny(Reason::OriginNotAllowed(raw.to_owned()));
        };
        if !self.allowed.contains(&parsed) {
            return deny(Reason::OriginNotAllowed(parsed.to_string()));
        }

        // The **canonical** form is echoed, never the request's bytes. Echoing the raw
        // header would put a value the client chose into a header the browser then
        // compares — so a client that sent `https://example.com ` (trailing space, or
        // any other text a proxy might pass through) would see its own bytes returned
        // and, in the worst case, a value that differs from what a cache keyed on.
        let mut headers = vec![
            ("Access-Control-Allow-Origin", parsed.to_string()),
            ("Vary", "Origin".to_owned()),
        ];
        if self.credentials {
            headers.push(("Access-Control-Allow-Credentials", "true".to_owned()));
        }
        if !self.exposed_headers.is_empty() {
            let joined = self
                .exposed_headers
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            headers.push(("Access-Control-Expose-Headers", joined));
        }
        Decision::Granted(headers)
    }

    /// The decision for a preflight (`OPTIONS` + `Access-Control-Request-Method`).
    ///
    /// `requested_method` is the value of `Access-Control-Request-Method`, and
    /// `requested_headers` the (comma-separated, possibly repeated) values of
    /// `Access-Control-Request-Headers`.
    ///
    /// # Why the requested method and headers are checked, not merely echoed
    ///
    /// A preflight that echoes whatever was asked for is not a policy — it grants
    /// every method and header on demand, and the allow-list of *origins* becomes the
    /// only constraint. The browser then believes it may `DELETE` a route the server
    /// only accepts `GET` on. Checking here means the refusal happens before the real
    /// request is ever sent, which is the entire purpose of a preflight.
    #[must_use]
    pub fn preflight(
        &self,
        origin: Option<&str>,
        requested_method: Option<&str>,
        requested_headers: Option<&str>,
    ) -> Decision {
        let base = self.simple(origin);
        if !base.is_granted() {
            return base;
        }

        let Some(method) = requested_method else {
            // An `OPTIONS` without `Access-Control-Request-Method` is not a preflight;
            // it is an ordinary OPTIONS request that happens to carry an Origin. The
            // simple-request decision is the right answer for it.
            return base;
        };
        let method = method.trim().to_ascii_uppercase();
        // An empty `methods` set means the caller did not configure one; the policy
        // then refuses to advertise anything, rather than guessing. A guess here is
        // how a route that only accepts `GET` comes back advertising `DELETE`.
        if !self.methods.contains(&method) {
            return deny(Reason::MethodNotAllowed(method));
        }

        let mut requested: Vec<String> = Vec::new();
        if let Some(headers) = requested_headers {
            for name in headers.split(',') {
                let name = name.trim().to_ascii_lowercase();
                if name.is_empty() {
                    continue;
                }
                if !self.allowed_headers.contains(&name) {
                    return deny(Reason::HeaderNotAllowed(name));
                }
                requested.push(name);
            }
        }

        let Decision::Granted(mut headers) = base else {
            unreachable!("granted above")
        };
        headers.push(("Access-Control-Allow-Methods", method.clone()));
        if !requested.is_empty() {
            headers.push(("Access-Control-Allow-Headers", requested.join(", ")));
        }
        if let Some(age) = self.max_age {
            headers.push(("Access-Control-Max-Age", age.to_string()));
        }
        Decision::Granted(headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decided(headers: &[(&'static str, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    // -- the default is deny ------------------------------------------------

    /// **With no configuration, no CORS headers are sent for any request.**
    ///
    /// The item says "safe defaults", and this is the safety: a QQQ application is
    /// same-origin until its author says otherwise. The test asserts the *absence*,
    /// because a default that emitted anything would be the defect.
    #[test]
    fn the_default_policy_allows_nothing() {
        let cors = Cors::none();
        assert!(cors.is_empty());
        assert_eq!(cors.len(), 0);

        for origin in [
            Some("https://app.example.com"),
            Some("https://evil.example.com"),
            Some("null"),
            None,
        ] {
            let decision = cors.simple(origin);
            assert!(
                !decision.is_granted(),
                "the default must deny {origin:?}, got {decision:?}"
            );
            assert!(
                decided(decision.headers(), "Access-Control-Allow-Origin").is_none(),
                "no ACAO header may be emitted by the default policy"
            );
        }
    }

    /// **An empty `allow_origins` allows nothing.**
    ///
    /// The vacuity failure this project refuses everywhere else: a configuration that
    /// lists nothing must not be read as "everything". Treating an empty list as a
    /// wildcard is the single most dangerous possible reading of this field.
    #[test]
    fn an_empty_allow_list_is_not_a_wildcard() {
        let cors = Cors::from_manifest::<&str, _>(&[]).expect("an empty list is valid");
        assert!(cors.is_empty());
        assert!(!cors.simple(Some("https://app.example.com")).is_granted());
    }

    /// **`*` in the manifest is refused, with a reason.**
    ///
    /// Not accepted-and-ignored: a policy that silently did nothing would be worse
    /// than one that failed, because the author would believe CORS was configured.
    #[test]
    fn a_bare_wildcard_is_refused() {
        let err = Cors::from_manifest(["*"]).expect_err("must refuse");
        assert!(matches!(err, CorsError::Unsupported(_)), "{err:?}");
        let text = err.to_string();
        assert!(text.contains("explicitly"), "{text}");
    }

    /// **A wildcard host is refused rather than matched too broadly.**
    ///
    /// `https://*.example.com` is a substring matcher with extra steps unless it is
    /// written against the URL standard's label rules. Refusing it means an author who
    /// wants subdomains names them, instead of getting `evil.example.com.attacker.net`
    /// allowed by a matcher that looks right.
    #[test]
    fn a_wildcard_host_is_refused() {
        for pattern in [
            "https://*.example.com",
            "https://example.*",
            "*://example.com",
        ] {
            let err = Cors::from_manifest([pattern]).expect_err("must refuse");
            assert!(
                matches!(err, CorsError::Unsupported(_)),
                "{pattern}: {err:?}"
            );
        }
    }

    // -- the allow-list -----------------------------------------------------

    /// A configured origin is granted, and the canonical form is echoed.
    #[test]
    fn a_configured_origin_is_granted() {
        let cors = Cors::from_manifest(["https://app.example.com"]).expect("valid");
        let decision = cors.simple(Some("https://app.example.com"));
        assert!(decision.is_granted(), "{decision:?}");

        let headers = decision.headers();
        assert_eq!(
            decided(headers, "Access-Control-Allow-Origin").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(decided(headers, "Vary").as_deref(), Some("Origin"));
    }

    /// **An origin not in the list is denied.**
    #[test]
    fn an_unlisted_origin_is_denied() {
        let cors = Cors::from_manifest(["https://app.example.com"]).expect("valid");
        let decision = cors.simple(Some("https://evil.example.com"));
        assert!(!decision.is_granted());
        assert!(matches!(
            decision.reason(),
            Some(Reason::OriginNotAllowed(_))
        ));
        assert!(
            decided(decision.headers(), "Access-Control-Allow-Origin").is_none(),
            "a denial never carries the grant header"
        );
    }

    /// **A suffix match is not a match.**
    ///
    /// The classic CORS bypass: an implementation that checks `origin.ends_with(
    /// allowed)` accepts every one of these. They are all attacker-registrable
    /// domains for a target of `example.com`.
    #[test]
    fn a_suffix_of_an_allowed_origin_is_not_allowed() {
        let cors = Cors::from_manifest(["https://example.com"]).expect("valid");
        for attacker in [
            "https://evil-example.com",
            "https://example.com.evil.net",
            "https://notexample.com",
            "https://example.com.evil",
            "https://xexample.com",
        ] {
            assert!(
                !cors.simple(Some(attacker)).is_granted(),
                "`{attacker}` must not be treated as `example.com`"
            );
        }
    }

    /// A prefix of an allowed origin is not a match either.
    #[test]
    fn a_prefix_of_an_allowed_origin_is_not_allowed() {
        let cors = Cors::from_manifest(["https://app.example.com"]).expect("valid");
        for attacker in [
            "https://app.example.co",
            "https://app.exampl",
            "https://app",
        ] {
            assert!(
                !cors.simple(Some(attacker)).is_granted(),
                "`{attacker}` must not be treated as `app.example.com`"
            );
        }
    }

    /// **The scheme is part of the origin.**
    ///
    /// `http://example.com` and `https://example.com` are different origins, and an
    /// allow-list that forgot the scheme would grant the insecure one. This is why
    /// [`Origin::parse`] requires `://` rather than defaulting a scheme.
    #[test]
    fn the_scheme_is_significant() {
        let cors = Cors::from_manifest(["https://example.com"]).expect("valid");
        assert!(!cors.simple(Some("http://example.com")).is_granted());
        assert!(cors.simple(Some("https://example.com")).is_granted());
        // And the reverse, so this is not "https always wins".
        let http = Cors::from_manifest(["http://example.com"]).expect("valid");
        assert!(!http.simple(Some("https://example.com")).is_granted());
        assert!(http.simple(Some("http://example.com")).is_granted());
    }

    /// **The port is part of the origin.**
    #[test]
    fn the_port_is_significant() {
        let cors = Cors::from_manifest(["https://example.com"]).expect("valid");
        assert!(!cors.simple(Some("https://example.com:8443")).is_granted());
        assert!(cors.simple(Some("https://example.com")).is_granted());

        let with_port = Cors::from_manifest(["https://example.com:8443"]).expect("valid");
        assert!(with_port
            .simple(Some("https://example.com:8443"))
            .is_granted());
        assert!(!with_port.simple(Some("https://example.com")).is_granted());
    }

    /// **A host is matched case-insensitively**, because the URL standard says so.
    ///
    /// A browser sends `Origin: https://APP.example.com` for a page at
    /// `https://app.example.com`? No — but it may send mixed case for an origin the
    /// user typed, and the URL standard lowercases the host. What must **not** happen is
    /// the scheme being compared case-insensitively *at the call site* in a way that
    /// lets `HTTPS://` bypass a scheme check; that is why normalization is in the type.
    #[test]
    fn the_host_is_matched_case_insensitively() {
        let cors = Cors::from_manifest(["https://app.example.com"]).expect("valid");
        for variant in [
            "https://APP.example.com",
            "https://App.Example.COM",
            "HTTPS://app.example.com",
        ] {
            assert!(cors.simple(Some(variant)).is_granted(), "{variant}");
        }
    }

    /// The echoed origin is the **canonical** form, not the request's bytes.
    ///
    /// Echoing the raw header puts a client-chosen string into a header the browser
    /// compares. Returning the parsed form means the grant is always exactly one of
    /// the configured origins.
    #[test]
    fn the_granted_origin_is_the_canonical_form() {
        let cors = Cors::from_manifest(["https://app.example.com"]).expect("valid");
        let Decision::Granted(headers) = cors.simple(Some("https://APP.Example.COM")) else {
            panic!("must be granted");
        };
        assert_eq!(
            decided(&headers, "Access-Control-Allow-Origin").as_deref(),
            Some("https://app.example.com"),
            "the echoed value must be the configured origin, not the request's bytes"
        );
    }

    // -- the null origin ----------------------------------------------------

    /// **`null` is never granted, even if it is configured.**
    ///
    /// `null` is what a sandboxed iframe, a `file://` page and some redirects send. It
    /// is the origin an attacker can most easily obtain, so `Origin::parse` refuses it
    /// and the policy denies it explicitly rather than by falling through to
    /// "not in the list".
    #[test]
    fn the_null_origin_is_never_granted() {
        let cors = Cors::from_manifest(["https://app.example.com"]).expect("valid");
        let decision = cors.simple(Some("null"));
        assert!(
            matches!(decision.reason(), Some(Reason::NullOrigin)),
            "{decision:?}"
        );

        // Even spelled differently, and even if someone configures it.
        assert!(matches!(
            cors.simple(Some("NULL")).reason(),
            Some(Reason::NullOrigin)
        ));
        let err = Cors::from_manifest(["null"]).expect_err("cannot be configured");
        assert!(matches!(err, CorsError::BadOrigin(_)), "{err:?}");
    }

    // -- absent Origin ------------------------------------------------------

    /// **A request with no `Origin` is `NotACorsRequest`, not a denial of a policy.**
    ///
    /// The distinction is operational: a same-origin browser `GET` sends no `Origin`,
    /// and a non-browser client never does. Recording those as "CORS denied" would make
    /// an access log's denial count meaningless.
    #[test]
    fn an_absent_origin_is_not_a_cors_denial() {
        let cors = Cors::from_manifest(["https://app.example.com"]).expect("valid");
        let decision = cors.simple(None);
        assert!(matches!(decision.reason(), Some(Reason::NotACorsRequest)));
        assert!(
            decision.headers().is_empty(),
            "a non-CORS request needs no Vary: nothing about it is origin-dependent"
        );
    }

    // -- Vary ---------------------------------------------------------------

    /// **`Vary: Origin` is emitted on a denial too.**
    ///
    /// A denial is origin-dependent. Without `Vary`, a shared cache stores the denial
    /// for one origin and serves it to an origin that should have been granted — so the
    /// header is not decoration on the error path.
    #[test]
    fn vary_is_emitted_on_a_denial_as_well_as_a_grant() {
        let cors = Cors::from_manifest(["https://app.example.com"]).expect("valid");
        let denied = cors.simple(Some("https://evil.example.com"));
        assert_eq!(
            decided(denied.headers(), "Vary").as_deref(),
            Some("Origin"),
            "a cached denial must not be served to an origin that is allowed"
        );
    }

    // -- credentials --------------------------------------------------------

    /// Credentials are advertised only when configured.
    #[test]
    fn credentials_are_sent_only_when_configured() {
        let plain = Cors::from_manifest(["https://app.example.com"]).expect("valid");
        let Decision::Granted(h) = plain.simple(Some("https://app.example.com")) else {
            panic!("granted");
        };
        assert!(decided(&h, "Access-Control-Allow-Credentials").is_none());

        let creds = Cors::from_manifest(["https://app.example.com"])
            .expect("valid")
            .with_credentials();
        let Decision::Granted(h) = creds.simple(Some("https://app.example.com")) else {
            panic!("granted");
        };
        assert_eq!(
            decided(&h, "Access-Control-Allow-Credentials").as_deref(),
            Some("true")
        );
    }

    /// **Credentials do not widen the allow-list.**
    ///
    /// The dangerous combination is "reflect any origin AND allow credentials". Since
    /// the allow-list is always enforced, enabling credentials cannot grant a new
    /// origin — and this test pins that, because it is the one change that would turn
    /// the policy into a universal credential grant.
    #[test]
    fn credentials_do_not_widen_the_allow_list() {
        let cors = Cors::from_manifest(["https://app.example.com"])
            .expect("valid")
            .with_credentials();
        assert!(
            !cors.simple(Some("https://evil.example.com")).is_granted(),
            "credentials must not make an unlisted origin readable"
        );
    }

    // -- preflight ----------------------------------------------------------

    /// A preflight for an allowed method and headers is granted, with the extra headers.
    #[test]
    fn a_preflight_is_granted_for_allowed_method_and_headers() {
        let cors = Cors::from_manifest(["https://app.example.com"])
            .expect("valid")
            .with_methods(["GET", "POST"])
            .with_allowed_headers(["content-type", "x-trace"])
            .with_max_age(600);

        let decision = cors.preflight(
            Some("https://app.example.com"),
            Some("POST"),
            Some("content-type, x-trace"),
        );
        assert!(decision.is_granted(), "{decision:?}");
        let h = decision.headers();
        assert_eq!(
            decided(h, "Access-Control-Allow-Methods").as_deref(),
            Some("POST")
        );
        assert_eq!(
            decided(h, "Access-Control-Allow-Headers").as_deref(),
            Some("content-type, x-trace")
        );
        assert_eq!(
            decided(h, "Access-Control-Max-Age").as_deref(),
            Some("600")
        );
    }

    /// **A preflight for a method the policy does not allow is denied.**
    ///
    /// The check that makes a preflight a policy rather than an echo. Without it the
    /// browser believes it may `DELETE` a route the server only accepts `GET` on.
    #[test]
    fn a_preflight_for_a_disallowed_method_is_denied() {
        let cors = Cors::from_manifest(["https://app.example.com"])
            .expect("valid")
            .with_methods(["GET"]);
        let decision = cors.preflight(Some("https://app.example.com"), Some("DELETE"), None);
        assert!(
            matches!(decision.reason(), Some(Reason::MethodNotAllowed(_))),
            "{decision:?}"
        );
        assert!(
            decided(decision.headers(), "Access-Control-Allow-Methods").is_none(),
            "a refusal must not advertise the method it refused"
        );
    }

    /// **A preflight for a header the policy does not allow is denied.**
    #[test]
    fn a_preflight_for_a_disallowed_header_is_denied() {
        let cors = Cors::from_manifest(["https://app.example.com"])
            .expect("valid")
            .with_methods(["POST"])
            .with_allowed_headers(["content-type"]);
        let decision = cors.preflight(
            Some("https://app.example.com"),
            Some("POST"),
            Some("content-type, x-secret-exfil"),
        );
        assert!(
            matches!(decision.reason(), Some(Reason::HeaderNotAllowed(_))),
            "{decision:?}"
        );
    }

    /// A preflight from a disallowed origin is denied before the method is even read.
    #[test]
    fn a_preflight_from_a_disallowed_origin_is_denied() {
        let cors = Cors::from_manifest(["https://app.example.com"])
            .expect("valid")
            .with_methods(["GET"]);
        let decision = cors.preflight(Some("https://evil.example.com"), Some("GET"), None);
        assert!(
            matches!(decision.reason(), Some(Reason::OriginNotAllowed(_))),
            "{decision:?}"
        );
    }

    /// **An unconfigured method set advertises nothing.**
    ///
    /// A guess here is how a `GET`-only route comes back advertising `DELETE`. The
    /// policy refuses instead, and the message says which configuration is missing.
    #[test]
    fn an_unconfigured_method_set_advertises_nothing() {
        let cors = Cors::from_manifest(["https://app.example.com"]).expect("valid");
        let decision = cors.preflight(Some("https://app.example.com"), Some("GET"), None);
        assert!(
            matches!(decision.reason(), Some(Reason::MethodNotAllowed(_))),
            "{decision:?}"
        );
    }

    /// An `OPTIONS` with an `Origin` but no `Access-Control-Request-Method` is not a
    /// preflight, and gets the simple-request answer.
    #[test]
    fn an_options_without_a_requested_method_is_not_a_preflight() {
        let cors = Cors::from_manifest(["https://app.example.com"]).expect("valid");
        let decision = cors.preflight(Some("https://app.example.com"), None, None);
        assert!(decision.is_granted(), "{decision:?}");
        assert!(
            decided(decision.headers(), "Access-Control-Allow-Methods").is_none(),
            "an ordinary OPTIONS must not be answered with preflight headers"
        );
    }

    /// The requested method is matched case-insensitively and echoed normalized.
    #[test]
    fn the_requested_method_is_normalized() {
        let cors = Cors::from_manifest(["https://app.example.com"])
            .expect("valid")
            .with_methods(["POST"]);
        let decision = cors.preflight(Some("https://app.example.com"), Some("post"), None);
        assert!(decision.is_granted(), "{decision:?}");
        assert_eq!(
            decided(decision.headers(), "Access-Control-Allow-Methods").as_deref(),
            Some("POST")
        );
    }

    // -- exposed headers ----------------------------------------------------

    /// Exposed headers are listed when configured and absent otherwise.
    #[test]
    fn exposed_headers_are_listed_when_configured() {
        let cors = Cors::from_manifest(["https://app.example.com"])
            .expect("valid")
            .with_exposed_headers(["x-request-id", "x-trace"]);
        let Decision::Granted(h) = cors.simple(Some("https://app.example.com")) else {
            panic!("granted");
        };
        assert_eq!(
            decided(&h, "Access-Control-Expose-Headers").as_deref(),
            Some("x-request-id, x-trace")
        );

        let plain = Cors::from_manifest(["https://app.example.com"]).expect("valid");
        let Decision::Granted(h) = plain.simple(Some("https://app.example.com")) else {
            panic!("granted");
        };
        assert!(decided(&h, "Access-Control-Expose-Headers").is_none());
    }

    // -- origin parsing -----------------------------------------------------

    /// Origins are parsed and canonicalized.
    #[test]
    fn origins_are_canonicalized_on_parse() {
        let cases = [
            ("https://EXAMPLE.com", "https://example.com"),
            ("HTTPS://example.com", "https://example.com"),
            ("https://example.com:8443", "https://example.com:8443"),
            ("http://localhost:3000", "http://localhost:3000"),
            (" https://example.com ", "https://example.com"),
            ("https://[::1]:8080", "https://[::1]:8080"),
        ];
        for (input, want) in cases {
            let got = Origin::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(got.as_str(), want, "parsing {input}");
        }
    }

    /// Malformed origins are refused, with a reason naming what is wrong.
    #[test]
    fn malformed_origins_are_refused() {
        for bad in [
            "",
            "example.com",
            "https://",
            "https://example.com/path",
            "https://example.com?q=1",
            "https://example.com#frag",
            "null",
        ] {
            let err = Origin::parse(bad).expect_err("must refuse");
            assert!(matches!(err, CorsError::BadOrigin(_)), "{bad:?}: {err:?}");
        }
    }

    /// **An origin with a path is refused, because it is a URL.**
    ///
    /// The `Origin` header is an origin, never a URL. Accepting `https://example.com/x`
    /// would mean matching a prefix, which is the substring bug wearing a different hat.
    #[test]
    fn an_origin_with_a_path_is_a_url_and_is_refused() {
        let err = Origin::parse("https://example.com/admin").expect_err("must refuse");
        assert!(err.to_string().contains("not a URL"), "{err}");
    }

    // -- determinism --------------------------------------------------------

    /// The same policy and request always produce the same header order.
    ///
    /// §10.5 requires determinism of observable output, and a header list is output. A
    /// `HashSet` in this type would make the order vary, which would show up as a
    /// flapping snapshot test somewhere downstream.
    #[test]
    fn decisions_are_deterministic() {
        let cors = Cors::from_manifest(["https://app.example.com", "https://b.example.com"])
            .expect("valid")
            .with_methods(["GET", "POST"])
            .with_exposed_headers(["x-a", "x-b"]);
        let policy = cors.simple(Some("https://app.example.com"));
        let first = policy.headers();
        for _ in 0..50 {
            let again = cors.simple(Some("https://app.example.com"));
            assert_eq!(again.headers(), first);
        }
    }
}
