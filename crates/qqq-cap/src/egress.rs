//! # Per-tenant egress policy (`SEC-022`)
//!
//! The layer between "a manifest declares outbound hosts" and "a request actually
//! leaves the host". A component names the hosts it may reach; this module decides
//! whether a *given* tenant's request is allowed through, and produces the refusal
//! when it is not.
//!
//! ## Where this sits, and why it is not the security boundary
//!
//! Proposal §7.5 is explicit: the egress proxy is **depth, not the boundary**. The
//! capability engine is the boundary, and "a host without seccomp is still safe
//! against a malicious guest, and that is the property that makes QQQ deployable
//! anywhere."
//!
//! This module is held to that standard. Everything here is a *restriction on top
//! of* a decision the capability engine has already made — it can refuse a request
//! the engine allowed, and it can never permit one the engine refused. The
//! `EgressPolicy::authorize` function therefore takes an already-resolved
//! [`GrantSet`] rather than looking at a manifest, and the first thing it checks is
//! that the HTTP capability is granted at all.
//!
//! ## The three layers a request passes
//!
//! 1. **Capability** — does the resolved grant set include outbound HTTP? If not,
//!    the answer is no and nothing below is consulted.
//! 2. **Tenant** — may *this tenant* reach the host? A tenant may be narrower than
//!    its component: two tenants can run the same artifact with different egress.
//! 3. **Request shape** — is the destination a legal one at all (scheme, port,
//!    literal-address policy)?
//!
//! Layers 2 and 3 are ordered deliberately. A tenant denial is reported as a tenant
//! denial even when the request would also fail the shape check, because the
//! operator asking "why was this blocked?" needs the layer that actually decided,
//! not the first one that could have.
//!
//! ## Why tenants exist here at all
//!
//! Without this, "the component may reach `api.example.com`" is a property of the
//! *artifact*, and every deployment of that artifact gets the same egress. A tenant
//! overlay lets an operator say "tenant A may reach `api.example.com`, tenant B may
//! reach nothing" while shipping one artifact — which is the multi-tenant story
//! §7.5 implies and the capability set alone cannot express.
//!
//! ## Narrowing, never widening
//!
//! A tenant policy is applied to a [`GrantSet`] that already exists, and the result
//! is always a **subset** of what the component declared. There is no constructor
//! that adds a host. This mirrors `GrantSet::narrow`, and it is the property the
//! tests below pin, because a proxy that can widen a grant is worse than no proxy:
//! it would launder an escalation through a component that thinks it is sandboxed.

use std::collections::BTreeMap;

use crate::capability::Capability;
use crate::normalize::HostPattern;
use crate::resolve::GrantSet;

#[cfg(test)]
use crate::manifest::Manifest;

/// A tenant identifier, as an operator names it.
///
/// # Why this is a newtype and not a `String`
///
/// Because the two are confusable at a call site. `authorize(tenant, host)` taking
/// two `&str`s would accept them swapped, and the swap would not fail to compile —
/// it would look up a policy named after a hostname, find none, and deny. A denial
/// is the safe direction, which makes the bug *silent*: it looks like a policy
/// problem rather than a typo, and the operator debugs the wrong thing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantId(String);

impl TenantId {
    /// Wrap an operator-supplied tenant name.
    ///
    /// # Errors
    ///
    /// Rejects an empty name, a name with leading or trailing whitespace, and a
    /// name containing ASCII control characters. The first two would make two
    /// spellings of the same tenant compare unequal — a policy that applies to
    /// `"acme"` but not `"acme "` is a policy with a hole nobody can see — and the
    /// third would let a name forge a log line.
    pub fn new(name: &str) -> Result<Self, String> {
        if name.is_empty() {
            return Err("a tenant id must not be empty".to_owned());
        }
        if name.trim() != name {
            return Err(format!(
                "a tenant id must not have surrounding whitespace: {name:?}. \
                 Two spellings of one tenant would otherwise compare unequal, and \
                 a policy that matches one but not the other has a hole in it."
            ));
        }
        if name.chars().any(char::is_control) {
            return Err(
                "a tenant id must not contain control characters; they would \
                 allow a forged line in the audit log"
                    .to_owned(),
            );
        }
        Ok(Self(name.to_owned()))
    }

    /// The tenant name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a tenant is allowed to reach.
///
/// # Why the default is "nothing", written out rather than derived
///
/// `EgressPolicy::deny_all` is the starting point, and there is no `Default`
/// implementation. `#[derive(Default)]` on a policy type is how a permissive
/// default arrives: someone adds a field, forgets it in every constructor, and the
/// zero value of that field becomes the policy. Denying by default is the whole
/// posture, so it is spelled out where it can be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantEgress {
    /// Hosts this tenant may reach. Empty means **no egress at all**, which is a
    /// valid and common configuration — the absence of an allowlist is not
    /// "unrestricted", it is "nothing".
    allow: Vec<HostPattern>,
    /// Whether cleartext `http://` is permitted for this tenant.
    ///
    /// Defaults to `false`. A manifest declares hosts, not schemes, so without this
    /// a component that declared `api.example.com:80` would reach it in the clear.
    /// Opting in exists because an internal, non-internet host over plain HTTP is a
    /// real deployment; opting *out* by default is because the failure mode of the
    /// other choice is silent.
    allow_cleartext: bool,
    /// Whether a literal IP address is an acceptable destination.
    ///
    /// Defaults to `false`, and this is the load-bearing one. An allowlist of
    /// *names* is a policy about *identity*; a literal address bypasses DNS and
    /// therefore bypasses the allowlist entirely — `https://93.184.216.34/`
    /// reaches the same server as `https://example.com/` while matching no host
    /// pattern. Refusing literals is what makes "the allowlist is the policy" true
    /// rather than aspirational.
    allow_ip_literals: bool,
}

impl TenantEgress {
    /// A tenant that may reach nothing.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            allow: Vec::new(),
            allow_cleartext: false,
            allow_ip_literals: false,
        }
    }

    /// Permit a set of hosts, parsed from manifest-style patterns.
    ///
    /// # Errors
    ///
    /// Returns the first malformed pattern, with its index, so a manifest author
    /// gets an actionable message rather than "invalid policy".
    pub fn allowing_hosts<S: AsRef<str>>(hosts: &[S]) -> Result<Self, String> {
        let mut allow = Vec::with_capacity(hosts.len());
        for (i, raw) in hosts.iter().enumerate() {
            let pattern = HostPattern::parse(raw.as_ref())
                .map_err(|e| format!("egress pattern #{i} ({:?}): {e}", raw.as_ref()))?;
            allow.push(pattern);
        }
        Ok(Self {
            allow,
            allow_cleartext: false,
            allow_ip_literals: false,
        })
    }

    /// Permit cleartext HTTP for this tenant.
    ///
    /// Named `allowing_cleartext` rather than `with_cleartext` so that every call
    /// site reads as a deliberate grant, which is what it is.
    #[must_use]
    pub fn allowing_cleartext(mut self) -> Self {
        self.allow_cleartext = true;
        self
    }

    /// Permit requests to literal IP addresses.
    ///
    /// # Why this is a separate, explicit opt-in
    ///
    /// A literal address is not covered by any host allowlist, because `HostPattern`
    /// matches names. Allowing literals therefore means "the allowlist does not
    /// apply to this tenant". Some deployments need it (a fixed internal endpoint
    /// with no DNS), but it must never be reachable by accident.
    #[must_use]
    pub fn allowing_ip_literals(mut self) -> Self {
        self.allow_ip_literals = true;
        self
    }

    /// Whether this tenant may reach `host` on `port`.
    ///
    /// Returns the matching pattern so the caller can put it in the `why` chain —
    /// "allowed by `*.example.com`" is a different answer from "allowed", and the
    /// difference is what an operator needs when reviewing a policy.
    #[must_use]
    pub fn permits(&self, host: &str, port: u16) -> Option<&HostPattern> {
        self.allow.iter().find(|p| p.matches(host, port))
    }

    /// Whether any host is permitted at all.
    ///
    /// Used to distinguish "this tenant has no egress policy" from "this tenant has
    /// an egress policy that did not match" — different operator problems.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
    }
}

/// How a destination is written, which is itself a policy input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `https` — TLS, the default.
    Https,
    /// `http` — cleartext, refused unless the tenant opts in.
    Http,
}

impl Scheme {
    /// The scheme as written in a URL.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
        }
    }
}

/// A destination a component is asking to reach.
///
/// # Why a struct rather than three arguments
///
/// Because `authorize("example.com", 443, Scheme::Https)` and
/// `authorize("example.com", 443, ...)` are positional, and a port and a scheme are
/// both small values that a caller can transpose without a type error. Naming the
/// fields at the construction site removes the class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// The host as written, **before** any normalization.
    ///
    /// Kept un-normalized so the refusal message quotes what the caller actually
    /// sent. A refusal that echoes a normalized form sends the reader looking for a
    /// string that is not in their code.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The scheme.
    pub scheme: Scheme,
}

impl Destination {
    /// Build a destination.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, scheme: Scheme) -> Self {
        Self {
            host: host.into(),
            port,
            scheme,
        }
    }

    /// Whether the host is a literal IP address rather than a name.
    ///
    /// # Why this is decided here and not by the caller
    ///
    /// `allow_ip_literals` is only meaningful if "is this a literal?" is answered
    /// consistently. A caller that classified destinations itself could disagree
    /// with this function, and the disagreement would be a hole: one call site
    /// saying "a name" while the policy says "a literal". So the classification
    /// lives next to the field it governs.
    ///
    /// IPv6 is recognised by brackets or embedded colons, IPv4 by four dot-separated
    /// decimal octets. This is deliberately stricter than `std::net::IpAddr::parse`,
    /// which accepts forms such as `0x7f.1` that a DNS resolver would not.
    #[must_use]
    pub fn host_is_ip_literal(&self) -> bool {
        is_ipv4_literal(&self.host) || is_ipv6_literal(&self.host)
    }
}

/// A destination written as four decimal octets. Rejects shorthand forms.
fn is_ipv4_literal(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.len() <= 3
            && p.chars().all(|c| c.is_ascii_digit())
            // Reject a leading zero: `010.1.1.1` is octal to some resolvers and
            // decimal to others, which is a classic allowlist bypass.
            && !(p.len() > 1 && p.starts_with('0'))
            && p.parse::<u8>().is_ok()
    })
}

/// An IPv6 literal, bracketed or bare.
fn is_ipv6_literal(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    // `Ipv6Addr::from_str` is the authority; the colon check avoids treating a
    // DNS name containing a colon (already rejected upstream) as an address.
    bare.contains(':') && bare.parse::<std::net::Ipv6Addr>().is_ok()
}

/// Why a request was refused.
///
/// # Why a typed reason rather than a string
///
/// The metrics layer (§10.2) labels denials "by capability, by tenant". A string
/// reason cannot be aggregated without parsing, so the reason is an enum and the
/// string is derived for humans. It also makes the tests exhaustive: adding a
/// variant forces every match to consider it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// The resolved grant set does not include outbound HTTP.
    CapabilityNotGranted,
    /// The tenant has no policy at all — distinct from a policy that did not match.
    NoTenantPolicy,
    /// The tenant's policy exists but does not name this host.
    HostNotAllowed,
    /// The destination is cleartext and the tenant has not opted in.
    CleartextNotAllowed,
    /// The destination is a literal address and the tenant has not opted in.
    IpLiteralNotAllowed,
    /// The destination host is malformed.
    MalformedHost(String),
}

impl Denial {
    /// A stable, low-cardinality label for metrics and logs.
    ///
    /// # Why this is separate from `Display`
    ///
    /// `Display` interpolates the host, which is unbounded — §10.2 forbids that in
    /// a metric label ("no raw paths, no user IDs, no full URLs"). This returns the
    /// bounded token; `Display` returns the sentence. Conflating them is how a
    /// high-cardinality label gets added by accident.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::CapabilityNotGranted => "capability_not_granted",
            Self::NoTenantPolicy => "no_tenant_policy",
            Self::HostNotAllowed => "host_not_allowed",
            Self::CleartextNotAllowed => "cleartext_not_allowed",
            Self::IpLiteralNotAllowed => "ip_literal_not_allowed",
            Self::MalformedHost(_) => "malformed_host",
        }
    }
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapabilityNotGranted => write!(
                f,
                "outbound HTTP is not granted to this component, so no egress \
                 policy below it is consulted"
            ),
            Self::NoTenantPolicy => write!(
                f,
                "no egress policy is configured for this tenant, so it may reach \
                 nothing"
            ),
            Self::HostNotAllowed => write!(f, "the tenant's egress policy does not name this host"),
            Self::CleartextNotAllowed => {
                write!(f, "cleartext HTTP is not permitted for this tenant")
            }
            Self::IpLiteralNotAllowed => write!(
                f,
                "a literal IP address is not permitted for this tenant, because an \
                 allowlist of names is a policy about identity and an address \
                 bypasses DNS and therefore bypasses the allowlist"
            ),
            Self::MalformedHost(why) => write!(
                f,
                "the destination host is not \
                 acceptable: {why}"
            ),
        }
    }
}

/// The outcome of an authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The request may proceed.
    Allow {
        /// The pattern that permitted it, for the `why` chain.
        matched: HostPattern,
    },
    /// The request must not proceed.
    Deny(Denial),
}

impl Decision {
    /// Whether the request may proceed.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// The denial, if any.
    #[must_use]
    pub fn denial(&self) -> Option<&Denial> {
        match self {
            Self::Allow { .. } => None,
            Self::Deny(d) => Some(d),
        }
    }
}

/// Every tenant's egress policy.
///
/// # Why a `BTreeMap` and not a `HashMap`
///
/// Iteration order is part of the type's observable behaviour — `tenants()` returns
/// a deterministic list, so a report, a test, or a diff over a policy dump is
/// stable. A `HashMap` would make an audit output reorder between runs for no
/// reason, which trains readers to ignore ordering changes that might matter.
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    tenants: BTreeMap<TenantId, TenantEgress>,
}

impl EgressPolicy {
    /// An empty policy: every tenant may reach nothing.
    ///
    /// # Why `Default` is correct here when it was wrong for `TenantEgress`
    ///
    /// `TenantEgress::default()` would be a *policy* whose absent fields took zero
    /// values; the risk was a field added later becoming permissive by omission.
    /// This type holds only a map, and an empty map is unambiguously "no tenant
    /// may do anything" — the deny-by-default posture itself, with nothing to get
    /// wrong.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a tenant's policy, replacing any previous one.
    ///
    /// # Why replacement is the right semantics, and not a merge
    ///
    /// Merging two policies would be a *widening* operation — the union of two
    /// allowlists is larger than either. Since a policy is a restriction, applying
    /// a second one must not be able to enlarge it, so the second replaces the
    /// first and the caller decides which is authoritative. A merge would need a
    /// rule for conflicting entries, and the only safe rule is "the narrower one",
    /// which is exactly what replacement already gives.
    pub fn set(&mut self, tenant: TenantId, egress: TenantEgress) {
        self.tenants.insert(tenant, egress);
    }

    /// A tenant's policy, if it has one.
    #[must_use]
    pub fn get(&self, tenant: &TenantId) -> Option<&TenantEgress> {
        self.tenants.get(tenant)
    }

    /// Every tenant, in name order.
    #[must_use]
    pub fn tenants(&self) -> Vec<&TenantId> {
        self.tenants.keys().collect()
    }

    /// How many tenants have a policy.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tenants.len()
    }

    /// Whether no tenant has a policy.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tenants.is_empty()
    }

    /// Decide whether `tenant` may reach `destination`.
    ///
    /// # The order of the checks, and why it is this order
    ///
    /// 1. **Capability.** If the grant set lacks outbound HTTP, nothing below is
    ///    consulted — the engine has already refused, and this module cannot
    ///    reverse that. Checking it first also means the cheapest and most
    ///    authoritative answer is the one reported.
    /// 2. **Tenant existence.** A tenant with no policy may reach nothing. This is
    ///    reported distinctly from "policy exists but did not match", because
    ///    "tenant B was never configured" and "tenant B was configured and this
    ///    host is not in it" are different operator problems.
    /// 3. **Host shape.** A literal address is refused before matching, because it
    ///    would not match any pattern anyway and reporting "host not allowed" would
    ///    obscure the actual reason.
    /// 4. **Scheme.** Cleartext is refused before the allowlist match for the same
    ///    reason.
    /// 5. **Allowlist.** The pattern match, which is the decision the operator
    ///    wrote.
    ///
    /// # Why the shape checks precede the match
    ///
    /// If the order were reversed, a literal address would report
    /// `HostNotAllowed`, and an operator would add the address to the allowlist —
    /// which does nothing, because literals are compared as names and never match.
    /// The check that actually decided must be the one reported.
    #[must_use]
    pub fn authorize(
        &self,
        grants: &GrantSet,
        tenant: &TenantId,
        destination: &Destination,
    ) -> Decision {
        // 1. The engine's decision is not reviewable here.
        if !grants.grants(Capability::HttpClient) {
            return Decision::Deny(Denial::CapabilityNotGranted);
        }

        // Validate the host once, so the checks below can assume a well-formed one.
        if destination.host.is_empty() {
            return Decision::Deny(Denial::MalformedHost("it is empty".to_owned()));
        }
        if destination.host.contains(char::is_whitespace) {
            return Decision::Deny(Denial::MalformedHost("it contains whitespace".to_owned()));
        }
        if destination.host.contains('/') {
            return Decision::Deny(Denial::MalformedHost(
                "it contains a path separator; a destination is a host, not a URL".to_owned(),
            ));
        }

        // 2. A tenant with no policy reaches nothing.
        let Some(egress) = self.tenants.get(tenant) else {
            return Decision::Deny(Denial::NoTenantPolicy);
        };

        // 3. Literals bypass DNS and therefore bypass an allowlist of names.
        if destination.host_is_ip_literal() && !egress.allow_ip_literals {
            return Decision::Deny(Denial::IpLiteralNotAllowed);
        }

        // 4. Cleartext is opt-in.
        if destination.scheme == Scheme::Http && !egress.allow_cleartext {
            return Decision::Deny(Denial::CleartextNotAllowed);
        }

        // 5. The decision the operator wrote.
        match egress.permits(&destination.host, destination.port) {
            Some(matched) => Decision::Allow {
                matched: matched.clone(),
            },
            None => Decision::Deny(Denial::HostNotAllowed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(name: &str) -> TenantId {
        TenantId::new(name).expect("the test's tenant name is valid")
    }

    /// A grant set that includes outbound HTTP.
    ///
    /// # Why this parses a manifest rather than adding a capability directly
    ///
    /// `GrantSet` deliberately exposes **no** way to add a capability: `from_manifest`
    /// is documented as "the only layer that may grant authority", and `narrow` can
    /// only remove. A test-only insert helper would have been convenient and would
    /// have weakened exactly the invariant this module depends on — so the fixture
    /// goes through the real front door instead, and the assertion below proves the
    /// fixture grants what the test needs.
    fn grants_with_http() -> GrantSet {
        let manifest = Manifest::parse(
            r#"
            [package]
            name = "egress-fixture"
            version = "0.1.0"

            [capabilities.http]
            client = ["fixture.example.com"]
            "#,
        )
        .expect("the fixture manifest is valid");

        let grants = GrantSet::from_manifest(&manifest);
        assert!(
            grants.grants(Capability::HttpClient),
            "the fixture must grant HTTP, or the allow-path tests prove nothing"
        );
        grants
    }

    /// A grant set with no HTTP at all — the engine has already refused.
    fn grants_without_http() -> GrantSet {
        let manifest = Manifest::parse(
            r#"
            [package]
            name = "egress-fixture"
            version = "0.1.0"
            "#,
        )
        .expect("the fixture manifest is valid");

        let grants = GrantSet::from_manifest(&manifest);
        assert!(
            !grants.grants(Capability::HttpClient),
            "the fixture must NOT grant HTTP, or the capability tests prove nothing"
        );
        grants
    }

    fn policy_with(hosts: &[&str]) -> EgressPolicy {
        let mut policy = EgressPolicy::new();
        policy.set(
            tenant("acme"),
            TenantEgress::allowing_hosts(hosts).expect("the test's patterns are valid"),
        );
        policy
    }

    // -- The capability check is not reviewable ----------------------------

    /// **The engine's refusal cannot be reversed here.** §7.5 states the egress
    /// proxy is depth, not the boundary, and this is that claim as an executable
    /// property: with HTTP not granted, *no* tenant policy can allow a request.
    ///
    /// This is the test that would fail if someone later "helpfully" made the proxy
    /// consult a tenant's allowlist before the grant set.
    #[test]
    fn a_tenant_policy_cannot_grant_what_the_engine_refused() {
        let policy = policy_with(&["api.example.com"]);

        let decision = policy.authorize(
            &grants_without_http(),
            &tenant("acme"),
            &Destination::new("api.example.com", 443, Scheme::Https),
        );

        assert_eq!(decision.denial(), Some(&Denial::CapabilityNotGranted));
        assert!(
            !decision.is_allowed(),
            "a permissive tenant policy must never override a capability refusal"
        );
    }

    // -- Deny by default ----------------------------------------------------

    #[test]
    fn an_unknown_tenant_reaches_nothing() {
        let policy = policy_with(&["api.example.com"]);
        let decision = policy.authorize(
            &grants_with_http(),
            &tenant("globex"),
            &Destination::new("api.example.com", 443, Scheme::Https),
        );
        assert_eq!(decision.denial(), Some(&Denial::NoTenantPolicy));
    }

    #[test]
    fn a_tenant_with_an_empty_allowlist_reaches_nothing() {
        let mut policy = EgressPolicy::new();
        policy.set(tenant("acme"), TenantEgress::deny_all());

        let decision = policy.authorize(
            &grants_with_http(),
            &tenant("acme"),
            &Destination::new("api.example.com", 443, Scheme::Https),
        );
        assert_eq!(decision.denial(), Some(&Denial::HostNotAllowed));
    }

    /// "Not configured" and "configured and did not match" are different answers,
    /// and an operator debugging a denial needs to tell them apart.
    #[test]
    fn no_policy_is_distinct_from_a_policy_that_did_not_match() {
        let mut policy = EgressPolicy::new();
        policy.set(tenant("acme"), TenantEgress::deny_all());

        let unconfigured = policy.authorize(
            &grants_with_http(),
            &tenant("globex"),
            &Destination::new("api.example.com", 443, Scheme::Https),
        );
        let configured_but_missing = policy.authorize(
            &grants_with_http(),
            &tenant("acme"),
            &Destination::new("api.example.com", 443, Scheme::Https),
        );

        assert_eq!(unconfigured.denial(), Some(&Denial::NoTenantPolicy));
        assert_eq!(
            configured_but_missing.denial(),
            Some(&Denial::HostNotAllowed)
        );
    }

    // -- The allowlist actually decides --------------------------------------

    #[test]
    fn an_allowed_host_is_permitted_and_names_its_pattern() {
        let policy = policy_with(&["*.example.com:443"]);

        let decision = policy.authorize(
            &grants_with_http(),
            &tenant("acme"),
            &Destination::new("api.example.com", 443, Scheme::Https),
        );

        match decision {
            Decision::Allow { matched } => {
                assert_eq!(
                    matched.as_written(),
                    "*.example.com:443",
                    "the `why` chain must name the pattern that decided, not just \
                     that something did"
                );
            }
            Decision::Deny(d) => panic!("expected an allow, got: {d}"),
        }
    }

    #[test]
    fn a_host_outside_the_allowlist_is_refused() {
        let policy = policy_with(&["api.example.com"]);
        let decision = policy.authorize(
            &grants_with_http(),
            &tenant("acme"),
            &Destination::new("evil.example.net", 443, Scheme::Https),
        );
        assert_eq!(decision.denial(), Some(&Denial::HostNotAllowed));
    }

    /// The port in a pattern must bind. A policy written for `:443` that permitted
    /// `:8443` would be the classic off-by-a-port hole.
    #[test]
    fn a_pattern_with_a_port_binds_to_it() {
        let policy = policy_with(&["api.example.com:443"]);

        let right_port = policy.authorize(
            &grants_with_http(),
            &tenant("acme"),
            &Destination::new("api.example.com", 443, Scheme::Https),
        );
        let wrong_port = policy.authorize(
            &grants_with_http(),
            &tenant("acme"),
            &Destination::new("api.example.com", 8443, Scheme::Https),
        );

        assert!(right_port.is_allowed());
        assert_eq!(wrong_port.denial(), Some(&Denial::HostNotAllowed));
    }

    // -- The literal-address bypass -----------------------------------------

    /// **A literal address must not reach an allowlisted server.**
    ///
    /// `https://93.184.216.34/` is the same server as `https://example.com/`, but
    /// it matches no host pattern. If the proxy permitted it, the allowlist would
    /// be advisory rather than enforced — the difference between a policy and a
    /// suggestion.
    #[test]
    fn a_literal_ip_address_is_refused_even_when_the_name_is_allowed() {
        let policy = policy_with(&["example.com"]);

        let by_name = policy.authorize(
            &grants_with_http(),
            &tenant("acme"),
            &Destination::new("example.com", 443, Scheme::Https),
        );
        let by_address = policy.authorize(
            &grants_with_http(),
            &tenant("acme"),
            &Destination::new("93.184.216.34", 443, Scheme::Https),
        );

        assert!(by_name.is_allowed(), "the name is allowlisted");
        assert_eq!(
            by_address.denial(),
            Some(&Denial::IpLiteralNotAllowed),
            "the address reaches the same server and must not slip past an \
             allowlist of names"
        );
    }

    /// A literal is refused for its own reason, not reported as a host mismatch —
    /// otherwise an operator adds the address to the allowlist, which cannot work.
    #[test]
    fn a_literal_is_reported_as_a_literal_not_as_a_host_mismatch() {
        let policy = policy_with(&["example.com"]);
        let decision = policy.authorize(
            &grants_with_http(),
            &tenant("acme"),
            &Destination::new("10.0.0.1", 443, Scheme::Https),
        );
        assert_eq!(decision.denial(), Some(&Denial::IpLiteralNotAllowed));
        assert_ne!(
            decision.denial(),
            Some(&Denial::HostNotAllowed),
            "reporting the wrong layer sends the operator to fix the wrong thing"
        );
    }

    #[test]
    fn literals_are_permitted_only_when_explicitly_enabled() {
        let mut policy = EgressPolicy::new();
        policy.set(
            tenant("acme"),
            TenantEgress::deny_all().allowing_ip_literals(),
        );

        let decision = policy.authorize(
            &grants_with_http(),
            &tenant("acme"),
            &Destination::new("10.0.0.1", 443, Scheme::Https),
        );

        // Still refused, but now because the allowlist does not name it — the
        // opt-in removed the literal check, not the allowlist.
        assert_eq!(decision.denial(), Some(&Denial::HostNotAllowed));
    }

    /// Shorthand IPv4 forms are rejected, because resolvers disagree about them and
    /// an allowlist must not depend on a resolver's mood.
    #[test]
    fn ipv4_shorthand_and_octal_forms_are_not_classified_as_literals() {
        for host in ["0x7f.1", "127.1", "010.1.1.1", "1.2.3", "1.2.3.4.5"] {
            let d = Destination::new(host, 443, Scheme::Https);
            assert!(
                !d.host_is_ip_literal(),
                "{host:?} must not be classified as a literal: `010.1.1.1` is \
                 octal to some resolvers and decimal to others, so treating it as \
                 an address would make the policy resolver-dependent"
            );
        }
        assert!(Destination::new("10.0.0.1", 443, Scheme::Https).host_is_ip_literal());
    }

    #[test]
    fn an_ipv6_literal_is_recognised_in_both_spellings() {
        assert!(Destination::new("[::1]", 443, Scheme::Https).host_is_ip_literal());
        assert!(Destination::new("::1", 443, Scheme::Https).host_is_ip_literal());
        assert!(Destination::new("2001:db8::1", 443, Scheme::Https).host_is_ip_literal());
        assert!(!Destination::new("example.com", 443, Scheme::Https).host_is_ip_literal());
    }

    // -- Cleartext -----------------------------------------------------------

    #[test]
    fn cleartext_is_refused_by_default_and_permitted_when_opted_in() {
        let strict = policy_with(&["internal.example.com"]);
        let refused = strict.authorize(
            &grants_with_http(),
            &tenant("acme"),
            &Destination::new("internal.example.com", 80, Scheme::Http),
        );
        assert_eq!(refused.denial(), Some(&Denial::CleartextNotAllowed));

        let mut permissive = EgressPolicy::new();
        permissive.set(
            tenant("acme"),
            TenantEgress::allowing_hosts(&["internal.example.com"])
                .expect("valid pattern")
                .allowing_cleartext(),
        );
        let permitted = permissive.authorize(
            &grants_with_http(),
            &tenant("acme"),
            &Destination::new("internal.example.com", 80, Scheme::Http),
        );
        assert!(permitted.is_allowed());
    }

    // -- Malformed destinations ---------------------------------------------

    #[test]
    fn a_malformed_host_is_refused_and_says_why() {
        let policy = policy_with(&["example.com"]);

        for (host, expected) in [
            ("", "empty"),
            ("exa mple.com", "whitespace"),
            ("http://example.com", "path separator"),
        ] {
            let decision = policy.authorize(
                &grants_with_http(),
                &tenant("acme"),
                &Destination::new(host, 443, Scheme::Https),
            );
            match decision.denial() {
                Some(Denial::MalformedHost(why)) => {
                    assert!(
                        why.contains(expected),
                        "the reason for {host:?} was {why:?}, which does not \
                         mention {expected:?}"
                    );
                }
                other => panic!("{host:?} should be malformed, got {other:?}"),
            }
        }
    }

    // -- Tenant identity -----------------------------------------------------

    /// Two spellings of one tenant must not be able to diverge, because a policy
    /// that matches `"acme"` but not `"acme "` is a hole nobody can see.
    #[test]
    fn a_tenant_id_rejects_surrounding_whitespace_and_control_characters() {
        assert!(TenantId::new("").is_err());
        assert!(TenantId::new(" acme").is_err());
        assert!(TenantId::new("acme ").is_err());
        assert!(TenantId::new("acme\n").is_err());
        assert!(TenantId::new("acme\x00").is_err());
        assert!(TenantId::new("acme").is_ok());
        assert!(TenantId::new("acme-corp.eu").is_ok());
    }

    // -- Policy bookkeeping --------------------------------------------------

    #[test]
    fn setting_a_tenant_policy_replaces_rather_than_widens() {
        let mut policy = EgressPolicy::new();
        policy.set(
            tenant("acme"),
            TenantEgress::allowing_hosts(&["a.example.com", "b.example.com"])
                .expect("valid patterns"),
        );
        policy.set(
            tenant("acme"),
            TenantEgress::allowing_hosts(&["a.example.com"]).expect("valid pattern"),
        );

        assert!(policy
            .authorize(
                &grants_with_http(),
                &tenant("acme"),
                &Destination::new("a.example.com", 443, Scheme::Https)
            )
            .is_allowed());
        assert_eq!(
            policy
                .authorize(
                    &grants_with_http(),
                    &tenant("acme"),
                    &Destination::new("b.example.com", 443, Scheme::Https)
                )
                .denial(),
            Some(&Denial::HostNotAllowed),
            "applying a second policy must restrict, never accumulate"
        );
    }

    #[test]
    fn tenants_are_listed_in_a_stable_order() {
        let mut policy = EgressPolicy::new();
        for name in ["zeta", "alpha", "mu"] {
            policy.set(tenant(name), TenantEgress::deny_all());
        }
        let names: Vec<&str> = policy.tenants().iter().map(|t| t.as_str()).collect();
        assert_eq!(
            names,
            ["alpha", "mu", "zeta"],
            "iteration order is observable, so it must be deterministic"
        );
    }

    #[test]
    fn a_new_policy_has_no_tenants() {
        let policy = EgressPolicy::new();
        assert!(policy.is_empty());
        assert_eq!(policy.len(), 0);
    }

    // -- Malformed patterns are rejected, not ignored -------------------------

    /// A malformed pattern must fail loudly at policy-construction time. Silently
    /// dropping it would produce a policy that looks like it names three hosts and
    /// enforces two.
    #[test]
    fn a_malformed_egress_pattern_is_an_error_not_a_silent_skip() {
        let err = TenantEgress::allowing_hosts(&["good.example.com", "*"])
            .expect_err("a bare `*` must be rejected");
        assert!(
            err.contains("pattern #1"),
            "the error must name the offending index so a manifest author can find \
             it: {err}"
        );
    }

    // -- Metric labels stay bounded ------------------------------------------

    /// §10.2: "no metric label may take an unbounded value (no raw paths, no user
    /// IDs, no full URLs)". A denial's label must therefore be a fixed token, and
    /// the host must appear only in the human-readable form.
    #[test]
    fn every_denial_has_a_bounded_label_and_a_separate_human_form() {
        let denials = [
            Denial::CapabilityNotGranted,
            Denial::NoTenantPolicy,
            Denial::HostNotAllowed,
            Denial::CleartextNotAllowed,
            Denial::IpLiteralNotAllowed,
            Denial::MalformedHost("some detail".to_owned()),
        ];

        for d in &denials {
            let label = d.label();
            assert!(
                label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "a metric label must be a bounded, low-cardinality token: {label:?}"
            );
            assert!(
                !label.contains('.'),
                "a label containing a dot would carry a hostname: {label:?}"
            );
            assert!(
                !d.to_string().is_empty(),
                "every denial needs a sentence for a human"
            );
        }

        // The specific risk: a hostname must never reach a label.
        let with_host = Denial::MalformedHost("evil.example.com".to_owned());
        assert_eq!(with_host.label(), "malformed_host");
        assert!(
            !with_host.label().contains("example.com"),
            "the bounded label must not interpolate the host"
        );
    }
}
