// SPDX-License-Identifier: Apache-2.0

//! `qqq:dns/resolver` — name resolution from an explicit allowlist.
//!
//! Resolution is a **capability**, and a covert one: a guest that can resolve
//! an arbitrary name can exfiltrate data in the queries themselves, with no
//! HTTP request and no payload to inspect. So resolution is allowlisted by
//! name, not merely restricted by protocol.
//!
//! The manifest names resolvable names; the deploy layer resolves that list
//! once and hands this module a [`DnsConfig`]. Nothing here reads the
//! manifest or the environment per call: membership in the config is the
//! allowlist, exactly as `host_env`'s map is.
//!
//! Actual lookup goes through a [`DnsResolver`]. Production serves the
//! [`SystemResolver`], which asks the operating system; tests and
//! deterministic runs use the [`StaticResolver`], which answers from a
//! fixed table without touching the network. The host code never knows
//! which it holds — the trait is the seam, and the seam is what makes the
//! boundary testable without the network.
//!
//! V1 resolves synchronously: `timeout-ms` is accepted (it is a `u64`, so
//! any guest value is representable) but the host sets no deadline of its
//! own — there is nothing to wait on, since lookup is a single call, not a
//! subscription. `timeout` surfaces only when the platform itself reports
//! one; a lookup that fails otherwise produces `not-found` or
//! `resolver-failed`, never silence.
//!
//! Deterministic runs use the same system resolver (`DET-011` owns network
//! replay, which does not exist yet): a `--deterministic` run that resolves
//! records real-network answers, so replay of DNS reads is explicitly out
//! of scope until `DET-011` lands. This mirrors the shared-backend
//! treatment in `host_kv`/`host_queue`, whose cross-request ordering is
//! likewise owned by `DET-012`, not re-solved per interface.
//!
//! ```
//! let config = qqq_host::host_dns::DnsConfig::new(vec!["api.example.com".to_owned()]);
//! assert!(config.allows("api.example.com"));
//! assert!(!config.allows("other.example.com"));
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use qqq_cap::capability::Capability::DnsResolve;

/// The WIT package this module implements.
///
/// ```
/// assert_eq!(qqq_host::host_dns::INTERFACE, "qqq:dns@1.0.0");
/// ```
pub const INTERFACE: &str = "qqq:dns@1.0.0";

/// The generated bindings carry no doc comments of their own, and re-exporting
/// them would fail `missing_docs` on the WIT's definition rather than on any
/// prose this crate wrote. The allow is scoped to the generated module so
/// hand-written items keep the lint.
#[allow(missing_docs)]
mod bindings {
    wasmtime::component::bindgen!({
        path: "../../wit/qqq-dns.wit",
        interfaces: "import qqq:dns/resolver@1.0.0;",
    });
}

/// The WIT `dns-error`, re-exported rather than re-declared: the WIT variant
/// is the definition. (Same rule as `host_log` and `host_secrets`.)
pub use bindings::qqq::dns::resolver::DnsError as WitDnsError;

/// A resolved address, in host form: the guest sees the WIT variant, and
/// this is the shape the resolver trait speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAddr {
    /// An IPv4 address in dotted form.
    V4(String),
    /// An IPv6 address in colon form.
    V6(String),
}

/// Why a lookup failed, without leaking how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupFailure {
    /// The name is valid and allowlisted but resolves to nothing.
    NotFound,
    /// The lookup timed out waiting for the resolver.
    TimedOut,
    /// The resolver itself failed: no network, refused query, broken
    /// configuration. Carries no detail by design — OS resolver strings
    /// can name local search domains and servers, and the guest contract
    /// needs only the fact of failure (see `SystemResolver`).
    Failed,
}

/// The lookup seam: production asks the operating system, tests answer from
/// a fixed table. Object-safe and thread-safe, so a view can share one
/// behind an `Arc` across every request of a deployment.
///
/// Splitting "who may ask" (the config, checked by the host) from "who
/// answers" (this trait) is what keeps the allowlist testable without the
/// network: every grant and membership test below drives the real `Host`
/// impl against a table, and only [`SystemResolver`]'s own test touches the
/// real resolver — against `localhost`, which needs no network.
pub trait DnsResolver: Send + Sync + std::fmt::Debug {
    /// Resolve `name` to its addresses.
    ///
    /// # Errors
    ///
    /// `NotFound` when the name is valid and allowlisted but resolves to
    /// nothing; `TimedOut` when the resolver does not answer in time;
    /// `Failed` when the resolver itself cannot answer.
    fn lookup(&self, name: &str) -> Result<Vec<DnsAddr>, LookupFailure>;
}

/// Order addresses v4-first, then by address bytes, dropping duplicates.
///
/// One helper, used by every resolver, so ordering is a property of the
/// host rather than of whichever backend answered: an event that reorders
/// between resolvers would break replay determinism (`DET-006`) and the
/// guest-visible contract alike. Explicit family-then-address comparison —
/// not `Debug`-name order, where a variant rename would silently become a
/// resolution-order change.
fn sort_addrs(out: &mut Vec<DnsAddr>) {
    use std::cmp::Ordering;
    out.sort_by(|a, b| match (a, b) {
        (DnsAddr::V4(_), DnsAddr::V6(_)) => Ordering::Less,
        (DnsAddr::V6(_), DnsAddr::V4(_)) => Ordering::Greater,
        (DnsAddr::V4(x), DnsAddr::V4(y)) | (DnsAddr::V6(x), DnsAddr::V6(y)) => x.cmp(y),
    });
    out.dedup();
}

/// The production resolver: the operating system's resolver, synchronously.
///
/// `localhost` and literal IP addresses resolve without the network (hosts
/// file and parser, respectively); anything else goes to DNS. Failures the
/// platform reports as not-found surface as [`LookupFailure::NotFound`],
/// platform timeouts surface as [`LookupFailure::TimedOut`], and everything
/// else — no network, refused query, broken configuration — surfaces as
/// [`LookupFailure::Failed`], because retrying those as a missing name
/// would misdirect the guest exactly the way the WIT's
/// `name-not-allowed`/`not-found` split exists to prevent.
#[derive(Debug, Clone, Default)]
pub struct SystemResolver;

impl DnsResolver for SystemResolver {
    fn lookup(&self, name: &str) -> Result<Vec<DnsAddr>, LookupFailure> {
        use std::net::ToSocketAddrs as _;
        // Port zero: the lookup resolves the host and discards the port.
        // Literal IPs parse without touching the network at all.
        match format!("{name}:0").to_socket_addrs() {
            Ok(addrs) => {
                let mut out: Vec<DnsAddr> = addrs
                    .map(|socket| match socket.ip() {
                        std::net::IpAddr::V4(v4) => DnsAddr::V4(v4.to_string()),
                        std::net::IpAddr::V6(v6) => DnsAddr::V6(v6.to_string()),
                    })
                    .collect();
                sort_addrs(&mut out);
                if out.is_empty() {
                    Err(LookupFailure::NotFound)
                } else {
                    Ok(out)
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(LookupFailure::NotFound)
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                Err(LookupFailure::TimedOut)
            }
            Err(_) => {
                // Static to the guest: OS resolver strings can carry local
                // configuration (search domains, server addresses), and the
                // WIT contract needs only the fact of failure. An operator
                // debugging resolution uses the host's own diagnostics, not
                // a guest-visible string.
                Err(LookupFailure::Failed)
            }
        }
    }
}

/// A fixed-table resolver for tests and deterministic runs.
///
/// Answers from the map, never the network: a missing name is `NotFound`,
/// full stop. Deterministic by construction — the same table answers the
/// same way on every run, which is what `DET-011` (network recording,
/// absent) cannot yet promise for the system resolver.
///
/// ```
/// use std::collections::BTreeMap;
/// use std::net::IpAddr;
/// let mut records = BTreeMap::new();
/// records.insert("api.example.com".to_owned(), vec!["192.0.2.10".parse::<IpAddr>().expect("literal parses")]);
/// let resolver = qqq_host::host_dns::StaticResolver::new(records);
/// let found = resolver.lookup("api.example.com").expect("listed");
/// assert_eq!(found.len(), 1);
/// assert!(matches!(resolver.lookup("other.example.com"), Err(qqq_host::host_dns::LookupFailure::NotFound)));
/// ```
#[derive(Debug, Clone, Default)]
pub struct StaticResolver {
    records: BTreeMap<String, Vec<std::net::IpAddr>>,
}

impl StaticResolver {
    /// Answer exactly `records`, nothing else.
    #[must_use]
    pub fn new(records: BTreeMap<String, Vec<std::net::IpAddr>>) -> Self {
        Self { records }
    }
}

impl DnsResolver for StaticResolver {
    fn lookup(&self, name: &str) -> Result<Vec<DnsAddr>, LookupFailure> {
        match self.records.get(name) {
            None => Err(LookupFailure::NotFound),
            Some(addrs) => {
                let mut out: Vec<DnsAddr> = addrs
                    .iter()
                    .map(|ip| match ip {
                        std::net::IpAddr::V4(v4) => DnsAddr::V4(v4.to_string()),
                        std::net::IpAddr::V6(v6) => DnsAddr::V6(v6.to_string()),
                    })
                    .collect();
                // Same order contract as the system resolver: the table's
                // insertion order must not leak into guest-visible results.
                sort_addrs(&mut out);
                Ok(out)
            }
        }
    }
}

/// The largest single name the host accepts, in bytes.
///
/// 253 is the DNS wire limit for a full name; anything longer cannot
/// resolve anywhere, so refusing it at the boundary saves a doomed lookup.
pub(crate) const MAX_DNS_NAME_BYTES: usize = 253;

/// The most names one `resolve-many` call may carry.
///
/// Each name is a lookup, and an unbounded batch is unbounded resolver
/// load for one call. 128 names fit comfortably in the guest's memory
/// while bounding the amplification a single call can drive.
pub(crate) const MAX_DNS_BATCH_NAMES: usize = 128;

/// Whether a name is safe to resolve.
///
/// Non-empty, within the wire limit, free of whitespace and control
/// characters, and shaped like dotted labels: those can never appear in a
/// configured name, so they can never be allowlisted, and asking the
/// resolver about them would leak the guest's malformed input into a query.
/// Failing closed here keeps malformed names out of the resolver entirely.
///
/// Dotless single labels (`localhost`, `db`) resolve via the hosts database
/// or search domains: valid DNS rather than a bypass, and blocking them
/// would break the one hermetic name every test relies on.
fn valid_name(name: &str) -> bool {
    const MAX_DNS_SEGMENTS: usize = 127;
    if name.is_empty() || name.len() > MAX_DNS_NAME_BYTES {
        return false;
    }
    if name
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return false;
    }
    if !name.contains('.') {
        return true;
    }
    // No empty labels (`a..b`), no leading or trailing dot, no overlong
    // label: those never appear in the allowlist, which stores bare names.
    let mut labels = 0usize;
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        labels += 1;
        if labels > MAX_DNS_SEGMENTS {
            return false;
        }
    }
    true
}

/// Which names the guest may resolve.
///
/// Resolved once at deploy from the manifest; cloned per request, never
/// re-resolved per call.
///
/// ```
/// let config = qqq_host::host_dns::DnsConfig::new(Vec::new());
/// assert!(!config.allows("anything"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct DnsConfig {
    /// Names the manifest configures, in declaration order.
    pub names: Vec<String>,
}

impl DnsConfig {
    /// The deploy-time resolution: exactly what the manifest configures.
    ///
    /// ```
    /// let config = qqq_host::host_dns::DnsConfig::new(vec!["a.example.com".to_owned()]);
    /// assert!(config.allows("a.example.com"));
    /// ```
    #[must_use]
    pub fn new(names: Vec<String>) -> Self {
        Self { names }
    }

    /// Whether `name` is configured. Membership is the allowlist: an
    /// unlisted name is `name-not-allowed`, never a failed lookup the guest
    /// could mistake for a missing record.
    ///
    /// Names compare case-insensitively per RFC 4343 §2.1, mirroring
    /// `Normalized::dns_allows`: `API.EXAMPLE.COM` and `api.example.com`
    /// name the same host, so they must agree here too.
    #[must_use]
    pub fn allows(&self, name: &str) -> bool {
        let query = name.trim().to_ascii_lowercase();
        self.names.iter().any(|allowed| allowed == &query)
    }
}

/// The per-instance view: deploy-resolved config plus the resolver.
///
/// Both halves are `Arc`s: the config is read-only after deploy, and the
/// resolver is stateless, so sharing one across every request of the
/// deployment is free of the locking the stateful backends need.
///
/// ```
/// let view = qqq_host::host_dns::DnsView::default();
/// assert!(view.config.names.is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct DnsView {
    /// The deploy-resolved allowlist.
    pub config: Arc<DnsConfig>,
    /// The lookup backend: system in production, static in tests.
    pub resolver: Arc<dyn DnsResolver>,
}

impl Default for DnsView {
    fn default() -> Self {
        Self {
            config: Arc::new(DnsConfig::new(Vec::new())),
            resolver: Arc::new(SystemResolver),
        }
    }
}

impl DnsView {
    /// A view over `config` and `resolver`.
    ///
    /// ```
    /// let view = qqq_host::host_dns::DnsView::new(
    ///     std::sync::Arc::new(qqq_host::host_dns::DnsConfig::new(vec!["a.example.com".to_owned()])),
    ///     std::sync::Arc::new(qqq_host::host_dns::SystemResolver),
    /// );
    /// assert!(view.config.allows("a.example.com"));
    /// ```
    #[must_use]
    pub fn new(config: Arc<DnsConfig>, resolver: Arc<dyn DnsResolver>) -> Self {
        Self { config, resolver }
    }
}

/// Register the DNS interface for the granted capability.
///
/// Links `qqq:dns/resolver` only when `dns.resolve` is granted; every
/// function re-checks at call time.
///
/// ```
/// let engine = wasmtime::Engine::default();
/// let mut linker = wasmtime::component::Linker::<qqq_host::linker::StoreData>::new(&engine);
/// qqq_host::host_dns::register(&mut linker, &qqq_cap::resolve::GrantSet::empty())
///     .expect("empty grants register nothing");
/// ```
///
/// # Errors
///
/// A `wasmtime::Error` if the linker rejects an interface.
pub fn register(
    linker: &mut wasmtime::component::Linker<crate::linker::StoreData>,
    grants: &qqq_cap::resolve::GrantSet,
) -> wasmtime::Result<()> {
    use wasmtime::component::HasSelf;
    if !grants.grants(DnsResolve) {
        return Ok(());
    }
    bindings::qqq::dns::resolver::add_to_linker::<
        crate::linker::StoreData,
        HasSelf<crate::linker::StoreData>,
    >(linker, |state| state)?;
    Ok(())
}

/// Check a resolution and return the normalized name to resolve.
///
/// Grant first (an ungranted call fails before its name is judged), then
/// shape, then membership. An unlistable name is `name-not-allowed`, never
/// a failed lookup: the resolver must never see a name the allowlist
/// could not have contained.
///
/// Normalization happens exactly once, here: trim plus ASCII-lowercase per
/// RFC 4343 §2.1, matching `Normalized::dns_allows` and the deploy-time
/// `resolve_dns_config`. Every downstream user — the allowlist check and
/// the resolver call alike — sees the same canonical form, so a guest
/// asking `API.EXAMPLE.COM` and a manifest listing `api.example.com`
/// agree everywhere instead of only at the gate.
fn check(data: &crate::linker::StoreData, name: &str) -> std::result::Result<String, WitDnsError> {
    if !data.grants.grants(DnsResolve) {
        return Err(WitDnsError::NotGranted);
    }
    let normalized = name.trim().to_ascii_lowercase();
    if !valid_name(&normalized) || !data.dns.config.allows(&normalized) {
        return Err(WitDnsError::NameNotAllowed);
    }
    Ok(normalized)
}

/// The host implementation of `qqq:dns/resolver`.
///
/// # Why every method re-checks both the grant and the config
///
/// Registration is conditional on the grant AND the body re-checks it, so a
/// mis-built linker still denies (`ARCH-012`). The config check is separate
/// because grants are capability-level while names are allowlisted:
/// `dns.resolve` says the guest may resolve *some* name, and only the
/// config says which.
impl bindings::qqq::dns::resolver::Host for crate::linker::StoreData {
    fn resolve(
        &mut self,
        name: String,
    ) -> std::result::Result<Vec<bindings::qqq::dns::resolver::Address>, WitDnsError> {
        // `check` returns the normalized name; the lookup below must use
        // *it*, not the raw guest string, or a differently-cased query
        // would pass the gate and then miss the table.
        let name = check(self, &name)?;
        match self.dns.resolver.lookup(&name) {
            Ok(addrs) if !addrs.is_empty() => Ok(addrs
                .into_iter()
                .map(|addr| match addr {
                    DnsAddr::V4(text) => bindings::qqq::dns::resolver::Address::Ipv4(text),
                    DnsAddr::V6(text) => bindings::qqq::dns::resolver::Address::Ipv6(text),
                })
                .collect()),
            Ok(_) | Err(LookupFailure::NotFound) => Err(WitDnsError::NotFound),
            Err(LookupFailure::TimedOut) => Err(WitDnsError::Timeout),
            Err(LookupFailure::Failed) => Err(WitDnsError::ResolverFailed(
                "the resolver failed".to_owned(),
            )),
        }
    }

    fn resolve_many(
        &mut self,
        names: Vec<String>,
    ) -> std::result::Result<
        Vec<std::result::Result<Vec<bindings::qqq::dns::resolver::Address>, WitDnsError>>,
        WitDnsError,
    > {
        // Grant first, like every other method: an ungranted oversize batch
        // is denied for the missing grant, not for its size — the module's
        // own grant-first rule, applied uniformly rather than where it is
        // convenient.
        if !self.grants.grants(DnsResolve) {
            return Err(WitDnsError::NotGranted);
        }
        // The batch count is bounded before any lookup runs: each name is a
        // resolver round-trip, and an unbounded batch is unbounded resolver
        // load for one call. `resolver-failed` names the host's own refusal
        // (no single entry is at fault), with the limit in the message.
        if names.len() > MAX_DNS_BATCH_NAMES {
            return Err(WitDnsError::ResolverFailed(format!(
                "batch of {} names exceeds the host limit of {MAX_DNS_BATCH_NAMES}",
                names.len()
            )));
        }
        let mut out = Vec::with_capacity(names.len());
        for name in &names {
            // Order preserved by construction: one slot per input, in input
            // order — the WIT's explicit contract, not an emergent property.
            out.push(self.resolve(name.clone()));
        }
        Ok(out)
    }

    fn allowed_names(&mut self) -> Vec<String> {
        // Infallible by WIT design (the manifest set is public), so the
        // grant re-check fails closed by answering empty rather than by
        // erroring: an ungranted caller learns nothing, including membership.
        if !self.grants.grants(DnsResolve) {
            return Vec::new();
        }
        self.dns.config.names.clone()
    }
}

// Test indexing (`F-18`): assertions index vectors built inline above.
// One module-level reason, not per-site noise; shipping code above
// carries no such allowance.
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions index inline vectors"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::linker::StoreData;
    use qqq_cap::manifest::Manifest;
    use qqq_cap::resolve::GrantSet;

    fn granted_store() -> StoreData {
        let manifest = Manifest::parse(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.dns]\nresolve = [\"api.example.com\"]\n",
        )
        .expect("manifest parses");
        let grants = GrantSet::from_manifest(&manifest);
        let view = DnsView::new(
            Arc::new(DnsConfig::new(vec!["api.example.com".to_owned()])),
            Arc::new(StaticResolver::new(
                [(
                    "api.example.com".to_owned(),
                    vec![
                        "192.0.2.10".parse().expect("literal parses"),
                        "2001:db8::10".parse().expect("literal parses"),
                    ],
                )]
                .into_iter()
                .collect(),
            )),
        );
        StoreData::new(grants).with_dns(view)
    }

    fn ungranted_store() -> StoreData {
        StoreData::new(GrantSet::empty())
    }

    /// A granted, listed name resolves through the injected table, v4 first
    /// in table order — no network touched.
    #[test]
    fn granted_listed_name_resolves() {
        let mut data = granted_store();
        let addrs =
            bindings::qqq::dns::resolver::Host::resolve(&mut data, "api.example.com".to_owned())
                .expect("listed resolves");
        assert_eq!(addrs.len(), 2);
        assert!(matches!(
            &addrs[0],
            bindings::qqq::dns::resolver::Address::Ipv4(text) if text == "192.0.2.10"
        ));
        assert!(matches!(
            &addrs[1],
            bindings::qqq::dns::resolver::Address::Ipv6(_)
        ));
    }

    /// Ungranted reads fail before the name is judged: spraying names at an
    /// ungranted interface learns nothing, not even membership.
    #[test]
    fn ungranted_reads_fail_closed() {
        let mut data = ungranted_store();
        let err =
            bindings::qqq::dns::resolver::Host::resolve(&mut data, "api.example.com".to_owned())
                .expect_err("no grant");
        assert!(matches!(err, WitDnsError::NotGranted));
    }

    /// Unlisted names are unresolvable by policy, even when the resolver
    /// behind them would answer: the allowlist is membership, and a failed
    /// lookup must never be confusable with a denied one.
    #[test]
    fn unlisted_names_are_not_allowed() {
        let mut data = granted_store();
        let err =
            bindings::qqq::dns::resolver::Host::resolve(&mut data, "other.example.com".to_owned())
                .expect_err("unlisted");
        assert!(matches!(err, WitDnsError::NameNotAllowed));
    }

    /// Malformed names fail at the boundary, before any resolver sees them:
    /// empty, overlong, and whitespace-bearing names can never be allowlisted.
    #[test]
    fn hostile_names_are_not_allowed() {
        let mut data = granted_store();
        for hostile in [
            "",
            &"a".repeat(MAX_DNS_NAME_BYTES + 1),
            "exa mple.com",
            "a\nb.com",
        ] {
            let err = bindings::qqq::dns::resolver::Host::resolve(&mut data, hostile.to_owned())
                .expect_err("hostile name refused");
            assert!(
                matches!(err, WitDnsError::NameNotAllowed),
                "{hostile:?} must fail closed"
            );
        }
    }

    /// A listed name the table does not know is `not-found`: absence, not
    /// denial, and the distinction is the WIT's explicit contract.
    #[test]
    fn listed_but_unknown_is_not_found() {
        let mut data = granted_store();
        // `missing.example.com` is not in the static table.
        let mut listed = data.dns.config.names.clone();
        listed.push("missing.example.com".to_owned());
        data.dns.config = Arc::new(DnsConfig::new(listed));
        let err = bindings::qqq::dns::resolver::Host::resolve(
            &mut data,
            "missing.example.com".to_owned(),
        )
        .expect_err("unknown is not found, not denied");
        assert!(matches!(err, WitDnsError::NotFound));
    }

    /// Batch results keep input order, mixing answers and per-name errors.
    #[test]
    fn resolve_many_preserves_order() {
        let mut data = granted_store();
        let mut listed = data.dns.config.names.clone();
        listed.push("missing.example.com".to_owned());
        data.dns.config = Arc::new(DnsConfig::new(listed));
        let out = bindings::qqq::dns::resolver::Host::resolve_many(
            &mut data,
            vec![
                "missing.example.com".to_owned(),
                "api.example.com".to_owned(),
            ],
        )
        .expect("the batch itself succeeds");
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], Err(WitDnsError::NotFound)));
        assert!(matches!(&out[1], Ok(addrs) if addrs.len() == 2));
    }

    /// Oversize batches fail whole-call before any lookup runs.
    #[test]
    fn oversize_batches_fail_closed() {
        let mut data = granted_store();
        let names: Vec<String> = (0..=MAX_DNS_BATCH_NAMES)
            .map(|i| format!("n{i}.example.com"))
            .collect();
        let err = bindings::qqq::dns::resolver::Host::resolve_many(&mut data, names)
            .expect_err("too many names");
        assert!(matches!(err, WitDnsError::ResolverFailed(_)));
    }

    /// Grant first, even for batches: an ungranted oversize batch is
    /// denied for the missing grant, not refused for its size.
    #[test]
    fn oversize_batch_without_grant_is_not_granted() {
        let mut data = ungranted_store();
        let names: Vec<String> = (0..=MAX_DNS_BATCH_NAMES)
            .map(|i| format!("n{i}.example.com"))
            .collect();
        let err = bindings::qqq::dns::resolver::Host::resolve_many(&mut data, names)
            .expect_err("no grant means no batch");
        assert!(matches!(err, WitDnsError::NotGranted));
    }

    /// Case is not identity: a differently-cased query resolves against the
    /// same lowercase config the deploy layer stores, so the gate and the
    /// lookup agree instead of one passing what the other misses.
    #[test]
    fn mixed_case_query_resolves() {
        let mut data = granted_store();
        let addrs =
            bindings::qqq::dns::resolver::Host::resolve(&mut data, "API.EXAMPLE.COM".to_owned())
                .expect("case must not matter");
        assert_eq!(addrs.len(), 2);
    }

    /// The static resolver orders v4-first regardless of table order: the
    /// order contract lives in the shared helper, not in any one backend.
    #[test]
    fn static_resolver_sorts_v4_first() {
        use std::net::IpAddr;
        let mut records = BTreeMap::new();
        records.insert(
            "x.example.com".to_owned(),
            vec![
                "2001:db8::10".parse::<IpAddr>().expect("literal parses"),
                "192.0.2.10".parse::<IpAddr>().expect("literal parses"),
            ],
        );
        let resolver = StaticResolver::new(records);
        let found = resolver.lookup("x.example.com").expect("listed");
        assert!(matches!(found[0], DnsAddr::V4(_)));
        assert!(matches!(found[1], DnsAddr::V6(_)));
    }

    /// A resolver timeout surfaces as the WIT `timeout`, not as a generic
    /// failure: the variant exists for exactly this outcome.
    #[test]
    fn resolver_timeout_maps_to_timeout() {
        #[derive(Debug)]
        struct Hanging;
        impl DnsResolver for Hanging {
            fn lookup(&self, _name: &str) -> Result<Vec<DnsAddr>, LookupFailure> {
                Err(LookupFailure::TimedOut)
            }
        }
        // `Hanging` is test-only on purpose: no production resolver hangs
        // on demand, and the seam exists so no test needs one that does.
        let mut data = granted_store();
        data.dns.resolver = Arc::new(Hanging);
        let err =
            bindings::qqq::dns::resolver::Host::resolve(&mut data, "api.example.com".to_owned())
                .expect_err("a timeout is an error, not an empty answer");
        assert!(matches!(err, WitDnsError::Timeout));
    }

    /// `allowed-names` without a grant answers empty rather than erroring.
    #[test]
    fn allowed_names_without_grant_is_empty() {
        let mut data = ungranted_store();
        assert!(bindings::qqq::dns::resolver::Host::allowed_names(&mut data).is_empty());
    }

    /// The system resolver answers `localhost` without leaving the host.
    ///
    /// Hermetic basis, stated exactly: `localhost` resolves through the
    /// local hosts database (or the loopback interface), never through a
    /// DNS query on the wire. If a platform lacks even that, this test
    /// fails loudly rather than silently skipping — a resolver that cannot
    /// answer `localhost` is itself the finding.
    #[test]
    fn system_resolver_answers_localhost() {
        let found = SystemResolver
            .lookup("localhost")
            .expect("localhost resolves");
        assert!(!found.is_empty(), "localhost must have an address");
    }

    /// The register links only when the dns grant is present.
    #[test]
    fn register_links_only_when_granted() {
        const EMPTY: &str = r#"(component
          (import "qqq:dns/resolver@1.0.0" (instance $r))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        const NAMED: &str = r#"(component
          (import "qqq:dns/resolver@1.0.0" (instance $r
            (export "allowed-names" (func (result (list string))))))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        fn link(grants: &GrantSet, wat: &str) -> wasmtime::Result<()> {
            let mut config = wasmtime::Config::new();
            config.wasm_component_model(true);
            let engine = wasmtime::Engine::new(&config).expect("engine builds");
            let mut linker = wasmtime::component::Linker::new(&engine);
            register(&mut linker, grants)?;
            let bytes = wat::parse_str(wat).expect("fixture assembles");
            let component =
                wasmtime::component::Component::new(&engine, &bytes).expect("fixture compiles");
            let mut store = wasmtime::Store::new(&engine, StoreData::new(grants.clone()));
            linker.instantiate(&mut store, &component).map(|_| ())
        }
        let manifest = Manifest::parse(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.dns]\nresolve = [\"a.example.com\"]\n",
        )
        .expect("manifest parses");
        link(&GrantSet::from_manifest(&manifest), EMPTY).expect("a granted import links");
        link(&GrantSet::from_manifest(&manifest), NAMED).expect("granted names link");
        let err = link(&GrantSet::empty(), NAMED).expect_err("no grant means no instance");
        assert!(
            format!("{err:#}").contains("qqq:dns/resolver"),
            "the refusal must name the interface: {err:#}"
        );
    }
}
