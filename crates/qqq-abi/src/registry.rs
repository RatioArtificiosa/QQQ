//! The interface registry: the single source of truth binding capabilities to
//! the interfaces they unlock.
//!
//! # Why this lives in `qqq-abi` and not in `qqq-host`
//!
//! `qqqai inspect` must answer *"what can this component import?"* **without
//! instantiating it** (Non-Negotiable #5). That means the mapping has to be
//! available to a static analysis path in `qqq-run`, not only to the runtime in
//! `qqq-host`.
//!
//! Having exactly one mapping, used by both, is what guarantees the security
//! report a user reads and the enforcement the runtime performs cannot
//! disagree. Two mappings — even two that start identical — is how a report
//! ends up saying a component *cannot* reach the network while the runtime
//! quietly lets it.
//!
//! See Proposal §6.3, §8.3 and Checklist `ABI-011`, `ABI-014`, `CON-014`.

use std::fmt;

use qqq_cap::capability::Capability;
use serde::{Deserialize, Serialize};

/// One host interface: its versioned name, its capability mappings, and whether
/// the host currently implements it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostInterface {
    /// The versioned WIT name, e.g. `qqq:crypto@1.0.0`.
    pub name: String,
    /// The capabilities that unlock it. Empty for interfaces with no capability
    /// gate (there are none in V1 — everything is gated).
    pub unlocked_by: Vec<Capability>,
    /// Whether this build provides a Rust implementation.
    ///
    /// `false` means a granted capability unlocks an interface the host cannot
    /// yet serve. That is surfaced as `QQQ-6004` at instantiation rather than
    /// failing opaquely at first call — a partially-implemented milestone stays
    /// honest instead of appearing to work.
    pub implemented: bool,
    /// A one-line description, shown by `qqqai schema --wit`.
    pub summary: String,
}

impl HostInterface {
    /// Whether granting `c` unlocks this interface.
    #[must_use]
    pub fn is_unlocked_by(&self, c: Capability) -> bool {
        self.unlocked_by.contains(&c)
    }
}

impl fmt::Display for HostInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({})",
            self.name,
            if self.implemented {
                "implemented"
            } else {
                "declared"
            }
        )
    }
}

/// Build a [`HostInterface`], keeping the two table functions readable.
///
/// Module-level rather than nested so both [`ambient_interfaces`] and
/// [`io_interfaces`] can use it without duplicating the construction.
fn iface(name: &str, caps: &[Capability], implemented: bool, summary: &str) -> HostInterface {
    HostInterface {
        name: name.to_owned(),
        unlocked_by: caps.to_vec(),
        implemented,
        summary: summary.to_owned(),
    }
}

/// The complete V1 interface set.
///
/// # Exhaustiveness
///
/// A test asserts that **every** capability maps to at least one interface in
/// this table. A capability with no interface is a capability that grants
/// nothing while appearing in `qqqai inspect` — a security report that lies.
///
/// `implemented` is set per interface and is honest about the current state.
/// When a host implementation lands, its flag flips to `true` — and the test
/// that asserts no interface claims to be implemented until one is will need
/// updating at the same moment, so the claim cannot rot.
#[must_use]
pub fn interfaces() -> Vec<HostInterface> {
    let mut out = ambient_interfaces();
    out.extend(io_interfaces());
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The interfaces that represent ambient capabilities: time, randomness,
/// observability and the privileged `secrets`.
///
/// Split from [`io_interfaces`] because they answer a different question. These
/// are capabilities a guest uses *within* its own execution; the I/O group is
/// what it uses to reach the outside world. An auditor reading `qqqai inspect`
/// should be able to tell those apart at a glance.
fn ambient_interfaces() -> Vec<HostInterface> {
    use Capability::{
        ClockMonotonic, ClockWall, CryptoAead, CryptoHash, CryptoHmac, CryptoRandom, CryptoSign,
        LogWrite, SecretUse, TraceWrite,
    };

    vec![
        iface(
            "qqq:clock@1.0.0",
            &[ClockWall, ClockMonotonic],
            true,
            "Wall-clock and monotonic time, virtualised in deterministic mode",
        ),
        iface(
            "qqq:crypto@1.0.0",
            &[CryptoRandom, CryptoHash, CryptoHmac, CryptoAead, CryptoSign],
            // Partially implemented: `random` and `hashing` are real and bound
            // (`qqq-host::host_crypto`, backed by `qqq-host::ambient`);
            // `hmac`, `aead` and `signing` are not registered at all.
            //
            // The flag stays `false` until the whole interface is servable —
            // claiming `true` for a partially-served interface would let a
            // guest that needs AEAD pass admission and fail at first call,
            // which is exactly the opaque failure this flag exists to prevent.
            //
            // Note the two levels at which this is enforced, and that they are
            // deliberately redundant: this flag is what `qqqai inspect` reports
            // *statically*, while `build_linker` is what actually refuses at
            // instantiation. A component importing `qqq:crypto/hmac` fails
            // there regardless of what this flag says, because no host function
            // is registered for it.
            false,
            "Randomness, hashing, HMAC, AEAD and signatures, all explicitly named",
        ),
        iface(
            "qqq:log@1.0.0",
            &[LogWrite],
            false,
            "Structured logging with host-applied redaction",
        ),
        iface(
            "qqq:trace@1.0.0",
            &[TraceWrite],
            false,
            "Spans and events with W3C Trace Context propagation",
        ),
        iface(
            "qqq:secrets@1.0.0",
            &[SecretUse],
            false,
            "Use a secret without ever reading it",
        ),
    ]
}

/// The interfaces that reach outside the guest: network, storage, data and
/// configuration.
fn io_interfaces() -> Vec<HostInterface> {
    use Capability::{
        AiInfer, DnsResolve, EnvRead, FsRead, FsWatch, FsWrite, HttpClient, HttpServer, KvRead,
        KvWrite, QueuePublish, QueueSubscribe, SqlExecute, SqlQuery,
    };

    vec![
        iface(
            "qqq:http@1.0.0",
            &[HttpServer, HttpClient],
            false,
            "Inbound handlers and allowlisted outbound requests",
        ),
        iface(
            "qqq:fs@1.0.0",
            &[FsRead, FsWrite, FsWatch],
            false,
            "Preopened directories with mode and quota enforcement",
        ),
        iface(
            "qqq:sql@1.0.0",
            &[SqlQuery, SqlExecute],
            false,
            "Host-pooled SQL; the guest never sees credentials",
        ),
        iface(
            "qqq:kv@1.0.0",
            &[KvRead, KvWrite],
            false,
            "Namespaced key-value access with TTL",
        ),
        iface(
            "qqq:queue@1.0.0",
            &[QueuePublish, QueueSubscribe],
            false,
            "Publish and subscribe with acknowledgement",
        ),
        iface(
            "qqq:dns@1.0.0",
            &[DnsResolve],
            false,
            "Name resolution from an explicit allowlist",
        ),
        iface(
            "qqq:env@1.0.0",
            &[EnvRead],
            false,
            "Individually named environment variables",
        ),
        iface(
            "qqq:ai@1.0.0",
            &[AiInfer],
            false,
            "Model inference with token accounting",
        ),
    ]
}

/// The interface a capability unlocks, if any.
///
/// Returns the **first** match in the sorted table. A capability that unlocks
/// more than one interface would be a design error — a grant should map to one
/// surface, so an auditor reading the manifest can predict the blast radius.
#[must_use]
pub fn interface_for(c: Capability) -> Option<HostInterface> {
    interfaces().into_iter().find(|i| i.is_unlocked_by(c))
}

/// The interfaces a grant set unlocks, sorted.
#[must_use]
pub fn required_interfaces(grants: &qqq_cap::resolve::GrantSet) -> Vec<HostInterface> {
    let granted = grants.capabilities();
    let mut out: Vec<HostInterface> = interfaces()
        .into_iter()
        .filter(|i| i.unlocked_by.iter().any(|c| granted.contains(c)))
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Whether every capability in a grant set is currently servable.
///
/// Returns the capabilities whose interface is declared but unimplemented.
/// Callers use this to fail at **instantiation** with a clear `QQQ-6004`
/// naming the capability, rather than at first call with an opaque linker
/// error.
#[must_use]
pub fn unimplemented_capabilities(grants: &qqq_cap::resolve::GrantSet) -> Vec<Capability> {
    let table = interfaces();
    let mut out: Vec<Capability> = grants
        .capabilities()
        .into_iter()
        .filter(|c| {
            table
                .iter()
                .find(|i| i.is_unlocked_by(*c))
                .is_some_and(|i| !i.implemented)
        })
        .collect();
    out.sort_unstable();
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// **The critical invariant.** Every capability must map to exactly one
    /// interface. A capability with no interface grants nothing while appearing
    /// in `qqqai inspect` — a security report that lies.
    #[test]
    fn every_capability_maps_to_exactly_one_interface() {
        let table = interfaces();
        for &c in Capability::all() {
            let matches: Vec<&HostInterface> =
                table.iter().filter(|i| i.is_unlocked_by(c)).collect();
            assert_eq!(
                matches.len(),
                1,
                "capability `{c}` maps to {} interfaces ({}); it must map to exactly one",
                matches.len(),
                matches
                    .iter()
                    .map(|i| i.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    #[test]
    fn interface_names_are_versioned_and_unique() {
        let mut seen = BTreeSet::new();
        for i in interfaces() {
            assert!(
                seen.insert(i.name.clone()),
                "duplicate interface {}",
                i.name
            );
            assert!(i.name.starts_with("qqq:"));
            let (_, v) = i.name.split_once('@').expect("must carry a version");
            // Full semver, verified against `wasm-tools`: `@1.0` is a syntax
            // error while `@1.0.0` parses. See Observations §O-017.
            let parts: Vec<&str> = v.split('.').collect();
            assert_eq!(
                parts.len(),
                3,
                "`{}` must be major.minor.patch — WIT requires full semver",
                i.name
            );
            assert!(
                parts.iter().all(|p| p.parse::<u32>().is_ok()),
                "`{}` has a non-numeric version part",
                i.name
            );
        }
    }

    #[test]
    fn interfaces_are_sorted_and_have_summaries() {
        let table = interfaces();
        let names: Vec<&str> = table.iter().map(|i| i.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "the table must be sorted by name");
        for i in &table {
            assert!(!i.summary.is_empty(), "{} needs a summary", i.name);
        }
    }

    #[test]
    fn every_interface_has_wit_source() {
        for i in interfaces() {
            assert!(
                crate::wit::wit_source(&i.name).is_some(),
                "interface `{}` has no WIT source; the registry and the definitions \
                 must not disagree",
                i.name
            );
        }
    }

    #[test]
    fn lookup_finds_a_known_capability() {
        let i = interface_for(Capability::CryptoHash).expect("must map");
        assert_eq!(i.name, "qqq:crypto@1.0.0");
        let i = interface_for(Capability::SqlQuery).expect("must map");
        assert_eq!(i.name, "qqq:sql@1.0.0");
    }

    #[test]
    fn required_interfaces_reflects_the_grant_set() {
        use qqq_cap::manifest::Manifest;
        let m = Manifest::parse(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nhash = [\"sha256\"]\nrandom = true\n\
             [capabilities.clock]\nmonotonic = true\n",
        )
        .unwrap();
        let g = qqq_cap::resolve::GrantSet::from_manifest(&m);
        let names: Vec<String> = required_interfaces(&g)
            .into_iter()
            .map(|i| i.name)
            .collect();
        assert!(names.contains(&"qqq:crypto@1.0.0".to_owned()));
        assert!(names.contains(&"qqq:clock@1.0.0".to_owned()));
        assert!(!names.contains(&"qqq:sql@1.0.0".to_owned()));
        assert!(!names.contains(&"qqq:fs@1.0.0".to_owned()));
    }

    #[test]
    fn empty_grants_require_no_interfaces() {
        let g = qqq_cap::resolve::GrantSet::empty();
        assert!(required_interfaces(&g).is_empty());
        assert!(unimplemented_capabilities(&g).is_empty());
    }

    /// Until a host implementation lands, a granted capability must be reported
    /// as unimplemented — so the failure is loud at bind time rather than
    /// opaque at first call.
    #[test]
    fn unimplemented_capabilities_are_reported() {
        use qqq_cap::manifest::Manifest;
        let m = Manifest::parse(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nhash = [\"sha256\"]\n",
        )
        .unwrap();
        let g = qqq_cap::resolve::GrantSet::from_manifest(&m);
        let missing = unimplemented_capabilities(&g);
        assert!(
            missing.contains(&Capability::CryptoHash),
            "crypto.hash has no host implementation yet and must be reported: {missing:?}"
        );
    }

    /// The `implemented` flags are claims about reality. This test pins the
    /// current state so that flipping a flag **without landing the code** fails
    /// the build.
    ///
    /// Update this list in the same commit that lands an implementation, and
    /// note in the commit message which interface became servable. The point is
    /// that the two cannot drift: a flag is a promise to a guest that a granted
    /// capability will work.
    #[test]
    fn implemented_flags_match_reality() {
        let table = interfaces();
        let implemented: Vec<&str> = table
            .iter()
            .filter(|i| i.implemented)
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(
            implemented,
            vec!["qqq:clock@1.0.0"],
            "the set of implemented interfaces changed; update this test in the \
             same commit that lands (or removes) an implementation"
        );
    }

    /// A **partially** implemented interface must still report `false`.
    ///
    /// `qqq:crypto` serves `random` and `hash` today but not `hmac`, `aead` or
    /// `sign`. Reporting it as implemented would let a component needing AEAD
    /// pass admission and then fail at first call — the opaque failure the flag
    /// exists to prevent.
    #[test]
    fn partial_implementations_do_not_claim_completeness() {
        let crypto = interfaces()
            .into_iter()
            .find(|i| i.name.starts_with("qqq:crypto"))
            .expect("crypto interface must exist");
        assert!(
            !crypto.implemented,
            "qqq:crypto serves only random+hash; it must not claim to be implemented"
        );
    }

    #[test]
    fn interface_display_is_informative() {
        let i = HostInterface {
            name: "qqq:crypto@1.0.0".to_owned(),
            unlocked_by: vec![Capability::CryptoHash],
            implemented: false,
            summary: "test".to_owned(),
        };
        assert_eq!(i.to_string(), "qqq:crypto@1.0.0 (declared)");
    }

    #[test]
    fn registry_serializes_for_the_schema_surface() {
        let table = interfaces();
        let j = serde_json::to_value(&table).unwrap();
        assert!(j.is_array());
        assert_eq!(j.as_array().unwrap().len(), table.len());
        assert!(j[0]["name"].is_string());
        assert!(j[0]["implemented"].is_boolean());
    }
}
