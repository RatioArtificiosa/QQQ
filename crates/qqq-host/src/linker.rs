//! The grant-built linker — where the capability model becomes enforcement.
//!
//! This is **the single most security-critical function in QQQ**. It is the
//! point at which a resolved [`GrantSet`] is turned into the set of imports a
//! guest can actually reach.
//!
//! # The property being enforced
//!
//! > A capability the manifest did not grant is **absent**, not denied.
//!
//! The distinction matters more than it first appears:
//!
//! * A **denied** call is one the guest can attempt and be refused. That means
//!   the guest can *enumerate* what exists, the host must handle the attempt,
//!   and any bug in the denial path is a vulnerability.
//! * An **absent** import cannot be referenced at all. The guest's module
//!   validation fails at instantiation, before a single instruction runs. There
//!   is no denial path to get wrong.
//!
//! This was verified against the real toolchain: instantiating a component
//! through an empty linker fails with *"component imports instance
//! `host:probe/greeter`, but a matching implementation was not found in the
//! linker"* — naming the exact missing import. See Observations §O-006.
//!
//! # Why the linker is built per instance, not per process
//!
//! A per-process linker would give every tenant the union of every tenant's
//! grants — a catastrophic cross-tenant authority leak, and exactly the failure
//! the whole architecture exists to prevent. Building per instance costs
//! microseconds (measured p50 800 ns for instantiation) and is the difference
//! between "the server has permissions" and "**this request** has permissions".
//!
//! # Defence in depth
//!
//! [`GrantSet`] is consulted twice: here at bind time, and again at call time by
//! [`recheck`]. The second check is cheap (a set lookup on a small enum) and
//! exists specifically to catch a host bug that mis-built a linker. Belt and
//! braces, deliberately.
//!
//! See Proposal §4.4, §7.3 and Checklist `CAP-008`, `SEC-002`.

use std::fmt;

use qqq_cap::capability::Capability;
use qqq_cap::resolve::GrantSet;
use serde::{Deserialize, Serialize};
use wasmtime::component::Linker;
use wasmtime::StoreLimits;

/// The host-state type every store carries.
///
/// Deliberately minimal. `qqq-host`'s fuller store data (resource tables, quota
/// counters, tenant identity) is layered on this in later work; keeping the
/// security-critical path free of unnecessary state makes it auditable.
#[derive(Debug)]
pub struct StoreData {
    /// The grants this instance was created with.
    ///
    /// Retained so the call-time re-check has something authoritative to
    /// consult, rather than re-deriving it from the linker — which would make
    /// the second check vacuous, since a mis-built linker would produce the
    /// same wrong answer twice.
    pub grants: GrantSet,

    /// The Wasmtime resource limiter, applied to every store.
    ///
    /// # Why the resource limiter lives inside the store data
    ///
    /// `Store::limiter` takes a closure returning `&mut StoreLimits`, and the
    /// returned reference must outlive the store. Storing it in the store's own
    /// data is the only arrangement that satisfies that without self-reference
    /// — and it keeps the limits travelling with the instance they constrain,
    /// so they cannot be swapped by mistake.
    resource_limits: StoreLimits,

    /// The QQQ-level limits, for diagnostics and fuel accounting.
    limits: Option<crate::config::StoreLimits>,

    /// Hash algorithms the manifest's `[capabilities.crypto] hash` list named.
    ///
    /// Retained so the host can refuse an algorithm it is perfectly capable of
    /// computing but was not granted. Without this the manifest's allowlist
    /// would be advisory, and a guest could use any primitive the host happened
    /// to link — which is ambient authority by another route.
    pub allowed_hashes: Vec<crate::ambient::HashAlgorithm>,

    /// The ambient state: clock and RNG, deterministic or not.
    pub ambient: crate::ambient::AmbientState,
}

impl Default for StoreData {
    /// An instance with **no** capability and no explicit limits. The safe
    /// default twice over: a store that was not explicitly given grants cannot
    /// do anything, and one without limits has Wasmtime's own defaults.
    fn default() -> Self {
        Self {
            grants: GrantSet::empty(),
            resource_limits: StoreLimits::default(),
            limits: None,
            allowed_hashes: Vec::new(),
            ambient: crate::ambient::AmbientState::default(),
        }
    }
}

impl StoreData {
    /// Build store data from a grant set, with no explicit resource limits.
    #[must_use]
    pub fn new(grants: GrantSet) -> Self {
        Self {
            grants,
            resource_limits: StoreLimits::default(),
            limits: None,
            allowed_hashes: Vec::new(),
            ambient: crate::ambient::AmbientState::default(),
        }
    }

    /// Build store data from a manifest, deriving the ambient state and the
    /// algorithm allowlists from its capability declaration.
    ///
    /// # Why this takes the manifest rather than the grant set
    ///
    /// The grant set says *that* `crypto.hash` is permitted; only the manifest
    /// says *which algorithms*. A host that enforced only the grant would let a
    /// guest use any algorithm the host links, which is not what the developer
    /// declared.
    #[must_use]
    pub fn from_manifest(manifest: &qqq_cap::manifest::Manifest) -> Self {
        let grants = GrantSet::from_manifest(manifest);

        let allowed_hashes = manifest
            .capabilities
            .crypto
            .as_ref()
            .map(|c| {
                c.hash
                    .iter()
                    .filter_map(|h| crate::ambient::HashAlgorithm::parse(h))
                    .collect()
            })
            .unwrap_or_default();

        Self {
            grants,
            resource_limits: StoreLimits::default(),
            limits: None,
            allowed_hashes,
            ambient: crate::ambient::AmbientState::default(),
        }
    }

    /// Install the deterministic ambient state.
    #[must_use]
    pub fn with_deterministic_ambient(mut self, deterministic: bool) -> Self {
        self.ambient = crate::ambient::AmbientState::new(deterministic);
        self
    }

    /// Mutable access to the resource limiter, for `Store::limiter`.
    #[must_use]
    pub fn limiter_mut(&mut self) -> &mut StoreLimits {
        &mut self.resource_limits
    }

    /// Install the Wasmtime limiter and record the QQQ limits.
    pub fn set_limits(&mut self, limiter: StoreLimits, limits: crate::config::StoreLimits) {
        self.resource_limits = limiter;
        self.limits = Some(limits);
    }

    /// The QQQ-level limits, when set.
    #[must_use]
    pub const fn limits(&self) -> Option<crate::config::StoreLimits> {
        self.limits
    }
}

/// Which host interfaces the built linker actually provides.
///
/// Returned alongside the linker so callers (and tests) can assert the mapping
/// from capabilities to interfaces without introspecting Wasmtime internals.
///
/// # Why `String` and not `&'static str`
///
/// The values originate as `'static` constants (see [`interface_for`]), and
/// keeping them `'static` would be marginally cheaper. But this type must be
/// **serializable** — it is part of `qqqai inspect --json` and of the audit
/// record — and `Deserialize` cannot produce a `&'static str`. Owning the
/// strings costs one small allocation per interface at bind time, on a path
/// that happens once per component rather than once per request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundInterfaces {
    /// The `qqq:` interfaces that were bound.
    pub interfaces: Vec<String>,
    /// The capabilities that were granted but have no host implementation yet.
    ///
    /// **Surfaced rather than silently ignored.** A capability that is granted
    /// with no implementation behind it will fail at runtime with a confusing
    /// error; naming it at bind time turns that into a clear diagnostic. It is
    /// also how a partially-implemented milestone stays honest.
    pub unimplemented: Vec<Capability>,
}

impl BoundInterfaces {
    /// Whether a specific interface was bound.
    #[must_use]
    pub fn has(&self, interface: &str) -> bool {
        self.interfaces.iter().any(|i| i == interface)
    }
}

impl fmt::Display for BoundInterfaces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.interfaces.is_empty() {
            return f.write_str("(none)");
        }
        f.write_str(&self.interfaces.join(", "))
    }
}

/// The canonical mapping from a capability to the WIT interface it unlocks.
///
/// # One mapping, two consumers
///
/// This delegates to `qqq_abi`, which owns the **single** source of truth shared
/// with the static capability report (`qqqai inspect`). Keeping a second table
/// here — even one that started identical — is how a report ends up saying a
/// component cannot reach the network while the runtime quietly lets it.
///
/// # The fallback is deliberate
///
/// `Capability` is `#[non_exhaustive]`, so a variant added in a later version
/// reaches this function. Unlocking no interface is the **safe** direction, and
/// `describe_gap` makes the gap loud rather than silent.
#[must_use]
pub fn interface_for(c: Capability) -> Option<&'static str> {
    qqq_abi::interfaces()
        .into_iter()
        .find(|i| i.is_unlocked_by(c))
        .map(|i| interface_name_static(&i.name))
}

/// Map a registry interface name to its `&'static str` form.
///
/// # Why this projection exists
///
/// The registry owns `String`s because it must be serializable — it is part of
/// `qqqai inspect --json`. Callers on the hot path want a `'static` handle
/// without allocating, so this maps to string literals.
///
/// # Why the fallback is `"<unmapped>"`
///
/// Adding an interface to `qqq_abi` without adding it here would otherwise
/// silently produce an empty name. Returning a visibly wrong value means the
/// test `static_names_cover_the_registry` fails the build instead, and a
/// surprise at runtime is impossible.
#[must_use]
fn interface_name_static(name: &str) -> &'static str {
    match name {
        "qqq:ai@1.0.0" => "qqq:ai@1.0.0",
        "qqq:clock@1.0.0" => "qqq:clock@1.0.0",
        "qqq:crypto@1.0.0" => "qqq:crypto@1.0.0",
        "qqq:dns@1.0.0" => "qqq:dns@1.0.0",
        "qqq:env@1.0.0" => "qqq:env@1.0.0",
        "qqq:fs@1.0.0" => "qqq:fs@1.0.0",
        "qqq:http@1.0.0" => "qqq:http@1.0.0",
        "qqq:kv@1.0.0" => "qqq:kv@1.0.0",
        "qqq:log@1.0.0" => "qqq:log@1.0.0",
        "qqq:queue@1.0.0" => "qqq:queue@1.0.0",
        "qqq:secrets@1.0.0" => "qqq:secrets@1.0.0",
        "qqq:sql@1.0.0" => "qqq:sql@1.0.0",
        "qqq:trace@1.0.0" => "qqq:trace@1.0.0",
        _ => "<unmapped>",
    }
}

/// The interfaces a grant set unlocks, in stable sorted order.
///
/// This is the **static** half of the capability report: it needs only a grant
/// set, not a running instance, which is what makes `qqqai inspect` possible
/// before execution.
#[must_use]
pub fn required_interfaces(grants: &GrantSet) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = grants
        .capabilities()
        .into_iter()
        .filter_map(interface_for)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The result of building a linker for one instance.
///
/// Carries the linker together with the interfaces it actually bound, so a
/// caller never has to introspect Wasmtime internals to learn what a guest can
/// reach — and so tests can assert the capability-to-interface mapping without
/// reaching into the engine.
pub struct BuiltLinker<'a> {
    /// The linker to instantiate through.
    pub linker: Linker<StoreData>,
    /// What was bound — see [`BoundInterfaces`].
    pub bound: BoundInterfaces,
    /// Ties the linker to the engine's lifetime.
    _engine: std::marker::PhantomData<&'a wasmtime::Engine>,
}

impl fmt::Debug for BuiltLinker<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BuiltLinker")
            .field("bound", &self.bound)
            .finish_non_exhaustive()
    }
}

/// Build a linker containing **exactly** the interfaces the grants unlock.
///
/// # The security property
///
/// The returned linker provides an interface if and only if at least one
/// capability mapping to it is granted. There is no code path that adds an
/// interface the grant set does not justify.
///
/// # Errors
///
/// Returns an error only if Wasmtime rejects a definition, which would indicate
/// a QQQ bug rather than user error.
pub fn build_linker<'a>(
    engine: &'a wasmtime::Engine,
    grants: &GrantSet,
) -> wasmtime::Result<BuiltLinker<'a>> {
    let mut linker: Linker<StoreData> = Linker::new(engine);

    // Interfaces with a Rust host implementation land here as they are built.
    //
    // Each interface is registered **only when its capability is granted**. The
    // linker is never populated speculatively and then filtered: building it
    // from the grants alone is what makes an ungranted import absent rather than
    // denied, and that property is the whole security argument.
    let required = required_interfaces(grants);
    let mut interfaces: Vec<String> = Vec::with_capacity(required.len());
    let mut unimplemented = Vec::new();

    for iface in required {
        interfaces.push(iface.to_owned());
        match iface {
            "qqq:clock@1.0.0" => {
                crate::host_clock::register(&mut linker, grants)?;
            }
            "qqq:crypto@1.0.0" => {
                crate::host_crypto::register(&mut linker, grants)?;
            }
            // QQQ-STUB(CON-009): `qqq:fs`, `qqq:http`, `qqq:sql` and the rest
            // have no registered interface yet. `qqq:clock` and `qqq:crypto`
            // are the two wired up so far. Recording the gap keeps a
            // partially-implemented milestone honest: a component that imports
            // the others gets a clear diagnostic naming the capability, not
            // Wasmtime's "unknown import".
            //
            // Two notes on the reference, because getting it wrong twice is
            // itself worth recording (Observations §O-020d):
            //
            // * An earlier version cited `HOST-016`, which is
            //   `epoch_deadline_async_yield_and_update` — a scheduling concern,
            //   not interface implementation.
            // * There is no checklist item that says "implement the host
            //   functions of interface X". `CON-009` is the closest governing
            //   item: it fixes the contract each host call must honour
            //   (`result<T, E>` on every fallible call), which is what
            //   `host_clock.rs` and `host_crypto.rs` are written against.
            //   Per-interface work is tracked by the WIT files themselves and
            //   by the `implemented` flag in the `qqq-abi` registry.
            //
            // Note that `qqq:crypto` is only *partially* implemented — `random`
            // and `hashing` are real, `hmac`/`aead`/`signing` are absent on
            // purpose. A component importing the latter therefore still gets
            // this diagnostic, which is the correct outcome: `host_crypto`
            // registers what exists and the rest stays visibly missing.
            _ => {
                for &c in &grants.capabilities() {
                    if interface_for(c) == Some(iface) {
                        unimplemented.push(c);
                    }
                }
            }
        }
    }
    unimplemented.sort_unstable();
    unimplemented.dedup();

    Ok(BuiltLinker {
        linker,
        bound: BoundInterfaces {
            interfaces,
            unimplemented,
        },
        _engine: std::marker::PhantomData,
    })
}

/// Describe what a granted-but-unbound capability means for this instance.
///
/// Returns a `QQQ-6004` error naming the capability and the missing interface,
/// so a developer sees *"`qqq:crypto@1.0.0` is granted but this build has no
/// implementation"* rather than Wasmtime's generic "unknown import".
#[must_use]
pub fn describe_gap(capability: Capability) -> qqq_core::Error {
    let iface = interface_for(capability).unwrap_or("<unmapped>");
    qqq_core::Error::new(
        qqq_core::ErrorCode::InternalInvariantViolated,
        format!("capability `{capability}` is granted but `{iface}` has no host implementation"),
    )
    .with_context("capability", capability.name())
    .with_context("interface", iface)
    .with_remediation(
        "this is a QQQ build gap, not a configuration error — please report it; \
         meanwhile remove the capability from qqq.toml to run",
    )
}

/// The call-time re-check.
///
/// Consults the instance's grant set **again**, at the point of use, rather than
/// trusting that the linker was built correctly.
///
/// # Why a second check when the linker already enforces this
///
/// Because the two checks fail differently. A mis-built linker is a bug in
/// *our* code that would silently grant authority; this check is a bug in our
/// code that produces a *denial*. Given that the two failure modes are
/// "security hole" and "annoying error", the asymmetry justifies the cost — a
/// lookup in a small `BTreeSet`, on a path that is already dominated by the
/// ABI crossing itself.
///
/// # Errors
///
/// Returns `QQQ-4003` with the full resolution context when the capability is
/// not granted, so the error names *what* was denied and *how* to fix it.
#[must_use]
pub fn recheck(data: &StoreData, capability: Capability) -> Option<qqq_core::Error> {
    if data.grants.grants(capability) {
        return None;
    }
    Some(
        qqq_core::Error::new(
            qqq_core::ErrorCode::CapabilityDenied,
            format!("capability `{capability}` is not granted for this instance"),
        )
        .with_context("capability", capability.name())
        .with_context("grant-digest", data.grants.digest())
        .with_context("instance-grants", data.grants.to_string())
        .with_remediation(format!(
            "add a [[capabilities.*]] stanza granting `{capability}` to qqq.toml, \
             then run `qqqai why {capability}` to confirm"
        )),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_cap::manifest::Manifest;

    fn grants_from(src: &str) -> GrantSet {
        let m = Manifest::parse(src).expect("test manifest");
        GrantSet::from_manifest(&m)
    }

    /// Every capability must map to an interface. A gap here means a granted
    /// capability silently unlocks nothing — the guest fails at instantiation
    /// with no explanation of why.
    #[test]
    fn every_capability_maps_to_an_interface() {
        for &c in Capability::all() {
            assert!(
                interface_for(c).is_some(),
                "capability {c} has no interface mapping"
            );
        }
    }

    /// **The delegation must stay honest.** This crate projects the registry's
    /// owned names into `&'static str` literals for the hot path. If an
    /// interface is added to `qqq_abi` without being added to
    /// `interface_name_static`, the projection yields `"<unmapped>"` — a name
    /// that matches no linker definition, so the capability would silently bind
    /// nothing.
    ///
    /// This test is what makes that omission impossible to ship.
    #[test]
    fn static_names_cover_the_registry() {
        for i in qqq_abi::interfaces() {
            assert_ne!(
                interface_name_static(&i.name),
                "<unmapped>",
                "interface `{}` is in the qqq-abi registry but has no static \
                 projection in qqq-host::linker; add it to `interface_name_static`",
                i.name
            );
            assert_eq!(interface_name_static(&i.name), i.name);
        }
    }

    /// The two crates must agree about which capability unlocks which interface.
    /// A disagreement is exactly the drift that makes `qqqai inspect` lie.
    #[test]
    fn host_and_abi_agree_on_every_mapping() {
        for &c in Capability::all() {
            let via_abi = qqq_abi::interface_for(c).map(|i| i.name);
            let via_host = interface_for(c).map(str::to_owned);
            assert_eq!(
                via_abi, via_host,
                "qqq-abi and qqq-host disagree about capability `{c}`"
            );
        }
    }

    /// Interface names must be well-formed and versioned, because they are part
    /// of the machine contract an agent reads.
    ///
    /// # Version shape: `major.minor.patch`
    ///
    /// **Corrected.** This test previously asserted `major.minor` and asserted
    /// that full semver would be wrong — on the reasoning that "the patch level
    /// of an interface carries no meaning". That reasoning was plausible and
    /// **incorrect**: WIT requires full semver, verified by parsing with the
    /// real toolchain:
    ///
    /// ```text
    /// package qqq:x@1.0;    -> error: expected '.', found ';'
    /// package qqq:x@1.0.0;  -> parses
    /// ```
    ///
    /// The mistake is recorded in Observations `§O-017`. The lesson is that a
    /// plausible-sounding principle about a format is not evidence about that
    /// format — the parser is.
    #[test]
    fn interface_names_are_wellformed_and_versioned() {
        for &c in Capability::all() {
            let i = interface_for(c).unwrap();
            assert!(
                i.starts_with("qqq:"),
                "interface `{i}` must be in the qqq: namespace"
            );
            let (name, version) = i
                .split_once('@')
                .unwrap_or_else(|| panic!("interface `{i}` must carry a version"));
            assert!(name.len() > 4, "interface `{name}` is malformed");

            let parts: Vec<&str> = version.split('.').collect();
            assert_eq!(
                parts.len(),
                3,
                "interface version `{version}` must be major.minor.patch — \
                 WIT requires full semver"
            );
            for p in &parts {
                assert!(
                    !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()),
                    "interface version `{version}` has a non-numeric component `{p}`"
                );
            }
            let major: u32 = parts[0].parse().unwrap();
            assert!(major >= 1, "a published interface must be at major >= 1");
        }
    }

    #[test]
    fn granted_capabilities_unlock_their_interfaces() {
        let g = grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.http]\nserver = true\n\
             [capabilities.crypto]\nrandom = true\nhash = [\"sha256\"]\n\
             [capabilities.clock]\nwall = true\n",
        );
        let ifaces = required_interfaces(&g);
        assert!(ifaces.contains(&"qqq:http@1.0.0"));
        assert!(ifaces.contains(&"qqq:crypto@1.0.0"));
        assert!(ifaces.contains(&"qqq:clock@1.0.0"));
        // Never granted, never unlocked.
        assert!(!ifaces.contains(&"qqq:fs@1.0.0"));
        assert!(!ifaces.contains(&"qqq:sql@1.0.0"));
        assert!(!ifaces.contains(&"qqq:secrets@1.0.0"));
    }
    /// The headline security property, stated as a test: an empty grant set
    /// unlocks **nothing**.
    #[test]
    fn empty_grants_unlock_no_interfaces() {
        let g = GrantSet::empty();
        assert!(
            required_interfaces(&g).is_empty(),
            "an empty grant set must unlock no interfaces"
        );
    }

    #[test]
    fn interfaces_are_sorted_and_deduplicated() {
        // Two capabilities mapping to the same interface must yield it once.
        let g = grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nrandom = true\nhash = [\"sha256\"]\n\
             hmac = [\"sha256\"]\naead = [\"aes\"]\nsign = [\"ed25519\"]\n",
        );
        let ifaces = required_interfaces(&g);
        let crypto_count = ifaces.iter().filter(|i| **i == "qqq:crypto@1.0.0").count();
        assert_eq!(crypto_count, 1, "must be deduplicated: {ifaces:?}");
        let mut sorted = ifaces.clone();
        sorted.sort_unstable();
        assert_eq!(ifaces, sorted, "must be sorted");
    }

    /// A capability unlocked by *any* member of a family unlocks the interface
    /// once. A component granted only `fs.read` still gets `qqq:fs`.
    #[test]
    fn one_capability_per_family_is_enough_to_unlock_the_interface() {
        let g = grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [[capabilities.fs]]\npath = \".\"\nmode = \"read-only\"\n",
        );
        assert!(required_interfaces(&g).contains(&"qqq:fs@1.0.0"));
    }

    #[test]
    fn linker_builds_against_a_real_engine() {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&cfg).unwrap();
        let g = grants_from("[package]\nname = \"a\"\nversion = \"0.1.0\"\n");
        let built = build_linker(&engine, &g).expect("linker must build");
        // An empty grant set yields no bound interfaces.
        assert!(
            built.bound.interfaces.is_empty(),
            "no grants must mean no interfaces: {:?}",
            built.bound
        );
        assert!(built.bound.unimplemented.is_empty());
    }

    // -- HOST-011: every host function is panic-guarded ----------------------

    /// **`HOST-011`, enforced structurally.** Every `func_wrap` registration in
    /// this crate must route its body through [`crate::guard`].
    ///
    /// # Why this is a source-level test
    ///
    /// The guard is a *wrapper*, so a host function added without it compiles
    /// perfectly and behaves correctly on every input that does not panic —
    /// which is every input in every test anyone would write. The defect only
    /// appears when a guest finds the panicking path, and then it appears as a
    /// dead process rather than a failing test, because the release profile sets
    /// `panic = "abort"`.
    ///
    /// There is therefore no runtime test that can enforce this, and the rule
    /// exists precisely to prevent a failure that no test can reach. A source
    /// check is the only mechanism available, and it is honest about being one.
    ///
    /// # Why it counts rather than listing names
    ///
    /// Counting `func_wrap(` against `guard::guard(` means a *newly added* host
    /// function is caught, not just a known set. A list of names would go stale
    /// the moment somebody registered the next interface — which is exactly when
    /// this matters most, because new host code is where new panics live.
    ///
    /// # The one exclusion, and why it is safe
    ///
    /// The check reads only the **production** half of each file — everything
    /// before its `#[cfg(test)]` module. Registration in a test's own linker is
    /// not a host function the guest can reach; it exists to probe how Wasmtime
    /// reports a registration, and wrapping it would test the guard rather than
    /// the thing under test.
    ///
    /// Truncating at the test module rather than subtracting a hardcoded number
    /// is what keeps the check honest: a new unguarded registration in
    /// *production* code still fails it, and the first version of this test —
    /// which counted the whole file — reported a mismatch that was really the
    /// probe.
    #[test]
    fn every_host_function_is_panic_guarded() {
        // Each file that registers host functions. `include_str!` reads the
        // repository's own source, so the check runs against what is committed.
        let sources: [(&str, &str); 2] = [
            ("host_clock.rs", include_str!("host_clock.rs")),
            ("host_crypto.rs", include_str!("host_crypto.rs")),
        ];

        for (file, source) in sources {
            // Production code only: everything before the test module. The
            // marker is the same `#[cfg(test)]` every module in this crate uses.
            let production = source
                .split("#[cfg(test)]")
                .next()
                .expect("split always yields at least one element");

            // Whitespace is stripped for the same reason as in
            // `host_crypto::tests::registers`: a match that depends on how
            // `rustfmt` breaks a line is testing formatting, not behaviour.
            let squeezed: String = production.chars().filter(|c| !c.is_whitespace()).collect();

            let registrations = squeezed.matches("func_wrap(").count();
            let guards = squeezed.matches("guard::guard(").count();

            assert!(
                registrations > 0,
                "{file} registers no host functions in production code; if that is \
                 true this check should stop including it, and if it is not, the \
                 check is broken"
            );
            assert_eq!(
                registrations, guards,
                "{file} registers {registrations} host functions but only {guards} \
                 are wrapped in `guard`; an unguarded function unwinds through the \
                 engine on panic, and the release profile sets `panic = \"abort\"`, \
                 so one guest finding it kills the host process (HOST-011)"
            );
        }
    }

    /// A granted capability binds its interface, and one whose interface the
    /// host does not implement is reported as *unimplemented* — a loud,
    /// inspectable gap rather than a silent one.
    ///
    /// # Why this no longer uses `crypto.hash`
    ///
    /// It did, until `host_crypto.rs` landed and `qqq:crypto` became a real
    /// implementation for `random` and `hashing`. The test then failed, which is
    /// exactly right: it was asserting a gap that had been closed. Repointed at
    /// `fs.read`, which has no registered interface, so the property stays under
    /// test instead of being deleted along with its example.
    ///
    /// The general lesson, recorded because it keeps recurring: **a test that
    /// names a specific unfinished feature is a test with an expiry date.** When
    /// one fails after a feature lands, the fix is to repoint it at something
    /// still unfinished, not to remove the assertion.
    #[test]
    fn a_granted_capability_binds_its_interface_and_reports_the_gap() {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&cfg).unwrap();
        let g = grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [[capabilities.fs]]\npath = \"/tmp\"\nmode = \"read-only\"\n",
        );
        let built = build_linker(&engine, &g).unwrap();
        assert!(built.bound.has("qqq:fs@1.0.0"));
        assert!(
            built.bound.unimplemented.contains(&Capability::FsRead),
            "the unimplemented capability must be reported: {:?}",
            built.bound
        );
        // And crucially: nothing outside the grants is bound.
        assert!(!built.bound.has("qqq:sql@1.0.0"));
        assert!(!built.bound.has("qqq:http@1.0.0"));
    }

    /// The converse, now that `qqq:clock` and `qqq:crypto` are implemented: a
    /// capability whose interface *is* registered must **not** be reported as
    /// unimplemented. Without this, a change that marked everything
    /// unimplemented would leave the test above passing.
    #[test]
    fn an_implemented_capability_is_not_reported_as_a_gap() {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&cfg).unwrap();

        for (stanza, cap) in [
            (
                "[capabilities.crypto]\nhash = [\"sha256\"]\n",
                Capability::CryptoHash,
            ),
            (
                "[capabilities.crypto]\nrandom = true\n",
                Capability::CryptoRandom,
            ),
            ("[capabilities.clock]\nwall = true\n", Capability::ClockWall),
            (
                "[capabilities.clock]\nmonotonic = true\n",
                Capability::ClockMonotonic,
            ),
        ] {
            let src = format!("[package]\nname = \"a\"\nversion = \"0.1.0\"\n{stanza}");
            let built = build_linker(&engine, &grants_from(&src)).unwrap();
            assert!(
                !built.bound.unimplemented.contains(&cap),
                "{cap} has a host implementation and must not be reported as a gap: {:?}",
                built.bound
            );
        }
    }

    /// **The core security test.** A component importing a capability we did
    /// not grant must fail to instantiate, and the error must name the import.
    ///
    /// This is the claim verified against the real toolchain in Observations
    /// §O-006, now a permanent regression test.
    #[test]
    fn an_ungranted_import_fails_instantiation_and_names_itself() {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        cfg.consume_fuel(true);
        let engine = wasmtime::Engine::new(&cfg).unwrap();

        // A component that imports `host:probe/greeter`.
        let wat = r#"
            (component
              (import "host:probe/greeter" (instance $g
                (export "greet" (func (param "name" string) (result string)))
              ))
              (alias export $g "greet" (func $greet_comp))
              (core module $mem
                (memory (export "mem") 1)
                (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                  (i32.const 0))
              )
              (core instance $mi (instantiate $mem))
              (core func $greet_core (canon lower (func $greet_comp)
                (memory (core memory $mi "mem"))
                (realloc (core func $mi "realloc"))))
              (core instance $host (export "greet" (func $greet_core)))
              (core module $m
                (import "" "greet" (func $greet (param i32 i32 i32)))
                (func (export "run"))
              )
              (core instance $i (instantiate $m (with "" (instance $host))))
              (func (export "run") (canon lift (core func $i "run")))
            )
        "#;
        let component = wasmtime::component::Component::new(&engine, wat)
            .expect("the probe component must compile");

        let g = GrantSet::empty();
        let built = build_linker(&engine, &g).unwrap();
        let mut store = wasmtime::Store::new(&engine, StoreData::default());

        let result = built.linker.instantiate(&mut store, &component);
        let Err(err) = result else {
            panic!("instantiation MUST fail with an empty linker");
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("greet") || msg.contains("host:probe"),
            "the error must name the missing import: {msg}"
        );
    }

    /// The **control case** for the test above. Without it, the previous test
    /// could be passing because the harness is broken rather than because the
    /// capability model works. This is the pattern recorded in §O-006.
    #[test]
    fn a_satisfied_import_instantiates_and_runs() {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        cfg.consume_fuel(true);
        let engine = wasmtime::Engine::new(&cfg).unwrap();

        let wat = r#"
            (component
              (core module $m (func (export "f") (result i32) (i32.const 42)))
              (core instance $i (instantiate $m))
              (func (export "f") (result u32) (canon lift (core func $i "f")))
            )
        "#;
        let component = wasmtime::component::Component::new(&engine, wat).unwrap();
        let built = build_linker(&engine, &GrantSet::empty()).unwrap();
        let mut store = wasmtime::Store::new(&engine, StoreData::default());
        store.set_fuel(1_000_000).unwrap();

        let instance = built
            .linker
            .instantiate(&mut store, &component)
            .expect("a component with no imports must instantiate");
        let f = instance
            .get_typed_func::<(), (u32,)>(&mut store, "f")
            .unwrap();
        let (v,) = f.call(&mut store, ()).unwrap();
        assert_eq!(v, 42, "the control case must actually work");
    }

    // -- The call-time re-check -------------------------------------------

    #[test]
    fn recheck_passes_for_a_granted_capability() {
        let data = StoreData::new(grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nhash = [\"sha256\"]\n",
        ));
        assert!(recheck(&data, Capability::CryptoHash).is_none());
    }

    #[test]
    fn recheck_denies_an_ungranted_capability_with_full_context() {
        let data = StoreData::new(grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
        ));
        let err =
            recheck(&data, Capability::SqlQuery).expect("an ungranted capability must be denied");
        assert_eq!(err.code, qqq_core::ErrorCode::CapabilityDenied);
        assert_eq!(err.id(), "QQQ-4003");
        assert!(err.remediation.is_some());
        assert!(
            err.context.iter().any(|(k, _)| k == "grant-digest"),
            "the audit digest must be in the denial context"
        );
        assert!(!err.is_retryable());
    }

    /// The re-check consults the *store's* grants, not a re-derivation. If it
    /// re-derived from the linker it would agree with a mis-built linker and
    /// the second check would be vacuous.
    #[test]
    fn recheck_is_independent_of_the_linker() {
        // A store whose grants are empty, even though some other linker might
        // have been built with more.
        let data = StoreData::new(GrantSet::empty());
        for &c in Capability::all() {
            assert!(
                recheck(&data, c).is_some(),
                "{c} must be denied for an empty grant set"
            );
        }
    }

    #[test]
    fn gap_diagnostic_names_the_capability_and_interface() {
        let e = describe_gap(Capability::CryptoHash);
        let msg = e.message.clone();
        assert!(
            msg.contains("crypto.hash"),
            "must name the capability: {msg}"
        );
        assert!(
            msg.contains("qqq:crypto@1.0.0"),
            "must name the interface: {msg}"
        );
        assert!(e.remediation.is_some());
        assert!(e.render().contains("QQQ-6004"));
    }

    #[test]
    fn bound_interfaces_has_lookup_works() {
        let b = BoundInterfaces {
            interfaces: vec!["qqq:http@1.0.0".to_owned(), "qqq:clock@1.0.0".to_owned()],
            unimplemented: vec![],
        };
        assert!(b.has("qqq:http@1.0.0"));
        assert!(!b.has("qqq:sql@1.0.0"));
        assert!(b.to_string().contains("qqq:http@1.0.0"));

        let empty = BoundInterfaces {
            interfaces: Vec::new(),
            unimplemented: Vec::new(),
        };
        assert_eq!(empty.to_string(), "(none)");
        assert!(!empty.has("qqq:http@1.0.0"));
    }
}
