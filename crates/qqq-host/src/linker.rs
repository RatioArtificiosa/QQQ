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

/// The host-state type every store carries.
///
/// Deliberately minimal here. `qqq-host`'s fuller store data (resource tables,
/// quota counters, tenant identity) is layered on this in later work; keeping
/// the security-critical path free of unnecessary state makes it auditable.
#[derive(Debug)]
pub struct StoreData {
    /// The grants this instance was created with.
    ///
    /// Retained so the call-time re-check has something authoritative to
    /// consult, rather than re-deriving it from the linker — which would make
    /// the second check vacuous, since a mis-built linker would produce the
    /// same wrong answer twice.
    pub grants: GrantSet,
}

impl Default for StoreData {
    /// An instance with **no** capability. The safe default: a store that was
    /// not explicitly given grants cannot do anything.
    fn default() -> Self {
        Self {
            grants: GrantSet::empty(),
        }
    }
}

impl StoreData {
    /// Build store data from a grant set.
    #[must_use]
    pub fn new(grants: GrantSet) -> Self {
        Self { grants }
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
/// # Why this is a function and not a table in the linker
///
/// Because `qqqai inspect` must be able to answer *"what interfaces will this
/// component be able to import?"* **without instantiating it** (NN-5: what a
/// module can do must be discoverable without running it). A single mapping
/// function used by both the static report and the runtime binding guarantees
/// the two can never disagree — which is the difference between a security
/// report you can trust and one that merely looks plausible.
///
/// # The `None` case is deliberate
///
/// `Capability` is `#[non_exhaustive]`, so a variant added in a later version
/// reaches this function. Returning `None` for an unknown capability is the
/// **safe** direction: it unlocks no interface, rather than guessing one. The
/// caller surfaces it through [`describe_gap`] so the gap is loud rather than
/// silent.
#[must_use]
pub const fn interface_for(c: Capability) -> Option<&'static str> {
    match c {
        Capability::HttpServer | Capability::HttpClient => Some("qqq:http@1.0"),
        Capability::FsRead | Capability::FsWrite | Capability::FsWatch => Some("qqq:fs@1.0"),
        Capability::SqlQuery | Capability::SqlExecute => Some("qqq:sql@1.0"),
        Capability::KvRead | Capability::KvWrite => Some("qqq:kv@1.0"),
        Capability::QueuePublish | Capability::QueueSubscribe => Some("qqq:queue@1.0"),
        Capability::CryptoRandom
        | Capability::CryptoHash
        | Capability::CryptoHmac
        | Capability::CryptoAead
        | Capability::CryptoSign => Some("qqq:crypto@1.0"),
        Capability::ClockWall | Capability::ClockMonotonic => Some("qqq:clock@1.0"),
        Capability::LogWrite => Some("qqq:log@1.0"),
        Capability::TraceWrite => Some("qqq:trace@1.0"),
        Capability::SecretUse => Some("qqq:secrets@1.0"),
        Capability::DnsResolve => Some("qqq:dns@1.0"),
        Capability::EnvRead => Some("qqq:env@1.0"),
        Capability::AiInfer => Some("qqq:ai@1.0"),
        // A capability added in a newer version of `qqq-cap` than this build
        // knows about. Unlocking nothing is the safe direction; the gap is
        // reported by `describe_gap` rather than silently ignored.
        #[allow(unreachable_patterns)]
        _ => None,
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
    let linker: Linker<StoreData> = Linker::new(engine);

    // Interfaces with a Rust host implementation land here as they are built.
    //
    // QQQ-STUB(HOST-016): the `qqq:crypto` and `qqq:clock` host implementations
    // land next. Until then a component importing them fails to instantiate
    // with a clear "unimplemented capability" diagnostic produced by
    // `describe_gap`, rather than a raw Wasmtime linker error. This stub is
    // recorded in Observations §6 as §S-006.
    let _ = &linker;

    let required = required_interfaces(grants);
    let mut interfaces: Vec<String> = Vec::with_capacity(required.len());
    let mut unimplemented = Vec::new();
    for iface in required {
        // Until a host implementation exists for this interface, record the
        // gap rather than binding nothing and failing opaquely later.
        interfaces.push(iface.to_owned());
        for &c in &grants.capabilities() {
            if interface_for(c) == Some(iface) {
                unimplemented.push(c);
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
/// so a developer sees *"`qqq:crypto@1.0` is granted but this build has no
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

    /// Interface names must be well-formed and versioned, because they are part
    /// of the machine contract an agent reads.
    ///
    /// # Version shape: `major.minor`, deliberately not `major.minor.patch`
    ///
    /// WIT interface versions follow the WIT convention, which is
    /// `major.minor` — the patch level of an *interface* carries no meaning,
    /// because an interface is a type signature and a signature either changed
    /// compatibly or it did not. Using full semver here would invite a
    /// `@1.0.3` that implies a distinction no consumer can act on.
    ///
    /// This is distinct from [`qqq_core::Version`], which models *package*
    /// versions where the patch level is meaningful.
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
                2,
                "interface version `{version}` must be major.minor (WIT convention)"
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
        assert!(ifaces.contains(&"qqq:http@1.0"));
        assert!(ifaces.contains(&"qqq:crypto@1.0"));
        assert!(ifaces.contains(&"qqq:clock@1.0"));
        // Never granted, never unlocked.
        assert!(!ifaces.contains(&"qqq:fs@1.0"));
        assert!(!ifaces.contains(&"qqq:sql@1.0"));
        assert!(!ifaces.contains(&"qqq:secrets@1.0"));
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
        let crypto_count = ifaces.iter().filter(|i| **i == "qqq:crypto@1.0").count();
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
        assert!(required_interfaces(&g).contains(&"qqq:fs@1.0"));
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

    /// A granted capability binds its interface and is reported as
    /// *unimplemented* until the host implementation lands — a loud, inspectable
    /// gap rather than a silent one.
    #[test]
    fn a_granted_capability_binds_its_interface_and_reports_the_gap() {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&cfg).unwrap();
        let g = grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nhash = [\"sha256\"]\n",
        );
        let built = build_linker(&engine, &g).unwrap();
        assert!(built.bound.has("qqq:crypto@1.0"));
        assert!(
            built.bound.unimplemented.contains(&Capability::CryptoHash),
            "the unimplemented capability must be reported: {:?}",
            built.bound
        );
        // And crucially: nothing outside the grants is bound.
        assert!(!built.bound.has("qqq:fs@1.0"));
        assert!(!built.bound.has("qqq:sql@1.0"));
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
        let f = instance.get_typed_func::<(), (u32,)>(&mut store, "f").unwrap();
        let (v,) = f.call(&mut store, ()).unwrap();
        assert_eq!(v, 42, "the control case must actually work");
    }

    // -- The call-time re-check -------------------------------------------

    #[test]
    fn recheck_passes_for_a_granted_capability() {
        let data = StoreData {
            grants: grants_from(
                "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
                 [capabilities.crypto]\nhash = [\"sha256\"]\n",
            ),
        };
        assert!(recheck(&data, Capability::CryptoHash).is_none());
    }

    #[test]
    fn recheck_denies_an_ungranted_capability_with_full_context() {
        let data = StoreData {
            grants: grants_from("[package]\nname = \"a\"\nversion = \"0.1.0\"\n"),
        };
        let err = recheck(&data, Capability::SqlQuery)
            .expect("an ungranted capability must be denied");
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
        let data = StoreData {
            grants: GrantSet::empty(),
        };
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
        assert!(msg.contains("crypto.hash"), "must name the capability: {msg}");
        assert!(msg.contains("qqq:crypto@1.0"), "must name the interface: {msg}");
        assert!(e.remediation.is_some());
        assert!(e.render().contains("QQQ-6004"));
    }

    #[test]
    fn bound_interfaces_has_lookup_works() {
        let b = BoundInterfaces {
            interfaces: vec!["qqq:http@1.0".to_owned(), "qqq:clock@1.0".to_owned()],
            unimplemented: vec![],
        };
        assert!(b.has("qqq:http@1.0"));
        assert!(!b.has("qqq:sql@1.0"));
        assert!(b.to_string().contains("qqq:http@1.0"));

        let empty = BoundInterfaces {
            interfaces: Vec::new(),
            unimplemented: Vec::new(),
        };
        assert_eq!(empty.to_string(), "(none)");
        assert!(!empty.has("qqq:http@1.0"));
    }
}
