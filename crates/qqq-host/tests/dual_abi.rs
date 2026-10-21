// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! **HOST-025** — the dual-ABI host: retain 0.2, route 0.3, fail closed.
//!
//! # Why this file exists instead of unit tests alone
//!
//! `AbiVersion::detect` is unit-tested on hand-written names. That proves the
//! classifier works on strings the author believes imports look like — it
//! cannot detect the belief being wrong (same argument as `compatibility.rs`
//! makes for error strings). These tests compile real components, read their
//! real import names through `component_type().imports()`, feed those to the
//! real detector, build the real linker the decision names, and instantiate
//! on a real engine. A test that only asserted `detect` on literals could
//! pass while the wiring between detection and linking was broken.
//!
//! # What 0.3 means here, precisely
//!
//! The 0.3 path serves versioned **sync** shapes through the same code the 0.2
//! path runs — it does not emulate async. `wait-until` (async in the real
//! v0.3.2 WIT, verified against tag `bdadbbb`) is refused with a diagnostic
//! naming engine async support, not with a generic unknown import. When a
//! toolchain emits real 0.3 guests, serve-side wiring follows; until then
//! this file is the proof the routing exists and fails closed.

use qqq_cap::manifest::Manifest;
use qqq_cap::resolve::GrantSet;
use qqq_host::config::StoreLimits;
use qqq_host::instance::{Instance, PreparedComponent};
use qqq_host::linker::{AbiVersion, StoreData, build_linker, build_linker_for_abi};
use wasmtime::component::Component;
use wasmtime::{Engine, Store};

/// An engine with the features QQQ actually enables: component model, no
/// async lift, no stack switching — the production posture, not a superset.
fn engine() -> Engine {
    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true);
    Engine::new(&config).expect("engine must build with QQQ's feature set")
}

/// The engine `Instance::create` needs: the production posture plus fuel
/// metering and epoch interruption, which `ReadyStore::prepare` applies to
/// every store (fuel budget, epoch deadline). A plain component-model engine
/// would make creation itself fail, and the failure would name metering —
/// not routing — so the routing tests would pass or fail for the wrong
/// reason.
fn creation_engine() -> Engine {
    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true);
    config.consume_fuel(true);
    config.epoch_interruption(true);
    Engine::new(&config).expect("creation engine must build")
}

fn instance_limits() -> StoreLimits {
    StoreLimits {
        memory_bytes: 16 * 1024 * 1024,
        fuel: 10_000_000,
        epoch_deadline_ms: 5_000,
        max_open_handles: 64,
        max_subrequests: 32,
    }
}

fn grants_for(toml: &str) -> GrantSet {
    let text = format!(
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
         [capabilities.clock]\nmonotonic = true\n{toml}\n"
    );
    let manifest = Manifest::parse(&text).expect("fixture manifest parses");
    GrantSet::from_manifest(&manifest)
}

/// The clock grant the 0.3 tests below run under, as a manifest.
///
/// `grants_for("")` already carries it; this names the same value through the
/// path production uses (`Manifest::parse` → `GrantSet::from_manifest`), so a
/// test that passed on a hand-built grant set cannot drift from what the
/// manifest actually grants.
fn monotonic_grants() -> GrantSet {
    grants_for("")
}

/// A guest is a component whose imports name an ABI. Assert the names the
/// engine actually sees, not the WAT that was written: a typo in the fixture
/// must fail here, not ride through as a vacuous pass.
fn import_names(component: &Component, engine: &Engine) -> Vec<String> {
    let mut out: Vec<String> = component
        .component_type()
        .imports(engine)
        .map(|(name, _ty)| name.to_owned())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Lift the guest's `run() -> u64` and call it: exercising the export proves
/// the guest **ran**, not merely instantiated. Two calls assert the value is
/// non-decreasing, which is the monotonic-clock contract, not an arbitrary
/// inequality — a stub returning constants would pass the first call.
///
/// The store must carry the same grants the linker was built with: the 0.2
/// clock re-checks the grant at call time, so a default (empty-grant) store
/// would trap for lack of authority and the test would pass for the wrong
/// reason. Each caller builds its store explicitly; this helper only calls.
fn run_twice(instance: &wasmtime::component::Instance, store: &mut Store<StoreData>) -> (u64, u64) {
    let run = instance
        .get_typed_func::<(), (u64,)>(&mut *store, "run")
        .expect("the guest must export run() -> u64");
    let (first,) = run.call(&mut *store, ()).expect("first call serves");
    let (second,) = run.call(&mut *store, ()).expect("second call serves");
    (first, second)
}

const GUEST_02_CLOCK: &str = r#"
(component
  (import "qqq:clock/monotonic-clock@1.0.0" (instance $clock
    (export "now" (func (result u64)))))
  (core module $m
    (import "host" "now" (func $now (result i64)))
    (func (export "run") (result i64) (call $now)))
  (core func $now-lowered (canon lower (func $clock "now")))
  (core instance $host (export "now" (func $now-lowered)))
  (core instance $i (instantiate $m (with "host" (instance $host))))
  (func (export "run") (result u64) (canon lift (core func $i "run"))))
"#;

/// The 0.3 guest under test: `now` from the real v0.3.2 interface name
/// (`package wasi:clocks@0.3.2`, `now: func() -> mark`), which is sync in
/// both revisions — so serving it claims nothing about async.
const GUEST_03_CLOCK: &str = r#"
(component
  (import "wasi:clocks/monotonic-clock@0.3.2" (instance $clock
    (export "now" (func (result u64)))))
  (core module $m
    (import "host" "now" (func $now (result i64)))
    (func (export "run") (result i64) (call $now)))
  (core func $now-lowered (canon lower (func $clock "now")))
  (core instance $host (export "now" (func $now-lowered)))
  (core instance $i (instantiate $m (with "host" (instance $host))))
  (func (export "run") (result u64) (canon lift (core func $i "run"))))
"#;

/// A guest that imports the 0.3 async functions alongside `now`: it must
/// instantiate (the stubs exist), but calling either async function must
/// trap naming engine async support — never serve, never hang, never a
/// generic unknown import.
const GUEST_03_ASYNC: &str = r#"
(component
  (import "wasi:clocks/monotonic-clock@0.3.2" (instance $clock
    (export "now" (func (result u64)))
    (export "wait-until" (func (param "when" u64)))
    (export "wait-for" (func (param "when" u64)))))
  (core module $m
    (import "host" "now" (func $now (result i64)))
    (import "host" "wait-until" (func $wait_until (param i64)))
    (import "host" "wait-for" (func $wait_for (param i64)))
    (func (export "run") (result i64) (call $now))
    (func (export "wait") (call $wait_until (i64.const 0)))
    (func (export "wait2") (call $wait_for (i64.const 0))))
  (core func $now-lowered (canon lower (func $clock "now")))
  (core func $wait-until-lowered (canon lower (func $clock "wait-until")))
  (core func $wait-for-lowered (canon lower (func $clock "wait-for")))
  (core instance $host
    (export "now" (func $now-lowered))
    (export "wait-until" (func $wait-until-lowered))
    (export "wait-for" (func $wait-for-lowered)))
  (core instance $i (instantiate $m (with "host" (instance $host))))
  (func (export "run") (result u64) (canon lift (core func $i "run")))
  (func (export "wait") (canon lift (core func $i "wait")))
  (func (export "wait2") (canon lift (core func $i "wait2"))))
"#;

/// **The 0.2 path is retained: a 0.2 guest instantiates and runs.**
///
/// The control for everything below: if this fails, the breakage is in the
/// shared machinery, not the 0.3 branch. Same guest shape, same assertions
/// as the 0.3 guest — the only difference is the interface version.
#[test]
fn a_v02_guest_instantiates_and_runs_on_the_retained_path() {
    let engine = engine();
    let component = Component::new(&engine, GUEST_02_CLOCK).expect("the 0.2 guest must compile");
    let names = import_names(&component, &engine);
    assert!(
        names.iter().any(|n| n.contains("qqq:clock")),
        "the fixture must import what it claims: {names:?}"
    );
    assert_eq!(
        AbiVersion::detect(names.iter().map(String::as_str)),
        AbiVersion::V02,
        "a qqq-namespaced guest is the current ABI and stays on the 0.2 path"
    );

    let grants = grants_for("");
    let built = build_linker(&engine, &grants).expect("the 0.2 linker must build");
    // Same grants in the store as in the linker: the 0.2 clock re-checks at
    // call time, and a default (empty-grant) store would trap here.
    let mut store = Store::new(&engine, StoreData::new(grants));
    let instance = built
        .linker
        .instantiate(&mut store, &component)
        .expect("the 0.2 guest must instantiate on the retained path");
    let (first, second) = run_twice(&instance, &mut store);
    assert!(
        second >= first,
        "the guest must observe a monotonic clock: {first} then {second}"
    );
}

/// **A 0.3 guest instantiates and runs on the 0.3 path — same engine build.**
///
/// Detection runs on the real import table, not the WAT source: the test
/// would catch a fixture typo (wrong version string, misspelled interface)
/// instead of silently testing the fallback path.
#[test]
fn a_v03_guest_instantiates_and_runs_on_the_new_path() {
    let engine = engine();
    let component = Component::new(&engine, GUEST_03_CLOCK).expect("the 0.3 guest must compile");
    let names = import_names(&component, &engine);
    assert!(
        names.iter().any(|n| n.contains("0.3.2")),
        "the fixture must import a 0.3 name: {names:?}"
    );
    assert_eq!(
        AbiVersion::detect(names.iter().map(String::as_str)),
        AbiVersion::V03,
        "a 0.3 import must route to the new path"
    );

    let grants = monotonic_grants();
    let built =
        build_linker_for_abi(&engine, &grants, AbiVersion::V03).expect("the 0.3 linker must build");
    let mut store = Store::new(&engine, StoreData::new(monotonic_grants()));
    let instance = built
        .linker
        .instantiate(&mut store, &component)
        .expect("the 0.3 guest must instantiate on the new path in the same build");
    let (first, second) = run_twice(&instance, &mut store);
    assert!(
        second >= first,
        "the guest must observe a monotonic clock through the 0.3 path: {first} then {second}"
    );
}

/// **Async 0.3 imports trap by name instead of instantiating silently.**
///
/// `wait-until` and `wait-for` are `async func` in the real v0.3.2 WIT and
/// the engine runs without async support, so serving them is impossible
/// today. The host registers named traps instead of leaving them absent:
/// an absent import would fail instantiation with a generic "unknown
/// import", which names the wrong problem, while the trap names engine
/// async support and the path to unblock it — the same precedent as
/// `host_test`'s `not-assertable`. The fixture declares string-named parameters (the text format's spelling
/// here); the stub is name-matched, and a real
/// async-typed guest would fail even earlier, at validation. Either way:
/// fail closed, never serve, never hang.
#[test]
fn async_03_imports_trap_by_name() {
    let engine = engine();
    let component = Component::new(&engine, GUEST_03_ASYNC).expect("the async guest must compile");
    let names = import_names(&component, &engine);
    assert!(
        names.iter().any(|n| n.contains("0.3.2")),
        "the fixture must still be a 0.3 guest: {names:?}"
    );
    assert_eq!(
        AbiVersion::detect(names.iter().map(String::as_str)),
        AbiVersion::V03,
        "an async 0.3 import still routes to the 0.3 path: the refusal happens at call time, not routing time"
    );

    let grants = monotonic_grants();
    let built = build_linker_for_abi(&engine, &grants, AbiVersion::V03).expect(
        "the 0.3 linker must build: the async trap is a call-time refusal, not a link-time one",
    );

    // Each behavior gets a fresh store and instance: sharing one store across
    // unrelated calls would let store state leak between assertions, and an
    // assertion that passes because of leftover state proves nothing.
    let run_once = |export: &str| -> Result<(), String> {
        let mut store = Store::new(&engine, StoreData::default());
        let instance = built
            .linker
            .instantiate(&mut store, &component)
            .expect("each behavior gets a fresh instance");
        let call = instance
            .get_typed_func::<(), ()>(&mut store, export)
            .map_err(|e| format!("missing export {export}: {e:#}"))?;
        call.call(&mut store, ()).map_err(|e| format!("{e:#}"))
    };

    // Each async function traps naming engine async support — never serves,
    // never hangs, never a generic unknown import. Each call gets a fresh
    // store and instance so no shared state can leak between assertions.
    for (export, func) in [("wait", "wait-until"), ("wait2", "wait-for")] {
        let err =
            run_once(export).expect_err(&format!("calling {func} must trap: async is not served"));
        assert!(
            err.contains("async"),
            "the trap must name async support: {err}"
        );
        assert!(
            err.contains(func),
            "the trap must name the function the guest called: {err}"
        );
    }

    // The guest's sync part still serves through the same 0.3 linker that
    // traps async: presence is not the authority, the call is — in both
    // directions.
    let mut store = Store::new(&engine, StoreData::new(monotonic_grants()));
    let instance = built
        .linker
        .instantiate(&mut store, &component)
        .expect("the async guest must instantiate for its sync part too");
    let (first, second) = run_twice(&instance, &mut store);
    assert!(
        second >= first,
        "now must serve through the same 0.3 linker that traps async: {first} then {second}"
    );
}

/// **An unknown import fails closed and names itself, on the 0.3 path.**
///
/// The dual-ABI promise in the negative direction: a versioned name nobody
/// registered is absent, not denied — and the error must name the import so
/// the operator learns which interface to grant or which version drifted.
#[test]
fn an_unknown_03_import_fails_closed_and_names_itself() {
    let engine = engine();
    let wat = GUEST_03_CLOCK.replace(
        "wasi:clocks/monotonic-clock@0.3.2",
        "wasi:http/incoming-handler@0.3.2",
    );
    let component = Component::new(&engine, wat.as_str()).expect("the unknown guest must compile");
    let unknown_names = import_names(&component, &engine);
    assert!(
        unknown_names.iter().any(|n| n.contains("0.3.2")),
        "the fixture must still be a 0.3 guest: {unknown_names:?}"
    );

    let grants = GrantSet::empty();
    let built = build_linker_for_abi(&engine, &grants, AbiVersion::V03)
        .expect("the 0.3 linker must build for the refusal test");
    let mut store = Store::new(&engine, StoreData::default());
    let err = built
        .linker
        .instantiate(&mut store, &component)
        .expect_err("an unregistered 0.3 import must not instantiate");
    let text = format!("{err:#}");
    assert!(
        text.contains("incoming-handler"),
        "the refusal must name the missing import: {text}"
    );
}

/// **The 0.3 clock is grant-gated like the 0.2 clock: no grant, no instance.**
///
/// Independent review caught the 0.3 path serving time to empty-grant stores
/// while the 0.2 path denies it (`DeniedClock` / call-time recheck in
/// `host_clock`). A versioned name must not be a wider authority than the
/// unversioned one. With empty grants the 0.3 clock instance is absent, so
/// instantiation fails closed naming the clock — deny by default, in the same
/// direction as the retained path.
#[test]
fn v03_clock_without_grant_fails_closed() {
    let engine = engine();
    let component = Component::new(&engine, GUEST_03_CLOCK).expect("the 0.3 guest must compile");
    assert_eq!(
        AbiVersion::detect(import_names(&component, &engine).iter().map(String::as_str)),
        AbiVersion::V03,
        "routing still names 0.3: the refusal happens at link time, not routing time"
    );

    let built = build_linker_for_abi(&engine, &GrantSet::empty(), AbiVersion::V03)
        .expect("the linker builds; it is the instance that must be absent");
    let mut store = Store::new(&engine, StoreData::default());
    let err = built
        .linker
        .instantiate(&mut store, &component)
        .expect_err("an ungranted 0.3 clock must not instantiate");
    let text = format!("{err:#}");
    assert!(
        text.contains("monotonic-clock"),
        "the refusal must name the ungranted clock: {text}"
    );
}

/// **Defence in depth: a mis-built 0.3 linker still cannot serve time.**
///
/// `host_clock` checks the grant twice — once at registration, once per call —
/// so a linker built wrongly still denies. The 0.3 clock mirrors it: build the
/// linker *with* the grant, then instantiate with an *empty-grant* store (the
/// shape a mis-built linker would hand out). The call-time recheck must trap
/// naming the capability, never serve the ambient read.
#[test]
fn v03_clock_rechecks_grant_at_call_time() {
    let engine = engine();
    let component = Component::new(&engine, GUEST_03_CLOCK).expect("the 0.3 guest must compile");

    let built = build_linker_for_abi(&engine, &monotonic_grants(), AbiVersion::V03)
        .expect("the granted 0.3 linker must build");
    // The wrong store on purpose: the linker was built for a granted
    // instance, but this store carries no grant — the recheck is what stands
    // between a host bug and ambient authority.
    let mut store = Store::new(&engine, StoreData::default());
    let instance = built
        .linker
        .instantiate(&mut store, &component)
        .expect("instantiation succeeds; the refusal happens at the call");
    let run = instance
        .get_typed_func::<(), (u64,)>(&mut store, "run")
        .expect("the guest must export run() -> u64");
    let err = run
        .call(&mut store, ())
        .expect_err("time without the grant must trap, never serve");
    let text = format!("{err:#}");
    assert!(
        text.contains("not granted"),
        "the trap must name the missing grant: {text}"
    );
    assert!(
        text.contains("clock") || text.contains("Clock"),
        "the trap must name the clock capability: {text}"
    );
}

/// **Creation routes a 0.3 guest to the 0.3 implementation — CON-019.**
///
/// The linker-level tests above prove detection and linking; this proves the
/// path `qqqai run` and `qqqai serve` actually take. `Instance::create` builds
/// its linker from the component in hand today (the retained 0.2 path, which
/// knows no 0.3 names), so a granted 0.3 guest fails creation with an unknown
/// import — the red this test is written to show first. The fix routes
/// creation by declared ABI. The guest runs its real export twice through
/// the real instance: presence of a linker is not proof the clock serves.
#[test]
fn instance_create_routes_03_guest_to_its_implementation() {
    let engine = creation_engine();
    let prepared = PreparedComponent::compile(&engine, GUEST_03_CLOCK.as_bytes())
        .expect("the 0.3 guest must compile");
    let instance = Instance::create(&engine, &prepared, &monotonic_grants(), instance_limits())
        .expect("a granted 0.3 guest must create: creation routes by declared ABI");
    let (first, second) = instance
        .run(|store, wasm| {
            let run = wasm.get_typed_func::<(), (u64,)>(&mut *store, "run")?;
            let (first,) = run.call(&mut *store, ())?;
            let (second,) = run.call(&mut *store, ())?;
            Ok((first, second))
        })
        .expect("the 0.3 guest must run through creation, not only link");
    assert!(
        second >= first,
        "the guest must observe a monotonic clock through creation: {first} then {second}"
    );
}

/// **Creation keeps an ungranted 0.3 guest fail-closed — CON-019.**
///
/// Same creation path, empty grants: the 0.3 instance is absent (grant-gated
/// registration), so creation must refuse naming the clock — never serve
/// time, never a generic error that hides which authority is missing.
#[test]
fn instance_create_keeps_ungranted_03_guest_fail_closed() {
    let engine = creation_engine();
    let prepared = PreparedComponent::compile(&engine, GUEST_03_CLOCK.as_bytes())
        .expect("the 0.3 guest must compile");
    let err = Instance::create(&engine, &prepared, &GrantSet::empty(), instance_limits())
        .expect_err("an ungranted 0.3 guest must not create");
    let text = err.render();
    assert!(
        text.contains("monotonic-clock"),
        "the refusal must name the ungranted clock: {text}"
    );
}

/// **Creation keeps unknown imports fail-closed — CON-019.**
///
/// The routing must not become a default: a version nobody registered still
/// refuses at creation, through the same path, naming the missing import.
#[test]
fn instance_create_keeps_unknown_imports_fail_closed() {
    let engine = creation_engine();
    let wat = GUEST_03_CLOCK.replace(
        "wasi:clocks/monotonic-clock@0.3.2",
        "wasi:http/incoming-handler@0.3.2",
    );
    let prepared = PreparedComponent::compile(&engine, wat.as_bytes())
        .expect("the unknown guest must compile");
    let err = Instance::create(&engine, &prepared, &monotonic_grants(), instance_limits())
        .expect_err("an unregistered 0.3 import must not create");
    let text = err.render();
    assert!(
        text.contains("incoming-handler"),
        "the refusal must name the missing import: {text}"
    );
}

/// **CON-019** — an unrecognized version fails closed at creation.
///
/// `Unknown` routes to the retained path rather than erroring at link time:
/// the refusal happens at instantiation with Wasmtime's unknown-import error
/// naming the versioned import — the same fail-closed backstop as before,
/// never a new link-time refusal for a guest that names nothing wrong.
#[test]
fn instance_create_keeps_unrecognized_version_fail_closed() {
    const GUEST_04: &str = r#"(component
      (import "wasi:http/incoming-handler@0.4.0" (instance $h
        (export "handle" (func))))
      (core module $m)
      (core instance $i (instantiate $m))
    )"#;
    let engine = creation_engine();
    let prepared =
        PreparedComponent::compile(&engine, GUEST_04.as_bytes()).expect("the guest must compile");
    let err = Instance::create(&engine, &prepared, &GrantSet::empty(), instance_limits())
        .expect_err("an unrecognized version must not create");
    let text = err.render();
    assert!(
        text.contains("incoming-handler@0.4.0"),
        "the refusal must name the versioned import: {text}"
    );
}

/// **CON-019** — a guest with no imports keeps the retained path.
///
/// An empty import list names no ABI (`Unknown`), and that must not become a
/// link-time refusal: the component instantiates exactly as it did before the
/// dual-ABI work, through the 0.2 builder, with an empty grant set.
#[test]
fn instance_create_keeps_no_import_guest_on_the_retained_path() {
    // Plain `r"..."`: the bare guest names no interfaces, so there are no
    // quotes inside and hashes would be decoration rather than escaping.
    const BARE: &str = r"(component
      (core module $m)
      (core instance $i (instantiate $m))
    )";
    let engine = creation_engine();
    let prepared =
        PreparedComponent::compile(&engine, BARE.as_bytes()).expect("the bare guest must compile");
    let instance = Instance::create(&engine, &prepared, &GrantSet::empty(), instance_limits())
        .expect("a guest with no imports must create on the retained path");
    assert!(
        instance.is_usable(),
        "the instance must be usable: nothing about it changed"
    );
}

/// **CON-019** — a mixed 0.2+0.3 guest routes 0.3 and fails closed naming the 0.2 half.
///
/// Precedence sends any 0.3 import down the 0.3 path, whose linker binds no
/// `qqq:` names: even fully granted, the 0.2 half fails at instantiation with
/// an unknown import. Fail-closed, no reinterpretation — a guest that asks
/// for two ABIs at once gets neither silently served as the other. (Review
/// follow-up: the 0.3 linker deliberately excludes the 0.2 baseline, so this
/// pin also guards that exclusion.)
#[test]
fn instance_create_routes_mixed_guest_03_and_names_the_02_half() {
    const GUEST_MIXED: &str = r#"(component
      (import "qqq:clock/wall-clock@1.0.0" (instance $w
        (export "now" (func (result u64)))))
      (import "wasi:clocks/monotonic-clock@0.3.2" (instance $clock
        (export "now" (func (result u64)))))
      (core module $m)
      (core instance $i (instantiate $m))
    )"#;
    let engine = creation_engine();
    let prepared = PreparedComponent::compile(&engine, GUEST_MIXED.as_bytes())
        .expect("the guest must compile");
    let both = grants_for("wall = true\n");
    let err = Instance::create(&engine, &prepared, &both, instance_limits())
        .expect_err("a mixed-ABI guest must not instantiate under either path");
    let text = err.render();
    assert!(
        text.contains("qqq:clock/wall-clock"),
        "the refusal must name the 0.2 half the 0.3 linker does not bind: {text}"
    );
}
