// SPDX-License-Identifier: Apache-2.0

//! Engine-level integration tests, ported from the `.scratch/witprobe` probe.
//!
//! Implements Checklist `FND-011`: *"Delete the scratch verification crate at
//! `.scratch/witprobe` once its findings are folded into the test suite; port
//! its three assertions into `crates/qqq-host/tests/`."*
//!
//! # Why these live here and not in the unit tests
//!
//! They assert properties of the **real Wasmtime engine**, not of our wrappers.
//! The probe existed because four load-bearing architecture claims in the
//! Proposal were unverified, and a claim verified by reading the documentation
//! is not verified. Each test below compiles and runs actual Wasm.
//!
//! Every claim carries a **control case**. A test that asserts "an empty linker
//! fails to instantiate" passes trivially if instantiation is broken for every
//! input; the control asserts the same shape *does* instantiate when satisfied.
//! That is `§M-006`'s discipline — a check must be shown able to fail for the
//! right reason, not merely to pass.

use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

/// A store with a fuel budget, which every test needs.
fn fuel_store(engine: &Engine, fuel: u64) -> Store<()> {
    let mut store = Store::new(engine, ());
    store.set_fuel(fuel).expect("fuel must be settable");
    store
}

/// An engine with the features QQQ actually enables.
fn engine() -> Engine {
    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true);
    config.consume_fuel(true);
    config.wasm_multi_memory(true);
    Engine::new(&config).expect("engine must build with QQQ's feature set")
}

/// A component that imports `host:probe/greeter`, which nothing provides.
const NEEDS_GREETER: &str = r#"
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

// ---------------------------------------------------------------------------
// Claim 1 — an absent import fails instantiation, and the error names it
// ---------------------------------------------------------------------------

/// **Claim 1.** A component whose import is not provided **cannot instantiate**.
///
/// This is the mechanism behind the project's central security property: an
/// ungranted capability is *absent, not denied*. If an unsatisfied import
/// merely produced a host function that refuses at call time, the guest would
/// still have a callable surface to probe. It does not: instantiation fails.
///
/// The test also asserts the error **names the import**, because an operator
/// diagnosing a deployment needs to know which capability is missing rather
/// than that "instantiation failed".
#[test]
fn an_unsatisfied_import_fails_instantiation_and_names_it() {
    let engine = engine();
    let component =
        Component::new(&engine, NEEDS_GREETER).expect("the probe component must compile");

    // Deliberately empty: no host functions registered at all.
    let linker: Linker<()> = Linker::new(&engine);
    let mut store = fuel_store(&engine, 10_000_000);

    let err = linker
        .instantiate(&mut store, &component)
        .expect_err("instantiation MUST fail when an import is unsatisfied");

    let message = format!("{err:#}");
    assert!(
        message.contains("greet") || message.contains("host:probe"),
        "the error must name the missing import, otherwise the operator cannot \
         tell which capability to grant. Got: {message}"
    );
}

/// **Claim 1, control.** The same engine and linker instantiate a component
/// that needs nothing, and it runs.
///
/// Without this, the test above would also pass if instantiation were broken
/// for every input — including valid ones. The control is what makes the
/// failure meaningful.
#[test]
fn a_component_with_no_imports_instantiates_and_runs() {
    let engine = engine();
    let wat = r#"
        (component
          (core module $m
            (func (export "f") (result i32) (i32.const 42))
          )
          (core instance $i (instantiate $m))
          (func (export "f") (result u32) (canon lift (core func $i "f")))
        )
    "#;
    let component = Component::new(&engine, wat).expect("the control component must compile");

    let linker: Linker<()> = Linker::new(&engine);
    let mut store = fuel_store(&engine, 10_000_000);
    let instance = linker
        .instantiate(&mut store, &component)
        .expect("a component with no imports must instantiate");

    let f = instance
        .get_typed_func::<(), (u32,)>(&mut store, "f")
        .expect("the export must be typed as declared");
    let (value,) = f.call(&mut store, ()).expect("the call must succeed");

    assert_eq!(
        value, 42,
        "the guest must actually run and return its value"
    );

    // A one-value return must be a tuple: `ComponentNamedList` is implemented
    // for tuples, so `u32` alone would not compile here. Asserted above by the
    // `(u32,)` annotation.
}

// ---------------------------------------------------------------------------
// Claim 3 — fuel exhaustion traps the guest, and the host survives
// ---------------------------------------------------------------------------

/// **Claim 3.** A guest that exhausts its fuel **traps**, and the trap does not
/// take down the host.
///
/// The second half is the part that matters for a server: a hostile or buggy
/// guest must not be able to stop the process serving everyone else. The test
/// proves the host is still usable by running **another** guest after the trap
/// on the same engine.
#[test]
fn fuel_exhaustion_traps_the_guest_and_the_host_survives() {
    let engine = engine();
    let wat = r#"
        (component
          (core module $m
            (func (export "spin") (result i32)
              (local $i i32)
              (loop $l
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $l)
              )
              (i32.const 0))
          )
          (core instance $i (instantiate $m))
          (func (export "spin") (result u32) (canon lift (core func $i "spin")))
        )
    "#;
    let component = Component::new(&engine, wat).expect("the spinning component must compile");
    let linker: Linker<()> = Linker::new(&engine);

    // A budget far too small to finish an infinite loop.
    let mut store = fuel_store(&engine, 10_000);
    let instance = linker
        .instantiate(&mut store, &component)
        .expect("instantiation does not need fuel");
    let spin = instance
        .get_typed_func::<(), (u32,)>(&mut store, "spin")
        .expect("the export must be typed as declared");

    let err = spin
        .call(&mut store, ())
        .expect_err("an infinite loop must exhaust its fuel and trap");

    let message = format!("{err:#}").to_lowercase();
    assert!(
        message.contains("fuel") || message.contains("all fuel"),
        "the trap must be attributable to fuel, so it maps to QQQ-3002 rather \
         than an unclassified trap. Got: {message}"
    );

    // The host must still work. A fresh store on the same engine, a guest that
    // terminates: if the trap had poisoned anything shared, this would fail.
    let mut store = fuel_store(&engine, 10_000_000);
    let control_wat = r#"
        (component
          (core module $m
            (func (export "f") (result i32) (i32.const 7))
          )
          (core instance $i (instantiate $m))
          (func (export "f") (result u32) (canon lift (core func $i "f")))
        )
    "#;
    let control = Component::new(&engine, control_wat).expect("control must compile");
    let instance = linker
        .instantiate(&mut store, &control)
        .expect("the host must still instantiate after a guest trapped");
    let f = instance
        .get_typed_func::<(), (u32,)>(&mut store, "f")
        .expect("export");
    let (value,) = f
        .call(&mut store, ())
        .expect("the host must still run guests");

    assert_eq!(
        value, 7,
        "a trapped guest must not have affected the host's ability to run others"
    );
}

// ---------------------------------------------------------------------------
// Claim 4 — the epoch deadline interrupts a spinning guest
// ---------------------------------------------------------------------------

/// **Claim 4.** An epoch interruption stops a guest that would otherwise spin
/// forever, independently of fuel.
///
/// Fuel and epochs answer different questions. Fuel bounds *work*; epochs bound
/// *time*. A guest waiting on something that consumes no fuel — or one whose
/// work per unit time varies with load — is bounded only by the epoch deadline.
/// Both are needed, and this asserts the second works.
#[test]
fn an_epoch_interruption_stops_a_spinning_guest() {
    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true);
    config.epoch_interruption(true);
    // Generous fuel: the point is that the *epoch* stops it, not the fuel.
    config.consume_fuel(true);
    let engine = Engine::new(&config).expect("engine with epochs must build");

    let wat = r#"
        (component
          (core module $m
            (func (export "spin")
              (loop $l (br $l)))
          )
          (core instance $i (instantiate $m))
          (func (export "spin") (canon lift (core func $i "spin")))
        )
    "#;
    let component = Component::new(&engine, wat).expect("the spinning component must compile");
    let linker: Linker<()> = Linker::new(&engine);

    let mut store = fuel_store(&engine, 1_000_000_000);
    // The deadline: this store is interrupted at the *next* epoch.
    store.set_epoch_deadline(1);

    let instance = linker
        .instantiate(&mut store, &component)
        .expect("instantiation needs no epoch");
    let spin = instance
        .get_typed_func::<(), ()>(&mut store, "spin")
        .expect("export");

    // Bump the engine's epoch from another thread while the guest spins. Without
    // this the guest would loop forever and the test would hang rather than
    // fail, which is why the increment must be concurrent.
    let ticker = std::thread::spawn({
        let engine = engine.clone();
        move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            engine.increment_epoch();
        }
    });

    let err = spin
        .call(&mut store, ())
        .expect_err("the epoch deadline must interrupt the guest");

    ticker.join().expect("the ticker thread must not panic");

    let message = format!("{err:#}").to_lowercase();
    assert!(
        message.contains("epoch") || message.contains("interrupt"),
        "the trap must be attributable to the epoch deadline, so it maps to \
         QQQ-3003 (a 504, never a 500). Got: {message}"
    );
}
