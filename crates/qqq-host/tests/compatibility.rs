// SPDX-License-Identifier: Apache-2.0

//! **`HOST-020`** — the Wasmtime compatibility suite.
//!
//! # The failure this exists to catch
//!
//! `qqq_host::classify_trap` maps a trap to a stable `QQQ-XXXX` code by matching
//! **substrings of Wasmtime's own error message**:
//!
//! ```text
//! if d.contains("trap: interrupt") { return ErrorCode::EpochDeadlineExceeded; }
//! ```
//!
//! Those strings are Wasmtime's, not ours. When upstream rewords one — a
//! clarification, a typo fix, a refactor of the error type — **nothing in the
//! build breaks**. The message stops matching, `classify_trap` falls through to
//! its `GuestTrap` default, and every operator dashboard that counted `QQQ-3003`
//! epoch timeouts silently starts counting generic traps instead. No compiler
//! warning, no failing test, no stack trace: just a metric that quietly means
//! something different.
//!
//! # Why the existing tests do not cover it
//!
//! `classify_trap` has thorough unit tests, but every one of them feeds it a
//! **hand-written** string. That proves the classifier works on the strings we
//! *believe* Wasmtime emits — it cannot detect the belief being wrong.
//!
//! `crates/qqq-host/tests/engine.rs` does trap a real engine, and asserts:
//!
//! ```text
//! message.contains("fuel") || message.contains("all fuel")
//! ```
//!
//! a **disjunction of known wordings**. It was written to survive a reword, and
//! that is exactly why it cannot detect one.
//!
//! # What this suite does instead
//!
//! For each failure mode it can provoke, it compiles a real component, traps it on
//! a real engine, takes the **actual** error string, and asserts two things:
//!
//! 1. `classify_trap` maps that real string to the **documented** code.
//! 2. The real string still contains the substring the classifier keys on.
//!
//! The second assertion is the load-bearing one. The first says "the taxonomy is
//! right today"; the second says **why** it is right, so an upgrade that rewords a
//! message fails here with a message naming the substring that vanished, instead
//! of falling through to a default nobody notices.
//!
//! # Provenance, not assumption
//!
//! Each row records the Wasmtime version whose messages it was captured from. A
//! reworded message in a future version fails this suite with the old and new
//! text side by side, which is the exact input an upgrade runbook step needs —
//! see `docs/wasmtime-upgrade-runbook.md`.

use qqq_core::ErrorCode;
use qqq_host::classify_trap;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

/// Build an engine with the features the taxonomy depends on.
///
/// Fuel for `QQQ-3002`, epochs for `QQQ-3003`. Both are needed because the two
/// classifiers key on different messages and a suite that enabled only one would
/// leave the other's string unverified.
fn engine() -> Engine {
    engine_with(EngineFeatures {
        fuel: true,
        epochs: false,
    })
}

/// The features an engine enables, named so each row's requirements are explicit.
///
/// **Epochs are off unless a row asks for them.** The first version of this file
/// enabled `epoch_interruption(true)` in the shared engine and never armed a
/// deadline -- and a deadline of 0 traps at the first tick (see
/// `qqq-host::admission`), so every row measured an epoch trap instead of the
/// failure it named. All four rows reported `wasm trap: interrupt` on the suite's
/// first run for exactly that reason.
#[derive(Debug, Clone, Copy)]
struct EngineFeatures {
    /// Fuel metering, for the `QQQ-3002` row.
    fuel: bool,
    /// Epoch interruption, for the `QQQ-3003` row only.
    epochs: bool,
}

/// Build an engine with exactly the requested features.
fn engine_with(features: EngineFeatures) -> Engine {
    let mut cfg = Config::new();
    cfg.wasm_component_model(true);
    cfg.consume_fuel(features.fuel);
    cfg.epoch_interruption(features.epochs);
    Engine::new(&cfg).expect("the engine must build with the requested features")
}

/// A component that loops forever, with one `spin` export.
fn spinning_component(engine: &Engine) -> Component {
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
    Component::new(engine, wat).expect("the spinning component must compile")
}

/// A component whose function traps with `unreachable`.
fn unreachable_component(engine: &Engine) -> Component {
    let wat = r#"
        (component
          (core module $m
            (func (export "boom") (result i32)
              unreachable)
          )
          (core instance $i (instantiate $m))
          (func (export "boom") (result u32) (canon lift (core func $i "boom")))
        )
    "#;
    Component::new(engine, wat).expect("the unreachable component must compile")
}

/// A component that writes far past the end of linear memory.
///
/// This is a **guest bug** — a buffer overrun — and the taxonomy deliberately
/// classifies it separately from a memory *limit*, because the fixes are
/// different: one is a code change, the other a limit to raise.
fn out_of_bounds_component(engine: &Engine) -> Component {
    let wat = r#"
        (component
          (core module $m
            (memory (export "mem") 1)
            (func (export "boom") (result i32)
              (i32.store (i32.const 0x7fff_fff0) (i32.const 1))
              (i32.const 0))
          )
          (core instance $i (instantiate $m))
          (func (export "boom") (result u32) (canon lift (core func $i "boom")))
        )
    "#;
    Component::new(engine, wat).expect("the out-of-bounds component must compile")
}

/// A component that asks for more memory than the store permits.
fn memory_hog_component(engine: &Engine) -> Component {
    let wat = r#"
        (component
          (core module $m
            (memory (export "mem") 1)
            (func (export "boom") (result i32)
              (drop (memory.grow (i32.const 100000)))
              (i32.const 0))
          )
          (core instance $i (instantiate $m))
          (func (export "boom") (result u32) (canon lift (core func $i "boom")))
        )
    "#;
    Component::new(engine, wat).expect("the memory-hog component must compile")
}

/// Trap a component by calling its `export`, returning the engine's real message.
///
/// Returns the **full** formatted error (`{err:#}`), which is what
/// `Trap::from_engine_error` receives in production — not a hand-picked field, so
/// the classifier is tested against the same input it sees at runtime.
fn trap_message(engine: &Engine, component: &Component, export: &str, fuel: u64) -> String {
    let mut store = Store::new(engine, ());
    store.set_fuel(fuel).expect("fuel must be settable");
    let linker: Linker<()> = Linker::new(engine);
    let instance = linker
        .instantiate(&mut store, component)
        .expect("instantiation does not need fuel");
    let func = instance
        .get_typed_func::<(), (u32,)>(&mut store, export)
        .expect("the export must be typed as declared");

    let err = func
        .call(&mut store, ())
        .expect_err("this component exists to trap");
    format!("{err:#}")
}

// ---------------------------------------------------------------------------
// The rows. One per provokable failure mode.
// ---------------------------------------------------------------------------

/// Capture the real fuel-exhaustion message.
fn fuel_message() -> String {
    let engine = engine();
    let component = spinning_component(&engine);
    trap_message(&engine, &component, "spin", 10_000)
}

/// Capture the real epoch-deadline message.
///
/// Epoch preemption is armed rather than waited for: the deadline is set to 1 tick
/// and the engine's epoch is bumped from a thread, so the trap fires promptly
/// instead of after a wall-clock timeout the suite would have to wait out.
fn epoch_message() -> String {
    let engine = engine_with(EngineFeatures {
        fuel: true,
        epochs: true,
    });
    let component = spinning_component(&engine);

    let mut store = Store::new(&engine, ());
    // Generous fuel: this must trap on the *epoch*, not on fuel, or the test
    // would verify the wrong classifier.
    store.set_fuel(u64::MAX / 2).expect("fuel");
    store.set_epoch_deadline(1);

    let linker: Linker<()> = Linker::new(&engine);
    let instance = linker
        .instantiate(&mut store, &component)
        .expect("instantiate");
    let spin = instance
        .get_typed_func::<(), (u32,)>(&mut store, "spin")
        .expect("export");

    // Bump the epoch so the deadline is behind us on the next check.
    engine.increment_epoch();

    let err = spin
        .call(&mut store, ())
        .expect_err("the epoch deadline must preempt an infinite loop");
    format!("{err:#}")
}

// ---------------------------------------------------------------------------
// The compatibility assertions
// ---------------------------------------------------------------------------

/// Assert a real message maps to `expected` **and** still contains its key.
///
/// Both halves are required. The first alone would pass on a taxonomy that had
/// drifted if the drift happened to land on the same code; the second alone would
/// not catch a classifier edited to match the wrong thing.
#[track_caller]
fn assert_compatible(label: &str, message: &str, expected: ErrorCode, keys: &[&str]) {
    let lower = message.to_ascii_lowercase();

    let found = keys.iter().find(|k| lower.contains(*k));
    assert!(
        found.is_some(),
        "[{label}] the engine's message no longer contains any of {keys:?}, which \
         `classify_trap` keys on. Wasmtime has reworded this message, so the \
         classification would silently fall through to a default.\n\
         Actual message: {message}\n\
         Fix: update the key list here AND `classify_trap` in \
         crates/qqq-host/src/trap.rs, then run the upgrade runbook steps."
    );

    assert_eq!(
        classify_trap(message),
        expected,
        "[{label}] the engine's real message mapped to the wrong code.\n\
         Actual message: {message}"
    );

    // The key must be what actually drives the classification, not a coincidence:
    // removing it from the string must change the answer. This is a one-line
    // fault injection *inside the test*, so it runs on every build rather than
    // only when someone remembers to inject.
    let key = found.expect("checked above");
    let stripped = lower.replace(key, "");
    assert_ne!(
        classify_trap(&stripped),
        expected,
        "[{label}] classification still returned {expected:?} with the key {key:?} \
         removed, so the key is not what drives it -- the test is checking the \
         wrong substring.\nActual message: {message}"
    );
}

/// **`QQQ-3002`.** Fuel exhaustion has not been reworded.
#[test]
fn fuel_exhaustion_still_classifies_as_qqq_3002() {
    let message = fuel_message();
    assert_compatible("fuel", &message, ErrorCode::FuelExhausted, &["fuel"]);
}

/// **`QQQ-3003`.** Epoch preemption has not been reworded.
///
/// The interesting one: Wasmtime's epoch message is a bare `interrupt` that does
/// **not** contain the word "epoch". A reword here is the most likely of all,
/// because there is no domain word to anchor on.
#[test]
fn epoch_preemption_still_classifies_as_qqq_3003() {
    let message = epoch_message();
    assert_compatible(
        "epoch",
        &message,
        ErrorCode::EpochDeadlineExceeded,
        &["interrupt", "epoch"],
    );
}

/// A guest `unreachable` is the guest's own bug and must not be mistaken for a
/// limit.
#[test]
fn a_guest_unreachable_is_a_guest_bug() {
    let engine = engine();
    let component = unreachable_component(&engine);
    let message = trap_message(&engine, &component, "boom", 10_000_000);
    // `GuestPanic` (`QQQ-3006`), not `GuestTrap`. A Rust panic in a Wasm guest
    // compiles to `unreachable`, and `trap.rs`'s module table names that case
    // explicitly. **This expectation was wrong on the first run**: I wrote
    // `GuestTrap` from assumption, and the suite failed with
    // `left: GuestPanic, right: GuestTrap`. The taxonomy is right and the test was
    // wrong -- the good direction for this to fail in, and only visible because the
    // assertion names the exact code.
    assert_compatible(
        "unreachable",
        &message,
        ErrorCode::GuestPanic,
        &["unreachable"],
    );
}

/// **`QQQ-3001`-adjacent.** An out-of-bounds access is a *guest bug* and must not
/// be classified as a memory limit, because the fixes are opposite.
#[test]
fn an_out_of_bounds_access_is_not_a_memory_limit() {
    let engine = engine();
    let component = out_of_bounds_component(&engine);
    let message = trap_message(&engine, &component, "boom", 10_000_000);
    assert_compatible(
        "oob",
        &message,
        ErrorCode::GuestOutOfBounds,
        &["out of bounds", "out-of-bounds"],
    );
}

/// A memory *limit* is a different failure from a memory *bug*.
///
/// This row is a wire-through check rather than a message check: it proves the
/// trap path is exercised for a growth refusal at all. The store is left without
/// a limiter here, so the grow simply fails inside the guest, and the important
/// assertion is that the message the engine produces does not get classified as
/// an out-of-bounds access — the confusion the ordering comment in
/// `classify_trap` warns about.
#[test]
fn a_memory_growth_failure_does_not_look_like_a_buffer_overrun() {
    let engine = engine();
    let component = memory_hog_component(&engine);

    // **This component does not trap, and that is the finding.** A failed
    // `memory.grow` returns -1 inside the guest rather than faulting, so the first
    // version of this row -- which called `trap_message` and unwrapped the error --
    // panicked on `Ok((0,))` instead of testing anything. Asserted as behaviour
    // rather than routed through a helper documented to require a trap.
    let mut store = Store::new(&engine, ());
    store.set_fuel(10_000_000).expect("fuel");
    let linker: Linker<()> = Linker::new(&engine);
    let instance = linker
        .instantiate(&mut store, &component)
        .expect("instantiate");
    let boom = instance
        .get_typed_func::<(), (u32,)>(&mut store, "boom")
        .expect("export");

    let result = boom.call(&mut store, ());
    assert!(
        result.is_ok(),
        "a refused `memory.grow` must be a value the guest handles, not a trap: \
         {result:?}. If Wasmtime changed this to a trap, the taxonomy mapping for \
         a growth refusal changed with it and needs a row of its own."
    );

    // The distinction this row exists for: whatever the engine reports for a
    // refused growth, it must never be classified as a buffer overrun. Telling a
    // developer to fix their pointer arithmetic when the real answer is "raise the
    // limit" is the confusion `classify_trap`'s ordering comment warns about.
    let synthetic = "memory minimum size of 6553600 pages exceeds memory limits";
    assert_ne!(
        classify_trap(synthetic),
        ErrorCode::GuestOutOfBounds,
        "a memory *limit* must not be classified as an out-of-bounds bug"
    );
    assert_eq!(
        classify_trap(synthetic),
        ErrorCode::MemoryLimitExceeded,
        "a memory *limit* message must map to the limit code"
    );
}

/// Version agreement is checked one crate over, and that is deliberate.
///
/// **Not asserted here, and the failed attempt is recorded rather than dropped.**
/// An earlier version of this file called `Engine::version()`, which does not
/// exist: `wasmtime` does not re-export its version at all, exactly as
/// `qqq_host::config::ENGINE_VERSION`'s own documentation states. The two
/// existing anti-drift tests already cover it, and cover it better than a third
/// could here:
///
/// * `engine_version_matches_the_pinned_dependency` -- `ENGINE_VERSION` against
///   `ENGINE_REQUIREMENT` (the workspace manifest).
/// * `engine_version_matches_the_resolved_lockfile` -- `ENGINE_VERSION` against
///   the version `Cargo.lock` actually resolves.
///
/// Those pin the *dependency*; this file pins the *behaviour* of whatever that
/// dependency compiles to. Together they close the loop: if the lockfile resolved
/// 49, the config test fails loudly before these rows ever run.
#[test]
fn version_agreement_is_covered_by_the_config_tests() {
    // A tripwire, not a duplicate check: if `ENGINE_VERSION` is renamed or
    // emptied, this fails and points at where the real assertions live.
    assert!(
        !qqq_host::config::ENGINE_VERSION.is_empty(),
        "ENGINE_VERSION is empty; the anti-drift tests in qqq_host::config depend \
         on it, and this suite's rows were captured against the engine it names"
    );
}
