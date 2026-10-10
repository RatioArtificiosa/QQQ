// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! F-08: the memory ceiling is aggregate across memories, proven against a
//! live engine — not just against the limiter in isolation.
//!
//! A component with two 16-page memories holds 32 pages. With a 24-page
//! ceiling the instantiation must trap with `MemoryLimitExceeded`. On the
//! old per-memory check both memories pass (16 < 24 each) and the instance
//! holds 8 pages more than admitted — the oversubscription F-08 exists to
//! prevent.
//!
//! This file also settles the initial-allocation semantics the delta formula
//! depends on: Wasmtime reports initial allocation as `memory_growing` with
//! `current == 0`, so the limiter charges it by delta with no pre-charge.
//! `f08_legal_initial_allocation_instantiates` pins that each initial byte is
//! charged exactly once — an earlier pre-charge design failed it by measuring
//! every initial byte twice (§O-557).

use qqq_cap::manifest::{Limits, Manifest};
use qqq_cap::resolve::GrantSet;
use qqq_core::ErrorCode;
use qqq_host::{EngineConfig, HostCapacity, Instance, LimitSet, PreparedComponent, build_engine};

/// Two memories of 16 pages each: 32 pages total, over a 24-page ceiling.
const TWO_MEMORIES: &str = r#"
    (component
      (core module $m
        (memory (export "a") 16)
        (memory (export "b") 16)
        (func (export "f") (result i32) (i32.const 7))
      )
      (core instance $i (instantiate $m))
      (func $f (result u32) (canon lift (core func $i "f")))
      (export "f" (func $f))
    )
"#;

fn engine() -> wasmtime::Engine {
    let mut cfg = wasmtime::Config::new();
    cfg.wasm_component_model(true);
    cfg.consume_fuel(true);
    cfg.epoch_interruption(true);
    cfg.wasm_multi_memory(true);
    wasmtime::Engine::new(&cfg).expect("engine must build")
}

/// One memory of 16 pages: under a 24-page ceiling.
const ONE_MEMORY_LEGAL: &str = r#"
    (component
      (core module $m
        (memory (export "a") 16)
        (func (export "f") (result i32) (i32.const 7))
      )
      (core instance $i (instantiate $m))
      (func $f (result u32) (canon lift (core func $i "f")))
      (export "f" (func $f))
    )
"#;

/// One memory of 32 pages: over a 24-page ceiling on its own.
const ONE_MEMORY_OVER: &str = r#"
    (component
      (core module $m
        (memory (export "b") 32)
        (func (export "f") (result i32) (i32.const 7))
      )
      (core instance $i (instantiate $m))
      (func $f (result u32) (canon lift (core func $i "f")))
      (export "f" (func $f))
    )
"#;

fn limits_24_pages() -> LimitSet {
    LimitSet {
        memory_bytes: 24 * 65536,
        fuel: 1_000_000_000,
        epoch_deadline_ms: 10_000,
        max_open_handles: 64,
        max_subrequests: 16,
    }
}

fn no_grants() -> GrantSet {
    GrantSet::from_manifest(
        &Manifest::parse("[package]\nname = \"aggregate\"\nversion = \"0.1.0\"\n")
            .expect("a minimal manifest parses"),
    )
}

/// **F-08: two memories over the aggregate ceiling trap at instantiation.**
///
/// Written first and failing first: on the per-memory check the component
/// instantiates (16 pages < 24 each), and `expect_err` fails because there
/// is no error. The `is_poisoned`-style anti-vacuity pin here is the error
/// CODE assertion below: a trap for the wrong reason (ungranted import,
/// missing export) must not pass.
///
/// The WAT is converted to binary explicitly (`wat` dev-dependency):
/// `PreparedComponent::compile` accepts WAT text through Wasmtime's own
/// parser, but the aggregate accounting reads component BYTES, so the test
/// must hand it bytes — passing text would measure nothing and the resulting
/// zero-sum would pass vacuously. The byte conversion below is what makes
/// this a proof about the shipped path rather than the test harness.
#[test]
fn f08_two_memories_over_the_aggregate_ceiling_trap_at_instantiation() {
    let engine = engine();
    let bytes = wat::parse_str(TWO_MEMORIES).expect("fixture WAT parses");
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("compiles");
    let err = Instance::create(&engine, &prepared, &no_grants(), limits_24_pages())
        .expect_err("32 pages against a 24-page ceiling must trap");
    assert_eq!(
        err.code,
        ErrorCode::MemoryLimitExceeded,
        "the trap must be the memory-limit code, not another failure: {err:?}"
    );
}

/// **F-08: a legal single-memory component instantiates — no false refusal.**
///
/// The pre-charge and the growth callbacks must not double-count initial
/// allocation. If Wasmtime called `memory_growing(current = 0)` for the
/// initial 16 pages on top of the 16 pre-charged pages, the total would read
/// 32 against the 24-page ceiling and this legal component would be refused.
/// Green here proves each initial byte is charged exactly once.
#[test]
fn f08_legal_initial_allocation_instantiates() {
    let engine = engine();
    let bytes = wat::parse_str(ONE_MEMORY_LEGAL).expect("fixture WAT parses");
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("compiles");
    assert_eq!(
        prepared.initial_memory_bytes(),
        16 * 65536,
        "the probe: one 16-page memory must measure exactly 16 pages"
    );
    let _instance = Instance::create(&engine, &prepared, &no_grants(), limits_24_pages())
        .expect("16 pages against a 24-page ceiling must instantiate");
}

/// **F-08: a single memory over the ceiling traps — the aggregate is not
/// only about multi-memory.**
///
/// Initial allocation arrives as `memory_growing(current = 0)`, so even a
/// one-memory component with a 32-page minimum is refused against a 24-page
/// ceiling. This test pins the single-memory case, which is also why the
/// multi-memory KEEP decision costs nothing extra: the callback machinery
/// enforces every initial byte either way.
#[test]
fn f08_single_memory_over_the_ceiling_traps_at_instantiation() {
    let engine = engine();
    let bytes = wat::parse_str(ONE_MEMORY_OVER).expect("fixture WAT parses");
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("compiles");
    let err = Instance::create(&engine, &prepared, &no_grants(), limits_24_pages())
        .expect_err("32 pages against a 24-page ceiling must trap");
    assert_eq!(
        err.code,
        ErrorCode::MemoryLimitExceeded,
        "the trap must be the memory-limit code, not another failure: {err:?}"
    );
}

/// **F-08: the ceiling refuses in pooling mode too, not just `OnDemand`.**
///
/// Production runs the pooling allocator by default. Under pooling Wasmtime
/// validates the declared initial sizes against the slot at COMPILE time, so
/// an over-ceiling component never reaches instantiation — the store limiter
/// cannot be the enforcement there. The ceiling still holds, but only if the
/// compile-time refusal carries the memory-limit code: without the
/// attribution branch in `PreparedComponent::compile` the operator is told to
/// re-target their toolchain for a defect in the memory budget.
///
/// A single-memory component, deliberately: `build_pooling` sizes
/// `total_memories` at one per instance while allowing eight per component,
/// so a two-memory component is refused by the pool's shape check before any
/// size is compared. That sizing mismatch is F-10's to fix (its spec already
/// names `memories_per_instance`); F-10's 2-memory pooled test is where the
/// aggregate-under-pooling proof belongs.
#[test]
fn f08_pooling_mode_refuses_over_ceiling_at_compile() {
    let manifest = Limits {
        memory: "1536KiB".to_owned(),
        fuel: 1_000_000_000,
        epoch_deadline_ms: 10_000,
        max_instances: 2,
        max_open_handles: 64,
        max_subrequests: 16,
        max_poll_per_tick: 10,
    };
    let roomy = HostCapacity {
        memory_budget_bytes: 4 * 1024 * 1024 * 1024,
        max_instances: 16,
        resident_bytes: 0,
        max_virtual_reservation_bytes: u64::MAX,
    };
    let (engine, _) = build_engine(&manifest, &EngineConfig::default(), &roomy)
        .expect("a 1.5 MiB manifest on a roomy host must be admitted");
    assert!(
        EngineConfig::default().pooling,
        "the fixture must run pooled: an OnDemand engine here would re-prove the test above"
    );
    let bytes = wat::parse_str(ONE_MEMORY_OVER).expect("fixture WAT parses");
    let err = PreparedComponent::compile(&engine, &bytes)
        .expect_err("a 32-page initial against a 24-page pool slot must be refused");
    assert_eq!(
        err.code,
        ErrorCode::MemoryLimitExceeded,
        "the refusal must be the memory-limit code, not another failure: {err:?}"
    );
}
