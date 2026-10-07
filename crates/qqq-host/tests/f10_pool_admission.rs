// SPDX-License-Identifier: Apache-2.0

//! F-10: the pool and admission agree, proven against live engines.
//!
//! `build_pooling` sized `total_memories` at one per instance while a
//! component may hold up to eight, so a two-memory component halved effective
//! concurrency and the failure appeared as an instantiation error under load
//! (measured in F-08: a two-memory fixture against a one-per-instance pool
//! fails at compile with "defined memories count of 2 exceeds the
//! per-instance limit of 1"). One `PoolShape` now feeds both paths, and these
//! tests pin the agreement from both sides: oversize refused at load, and
//! full concurrency for multi-memory guests.

use qqq_cap::manifest::{Limits, Manifest};
use qqq_cap::resolve::GrantSet;
use qqq_core::ErrorCode;
use qqq_host::{build_engine, EngineConfig, HostCapacity, Instance, LimitSet, PreparedComponent};

/// Nine memories in one core module: one past the eight the shape allows.
const NINE_MEMORIES: &str = r#"
    (component
      (core module $m
        (memory 1) (memory 1) (memory 1)
        (memory 1) (memory 1) (memory 1)
        (memory 1) (memory 1) (memory 1)
        (func (export "f") (result i32) (i32.const 7))
      )
      (core instance $i (instantiate $m))
      (func $f (result u32) (canon lift (core func $i "f")))
      (export "f" (func $f))
    )
"#;

/// Two memories of one page each: the concurrency probe guest.
const TWO_SMALL_MEMORIES: &str = r#"
    (component
      (core module $m
        (memory (export "a") 1)
        (memory (export "b") 1)
        (func (export "f") (result i32) (i32.const 7))
      )
      (core instance $i (instantiate $m))
      (func $f (result u32) (canon lift (core func $i "f")))
      (export "f" (func $f))
    )
"#;

fn on_demand_engine() -> wasmtime::Engine {
    let mut cfg = wasmtime::Config::new();
    cfg.wasm_component_model(true);
    cfg.consume_fuel(true);
    cfg.epoch_interruption(true);
    cfg.wasm_multi_memory(true);
    wasmtime::Engine::new(&cfg).expect("engine must build")
}

fn no_grants() -> GrantSet {
    GrantSet::from_manifest(
        &Manifest::parse("[package]\nname = \"shape\"\nversion = \"0.1.0\"\n")
            .expect("a minimal manifest parses"),
    )
}

/// **F-10: a component exceeding the memory count is refused at load.**
///
/// Written first and failing first: with no load-time validation the
/// nine-memory component compiles (the failure used to arrive at
/// instantiation, under load). The refusal must carry a limit code with the
/// count, not a validation dump: the operator's fix is a smaller component
/// or a larger shape, not a toolchain change.
#[test]
fn f10_component_exceeding_memory_count_is_refused_at_load() {
    let engine = on_demand_engine();
    let bytes = wat::parse_str(NINE_MEMORIES).expect("fixture WAT parses");
    let err = PreparedComponent::compile(&engine, &bytes)
        .expect_err("9 memories against a shape allowing 8 must be refused at load");
    assert_eq!(
        err.code,
        ErrorCode::LimitOutOfRange,
        "the refusal must be the limit code, not another failure: {err:?}"
    );
}

/// **F-10: eight concurrent two-memory instances on an eight-slot shape.**
///
/// The behavioural proof the audit demands. Eight threads meet at a barrier
/// and instantiate at once, then hold every instance past a second barrier
/// so the peak overlap is total, not hoped for: sixteen memory slots live at
/// once. Before the fix the pool held eight slots and at least four
/// instantiations failed; after it the shape reserves sixteen and all eight
/// succeed. Creation is the scarce resource — pool exhaustion surfaces as an
/// instantiation error — so creation success is the signal, not a call.
#[test]
fn f10_eight_concurrent_two_memory_instances_all_instantiate() {
    const WORKERS: usize = 8;
    let manifest = Limits {
        memory: "128KiB".to_owned(),
        fuel: 1_000_000,
        epoch_deadline_ms: 10_000,
        max_instances: u32::try_from(WORKERS).expect("eight workers fit"),
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
        .expect("a 128 KiB manifest on a roomy host must be admitted");
    assert!(
        EngineConfig::default().pooling,
        "the fixture must run pooled: the pool slots are what is contested"
    );
    let bytes = wat::parse_str(TWO_SMALL_MEMORIES).expect("fixture WAT parses");
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("compiles");
    let limits = LimitSet {
        memory_bytes: 128 * 1024,
        fuel: 1_000_000,
        epoch_deadline_ms: 10_000,
        max_open_handles: 64,
        max_subrequests: 16,
    };
    let start = std::sync::Barrier::new(WORKERS);
    let hold = std::sync::Barrier::new(WORKERS + 1);
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(WORKERS);
        for _ in 0..WORKERS {
            handles.push(s.spawn(|| {
                start.wait();
                let instance = Instance::create(&engine, &prepared, &no_grants(), limits)
                    .expect("a slot must exist for every worker");
                // Hold past the second barrier: all eight instances — sixteen
                // memory slots — are live at once before any is dropped.
                hold.wait();
                drop(instance);
            }));
        }
        // The main thread holds the extra barrier party until every worker
        // has instantiated: no worker drops before the peak overlap.
        hold.wait();
        for h in handles {
            h.join().expect("no worker may fail or panic");
        }
    });
}
