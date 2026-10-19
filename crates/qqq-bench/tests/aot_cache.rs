// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! The PERF-007 measurement: AOT cache round trip (`Budget::ALL` Perf007 row,
//! `crates/qqq-bench/tests/aot_cache.rs::aot_cache_roundtrip`).
//!
//! # Why an integration test and not a workload
//!
//! `qqqai bench` drives the ten closed `§9.1` HTTP workloads
//! (`BenchmarkName::all_specified`, `Workload::ALL` — both count-locked at
//! ten). An AOT round trip compiles locally; it is not an HTTP row and
//! cannot join that table without breaking both locks. So the measurement
//! lives here, next to PERF-005's `abi_cost.rs`, following its contract:
//! WAT fixtures (no guest toolchain), warmup + distributions, `AOTCACHE`
//! evidence lines, and assertions deliberately loose enough that a loaded
//! CI runner cannot fail them. The budget verdict is computed and
//! *printed*, never asserted: a verdict assert would turn every slow
//! runner into a red build, which is how PERF-020 learned the luck rule.
//! The item verdict comes from measured runs recorded in the checklist,
//! not from this file's exit code.
//!
//! # What "round trip" means
//!
//! Cold compile of fresh bytes on a fresh cache (miss), recompile of the
//! same bytes on the same engine (hit — the counter must move), then
//! hit-compile → instantiate → callable handle. The last chain is the
//! `§9.2` quantity adapted to the safe API: `§9.2` writes "from
//! `Component::deserialize` to callable", but `deserialize` is `unsafe`
//! and this workspace forbids it — Wasmtime's deserialization API is the
//! trust boundary the RFC leaves unapproved. The managed-cache hit path
//! (`Component::new` on warm bytes) is the safe equivalent and is what
//! production serve actually pays, so the method measures that and says
//! so instead of laundering an unsafe call through a benchmark. The cold
//! figure is context, reported with median/min/max only — five samples
//! cannot honestly carry a p99.
//!
//! # What this does not measure
//!
//! qqq-host's configured engine (pooling allocator, guard pages, epoch
//! interruption), the managed-cache *directory* identity beyond one temp
//! dir, cross-process reuse (covered by `live_components`), or any guest
//! behavior: the fixture imports nothing, so instantiation exercises the
//! component model alone. Same honesty boundary as PERF-005's harness.

use qqq_bench::budget::{Budget, Item};
use qqq_bench::stats::Distribution;
use std::time::Instant;

/// How many code-bearing functions the fixture compiles.
///
/// Enough Cranelift work to be a real compile (tens of KB of WAT) without
/// making the test slow: cold compiles stay in the tens of milliseconds
/// in debug builds.
const FUNCTIONS: usize = 200;

/// Cold-miss samples. Five fresh cache dirs; percentiles would be theater
/// at this n, so only median/min/max are reported.
const COLD_SAMPLES: usize = 5;

/// Warm-path samples. n ≥ 1000, so p99 is a genuinely observed rank.
const WARM_SAMPLES: usize = 1001;

/// Warmup iterations discarded before each warm distribution.
const WARMUP: usize = 100;

/// The budget row this file answers to.
const BUDGET_NS: u64 = 5_000_000;

/// A deterministic code-heavy component: `FUNCTIONS` arithmetic funcs, of
/// which `f0` is lifted as the callable check.
///
/// # Why arithmetic on the input
///
/// A body that ignores its input is a `return` the optimiser collapses;
/// `x + k` forces real instructions and makes the result depend on the
/// input, so a future rewrite that dropped bodies would answer differently
/// rather than faster. Same rationale as `abi_cost.rs`'s fixtures.
fn fixture_wat() -> String {
    use std::fmt::Write as _;
    let mut core = String::new();
    for i in 0..FUNCTIONS {
        let _ = writeln!(
            core,
            "(func (export \"f{i}\") (param i32) (result i32) \
             (i32.add (local.get 0) (i32.const {})))",
            7 + i
        );
    }
    format!(
        "(component\n  (core module $m\n{core}  )\n  \
         (core instance $i (instantiate $m))\n  \
         (func (export \"f0\") (param \"x\" u32) (result u32) \
         (canon lift (core func $i \"f0\")))\n)"
    )
}

/// What `f0(40)` must answer: input plus its constant.
fn f0_expected(x: u32) -> u32 {
    x + 7
}

/// A scratch cache dir owned by this test alone.
fn scratch(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "qqq-aotcache-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock runs forward")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("scratch must exist");
    root
}

fn engine_with_cache(dir: &std::path::Path) -> (wasmtime::Engine, wasmtime::Cache) {
    let mut cache_config = wasmtime::CacheConfig::new();
    cache_config.with_directory(dir);
    let cache = wasmtime::Cache::new(cache_config).expect("cache must build");
    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true);
    config.cache(Some(cache.clone()));
    let engine = wasmtime::Engine::new(&config).expect("engine must build");
    (engine, cache)
}

/// The full round trip: cold miss, warm hit, hit-compile to callable.
///
/// Returns the three distributions plus the budget verdict on the
/// to-callable p99. The verdict is data, not an assertion —
/// see the module docs.
#[must_use]
pub fn aot_cache_roundtrip() -> Roundtrip {
    let wat = fixture_wat();
    // Parse WAT once, up front: every sample feeds binary bytes, so the
    // distributions measure compile/cache/instantiate — never the WAT
    // parser. Feeding text would conflate parse cost into every sample
    // and punish the cache for the harness's own work.
    let binary = wat::parse_str(&wat).expect("fixture is valid WAT");

    // Cold: fresh cache dir per sample, so every compile is a miss.
    let mut cold = Distribution::with_capacity(COLD_SAMPLES);
    for _ in 0..COLD_SAMPLES {
        let root = scratch("cold");
        let (engine, _) = engine_with_cache(&root.join("cache"));
        let start = Instant::now();
        wasmtime::component::Component::new(&engine, &binary).expect("fixture compiles");
        cold.record(start.elapsed());
        std::fs::remove_dir_all(&root).ok();
    }

    // Warm: one engine, one dir. First compile warms, the rest must hit.
    let root = scratch("warm");
    let (engine, cache) = engine_with_cache(&root.join("cache"));
    wasmtime::component::Component::new(&engine, &binary).expect("warmup compile");
    let hits_before = cache.cache_hits();
    let mut warm = Distribution::with_capacity(WARM_SAMPLES);
    for _ in 0..WARMUP {
        wasmtime::component::Component::new(&engine, &binary).expect("warmup");
    }
    for _ in 0..WARM_SAMPLES {
        let start = Instant::now();
        wasmtime::component::Component::new(&engine, &binary).expect("hit compiles");
        warm.record(start.elapsed());
    }
    let hits = cache.cache_hits() - hits_before;

    // Deserialize to callable: the §9.2 quantity.
    let linker = wasmtime::component::Linker::new(&engine);
    let mut to_callable = Distribution::with_capacity(WARM_SAMPLES);
    for _ in 0..WARMUP {
        let component =
            wasmtime::component::Component::new(&engine, &binary).expect("hit compiles");
        let mut store = wasmtime::Store::new(&engine, ());
        linker
            .instantiate(&mut store, &component)
            .expect("no-import component instantiates");
    }
    for _ in 0..WARM_SAMPLES {
        let start = Instant::now();
        let component =
            wasmtime::component::Component::new(&engine, &binary).expect("hit compiles");
        let mut store = wasmtime::Store::new(&engine, ());
        let instance = linker
            .instantiate(&mut store, &component)
            .expect("no-import component instantiates");
        let _func = instance
            .get_typed_func::<(u32,), (u32,)>(&mut store, "f0")
            .expect("f0 handle acquired");
        to_callable.record(start.elapsed());
    }

    // Correctness, once: the callable answers from the input.
    let component = wasmtime::component::Component::new(&engine, &binary).expect("compile");
    let mut store = wasmtime::Store::new(&engine, ());
    let instance = linker
        .instantiate(&mut store, &component)
        .expect("instantiate for the answer check");
    let func = instance
        .get_typed_func::<(u32,), (u32,)>(&mut store, "f0")
        .expect("f0 handle");
    let (answer,) = func.call(&mut store, (40,)).expect("f0 runs");
    assert_eq!(
        answer,
        f0_expected(40),
        "the fixture must answer from its input"
    );

    let budget = Budget::for_item(Item::Perf007).expect("PERF-007 row exists");
    let p99 = to_callable.p99().expect("non-empty");
    let verdict = budget
        .meets_nanos(p99)
        .expect("PERF-007 is a millisecond time budget");

    let report = Roundtrip {
        cold,
        warm,
        to_callable,
        cache_hits: hits,
        verdict_met: verdict.met,
    };
    std::fs::remove_dir_all(&root).ok();
    report
}

/// The measured round trip plus its budget verdict.
pub struct Roundtrip {
    /// Cold-miss compiles (fresh cache each sample).
    pub cold: Distribution,
    /// Warm recompiles (hits).
    pub warm: Distribution,
    /// Deserialize → instantiate → callable handle.
    pub to_callable: Distribution,
    /// Cache hits registered across the warm samples.
    pub cache_hits: usize,
    /// Whether the to-callable p99 met the ≤ 5 ms budget.
    pub verdict_met: bool,
}

/// Print machine-readable rows: `label|n|min|p50|p90|p99|max` in ns, plus a
/// median-only row for the small-n cold distribution and a verdict row.
fn emit(report: &Roundtrip) {
    fn row(label: &str, d: &Distribution) -> String {
        format!(
            "{label}|{}|{}|{}|{}|{}|{}",
            d.len(),
            d.min().expect("non-empty"),
            d.p50().expect("non-empty"),
            d.p90().expect("non-empty"),
            d.p99().expect("non-empty"),
            d.max().expect("non-empty"),
        )
    }
    let cold = &report.cold;
    println!(
        "AOTCACHE cold_compile_median_only|{}|{}|{}|{}",
        cold.len(),
        cold.min().expect("non-empty"),
        {
            let mut v: Vec<u64> = cold.samples().to_vec();
            v.sort_unstable();
            v[v.len() / 2]
        },
        cold.max().expect("non-empty"),
    );
    println!("AOTCACHE {}", row("warm_hit", &report.warm));
    println!("AOTCACHE {}", row("to_callable", &report.to_callable));
    println!(
        "AOTCACHE verdict|{}|{}|{}",
        report.to_callable.p99().expect("non-empty"),
        BUDGET_NS,
        report.verdict_met
    );
    println!("AOTCACHE cache_hits|{}", report.cache_hits);
}

#[test]
fn aot_cache_roundtrip_reports_a_verdict() {
    let report = aot_cache_roundtrip();
    emit(&report);
    // Structural pins only — never timing comparisons (see module docs).
    assert!(
        report.cache_hits >= WARM_SAMPLES,
        "every warm recompile must hit: {}",
        report.cache_hits
    );
    assert!(!report.cold.is_empty() && !report.warm.is_empty() && !report.to_callable.is_empty());
    for d in [&report.cold, &report.warm, &report.to_callable] {
        assert!(
            d.samples().iter().all(|&ns| ns > 0),
            "the clock must advance during every step"
        );
    }
}
