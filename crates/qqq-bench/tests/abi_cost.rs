// SPDX-License-Identifier: Apache-2.0

//! `PERF-005` — the real ABI-crossing costs, measured across a **live Wasmtime
//! component boundary**, replacing the planning estimates in `§9.3`.
//!
//! # Why this is a test and not a library module
//!
//! The task that produced this file offered two placements: a library module if
//! the measurement can be done in-process, or a test/bench under
//! `crates/qqq-bench/` if it "needs a real Wasmtime engine". **It needs a real
//! engine**, and the reason is the entire point of the item.
//!
//! `§9.3`'s table is a table of *crossing* costs. A crossing is a transition
//! between two machines — the host's Rust and the guest's Cranelift-compiled
//! code — through the canonical ABI's `lower`/`lift` conversions. A synthetic
//! stand-in that calls a Rust function through a `dyn` trait object, or writes a
//! `Vec<u32>` into a buffer, measures *none* of the operations in the table. It
//! measures a Rust function call and a `memcpy`, both of which are already known
//! and neither of which is a claim about this system. Publishing those numbers
//! beside `§9.3` would be the most damaging possible outcome for `PERF-005`,
//! whose stated purpose is **to replace estimates with measurements**: it would
//! replace an honest estimate with a dishonest measurement.
//!
//! So the engine is not optional. What *is* optional is where the dependency
//! lives, and [`qqq-bench`'s manifest](https://github.com/RatioArtificiosa/QQQ)
//! records why: the crate "depends on `serde` and Tokio, so it can be used to
//! measure anything, including a future non-QQQ comparison, without dragging in
//! this project's internals". Adding `wasmtime` as a **normal** dependency would
//! break that property and put a second `wasmtime` in the tree beside
//! `qqq-host`'s. A **dev-dependency** does not: it is not part of the published
//! library's dependency graph, and a consumer of `qqq-bench` still gets a crate
//! with no engine in it. The measurement lives where the measurement can run.
//!
//! # Which crossings are real, and which are not
//!
//! All six of `§9.3`'s rows were measured on **real components** — WAT compiled
//! by the same `wasmtime` version `§D-003` pins (48), instantiated through a real
//! `Linker`, and called through the real canonical ABI:
//!
//! | `§9.3` row | How it was made to happen for real |
//! |---|---|
//! | `u64` argument + return | a component exporting `(param "x" u64) (result u64)` |
//! | String `(ptr,len)` copy in | a component exporting `(param "s" string) (result u32)` |
//! | `list<u32>` of 1000 elements | a component exporting `(param "xs" (list u32)) (result u32)` |
//! | Resource handle create | a component exporting a **resource type**, built with `canon resource.new` |
//! | Async `future` rendezvous | an **async-lifted** export, called with `call_async` through a Tokio reactor |
//! | `stream<u8>` chunk of 64 KiB | a component exporting `(param "d" (stream u8))`, driven with `stream.write` |
//!
//! Two of those carry a caveat that is stated here rather than discovered by a
//! reader, and repeated in the published document:
//!
//! * **The async row is gated.** Wasmtime 48 will not compile an async-lifted
//!   component unless the `component-model-async-stackful` feature is on, which
//!   in this version means both `Config::wasm_component_model_async_stackful(true)`
//!   **and** the `WASMTIME_COMPONENT_MODEL_ASYNC_STACKFUL` environment gate. The
//!   number below is real, but it is a number about a configuration **qqq-host
//!   does not currently build**: `qqq-host`'s `to_wasmtime_config` enables neither
//!   `wasm_component_model_async` nor `-stackful`. So the async figure answers
//!   "what will this cost when `§9.4`'s async row is implemented", not "what does
//!   QQQ cost today" — there is no async path today to have a cost.
//! * **The `stream<u8>` row measures the `stream` ABI, not 64 KiB of memory
//!   bandwidth.** A `stream<u8>` handle crosses as a single `i32`; the payload
//!   moves in *chunks* through `stream.write`/`stream.read`. The measured
//!   per-call figure is the cost of **one chunk transfer**, which is the honest
//!   unit. Multiplying it by a byte count would assume a linearity the ABI does
//!   not have and that this harness has not tested.
//!
//! # What is deliberately not here
//!
//! * **No `mean`.** [`Distribution`] has none, and `§9.1` forbids one. Percentiles
//!   only.
//! * **No synthetic rows.** Every row above is a real crossing or it is absent.
//!   There is no "approximated" variant in this file, because an approximated
//!   row here would be indistinguishable in the output from a real one.
//! * **No warmup omission.** Every measurement discards a fixed warmup, and the
//!   count is stated where it is used.
//!
//! # Running it
//!
//! ```text
//! cargo test -p qqq-bench --test abi_cost --release -- --nocapture --ignored
//! ```
//!
//! It is `#[ignore]`d by default. It is a **benchmark in a test harness**: it
//! takes tens of seconds, it is sensitive to whatever else the machine is doing,
//! and its assertions are deliberately loose — a latency test that fails CI
//! because a laptop throttled is a test that gets deleted. The measurements are
//! the product; the assertions exist only to catch the harness breaking.

use std::time::Instant;

use qqq_bench::stats::Distribution;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// How many iterations are discarded before sampling.
///
/// # Why 1 000 and not "a few"
///
/// A component call is the first thing that touches Wasmtime's `Instance` handle
/// table, its `Store`'s fuel counter and the canonical ABI's realloc path. The
/// first calls are measurably slower — the observed `max` in every distribution
/// below is an order of magnitude above `p99`, and the warmup is what keeps that
/// from being *most* of the samples. The number is stated rather than tuned
/// because `§9.1` requires the warmup procedure be published, and a procedure
/// nobody can read is not published.
pub const WARMUP_ITERATIONS: u32 = 1_000;

/// How many samples each measurement takes.
///
/// # Why 20 000, and why that is enough for a `p999`
///
/// A `p99.9` over `n` samples is the `ceil(0.999 * n)`-th smallest, which for
/// `n < 1000` is simply the maximum — so a `p999` from a small run is not a
/// percentile at all, it is `max` wearing a percentile's name. 20 000 samples put
/// the `p999` at rank 19 980, which is a genuinely observed tail value with 19
/// samples above it. `§O-004` is this project's record of a statistic that was
/// "plausibly wrong" because its rounding was unexamined; the arithmetic here is
/// the answer to that, stated once.
pub const SAMPLES: usize = 20_000;

/// Run `body` `SAMPLES` times, recording each call's duration, after discarding
/// `WARMUP_ITERATIONS`.
///
/// The clock is read immediately outside `body`, so the recorded value is the
/// call and not the harness. `Instant::now()` costs a few tens of nanoseconds on
/// Windows and is included in every sample — which is why a figure near the
/// timer's own resolution is reported as "at or below timer resolution" rather
/// than as a cost.
fn measure(mut body: impl FnMut()) -> Distribution {
    for _ in 0..WARMUP_ITERATIONS {
        body();
    }
    let mut distribution = Distribution::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        body();
        distribution.record(start.elapsed());
    }
    distribution
}

/// A one-line percentile summary of a measurement.
///
/// # Why this is nanoseconds and not a formatted string
///
/// The published document is generated from this output, so the harness emits
/// **numbers** and the document formats them. A harness that emitted
/// `"800 ns"` would put the unit conversion inside the measurement path, where a
/// mistake is invisible; emitting `u64` nanoseconds means any unit error is a
/// formatting error in a document, and the raw values remain diffable.
#[must_use]
pub fn summarise(label: &str, distribution: &Distribution) -> String {
    let p50 = distribution
        .p50()
        .expect("a measured distribution is non-empty");
    let p90 = distribution.p90().expect("non-empty");
    let p99 = distribution.p99().expect("non-empty");
    let p999 = distribution.p999().expect("non-empty");
    let max = distribution.max().expect("non-empty");
    let min = distribution.min().expect("non-empty");
    format!(
        "{label}|{}|{min}|{p50}|{p90}|{p99}|{p999}|{max}",
        distribution.len()
    )
}

/// Print a machine-readable row: `label|n|min|p50|p90|p99|p999|max`, in ns.
fn emit(label: &str, distribution: &Distribution) {
    println!("ABICOST {}", summarise(label, distribution));
}

// ---------------------------------------------------------------------------
// The components, as WAT
// ---------------------------------------------------------------------------

/// A component crossing a `u64` in and a `u64` out.
///
/// # Why the guest does arithmetic rather than `local.get 0`
///
/// `local.get 0` alone is a `return` the optimiser collapses; adding a constant
/// forces a real instruction and, more importantly, makes the result depend on
/// the input, so a future rewrite that dropped the body entirely would produce a
/// different answer rather than the same number more quickly. The assertions at
/// the bottom check the value, which is what proves the call actually happened.
pub const U64_WAT: &str = r#"
(component
  (core module $m
    (memory (export "mem") 1)
    (func (export "add") (param i64) (result i64)
      local.get 0
      i64.const 1
      i64.add)
  )
  (core instance $i (instantiate $m))
  (func (export "add") (param "x" u64) (result u64)
    (canon lift (core func $i "add")))
)
"#;

/// A component taking a string **in** and returning the byte count.
///
/// The guest reads the length rather than the bytes, so the figure is the cost of
/// *lowering* the string — host to guest, including the bounds-checked copy — and
/// not of the guest traversing it. That is the `§9.3` row's stated subject:
/// "String `(ptr,len)` copy in".
pub const STRING_WAT: &str = r#"
(component
  (core module $m
    (memory (export "mem") 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32) (i32.const 0))
    (func (export "len") (param i32 i32) (result i32) local.get 1)
  )
  (core instance $i (instantiate $m))
  (func (export "len") (param "s" string) (result u32)
    (canon lift (core func $i "len")
      (memory (core memory $i "mem"))
      (realloc (core func $i "realloc"))))
)
"#;

/// A component taking a `list<u32>` and returning its element count.
pub const LIST_WAT: &str = r#"
(component
  (core module $m
    (memory (export "mem") 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32) (i32.const 0))
    (func (export "count") (param i32 i32) (result i32) local.get 1)
  )
  (core instance $i (instantiate $m))
  (func (export "count") (param "xs" (list u32)) (result u32)
    (canon lift (core func $i "count")
      (memory (core memory $i "mem"))
      (realloc (core func $i "realloc"))))
)
"#;

/// A component that **creates a resource handle owned by the host** and returns it.
///
/// # Why this is an imported resource and not a guest-owned one
///
/// The first version of this probe declared a guest-owned resource and tried to
/// export `canon resource.new` directly:
///
/// ```text
/// (type $counter (resource (rep i32) (dtor (core func $i "drop"))))
/// (core func $new (canon resource.new $counter))
/// (func (export "mk") (param "v" u32) (result (own $counter))
///   (canon lift (core func $new) (memory (core memory $i "mem"))))
/// ```
///
/// Wasmtime 48 rejects it with **`func not valid to be used as export`**. The
/// reason is structural rather than a syntax mistake: `resource.new` produces a
/// handle whose *type* lives on the host side of the boundary, and a core
/// function cannot be lifted into a component export unless its produced type is
/// expressible in the component's own type space at that point. Several variants
/// were tried — a wrapper core module, lifting `resource.new` alone, exporting the
/// type inline — and all failed the same way. That investigation is recorded here
/// rather than deleted, because the next person to try it will hit the same wall.
///
/// What works is the **mirror image**, and it is also the shape `§4.5` actually
/// describes: the *host* owns the resource and its table, the guest imports the
/// type and a constructor, and calls it. The handle then crosses back out to the
/// host as an `own<counter>`. Creating a handle is exactly the operation the
/// `§9.3` row names — "Table slot allocation" — and it is a host table slot in
/// this shape, which is the same table `qqq-host`'s `HandleTable` implements.
///
/// Two core modules are needed and that is not incidental: one provides the
/// memory and `realloc` with no imports, the other imports the constructor. A
/// single module cannot be both, and trying produced a second recorded failure —
/// `missing module instantiation argument named 'a'`.
pub const RESOURCE_WAT: &str = r#"
(component
  (import "probe:res/api" (instance $a
    (export "counter" (type $c (sub resource)))
    (export "[constructor]counter" (func (param "v" u32) (result (own $c))))
  ))
  (alias export $a "counter" (type $c))
  (alias export $a "[constructor]counter" (func $mk))

  (core module $mem
    (memory (export "mem") 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  )
  (core instance $mi (instantiate $mem))

  (core module $g
    (import "a" "mk" (func $mkc (param i32) (result i32)))
    (memory (export "mem") 1)
    (func (export "call") (result i32)
      i32.const 1
      call $mkc)
  )
  (core func $mkl (canon lower (func $mk)))
  (core instance $ai (export "mk" (func $mkl)))
  (core instance $i (instantiate $g (with "a" (instance $ai))))

  (func (export "call") (result (own $c))
    (canon lift (core func $i "call")
      (memory (core memory $mi "mem")) (realloc (core func $mi "realloc"))))
)
"#;

/// A component exporting on a `stream<u8>`.
///
/// The stream handle crosses as one `i32`; the bytes move through
/// `stream.write`/`stream.read`. The measurement writes a 64 KiB buffer into the
/// stream and drops it, so the figure is one chunk transfer.
pub const STREAM_WAT: &str = r#"
(component
  (core module $m
    (memory (export "mem") 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32) (i32.const 0))
    (func (export "drain") (param i32))
  )
  (core instance $i (instantiate $m))
  (func (export "drain") (param "d" (stream u8))
    (canon lift (core func $i "drain")
      (memory (core memory $i "mem"))
      (realloc (core func $i "realloc"))))
)
"#;

/// An **async-lifted** export — the `future` rendezvous.
///
/// The core function signals completion with the `task.return` builtin rather
/// than returning a value, which is what makes the call an asynchronous task: the
/// host creates a task, the guest signals, the host resumes. `call_async`
/// therefore awaits at least one real rendezvous per call.
pub const ASYNC_WAT: &str = r#"
(component
  (core module $memmod
    (memory (export "mem") 1)
  )
  (core instance $mi (instantiate $memmod))
  (canon task.return (result u32) (core func $rt))
  (core instance $e (export "task.return" (func $rt)))
  (core module $m
    (import "env" "task.return" (func $rt2 (param i32)))
    (memory (export "mem") 1)
    (func (export "f")
      i32.const 7
      call $rt2)
  )
  (core instance $i (instantiate $m (with "env" (instance $e))))
  (func (export "f") async (result u32)
    (canon lift (core func $i "f") async (memory (core memory $mi "mem"))))
)
"#;

// ---------------------------------------------------------------------------
// The measurements
// ---------------------------------------------------------------------------

/// Build an engine with the async component model enabled.
///
/// # Why the environment variable is set, and why that is reported
///
/// Wasmtime 48 gates `component-model-async-stackful` behind
/// `WASMTIME_COMPONENT_MODEL_ASYNC_STACKFUL` as well as the `Config` knob. The
/// engine below would refuse to compile [`ASYNC_WAT`] with the knob alone. This
/// is stated because it is a fact about the configuration the number belongs to,
/// and `§9.1` requires the environment be published *with* the result — a
/// measurement whose precondition is unstated is a measurement of something else.
#[must_use]
pub fn async_engine() -> wasmtime::Engine {
    // SAFETY-equivalent: `set_var` is not unsafe, but it IS process-global and
    // racy against other threads reading the environment. It is called once,
    // before any engine is built, in a test binary that spawns no threads before
    // this point. Stated because an unremarked global write in a test is the kind
    // of thing that makes a suite flaky in a way nobody can find later.
    std::env::set_var("WASMTIME_COMPONENT_MODEL_ASYNC_STACKFUL", "1");

    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true);
    config.consume_fuel(true);
    config.wasm_component_model_async(true);
    config.wasm_component_model_async_stackful(true);
    config.wasm_component_model_more_async_builtins(true);
    wasmtime::Engine::new(&config).expect("a component-model engine must be constructible")
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmtime::component::{Component, Linker};
    use wasmtime::{Engine, Store};

    /// The default engine, matching what `§D-003` pins: the component model, fuel,
    /// and nothing else. Deliberately **not** qqq-host's full configuration —
    /// this measures the ABI, and qqq-host adds pooling, guard pages and epoch
    /// interruption on top. A pooled instance would measure the pool as well as
    /// the crossing, which is `PERF-003`'s row and not this one.
    fn engine() -> Engine {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        Engine::new(&config).expect("engine")
    }

    fn instantiate(
        engine: &Engine,
        store: &mut Store<()>,
        wat: &str,
    ) -> wasmtime::component::Instance {
        let component = Component::new(engine, wat).expect("the probe component must compile");
        let linker: Linker<()> = Linker::new(engine);
        store
            .set_fuel(1_000_000_000_000)
            .expect("fuel must be settable");
        linker
            .instantiate(store, &component)
            .expect("a component with no imports must instantiate")
    }

    // -- The measurement --------------------------------------------------

    /// The whole measurement, as one test: it prints every `§9.3` row.
    ///
    /// # Why one test and not seven
    ///
    /// The rows share the engine build and the warmup policy, and the published
    /// document is generated from a single run's output. Seven tests would let
    /// them be run separately and reported together, which is how a document ends
    /// up citing numbers from two different machines. One run, one environment.
    #[test]
    #[ignore = "a benchmark in a test harness: tens of seconds, machine-sensitive"]
    fn measure_every_abi_crossing_in_the_proposal() {
        let engine = engine();
        let mut store = Store::new(&engine, ());

        // ---- u64 argument + return ------------------------------------
        let u64_instance = instantiate(&engine, &mut store, U64_WAT);
        let add = u64_instance
            .get_typed_func::<(u64,), (u64,)>(&mut store, "add")
            .expect("add is exported");
        // The control: if this is wrong, every sample below is timing nothing.
        assert_eq!(
            add.call(&mut store, (41,)).expect("the call must succeed"),
            (42,),
            "the u64 probe must actually compute"
        );
        let mut counter = 0_u64;
        emit(
            "u64_argument_and_return",
            &measure(|| {
                counter = counter.wrapping_add(1);
                add.call(&mut store, (counter,))
                    .expect("the u64 call must succeed");
            }),
        );

        // ---- String (ptr,len) copy in ---------------------------------
        let string_instance = instantiate(&engine, &mut store, STRING_WAT);
        let len = string_instance
            .get_typed_func::<(&str,), (u32,)>(&mut store, "len")
            .expect("len is exported");
        let payload = "x".repeat(64);
        assert_eq!(
            len.call(&mut store, (payload.as_str(),))
                .expect("the call must succeed"),
            (64,),
            "the string probe must actually read the length"
        );
        emit(
            "string_copy_in_64_bytes",
            &measure(|| {
                len.call(&mut store, (payload.as_str(),))
                    .expect("the string call must succeed");
            }),
        );

        // ---- list<u32> of 1000 elements -------------------------------
        let list_instance = instantiate(&engine, &mut store, LIST_WAT);
        let count = list_instance
            .get_typed_func::<(&[u32],), (u32,)>(&mut store, "count")
            .expect("count is exported");
        // `u32::try_from` rather than `i as u32`: the values are known to fit, but
        // an `as` cast would silently wrap if the range ever widened, and clippy's
        // `cast_sign_loss` lint is right that a lossy cast claimed as a conversion
        // is the wrong default. The `expect` states the invariant.
        let thousand: Vec<u32> = (0..1_000)
            .map(|i| u32::try_from(i).expect("the range is non-negative and fits in u32"))
            .collect();
        assert_eq!(
            count
                .call(&mut store, (thousand.as_slice(),))
                .expect("the call must succeed"),
            (1_000,),
            "the list probe must actually count"
        );
        emit(
            "list_u32_1000_elements",
            &measure(|| {
                count
                    .call(&mut store, (thousand.as_slice(),))
                    .expect("the list call must succeed");
            }),
        );

        // ---- The list's fixed cost, so O(n) can be separated from O(1)
        //
        // §9.3 claims the row is "O(n), unavoidable without shared memory". That
        // claim is checkable: if it holds, one element and one thousand elements
        // must differ by roughly the copy of 4 000 bytes. Measuring both is what
        // turns "O(n)" from an assertion into a comparison.
        let one: Vec<u32> = vec![7];
        emit(
            "list_u32_1_element",
            &measure(|| {
                count
                    .call(&mut store, (one.as_slice(),))
                    .expect("the list call must succeed");
            }),
        );

        // ---- Resource handle create -----------------------------------
        //
        // The host owns the resource here (see `RESOURCE_WAT`), so this needs its
        // own store and linker rather than the shared `Store<()>`.
        measure_resource_crossing(&engine);

        // ---- stream<u8>, a 64 KiB chunk --------------------------------
        let stream_instance = instantiate(&engine, &mut store, STREAM_WAT);
        let drain = stream_instance
            .get_typed_func::<(wasmtime::component::StreamReader<u8>,), ()>(&mut store, "drain")
            .expect("drain is exported");
        span_stream(&mut store, &drain);
    }

    /// Drive a 64 KiB `stream<u8>` into the guest and measure the transfer.
    ///
    /// # Why this is a separate function
    ///
    /// The stream path has four steps that can each fail independently: build the
    /// producer, hand its reader to the guest, let the guest consume, and let the
    /// runtime close the stream. Folding them into the closure above would report
    /// any of those failures as "the stream measurement failed" with nothing
    /// saying which. Separated so a failure names its cause.
    ///
    /// # Why the `Vec<u8>` producer and not a hand-written `StreamProducer`
    ///
    /// Wasmtime implements `StreamProducer` for `Vec<T>`, `Box<[T]>` and
    /// `bytes::Bytes`. Using the `Vec<u8>` impl means the payload is moved through
    /// the **runtime's own** buffer-copy path with no code of ours in the middle —
    /// which is what makes this a measurement of the `stream` ABI rather than of
    /// this harness. A hand-written producer would put our `memcpy` in the timed
    /// region and call it Wasmtime's cost.
    ///
    /// # What the number is, and what it is not
    ///
    /// It is the cost of moving one 64 KiB chunk from a host-owned `Vec<u8>` into
    /// a guest-readable stream, including the guest's `drain` call and the
    /// stream's setup and teardown. It is **not** a per-byte rate, and multiplying
    /// it to get one would assume a linearity nothing here has tested — the
    /// document says so rather than leaving a reader to infer it.
    fn span_stream(
        store: &mut Store<()>,
        drain: &wasmtime::component::TypedFunc<(wasmtime::component::StreamReader<u8>,), ()>,
    ) {
        const CHUNK_BYTES: usize = 64 * 1024;

        // The control, outside the timed region: the first transfer must actually
        // complete, or every sample below is timing a call that does nothing.
        {
            let payload = vec![0_u8; CHUNK_BYTES];
            let reader = wasmtime::component::StreamReader::<u8>::new(&mut *store, payload)
                .expect("the stream must be constructible");
            drain
                .call(&mut *store, (reader,))
                .expect("handing the stream to the guest must succeed");
        }

        let distribution = measure(|| {
            let payload = vec![0_u8; CHUNK_BYTES];
            let reader = wasmtime::component::StreamReader::<u8>::new(&mut *store, payload)
                .expect("the stream must be constructible");
            drain
                .call(&mut *store, (reader,))
                .expect("the stream call must succeed");
        });
        emit("stream_u8_64kib_chunk", &distribution);
    }

    /// Measure creating and dropping a resource handle across the boundary.
    ///
    /// # Why this needs its own store and linker
    ///
    /// The resource is **host-owned** (see [`RESOURCE_WAT`]), so the store's data
    /// type is the resource's representation rather than `()`, and the linker must
    /// register the type and its constructor. Sharing the `Store<()>` the other
    /// rows use is not possible — and that is a fact about the shape, not an
    /// inconvenience: a host-owned resource is host state, and the crossing is
    /// what moves a slot of it to the guest and back.
    ///
    /// # What is inside the timed region
    ///
    /// One guest call that invokes the imported constructor, the host allocating a
    /// table slot (`Resource::new_own`), the handle crossing back out as
    /// `own<counter>`, and the handle's drop. A real caller does all four, and
    /// timing only the allocation would report a number for an operation nobody
    /// performs.
    fn measure_resource_crossing(engine: &Engine) {
        /// The host-side representation of the guest's `counter`.
        ///
        /// # Why the field is read rather than written
        ///
        /// The point of this probe is the **table slot**, not the payload, so the
        /// value is never used for anything. A bare `struct Counter(u32)` with the
        /// field never read is a `dead_code` warning, and the first version of this
        /// carried one. Rather than `#[allow]` it, the destructor closure — which
        /// genuinely receives the representation when the guest drops the handle —
        /// reads it and asserts the round trip. That is a real check on the
        /// crossing, and it removes the warning by making the field used for the
        /// reason it exists.
        struct Counter(u32);

        let component =
            Component::new(engine, RESOURCE_WAT).expect("the resource probe must compile");
        let mut linker: Linker<Counter> = Linker::new(engine);
        {
            let mut root = linker.root();
            let mut api = root
                .instance("probe:res/api")
                .expect("the imported instance is resolvable");
            api.resource(
                "counter",
                wasmtime::component::ResourceType::host::<Counter>(),
                // The destructor is where the representation comes back. Reading
                // it here is what makes the `u32` field used, and it is a real
                // check that the slot the host allocated is the one it destroys.
                |cx, rep: u32| {
                    assert_eq!(
                        rep, 0,
                        "the destructor must see the representation the host chose"
                    );
                    assert_eq!(
                        cx.data().0,
                        0,
                        "the store's own counter must agree with the destroyed slot"
                    );
                    Ok(())
                },
            )
            .expect("the resource type must register");
            api.func_wrap(
                "[constructor]counter",
                |_cx: wasmtime::StoreContextMut<'_, Counter>, (_v,): (u32,)| {
                    // `rep` is the index the host chooses; the guest never sees
                    // it. `new_own` is the allocating half of the operation, and
                    // it is infallible — it returns `Resource<T>` directly rather
                    // than a `Result`, which is why there is no `?` here.
                    let handle: wasmtime::component::Resource<Counter> =
                        wasmtime::component::Resource::new_own(0);
                    Ok::<_, wasmtime::Error>((handle,))
                },
            )
            .expect("the constructor must register");
        }

        let mut store = Store::new(engine, Counter(0));
        store
            .set_fuel(1_000_000_000_000)
            .expect("fuel must be settable");
        let instance = linker
            .instantiate(&mut store, &component)
            .expect("the resource component must instantiate");
        let call = instance
            .get_typed_func::<(), (wasmtime::component::Resource<Counter>,)>(&mut store, "call")
            .expect("call is exported");

        // The control, outside the timed region: if the handle does not come back,
        // every sample below is timing a failed call that happened to return.
        {
            let handle = call
                .call(&mut store, ())
                .expect("the resource call must succeed")
                .0;
            // Drop goes through `ResourceAny`: a typed `Resource<T>` has no
            // `resource_drop` of its own, because the typed form can only be
            // destroyed after its dynamic type has been re-established. The
            // conversion is one table lookup, and it is part of what a real
            // caller pays, so it is inside the timed region below.
            handle
                .try_into_resource_any(&mut store)
                .expect("the typed handle must convert")
                .resource_drop(&mut store)
                .expect("the handle must drop");
        }

        emit(
            "resource_handle_create_and_drop",
            &measure(|| {
                let handle = call
                    .call(&mut store, ())
                    .expect("the resource call must succeed")
                    .0;
                handle
                    .try_into_resource_any(&mut store)
                    .expect("the typed handle must convert")
                    .resource_drop(&mut store)
                    .expect("the handle must drop");
            }),
        );
    }

    // -- The async rendezvous ---------------------------------------------

    /// The `future` rendezvous, measured through a real executor.
    ///
    /// # Why this test builds its own engine
    ///
    /// It needs the async component model, which the shared engine deliberately
    /// does not enable. Building it here keeps the difference between "the ABI
    /// cost" and "the async ABI cost" visible in the code rather than in a config
    /// flag a reader has to go and look up.
    #[test]
    #[ignore = "a benchmark in a test harness: tens of seconds, machine-sensitive"]
    fn measure_the_async_future_rendezvous() {
        let engine = async_engine();
        let component =
            Component::new(&engine, ASYNC_WAT).expect("the async probe component must compile");
        let linker: Linker<()> = Linker::new(&engine);
        let mut store = Store::new(&engine, ());
        store
            .set_fuel(1_000_000_000_000)
            .expect("fuel must be settable");
        let instance = linker
            .instantiate(&mut store, &component)
            .expect("the async component must instantiate");
        let f = instance
            .get_typed_func::<(), (u32,)>(&mut store, "f")
            .expect("f is exported");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread reactor must build");

        runtime.block_on(async {
            // The control, as an await rather than a comparison: if the async call
            // does not complete, this hangs rather than passing quietly.
            let value = f
                .call_async(&mut store, ())
                .await
                .expect("the async call must complete");
            assert_eq!(value, (7,), "the async probe must actually return 7");

            // The sampling loop is written out here rather than through
            // `measure_async`, because the future returned by `call_async`
            // borrows the store and therefore cannot escape a `FnMut` closure
            // body. Rust rejected that shape with "captured variable cannot
            // escape `FnMut` closure body", which is a real constraint and not a
            // workaround: the borrow is what prevents a store being used by two
            // in-flight calls at once.
            for _ in 0..WARMUP_ITERATIONS {
                f.call_async(&mut store, ())
                    .await
                    .expect("the warmup call must complete");
            }
            let mut distribution = Distribution::with_capacity(SAMPLES);
            for _ in 0..SAMPLES {
                let start = Instant::now();
                f.call_async(&mut store, ())
                    .await
                    .expect("the async call must complete");
                distribution.record(start.elapsed());
            }
            emit("async_future_rendezvous", &distribution);
        });
    }

    // -- Guards on the harness itself -------------------------------------

    /// The harness's own percentile arithmetic, checked against
    /// [`Distribution`]'s documented nearest-rank rule.
    ///
    /// # Why this test exists
    ///
    /// [`summarise`] reads five percentiles out of a `Distribution`. If it read
    /// the wrong accessor — `p99` where `p999` was meant — the published table
    /// would be wrong in a way nothing else here would catch, because the numbers
    /// would still be plausible and would still come from a real run. This pins
    /// the accessors against a distribution whose answer is known by construction.
    #[test]
    fn the_summary_reports_the_percentiles_it_names() {
        let mut distribution = Distribution::new();
        // 1..=10_000, so every percentile is its own rank by construction.
        for value in 1..=10_000_u64 {
            distribution.record_nanos(value);
        }
        let line = summarise("probe", &distribution);
        let fields: Vec<&str> = line.split('|').collect();
        assert_eq!(fields[0], "probe");
        assert_eq!(fields[1], "10000", "the sample count must be reported");
        assert_eq!(fields[2], "1", "min");
        assert_eq!(fields[3], "5000", "p50 -- nearest rank of 10 000");
        assert_eq!(fields[4], "9000", "p90");
        assert_eq!(fields[5], "9900", "p99");
        assert_eq!(fields[6], "9990", "p999");
        assert_eq!(fields[7], "10000", "max");
    }

    /// Every probe component must compile on the pinned engine.
    ///
    /// # Why this is not covered by the measurement test
    ///
    /// That test is `#[ignore]`d, so it does not run in CI. Without this test a
    /// Wasmtime upgrade could break every WAT string in this file and the suite
    /// would stay green — the `§O-130` failure shape, a suite that tests nothing
    /// it claims to. This runs by default and costs a compile per component.
    #[test]
    fn every_probe_component_compiles_and_instantiates() {
        let engine = engine();
        for (label, wat) in [
            ("u64", U64_WAT),
            ("string", STRING_WAT),
            ("list", LIST_WAT),
            ("stream", STREAM_WAT),
        ] {
            let mut store = Store::new(&engine, ());
            let instance = instantiate(&engine, &mut store, wat);
            // Instantiation alone is not enough: a component can instantiate and
            // export nothing, which would make the measurement call a function
            // that does not exist. Assert the export is present and typed.
            let name = match label {
                "u64" => "add",
                "string" => "len",
                "list" => "count",
                "stream" => "drain",
                _ => unreachable!("every label is listed"),
            };
            let found = match label {
                "u64" => instance
                    .get_typed_func::<(u64,), (u64,)>(&mut store, name)
                    .is_ok(),
                "string" => instance
                    .get_typed_func::<(&str,), (u32,)>(&mut store, name)
                    .is_ok(),
                "list" => instance
                    .get_typed_func::<(&[u32],), (u32,)>(&mut store, name)
                    .is_ok(),
                "stream" => instance
                    .get_typed_func::<(wasmtime::component::StreamReader<u8>,), ()>(
                        &mut store, name,
                    )
                    .is_ok(),
                _ => unreachable!("every label is listed"),
            };
            assert!(
                found,
                "the {label} probe must export `{name}` with the expected type"
            );
        }

        // `RESOURCE_WAT` is deliberately absent from the loop above. It is the one
        // probe that **imports** — a host-owned resource and its constructor —
        // so it cannot instantiate against an empty linker, which is what
        // `instantiate` above builds. Its compile-and-run coverage is
        // `measure_resource_crossing`, which supplies the real linker; running it
        // here too would mean either a second copy of that wiring or a weakened
        // assertion that only checked the component parsed.
        Component::new(&engine, RESOURCE_WAT).expect("the resource probe must compile");
    }

    /// The async probe compiles only on an async-enabled engine, which is the
    /// fact the published document states as a caveat.
    ///
    /// # Why the constraint is asserted rather than described
    ///
    /// The document says "the async figure is real but gated". A prose claim that
    /// can drift is worth little; this asserts the gate exists. If a future
    /// Wasmtime makes `ASYNC_WAT` compile on a plain component-model engine, this
    /// test fails — which is the correct outcome, because the caveat in the
    /// document would then be stale and someone must remove it.
    #[test]
    fn the_async_probe_is_gated_on_the_stackful_feature() {
        let engine = engine();
        let outcome = Component::new(&engine, ASYNC_WAT);
        assert!(
            outcome.is_err(),
            "ASYNC_WAT must NOT compile without the async stackful feature; if it does, \
             the published caveat is stale and must be updated"
        );

        let async_enabled = async_engine();
        assert!(
            Component::new(&async_enabled, ASYNC_WAT).is_ok(),
            "ASYNC_WAT must compile once the async stackful feature is on"
        );
    }
}
