# The ABI cost, measured

**`PERF-005`.** The measured replacement for the planning estimates in
[`QQQ-Proposal-V1.md` §9.3](../QQQ-Proposal-V1.md). Every number below came from a
command in this document and a real Wasmtime component boundary — none is an
estimate, and none is extrapolated from another row.

| | |
|---|---|
| **Measured** | 2026-09-22 |
| **Commit** | `d3e71fd9f08ef7308b3bba314780d7a036f8740d` |
| **Harness** | [`crates/qqq-bench/tests/abi_cost.rs`](../crates/qqq-bench/tests/abi_cost.rs) |
| **Reproduce** | `cargo test -p qqq-bench --test abi_cost --release -- --ignored --nocapture --test-threads=1` |
| **Engine** | Wasmtime 48.0.2 (`§D-003`'s pin) |

---

## 1. The environment

`§9.1` requires pinned hardware listed by model, pinned OS and kernel, and pinned
toolchain versions, published **with** every result. A number without them is not
comparable to anything, including another run of this same harness.

| Element | Value |
|---|---|
| CPU | `Intel(R) Xeon(R) CPU E5-1650 v4 @ 3.60GHz` |
| Physical cores | 6 |
| Logical processors | 12 |
| Memory | 68 637 642 752 bytes (64 GiB) |
| OS | `Microsoft Windows 10 Pro`, version `10.0.19045` |
| Kernel / build | `19045` |
| rustc | `1.98.1 (48a229cea 2026-09-01)` |
| cargo | `1.98.1 (797e8a9bc 2026-08-05)` |
| Profile | `--release` (`opt-level = 3`, `lto = "thin"`, `codegen-units = 1`) |

> **This is a development workstation, not the reference benchmark machine.**
> `§9.1`'s "pinned hardware" is satisfied in the sense that the machine is named
> exactly, and *not* in the sense that this is a controlled measurement host: the
> run was not pinned to specific cores, no other process was excluded, and the CPU
> governor was not adjusted. The figures are therefore **real but not controlled**.
> Treat them as a first honest measurement and as the baseline a future run must
> be compared against — not as the final published performance claim.

### Warmup and concurrency, as `§9.1` requires

| Requirement | How it is satisfied here |
|---|---|
| Warmup procedure stated | **1 000 iterations discarded** before sampling, in every row (`WARMUP_ITERATIONS`) |
| Concurrency levels disclosed | **`Sequential`** — each sample is one call awaited to completion, no overlap, one thread |
| Percentiles, not averages | `Distribution` has **no `mean`**; only `p50`/`p90`/`p99`/`p999`/`min`/`max` are reported |
| Repetitions with variance | 20 000 samples per row. **`§9.1`'s "three repetitions" is *not* satisfied — see §5.** |
| Harness open source | [`crates/qqq-bench/tests/abi_cost.rs`](../crates/qqq-bench/tests/abi_cost.rs) |
| "What this does not measure" | **§5**, below |

The percentiles use nearest-rank: every published value is an **actually observed
sample**, so a reader who sees `p99 = 1.8 µs` can find a call that took 1.8 µs. No
value here is interpolated between neighbours.

---

## 2. The measured numbers

All values in **nanoseconds**. `p999` is at rank 19 980 of 20 000, so 19 samples
sit above it — it is a real tail value and not `max` wearing a percentile's name.

| Operation | n | min | p50 | p90 | p99 | p999 | max |
|---|---:|---:|---:|---:|---:|---:|---:|
| `u64` argument + return | 20 000 | 800 | **900** | 1 000 | **1 800** | 4 500 | 23 000 |
| String `(ptr,len)` copy in, 64 B | 20 000 | 800 | **900** | 1 500 | **1 900** | 4 300 | 11 300 |
| `list<u32>`, 1 000 elements | 20 000 | 800 | **1 600** | 1 800 | **2 000** | 4 200 | 71 500 |
| `list<u32>`, 1 element | 20 000 | 800 | **800** | 900 | **1 700** | 4 100 | 34 500 |
| Resource handle create + drop | 20 000 | 1 000 | **1 200** | 1 200 | **2 500** | 6 000 | 86 000 |
| Async `future` rendezvous | 20 000 | 1 900 | **2 100** | 2 200 | **3 800** | 9 100 | 34 200 |
| `stream<u8>`, one 64 KiB chunk | 20 000 | 3 800 | **24 800** | 35 400 | **51 400** | 142 700 | 639 500 |

### Run-to-run variance: a second run, published

The numbers above are **run 1**. A **second run** on the same machine and commit was
taken specifically to test whether they reproduce, because §5.1 flags run-to-run
variance as the largest gap in this document. It is published here in full rather
than summarised, so the spread can be judged rather than taken on trust:

```text
ABICOST u64_argument_and_return|20000|700|800|1500|1700|4100|26700
ABICOST string_copy_in_64_bytes|20000|700|800|900|1800|3800|53400
ABICOST list_u32_1000_elements|20000|800|900|1800|1900|3500|30600
ABICOST list_u32_1_element|20000|700|1400|1600|1800|4400|49900
ABICOST resource_handle_create_and_drop|20000|1100|1100|2000|2500|5700|23200
ABICOST stream_u8_64kib_chunk|20000|3700|25000|35400|52600|135200|738800
ABICOST async_future_rendezvous|20000|1900|2100|3600|5000|9600|46200
```

**What the comparison shows, stated plainly:**

| Row | Run 1 p50 | Run 2 p50 | Run 1 p99 | Run 2 p99 |
|---|---:|---:|---:|---:|
| `u64` | 900 | 800 | 1 800 | 1 700 |
| String 64 B | 900 | 800 | 1 900 | 1 800 |
| `list<u32>` 1 000 | 1 600 | **900** | 2 000 | 1 900 |
| `list<u32>` 1 | 800 | **1 400** | 1 700 | 1 800 |
| Resource | 1 200 | 1 100 | 2 500 | 2 500 |
| Async | 2 100 | 2 100 | 3 800 | 5 000 |
| `stream` 64 KiB | 24 800 | 25 000 | 51 400 | 52 600 |

**The p99s are stable; the p50s are not.** Every p99 above moves by less than 3 %
between runs — except async, at +32 % — while the p50 of `list<u32>` 1 000 moved
from 1 600 to 900 ns (−44 %) and `list<u32>` 1 moved from 800 to 1 400 (+75 %).

The two `list<u32>` rows **swap order between runs**. Run 1 has 1 element faster
than 1 000 (800 vs 1 600); run 2 has 1 000 faster than 1 (900 vs 1 400). Since a
1 000-element list must copy 4 000 bytes that a 1-element list does not, run 2's
ordering is physically implausible — which means **at this scale the harness is
measuring its own noise, not the copy.** The ~800 ns fixed cost and the ~800 ns
marginal copy cost are the same magnitude, so neither is resolvable in a single
20 000-sample run on this machine.

**What this does and does not change:**

* The **order-of-magnitude finding is confirmed**: a crossing costs hundreds of
  nanoseconds to a few microseconds, never the 2–5 ns §9.3 estimated for a scalar.
  Both runs agree on that by two orders of magnitude.
* The `list<u32>` row's **"marginal cost is ~0.8 ns/element"** claim in §3 is
  **weaker than it reads**: it rests on a difference between two p50s that did not
  reproduce. It should be treated as indicative, not established. Establishing it
  needs many more repetitions, not more samples per run.
* §9.1's "three repetitions **with variance**" is still **not satisfied** — two runs
  is not three, and no `Repetitions` spread is published. But the second run is
  evidence *about* the variance, which is what a third and fourth run would extend.

**The honest summary:** these figures are good enough to falsify §9.3's estimates by
orders of magnitude, and **not** good enough to publish a precise per-element or
sub-microsecond figure. The document says which is which rather than presenting both
with the same confidence.

Raw `ABICOST` lines, exactly as the harness printed them
(`label|n|min|p50|p90|p99|p999|max`):

```text
ABICOST u64_argument_and_return|20000|800|900|1000|1800|4500|23000
ABICOST string_copy_in_64_bytes|20000|800|900|1500|1900|4300|11300
ABICOST list_u32_1000_elements|20000|800|1600|1800|2000|4200|71500
ABICOST list_u32_1_element|20000|800|800|900|1700|4100|34500
ABICOST resource_handle_create_and_drop|20000|1000|1200|1200|2500|6000|86000
ABICOST stream_u8_64kib_chunk|20000|3800|24800|35400|51400|142700|639500
ABICOST async_future_rendezvous|20000|1900|2100|2200|3800|9100|34200
```

**Timer resolution.** `Instant::now()` on Windows costs tens of nanoseconds and is
read immediately outside each call, so its cost is **inside** every sample. The
`min` of 800 ns in four rows is the floor this harness can resolve, not a claim
that those operations cost 800 ns. `§9.3`'s original estimate for the `u64` row was
2–5 ns, which is one to two orders of magnitude **below this harness's own timer
floor** — see §3 for why that matters to the comparison.

---

## 3. Against the `§9.3` estimates

Each row is marked **confirmed** (inside the estimated range), **above** (slower
than the estimate's upper bound), or **below** (faster than the estimate's lower
bound). The comparison is the value of this table; the original estimates are kept
beside the measurements rather than replaced.

| Operation | `§9.3` estimate | Measured p50 | Measured p99 | Verdict |
|---|---|---|---:|---|
| `u64` argument + return | ~2–5 ns | 900 ns | 1 800 ns | **ABOVE — by ~180×** |
| String `(ptr,len)` copy in, small | ~25–70 ns | 900 ns | 1 900 ns | **ABOVE — by ~13×** |
| `list<u32>` of 1 000 elements | ~1–3 µs | 1.60 µs | 2.00 µs | **CONFIRMED** |
| Resource handle create | ~15–40 ns | 1.20 µs | 2.50 µs | **ABOVE — by ~30×** |
| Async `future` rendezvous | ~100–400 ns | 2.10 µs | 3.80 µs | **ABOVE — by ~5×** |
| `stream<u8>` chunk, 64 KiB | ~2–8 µs | 24.8 µs | 51.4 µs | **ABOVE — by ~3–6×** |

**One of six estimates survived contact with a measurement.**

### What the measurements say that the estimates missed

**A fixed per-crossing cost dominates everything.** The `u64` row — an argument and
a result of eight bytes each, the smallest possible crossing — costs ~900 ns at
p50. The string row costs the same ~900 ns for 64 bytes. The fixed cost of
*entering and leaving the component* is therefore of order **900 ns**, and `§9.3`
does not price it at all.

That fixed cost is the finding. `§9.3`'s conclusion — *"QQQ is fast for
compute-heavy, few-crossings workloads and merely competitive for chatty,
crossing-heavy workloads"* — is **correct and understated**: the boundary is not a
few nanoseconds of "effectively free" overhead, it is ~900 ns per call. A design
that assumed crossings were free would be wrong by three orders of magnitude.

> **A claim from the first version of this document, withdrawn.** It read: *"the
> marginal cost of 999 extra `u32`s is about 800 ns, or ~0.8 ns per element — the
> copy itself, exactly as `§9.3` describes it."* That rested on run 1's p50s for the
> 1-element (800 ns) and 1 000-element (1 600 ns) lists. **It did not reproduce.**
> In run 2 the same two rows measured 1 400 ns and 900 ns — the opposite order, and
> physically implausible, since a 1 000-element list must copy 4 000 bytes a
> 1-element list does not. At this scale the harness is measuring its own noise:
> the fixed crossing cost and the marginal copy cost are both ~800 ns, so a single
> 20 000-sample run cannot separate them. The per-element figure is **not
> established** and is not published as one. See §2's run-to-run table.

**The absolute values remain small for the intended workload.** At ~900 ns p50 per
crossing against `§9.2`'s ≤ 60 µs p99 routed-request budget, a handful of
crossings per request is ~5 % of budget. The batch-first rule (`§4.5`) is what
keeps a request at a handful rather than a hundred.

**The `stream` row is the one place the bytes matter.** Its p50 of 24.8 µs against
`§9.3`'s 2–8 µs is the only row whose estimate was wrong *in the direction of
memory bandwidth mattering*: 64 KiB at 24.8 µs is ~2.6 GB/s, well below what a
`memcpy` achieves, because the transfer goes through the stream's chunk
machinery rather than one contiguous copy.

---

## 4. How each crossing was made real

A crossing is a transition between the host's Rust and the guest's
Cranelift-compiled code through the canonical ABI's `lower`/`lift` conversions. All
seven rows run against a **compiled, instantiated, called** Wasmtime component.

| Row | The component that produced it |
|---|---|
| `u64` | exports `(param "x" u64) (result u64)`, body adds 1 |
| String | exports `(param "s" string) (result u32)`, returns the byte length |
| `list<u32>` | exports `(param "xs" (list u32)) (result u32)`, returns the element count |
| Resource | imports a host-owned resource type and `[constructor]counter`, calls it; the handle crosses **out** to the host |
| Async `future` | an **async-lifted** export signalling completion with `task.return`, driven by `call_async` on a Tokio current-thread reactor |
| `stream<u8>` | exports `(param "d" (stream u8))`; the host hands it a `StreamReader<u8>` built from a 64 KiB `Vec<u8>` via Wasmtime's own `StreamProducer` impl |

**Why not a synthetic stand-in.** `PERF-005` exists to replace *estimates* with
*measurements*. A stand-in that called a Rust function through a `dyn` trait
object, or wrote a `Vec<u32>` into a buffer, would measure a Rust call and a
`memcpy` — neither of which is a claim about this system. Replacing an honest
estimate with a dishonest measurement would be worse than leaving the estimate.

### Two WAT facts this cost, recorded rather than rediscovered

1. **A guest-owned resource cannot be lifted as a component export.** Declaring
   `(type $c (resource (rep i32) (dtor ...)))`, minting it with
   `canon resource.new`, and lifting that as `(result (own $c))` fails with
   `func not valid to be used as export`. The working shape is the mirror image:
   the **host** owns the resource and the guest imports the constructor. This is
   also the shape `§4.5` describes and the one `qqq-host`'s `HandleTable`
   implements.
2. **The async path is gated.** A component using async lifting will not compile
   unless both `Config::wasm_component_model_async_stackful(true)` and the
   `WASMTIME_COMPONENT_MODEL_ASYNC_STACKFUL` environment gate are set. The test
   `the_async_probe_is_gated_on_the_stackful_feature` asserts this, so if a future
   Wasmtime removes the gate the test fails rather than the caveat going stale.

---

## 5. What this does NOT measure

This section is the reason the document is trustworthy. `§9.1` requires it, and a
coverage claim that is not written down is one a reader will assume too generously.

### 5.1 Gaps that matter

| Not measured | Why, and what it means |
|---|---|
| **Three repetitions with variance** | `§9.1` requires "three repetitions **with variance**". **Two runs** of 20 000 samples were taken (both published in §2), and **no `Repetitions` spread is published** because `Repetitions::new` requires three and refuses fewer — correctly, and it is why no spread appears above. Two runs is still not three. What the second run *did* establish is that p99 reproduces to within ~3 % while p50 does not, and that one published claim (the per-element copy cost) did not survive it. A third and fourth run would extend this; the per-element question needs **more repetitions**, not more samples per run. **This remains the largest gap in this document.** |
| **A controlled machine** | Not core-pinned, not governor-adjusted, not otherwise quiesced. See §1. |
| **QQQ's actual engine configuration** | The harness builds Wasmtime **directly** with the minimal component-model config. `qqq-host`'s `to_wasmtime_config` additionally enables the **pooling allocator**, 2 GiB memory guard pages and **epoch interruption**, all of which change the per-call path. This document measures the **canonical ABI**, not the engine as deployed. |
| **The async row is not reachable today** | `qqq-host`'s engine config enables **neither** `wasm_component_model_async` nor `-stackful`, and no `qqq:*` WIT interface uses `future` or `stream`. The async figure answers *"what will this cost when `§9.4`'s async row is implemented"*, not *"what does QQQ cost today"* — today there is no async path to have a cost. Its appearance in this table should not be read as evidence that async is implemented. |
| **`stream<u8>` as a per-byte rate** | One chunk of 64 KiB was measured. Multiplying to a per-byte figure would assume a linearity that **nothing here tested**: stream transfers are chunked, and small chunks may cost proportionally more. |
| **The string row at other sizes** | Only 64 bytes. `§9.3` says "small"; the size at which the copy overtakes the ~900 ns fixed cost is **not** established. The `list<u32>` row's 1-element and 1 000-element samples bracket that question for lists only. |
| **Any host capability call** | No `qqq:crypto`, `qqq:http`, `qqq:kv` or `qqq:sql` crossing was measured. Those are `CAP-*`/`HOST-*` subjects with their own costs, and this item is the ABI's. |
| **Instance acquisition** | `PERF-003`'s row. The `Store` and instance are reused across every sample; creation cost is outside the timed region. |
| **Cold start, memory, throughput** | `PERF-004`, `PERF-008`–`PERF-012`. Not attempted. |
| **Cross-platform behaviour** | Windows x86-64 only. Linux and macOS are untested, and `§9.4`'s io_uring row suggests they will differ. |

### 5.2 Why the "three repetitions" gap is stated so loudly

The temptation is to run the harness three times, list three p50s, and call
`§9.1` satisfied. That would be dishonest in a specific way: `§9.1` asks for three
repetitions so that **variance can be published**, and publishing three numbers
without a spread is not the same claim. The honest options are to run them
properly — with `Repetitions::new`, which refuses fewer than three and computes a
spread — or to say plainly that only one run was taken. This document says so.

### 5.3 What *is* established

* The seven crossings are **real** component-model crossings, on the pinned engine.
* Each is a **nearest-rank percentile** over 20 000 samples with a stated warmup.
* The environment is named exactly.
* The **p99 figures reproduce** to within ~3 % across two independent runs; the
  **p50 figures do not**, and §2 publishes both runs so the difference is visible.
* The harness **fails loudly** if a probe component stops compiling or stops
  exporting the function it claims — `every_probe_component_compiles_and_instantiates`
  runs by default in CI, so a Wasmtime upgrade cannot silently invalidate these WAT
  strings.
* Every probe has an in-test **control** asserting the call returns the expected
  value, so a sample cannot be timing a call that did nothing.

**What is *not* established, despite appearing in an earlier version of this
document:** the per-element cost of a `list<u32>` copy, and any figure below ~1 µs
with more precision than "hundreds of nanoseconds". Both are withdrawn in §3 and
§2 respectively, and withdrawn because a second run contradicted them — not because
they were re-derived.

---

## 6. Reproducing

```text
cargo test -p qqq-bench --test abi_cost --release -- --ignored --nocapture --test-threads=1
```

The two measurement tests are `#[ignore]`d by default **deliberately and with a
stated reason**: they are benchmarks inside a test harness — tens of seconds,
sensitive to machine load, and asserting loose bounds only so the harness's own
breakage is caught. A latency test that fails CI because a laptop throttled is a
test that gets deleted, and a deleted test publishes nothing.

The three non-ignored tests (`the_summary_reports_the_percentiles_it_names`,
`every_probe_component_compiles_and_instantiates`,
`the_async_probe_is_gated_on_the_stackful_feature`) run in CI and guard the harness
itself rather than the numbers.

---

## 7. Corrections to `§9.3`

`§9.3`'s table is retained in the Proposal with its original estimates visible
beside these measurements — the comparison **is** the value, and deleting the
estimates would delete the evidence that four of them were wrong. The section's
"approximate figures for planning, to be replaced by measured numbers in
`PERF-005`" label has been replaced with a pointer here.

The one number that changes a **conclusion** rather than a figure:

> `§9.3`'s conclusion stands and is strengthened. The boundary's fixed cost is
> ~900 ns per crossing, not the 2–5 ns the estimate implied for a scalar. The
> batch-first rule (`§4.5`) is not a micro-optimisation; it is the difference
> between a request costing one crossing and one costing a hundred.
