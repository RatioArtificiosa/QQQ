# qqq-bench

**The QQQ benchmark harness: `§9.1`'s methodology as a type, `§9.2`'s budgets as data.**

Implements `PERF-001`, and provides the foundation for `PERF-002`, `PERF-005`,
`PERF-020` and `PERF-022`.

---

## Why this crate exists

`§9.1` ends with a sentence that decides the design:

> **Methodology requirements** (published with every result): pinned hardware listed
> by model; pinned OS and kernel; pinned toolchain versions; warmup procedure stated;
> percentiles, not averages; concurrency levels disclosed; three repetitions with
> variance; the benchmark harness itself open source; and a "what this does not
> measure" section. **A benchmark without these is marketing, and we should not
> publish it.**

Three words in that paragraph are load-bearing, and each rules out an easier
implementation:

| The words | What they rule out |
|---|---|
| "published with **every result**" | a methodology *page*. The fifth report can omit its warmup and the page still exists. So the elements are fields of the **result**. |
| "percentiles, **not averages**" | a `mean()`. A prohibition is honoured by the forbidden thing not existing. |
| "we should **not publish it**" | a warning, or a lint, or a `validate()`. The consequence is refusal, so the type must be unconstructible without the elements. |

## What is in the box

| Module | What it holds |
|---|---|
| `methodology` | `Methodology`, `Environment`, `Warmup`, `Concurrency`, `NonClaims`, `BenchmarkName`, `Pinning` — the nine elements, each required. |
| `stats` | `Distribution` (exact percentiles, **no mean**) and `Repetitions` (three-plus, with spread). |
| `budget` | `Budget::ALL` — the `§9.2` table as data — plus `Verdict`, `Direction` and the comparison that refuses a unit mismatch. |

## The three prohibitions, and how each is enforced by absence

```rust
// §9.1: "three repetitions with variance"
let too_few = Methodology::new(env, warmup, concurrency, 2, non_claims, HARNESS_SOURCE);
assert!(too_few.is_err());   // TooFewRepetitions { given: 2, required: 3 }

// §9.1: "percentiles, not averages" -- there is no mean to call
let d = Distribution::from_samples(&[100, 100, 100, 10_000]);
assert_eq!(d.p50(), Some(100));   // the median is unmoved by the tail
// d.mean()  -- does not exist

// §9.1: a "what this does not measure" section
let empty = NonClaims::qualified(Vec::<String>::new());
assert!(empty.is_err());   // an empty disclaimer states nothing
```

## The `db` caveat, made structural

`§O-155` records that the `db` workload measures a validated write and an in-guest
map lookup — **not** a Postgres round trip — because the host has no `qqq:sql`
implementation and `§4.2` creates one store per request.

That fact was recorded in prose. `§9.1`'s ninth requirement *is* "what this does
not measure", so the honest place for it is a **required field**: a `db` result
that omits the disclaimer does not compile. A caveat that survives as a compile
error cannot be lost by a reader who never opened the observation.

## Why the budget table is code

`§9.2` says each row "has a measurement method in `bench/`". That is a claim about
a mapping from twelve named targets to twelve named methods, and a mapping is data.
Written as a Markdown table it drifts silently; written as `Budget::ALL` it cannot,
because `tools/check_bench_contract.py` compares the two in CI and a test fails
when they disagree.

The **direction** of each comparison is a property of the row, not of the call
site. Half of `§9.2` is ceilings (`≤ 100 µs`) and half is floors (`≥ 60k RPS`),
and a comparison written the wrong way round makes a failing benchmark report
success while looking identical in review.

## What this crate is *not*

`PERF-001` is the harness. It is **not** the ten workloads — that is `PERF-002` —
and it is **not** any `§9.2` budget, which are `PERF-003`–`PERF-013`.

The distinction is load-bearing rather than bureaucratic. A budget item is met by a
harness that produces the number and a recorded comparison against the target,
never by asserting the target is achievable. Writing a number into the checklist
before something produced it would be the first fabricated measurement in a
document whose entire value is that its numbers came from commands.

## Testing

Every test here was fault-injected before being trusted: the defect was
reintroduced, the test observed to fail, and the file restored byte-for-byte. Tests
include controls — `a_complete_environment_is_accepted` exists so that the seven
refusal tests cannot all pass because the constructor rejects everything.

## Licence

Apache-2.0. See `LICENSE`.
