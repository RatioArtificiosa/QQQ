# Determinism

**Determinism is a product feature here, not a testing convenience.** `§D-007` records that as a
decision, and Proposal §10.5 states the claim it buys:

> With `[determinism] enabled = true`, executing the same component with the same inputs produces a
> bit-identical result, and the execution is recorded in a replay log sufficient to reproduce it
> exactly — including any failure.

This page is the honest account of what that costs, what it covers, and **where it stops**. It serves
`DET-010` (the limits) and `DET-014` (the use-cases and non-use-cases), which are the same page.

---

## 1. What is controlled, and what state each control is in

§10.5 states nine sources of nondeterminism and a control for each. **The table below is that table with
the tree's state beside it**, measured at `390ee8f`:

| # | source | control | state |
|---|---|---|---|
| 1 | Wall clock | `qqq:clock.wall` returns `determinism.fixed_clock`, advancing only by explicit host ticks | **partial** — `AmbientState` freezes it; `tick()` is called from tests only |
| 2 | Monotonic clock | virtualised; advances deterministically with fuel or explicit ticks | **partial** — same mechanism, same limit |
| 3 | Randomness | a seeded generator (`determinism.seed`) | **built** — `AmbientState::random_bytes`, `splitmix64` |
| 4 | Async scheduling | a deterministic scheduler: same poll order, same interleavings, single-threaded executor | **absent** — `DET-004` |
| 5 | Float behaviour | `cranelift_nan_canonicalization` on; relaxed-SIMD fusion disabled | **built** — `EngineConfig::deterministic` |
| 6 | HashMap iteration order | banned in host interfaces; ordered maps only | **built** — no `HashMap` in `qqq-host`'s source |
| 7 | Network timing | recorded and replayed from the replay log | **absent** — `DET-007`/`008`/`011` |
| 8 | Compilation | AOT artifact pinned by digest; same compiler version required | **built** — `aot_cache_key` over four inputs |
| 9 | Threads | deterministic mode is single-threaded; shared memory forbidden | **absent** — `DET-012`, behind `ARCH-014` |

**Four built, two partial, three absent.** The page says so rather than implying the feature is finished,
because a determinism guarantee with three holes is not a guarantee — and a reader who discovers that
from a failed reproduction has learned it the expensive way.

**Those three numbers are an assessment, not a count, and the difference matters here.** Every other
figure in this repository sits behind a `check_doc_claims.py` resolver, which is a *mechanical* way of
counting something real. These do not, and should not: "built" means a person read the source and judged
that the control is in place, and a resolver would have to encode that judgement. **So each row carries
the file it was read from instead**, and §6 gives the command for each — which is the honest form for a
claim that is not mechanical.

---

## 2. The honest limits

§10.5 states them and they are the four things this section would otherwise have to invent:

> determinism holds for a given (**artifact digest, engine version, target triple, config**). It does not
> survive a Wasmtime upgrade that changes codegen in an observable way, and it cannot serialise true
> external I/O without recording it.

**Each is a thing a user can check before trusting a reproduction:**

| limit | what it means | how to check |
|---|---|---|
| **artifact digest** | a different build of the same source can differ | the lockfile records it; the replay header names it |
| **engine version** | a codegen change invalidates a reproduction | `qqqai --version`; the replay header names it |
| **target triple** | native code is not portable | the replay header names it |
| **config** | `--deterministic` on and off are different runs | the replay header carries `deterministic` as a fifth field |
| **external I/O** | a real network or clock read outside the recorded set cannot be replayed | `--replay` fails rather than silently diverging |

**And one discrepancy between this document's source and the implementation, recorded rather than
smoothed over.** §10.5 calls the deterministic generator *"a seeded CSPRNG (ChaCha20 with
`determinism.seed`)"*. The implementation is `splitmix64`, and its own comment says why:

```rust
// splitmix64: deterministic, architecture-independent, and good
// enough for test reproducibility (it is explicitly NOT a CSPRNG,
// and is never used outside deterministic mode).
```

**In normal mode the guest gets the OS source** (`getrandom::fill`), and a failure there is surfaced
rather than substituted — *"because falling back to a weaker source would be worse than failing."*
**So the weak generator is reachable only when determinism is on and the seed is public.** Either §10.5
should say `splitmix64` and stop calling it a CSPRNG, or the implementation should change; the item that
would decide it (`DET-003`) is open.

---

## 3. Use cases

§10.5 names four, and the last is the commercial one:

- **Deterministic replay debugging.** A failure reproduces from a log rather than from a description.
- **Reliable property-based testing.** A counterexample is a value you can hand to someone.
- **Reproducible benchmarks.** Two runs differ because the code changed, not because the machine did.
- **Auditable AI agent actions** — *"you can replay exactly what an autonomous system did."* This is the
  one a compliance reader cares about, and it is why the log is hash-chained rather than appended.

---

## 4. Non-use cases

**A page that lists only use cases is a page that oversells.** Determinism is the wrong tool for:

- **Security.** A seeded generator is reproducible *by design*, so it is not a source of secrets. The
  guest-facing `random.get` uses the OS source unless determinism is on.
- **Performance-sensitive production traffic.** Deterministic mode disables relaxed SIMD and canonicalises
  NaNs. **That is a deliberate cost**, and `DET-016` exists to publish it.
- **Anything that must observe real time.** A guest that measures elapsed wall-clock time will read zero,
  because the clock advances only on an explicit tick and **nothing in the production path calls `tick()`**.
  A component whose logic depends on real elapsed time cannot be both deterministic and correct.
- **Cross-version reproduction.** See §2: an engine upgrade that changes codegen ends it.
- **Reproducing across machines with different targets.** The target triple is in the header for a reason.

---

## 5. The replay log

**Implemented for the synchronous CLI path.** `DET-007` is the format and
`DET-008` is `--replay`; the runtime records and verifies the log before it is
attached to an execution. Asynchronous deterministic execution is deliberately
refused until `DET-004` provides a deterministic scheduler (`QQQ-6008`).

- **A header of four fields** — artifact digest, engine version, target triple, `deterministic` — because
  a log that omits any of them cannot tell a reader whether the replay is valid.
- **Hash-chained records** of `(sequence, function, value)`, with every field length-prefixed before
  hashing so the encoding is injective.
- **`recorded` / `refused` counters**, so a gap is a **value** rather than a silence.
- **A closed set of function names**, so a replay file — which is attacker-supplied by construction —
  cannot make the reader intern an arbitrary string.
- **Header identity is enforced before consumption**: artifact digest, engine
  version, target triple, and deterministic setting must match the current run.

**`--replay` fails when the log runs out before the execution does.** A truncated log that silently
replays a shorter run is the one outcome the whole mechanism exists to prevent.

---

## 6. Reproducing this page

| claim | command |
|---|---|
| the control states in §1 | `rg -n 'wasm_threads\|relaxed_simd\|nan_canonical' crates/qqq-host/src/config.rs` |
| `splitmix64`, and its comment | `rg -n -A4 'if self.deterministic' crates/qqq-host/src/ambient.rs` |
| no `HashMap` in the host | `rg -c 'HashMap' crates/qqq-host/src/` |
| the AOT cache key's four inputs | `sed -n '354,398p' crates/qqq-host/src/config.rs` |
| the replay log's types | `sed -n '1,120p' crates/qqq-host/src/replay.rs` |
