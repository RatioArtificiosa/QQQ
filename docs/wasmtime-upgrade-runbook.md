# Wasmtime upgrade runbook — `HOST-020`

**Status:** active. **Owner:** maintainers (see `GOVERNANCE.md`).
**Cadence:** a scheduled sprint once per quarter, plus an out-of-band run for any
security advisory (that path is `docs/wasmtime-advisory-process.md`, which has a
72-hour clock; this one does not).

---

## 1. What this covers, and what it does not

Wasmtime is pinned to **48.x** (`§D-003`, and `A-3` in the Reconciliation
appendix). The advisory process answers *"a CVE landed, how fast can we ship the
fix"*. This runbook answers a different and much more common question:

> **"Upstream released a new version and nothing is broken — how do we take it
> without discovering three weeks later that something quietly changed?"**

The distinction matters because the dangerous upgrades are the ones that **pass**.
A Wasmtime upgrade that breaks the build is a good day: the compiler found the
problem for free. The upgrades worth writing a runbook for are the ones where
`cargo build`, `cargo test` and every existing test go green while a behaviour QQQ
depends on has moved underneath it.

Three such behaviours are known, and each has a mechanism below:

| Behaviour | How it can change silently | Mechanism that catches it |
|---|---|---|
| **Trap classification** | `classify_trap` matches substrings of Wasmtime's error messages. A reword drops a trap to its default code, so a dashboard counting `QQQ-3003` timeouts starts counting generic traps | `crates/qqq-host/tests/compatibility.rs` |
| **AOT cache validity** | A `.cwasm` is native code. New Cranelift codegen makes an old cache entry wrong rather than merely stale | `aot_cache_key` folds in `ENGINE_VERSION` |
| **Engine identity** | `ENGINE_VERSION` is hand-maintained because Wasmtime exports no version constant | two anti-drift tests in `qqq-host::config` |

---

## 2. The steps

Each step names its **evidence**: the command, and what a failure looks like.

| # | Step | Command | A failure looks like |
|---|---|---|---|
| 1 | **Read the changelog first.** Upstream's notes name API changes; they do *not* reliably name message changes, which is why steps 4–6 exist | upstream changelog for the target version | — |
| 2 | **Bump both pinned dependencies together.** `wasmtime` and `wasmtime-wasi` are released in lockstep and link the same component model | edit `[workspace.dependencies]` | A build error about two component-model versions, or worse: a *silent* ABI mismatch |
| 3 | **Move `ENGINE_VERSION`.** It is hand-maintained, and the lockfile test fails on purpose until it matches | edit `crates/qqq-host/src/config.rs` | `engine_version_matches_the_resolved_lockfile` fails, naming both versions |
| 4 | **Run the compatibility suite.** This is the step that catches a reword | `cargo test -p qqq-host --test compatibility` | A row fails with the **actual** message, the key list it expected, and which file to update |
| 5 | **Run the hostile-guest suite and the fuzz corpus.** An upgrade changes trap behaviour under adversarial input too | `cargo test -p qqq-host --test hostile_guests` | A case that used to trap no longer traps, or traps differently |
| 6 | **Run the full gate**, as one sequence, with no edit after it | the gate script | Any of fmt / clippy / workspace tests / guest tests |
| 7 | **Regenerate any AOT fixtures**, if a fixture pins a `.cwasm` digest | the AOT tests | A digest mismatch naming the cache key |
| 8 | **Run the benchmarks and compare against `§9.2`.** Codegen changes move numbers | `qqqai bench --json` | A budget row that was met and now is not |
| 9 | **Read the CI run.** A local gate is necessary and not sufficient | `gh run list --limit 1`, then `gh run view <id>` | A job that fails only on macOS or only in Docker |
| 10 | **Record the upgrade** in `QQQ-Observations-and-Memories.md`, with the run id | — | — |

### Why step 4 is the centre of this runbook

`classify_trap` (`crates/qqq-host/src/trap.rs`) maps a trap to a stable `QQQ-XXXX`
code by matching **substrings of Wasmtime's own error text**:

```text
if d.contains("trap: interrupt") { return ErrorCode::EpochDeadlineExceeded; }
```

The epoch case is the sharpest one: Wasmtime's epoch message is a bare `interrupt`
that does not contain the word "epoch", so there is no domain word to anchor on
and a reword is a single-word change.

Nothing in the build notices. The unit tests for `classify_trap` all feed it
**hand-written** strings, so they prove the classifier works on the strings we
*believe* upstream emits — they cannot detect the belief being wrong. And
`tests/engine.rs` asserts a disjunction of known wordings
(`contains("fuel") || contains("all fuel")`), which was written to survive a reword
and therefore cannot detect one.

The compatibility suite closes that gap by trapping real components on a real
engine, taking the **actual** message, and asserting both that `classify_trap` maps
it to the documented code *and* that the message still contains the substring the
classifier keys on. The second assertion is the load-bearing one: it fails with the
vanished key named, instead of falling through to a default nobody sees.

---

## 3. What is verified, and how

A runbook is worth what its checks are worth. Each of these is a real mechanism,
not an intention:

| Claim | Mechanism | Where |
|---|---|---|
| A reworded trap message fails the build | `compatibility.rs`, fault-injected by changing `classify_trap`'s key and confirming exactly one row fails | `crates/qqq-host/tests/compatibility.rs` |
| The engine version cannot drift silently | `engine_version_matches_the_pinned_dependency`, `engine_version_matches_the_resolved_lockfile` | `crates/qqq-host/src/config.rs` |
| An old AOT cache is not reused after an upgrade | `ENGINE_VERSION` is folded into `aot_cache_key` | `crates/qqq-host/src/config.rs` |
| A new engine is checked against real hostile guests | 200-case hostile-guest suite | `crates/qqq-host/tests/hostile_guests.rs` |
| A new engine is checked against the corpus | regression corpus in every build | `crates/*/tests/fuzz_corpus.rs` |
| The pinned version is recorded | `Cargo.lock` in the repository | root |

### The compatibility suite's own limits, stated

* **It covers five failure modes**, not every trap Wasmtime can produce. A trap
  QQQ never provokes is not covered, and the file does not pretend otherwise.
* **A `memory.grow` refusal is not a trap.** It returns -1 inside the guest, so
  that row asserts the classification of a limit message against a synthetic
  string rather than trapping a real engine. Recorded here because "the row
  passes" could otherwise be read as "a real engine was trapped".
* **Rows are pinned to one engine's wording.** That is the point — but it means a
  failure here is a *finding about upstream*, not a QQQ bug. Read the actual
  message in the failure output before changing anything.

---

## 4. Rollback

The upgrade is a two-file change (`[workspace.dependencies]` plus
`crates/qqq-host/src/config.rs`, with `Cargo.lock` regenerated), so rollback is a
`git revert` of one commit, followed by the gate.

**Nothing needs clearing by hand — and the honest reason is thinner than "the
cache is keyed correctly".** Two separate facts, checked rather than assumed:

* `aot_cache_key` *does* fold `ENGINE_VERSION` in (`h.update(ENGINE_VERSION
  .as_bytes())` in `crates/qqq-host/src/config.rs`), so an entry compiled by one
  engine version can never be mistaken for another's. That part is real.
* **There is no AOT cache on disk yet.** The only caller of `aot_cache_key` is
  `crates/qqq-host/src/preload.rs`, which computes the key for a report; no crate
  stores a `.cwasm`, reads one back, or looks one up. So nothing *can* be stale
  across a revert, because nothing is persisted.

The second point is the one to re-read when the cache lands. Once a store keyed on
`aot_cache_key` exists, this section gains a real step — the old entries remain on
disk, harmless but dead weight — and a revert should say so rather than leave an
operator wondering. Written down now so the sentence does not quietly become
false later: **the key design is what will make the cache safe; the cache itself
is not built.**

---

*Implements Checklist `HOST-020`. Relates to `R-03` (Wasmtime API instability),
`§D-003` (the pin), and `docs/wasmtime-advisory-process.md` (the CVE path).*
