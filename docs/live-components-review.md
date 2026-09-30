# Independent review of the hot-swap/AOT and Phase 3 delivery

**Verdict: MERGE — it is already merged, and this records why that was justified.**

Reviewer: the local agent, at the request of `LOCAL-AGENT-PROMPT.md`. Delivery revision
`ddeae943d32437463559f7c027ac4e57c968a1d0`, baseline `d12ad758d35e807e28ce178f4bb2df28b946d174`, branch
`coderabbit/evaluate-hot-swappable-wasm/bb675d22`, **`remote_pr_created: false`** — nothing was pushed
anywhere, and the delivery arrived as a bundle, a patch and a source archive.

**This is the fourth document of its kind and it does not repeat the other three.** `README.md` is the
delivery's scope, `CHANGE-MAP.md` its file map, `VALIDATION.md` its own running log and `REVIEW.md` its review
history. This one is the **independent** review, and its job is the part none of those can do: **what a
different reviewer, on a different machine, found when it ran the commands itself.**

## Findings first

**No finding blocked the merge.** Five findings were raised against the merged result — **all in the receiving
repository's own code, none in the delivery's** — and all five are fixed.

| # | severity | where | finding | state |
|---|---|---|---|---|
| 1 | **Major** | `crates/qqq-run/src/test.rs:564` | after `run_once` stopped going through `cargo test`, it kept `.arg("--")` — **Cargo's separator, which libtest does not use** | fixed `9cd2812` |
| 2 | minor | `test.rs` `isolation_dir` | printed *"tests will run in the project directory instead"* and **returned the unusable path anyway** | fixed `9cd2812` |
| 3 | minor | `src/flaky.rs` `read_history` | `let Ok(text) = … else { return Ok(Vec::new()) }` **swallowed every error**, so a permission failure read as an empty history | fixed `9cd2812` |
| 4 | minor | `QQQ-Checklist-V1.md` `TEST-014` | the note said *"nothing in this repository writes one yet"* — **false**; `record_run` does, and no caller passes `--history` by default | fixed `9cd2812` |
| 5 | minor | `QQQ-Checklist-V1.md` `TEST-012` | the tick presented an **off-by-default** guarantee as met | fixed `9cd2812` |

**Three of the five are shapes this repository already names.** Finding 1 is a comment and a code that
disagree (`§O-439`); finding 3 is a failure that looks like success (`§O-375`); findings 4 and 5 are claims
that outrun their code. **The asymmetry is the measurement: `REVIEW.md` documents six passes over the
delivery's changes, and this review found five things in the other half — because a review is scoped to a
range, and a range's edges are where the findings are** (`§O-453`).

## What was measured, with the commands

### The merge

```
git bundle verify …/qqq-live-components.bundle    -> contains ddeae943, requires d12ad758, sha1
git fetch <bundle> …:refs/heads/review/qqq-phase3  -> [new branch]; main untouched
git merge-tree --write-tree main review/qqq-phase3 -> FIVE conflicts
```

**Two additive, three derived.** `lib.rs` — both sides added a `pub mod` (`flaky` ours, `generations`
theirs), **both kept**. The observations — both appended at the end and **both reached for `§O-439`**.
`tools/backlog.json` had **486 hunks**, `docs/stability.md` said 250 against 259, `docs/unsafe-audit.md` 173
against 176 — **a derived file has no correct merge; it is a third number afterwards**, so the three took
ours and were regenerated (`§O-442`…`§O-447`).

**`crates/qqq-run/src/main.rs` AUTO-MERGED** even though both sides added flags, and `QQQ-Checklist-V1.md`,
`QQQ-Proposal-V1.md`, `llms.txt`, both gates and `tools/gen_llms_txt.py` all merged cleanly, because our ten
commits touched `TEST-`/`PLAN-`/`POS-` and theirs touched the `LANG-` section.

### `source/` against the merged tree

```
IN source/ BUT NOT IN THE MERGED TREE: 0
IN THE MERGED TREE BUT NOT source/:    49   (six non-pycache, all explained)
```

**`0` is the number that matters.** And the delivery shipped something stronger than a file list —
**`TESTED-INPUTS.json`, a 428-entry `path -> sha256` manifest**:

```
IDENTICAL : 411
DIFFERENT : 17
ABSENT    : 0
```

**The 17 are all ours, except one.** `tools/bootstrap.ps1` is **271 CRLF / 0 bare LF** in `source/` and
**0 CRLF / 271 bare LF** here — **`source/` is a Windows working-tree export from a zip, not a git export**,
which is what `normalize_eol.py` exists to catch, and its `--check` passes on the merged tree (`§O-456`).

### The gate, with the commands as written

```
cargo fmt --all                                                          -> 0
cargo clippy --workspace --all-targets --all-features -- -D warnings     -> 0
cargo test --workspace --all-features                                    -> WORKSPACE=0 · 71 binaries · 0 FAILED
cargo test -p qqq-run --test live_components                             -> 8 passed, 0 failed
python .scratch/run_ci_checkers.py                                       -> 131 reproduced · 73 OK · 0 FAIL · 24 NOT RUN
tools/fault_inject_live_components.py                                    -> PASS 4/4, and its --self-test PASSED
tools/check_live_dev.py · tools/check_language_parity.py                 -> PASS
gen_llms_txt --self-test · check_done_lines --self-test                  -> PASS
check_xrefs · check_doc_claims · check_done_lines · check_corpus_at_rest · check_spec · check_spdx
normalize_eol --check                                                    -> all OK
```

**The 24 `NOT RUN` are every one a `cargo`/`rustup`/`deny`/`machete`/`cyclonedx` command, printed with its
`working-directory` where it differs.** The gate is their **union** with the 131 reproduced, and the three
that matter were run directly (`§O-451`).

### The one CI failure this review caused, and how it was closed

**`dcf018e` turned two passing platforms red** — `clippy::manual_assert` on the retry helper — because it was
verified with `cargo clippy -p qqq-run --all-targets --all-features`, **which omits `-- -D warnings`, the flag
that makes this workspace's gate a gate.** Running it as written then found a **second** error the narrow form
had hidden: `value assigned to 'last' is never read` (`§O-450`).

**`a32fc45` closes it: 12 jobs, 0 failures, all three platforms.**

### The delivery's own failures, which this review did not soften

```
AssemblyScript 0.28.20       4,590 bytes       5/5 vectors passed
TinyGo 0.42.0 + Go 1.27.1  592,028 bytes       four small cases pass; the 64 KiB echo FAILS
componentize-py 0.25.1   18,364,731 bytes      link rejected; 0 vectors executed
WASI SDK 34 C               54,146 bytes       5/5 passed
WASI SDK 34 C++17           54,146 bytes       5/5 passed
TypeScript → ComponentizeJS 12,035,099 bytes   link rejected; 0 vectors executed
```

**These remain failed tests with owned gaps.** `VALIDATION.md:141` says it in the delivery's own words:
*"Governance passes do not turn these failed executions into conformance passes."*

## What was verified by this review rather than inherited

* **The merge is byte-exact for 411 of 428 manifest entries**, measured by hashing, with **0 absent**.
* **`LANG-007`'s budgets were not raised.** 15.68 / 15.02 / 15.01 s across three clean builds on a
  **2,726-line** application against a **10,000-line** requirement, so the **≤20 s / 10k LOC budget stays
  open** — and *"earlier 25.34-second evidence is retained; this is a different measurement, not a retroactive
  correction or a raised limit."*
* **The delivery's four tools are wired into BOTH gates**, measured: `check_live_dev` 2/2,
  `check_language_parity` 3/3, `fault_inject_live_components` 1/1, `run_language_probes` 2/2 — and
  `check_gate_parity` reports `GATE PARITY OK`, which is rule 5 doing its job on new checkers.
* **This repository's own rule corrected the contributor**: `VALIDATION.md:144` records that
  **`check_done_lines` failed** on the delivery's `→ Evidence:` / `→ Decision` markers and that they were
  replaced with `→ Done:` text. **A ratchet with a 53-item exemption list fired on new work and not on
  history, against an agent it had never seen** (`§O-457`).
* **The delivery corrected this repository**, in `LANG-039`: the item stayed open because *"the goal's
  sequencing forbids starting `LANG-009`…`LANG-040` before `TEST-010` lands"*, and it now says the complete
  language × capability coverage is missing. **The sequencing rule stopped being the blocker when the
  scaffolding existed.**

## What this review did NOT verify

**Stated as a list rather than implied by silence.**

* **The language probes were not reproduced.** Four of the six need toolchains absent here — measured:
  `clang` ABSENT, `componentize-py` ABSENT, `go` ABSENT, `tinygo` ABSENT, `wit-bindgen` ABSENT. **`node` here
  is `v23.11.0` against the delivery's pinned `24.14.1`.** The probe results above are the delivery's, and
  `docs/languages/evidence/*.json` carries its per-language hashes and versions.
* **Cloud Landlock and the Docker daemon remain blocked**, exactly as the delivery recorded. **Neither gate
  was weakened, and no privileged daemon was attempted.**
* **`TinyGo`'s 64 KiB defect is not root-caused.** The delivery records allocation-or-GC interaction during
  canonical ABI lowering as *"a hypothesis, not a proven root cause"*, and **no upstream issue was filed.**
* **`LANG-023` and `LANG-024` stay `blocked-by-upstream-and-time`**; the quarterly reassessment is due
  **2026-12-30** and technical gaps are reviewed **2026-10-30**. **Not ticked.**
* **Production language drivers are not implemented.** `qqqai build` remains Rust-only, and
  **no unexecuted language is marked supported.**

## The next bounded PR

**Production build drivers and templates**, as `LOCAL-AGENT-PROMPT.md` point 7 specifies — and it is a
separate PR precisely because the four failures above are not resolved: typed multi-step plans, truthful
dry-run and JSON output, exact tool diagnostics, canonical WIT generation, validation before atomic staging,
failed-build artifact retention, Rust compatibility and live/AOT cross-language tests, **with the existing
Rust-only conformance guard parser updated.**

**Its acceptance gate is the delivery's own, and it is a sequence of falsifiable conditions**: missing tools
diagnose clearly; generation comes from the canonical WIT; dry-run predicts every command; failed builds
retain the prior artifact; Rust CLI and manifest compatibility passes; new-language HTTP and large-buffer
vectors pass; a wrong ABI fails before live publication; and **no new grants, no budget increase, and no
unexecuted language is marked supported.**
