
# Verification appendix — plan steps 1–5 re-run on the evidence tree

Tree: `86ec3da`, `git status` empty before and after every step below.
Logs: this directory (`gates/`, `contract/`, `runtime/`, `tests/`, `evidence/`).

## Step 1 — gates (`gates/`)

- `fmt.log`: `cargo fmt --all -- --check` clean.
- `deny.log`: advisories/bans/licenses/sources ok.
- `machete.log`: no unused dependencies.
- `xtask-ci.log`: full `cargo xtask ci` (CARGO_BUILD_JOBS=6).
  - Attempt 1 (box busy with concurrent verification suites): RED —
    my own concurrent `cargo test` runs locked `target/debug/qqqai.exe`
    (os error 5), failing build/test/lang*/conformance/audit_load, plus the
    counts case below. Self-inflicted; discarded as evidence.
  - Attempt 2 (quiet box): RED on exactly one case —
    `check_checklist_counts --self-test`: live `progress.py` agreement
    exceeded its 120s deadline. Everything else (149 steps) green.
  - Attempt 3 (quiet box): same single red.
  - Diagnosis: `progress.py` shells `graf check-update --json`
    (8.7s standalone, 16.8s under a workspace-test load, 120s+ internal
    timeout under full-gate I/O storm). The case passes 19/19 standalone
    repeatedly and passed the prior round's gate (69s step). The 120s
    deadline in the checker cannot be raised to fit the box — that would
    weaken the gate. No in-repo change is legitimate: the repo, the
    checker, progress.py and graf are all unchanged by this round.
  - Standing evidence: the committed gate on this exact tree+commit
    (`docs/gate-evidence-2026-10-29/xtask-ci-REG-green.log` in `86ec3da`):
    GATE GREEN, 150 steps.

## Step 2 — contract (`contract/`)

- `contract.log`: clean tree; frozen-surface diff (3a21c4b..86ec3da over
  qqq-pkg/qqq-abi/qqq-cap/wit/Cargo.toml/Cargo.lock) = 47 insertions,
  0 deletions (docs + #[cfg(test)] only).
- `wasm.log`: core-only `wasm32-unknown-unknown` build succeeds.
- `pkg-test.log` / `abi-test.log` + `contract-summary.log`: pkg 120+1
  (default) and 108 (core-only) pass; abi 18+25 pass.
- Registry: no writes (all edits under E:/QQQ).

## Step 3 — runtime (`runtime/`)

- `runtime.log`: 4 normal-guest CLI tests green; 2 ungranted-import
  refusals green; serve unit suite 29/29; qqq-serve 711 passed total.
- `det009-10000.log`: DET009 OK 10000/10000 byte-identical, 0 failed.

## Step 4 — new tests (`tests/`)

- `tests.log` + `tool-verdicts.log`: qblock 6/6, lock 45/45, REG-018 1/1,
  install+audit+output 77/77, doc-claims 30/30 + self-test pass, catalogue
  check + self-test pass, parity OK, done-lines OK, admission 326≤326.
- `fault-inject-qblock.log`: 5/5 DETECTED on the evidence tree, restores
  byte-identical (`git status` empty after).

## Step 5 — evidence (`evidence/`)

- `final-report.md`: §8 items 1–8 (commit/tree, gate table, movement,
  runtime, performance, handoff, gaps, contradictions).
- `open-items.txt`: 125 blocked items with owner + tripwire.
- `checklist-before.md`: pre-round checklist (320/307/14/3 → 337/179/125/3).
- Before/after counts + newly-[x] (17) + new-[!] (111) recorded in the report.

Fresh re-run 2026-10-30 on clean 414bd6a: contract 47+/0-, wasm ok, pkg 120+1/108, abi 18+25; CLI 4+2, serve 29/29, qqq-serve 906/906; DET-009 10000/10000; qblock 6/6, lock 45/45, suites 77/77, injector 5/5; evidence checks all green. Tree clean before and after.
