# Handoff: QQQ runtime → registry owner (2026-10-27 work)

This records the runtime-side work of 2026-10-27 and exactly what the
registry side must re-verify. No registry files were touched; the registry
owner runs the commands in §2 and reports green rather than taking it on
faith.

## 1. What changed and why it is safe to pull

| Change | Files | Registry impact |
|---|---|---|
| Vendored `wasmtime-internal-cache` 48.0.7 with the zstd requirement 0.13 → 0.14 (resolves RUSTSEC-2026-0391/0398/0403/0410; `cargo deny` green) | `Cargo.toml` (`[patch.crates-io]`), `Cargo.lock`, `vendor/` | No API change (same crate version). The build resolves zstd 0.14.3 / zstd-safe 8.2.0 / zstd-sys 2.1.2. Re-run the suite; expect no changes. Decision record: `docs/dependency-decisions/zstd-cache.md`. |
| CON-020: `qqqai run` pre-flight admits the WASI 0.2 baseline without a grant (fixes §O-782: every normal `wasm32-wasip2` guest was refused) | `crates/qqq-run/src/run.rs`, tests | No ABI change. `inspect` output unchanged (baseline names stay unmapped; no grant exists for them). Re-run contract vectors. |
| Deterministic per-request tick for `serve --deterministic` | `crates/qqq-host` (`ambient.rs`, `instance.rs`), `crates/qqq-run/src/guest_handler.rs`, tests | New `InstanceOptions::deterministic_initial_ticks` (default 0) and per-app shared counter. Real-time paths untouched. Replay logs unchanged in shape. |
| Doc corrections: §10.5 randomness row (hash-DRBG, not ChaCha20), determinism.md state rows, stability serve row (no H2-on-listener, no H3), PRINCIPLES CON range | `QQQ-Proposal-V1.md`, `docs/determinism.md`, `docs/stability.md`, `PRINCIPLES.md` | Prose only. Generated docs re-recorded (`llms.txt`, `llms-full.txt`, backlog, dashboard, corpus digests); all generator checks green. |
| New checklist item CON-020 (631 items total) | `QQQ-Checklist-V1.md` + generated files | Counts only. |

Frozen surfaces verified unchanged: 13 `qqq:` catalogue names, 24 capability
names, 15 WIT packages, WASI 0.2 served / 0.3 narrow, `abi.host >=0.2,<0.4`,
workspace 0.1.1, Wasmtime/wasmparser pins (lockfile delta is zstd only).
`core-only` builds for `wasm32-unknown-unknown` (verified this round).

## 2. Registry re-run request

```
cargo test -p qqq-registry
python tools/check_specs.py --root specs --qqq-root E:/QQQ
python scripts/build_wasm.py
# plus: TypeScript checks, Vitest, Node bridge smoke
```

## 3. Blockers the runtime cannot close (owner/external)

- **Security audits** SEC-024/025: engage firms, pay, receive reports, fix findings.
- **Legal/governance/planning/hardware/market items**: see goal §5.13 table —
  counsel filings, appointments, reference machines (PLAN-013 unlocks PERF/DOD
  measurements), design partners, TinyGo upstream (LANG-023/024, quarterly check).
- **Needs-owner-decision designs**: deterministic scheduler scope (DET-004),
  network-timing record/replay (DET-011), compilation pinning ratification
  (DET-013), "seeded CSPRNG" wording for DET-003 (hash-DRBG is reproducible
  and statistically strong, but not secret), guest streaming ABI for WS/SSE,
  hyper cutover for `serve`, shared-memory policy (ARCH-014/PERF-015/ABI-016
  vs ratified `wasm_threads(false)`).
- **Performance**: §9.2 numeric budgets are UNMEASURED on reference hardware.
  Do not report local numbers as budget verdicts. DET-016 cost report needs
  PLAN-013 machines.

## 4. Evidence produced this round

- `cargo deny check`: advisories/bans/licenses/sources ok.
- `cargo fmt --all --check`, workspace clippy `-D warnings`, machete: green.
- Full workspace suite: 3,530 passed, 0 failed (14 ignored, named in log).
- `cargo xtask ci`: GATE GREEN, 146 steps, 0 failed on the final tree (full log kept with the goal evidence; evidence commit pending owner request).
- 10,000 deterministic reference-app trials: 0 diverged (log + digests kept).
- CON-020: red-first unit + CLI e2e (fault-injected QQQ-6003), green after;
  independent review (Meta Muse proxy, subscription quota exhausted), 9
  findings, all triaged/fixed.
- Tick wiring: red-first e2e (frozen zero), green after; 3/3 stable runs;
  second review: pass, no findings.
