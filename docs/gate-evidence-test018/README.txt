TEST-018 CI integration examples — red-first and green gate evidence.

Red (proves the checker fails without the shipped examples):
- test018-red.log — `check_ci_examples.py` on the empty `examples/ci/`
  (3 missing-file findings, exit 1); `--self-test` green on fixtures.

Green (verification-plan step 1 re-run on clean HEAD 0abed63):
- gate-fmt.log, gate-clippy.log, gate-deny.log, gate-machete.log — fast
  gates exit 0 on 0abed63.
- gate-test.log — `cargo test --workspace --all-features` exit 0 on
  0abed63.
- gate-xtask-ci.log — `cargo xtask ci` GATE GREEN 152 steps (150 + new
  check_ci_examples + its self-test) on clean 0abed63.
- Prior identical green on 3351e22/code-identical f8cc16f superseded by
  this re-run; TEST-018 close (0abed63) changed only checklist + derived
  docs since, and the gate re-confirms them.

Dependency note (same window): `cargo deny` went red on RUSTSEC-2026-0420
(wasip3 UDP, fixed in wasmtime-wasi 48.0.8). A plain update would have
downgraded zstd 0.14.3 → 0.13.3, re-opening 0391/0398/0403/0410 — so the
vendor dir was re-based onto upstream 48.0.8 with the same one-line zstd
requirement (commits fc75427 + f8cc16f ENGINE_VERSION bump, caught by the
existing lockfile test: 788 passed, 1 failed before the bump).

Review (Meta Muse proxy via Copilot CLI, subscription quota exhausted):
- cr-test018-proxy.log — 1 finding (bare-`qqqai` mention passed the gate).
- cr-test018-proxy2.log — CLEAN re-review after fix (gate requires
  `qqqai test`; self-test covers the no-qqqai fixture).
