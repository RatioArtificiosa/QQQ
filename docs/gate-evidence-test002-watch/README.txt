TEST-002 watch half — red-first and green gate evidence.

Red (proves the tests fail without the shipped code):
- test002-watch-red-unit.log — `test_watch_rules` missing (E0425) before implementation.
- test002-watch-red-cli.log — `--watch` unknown flag (QQQ-7001), 1 passed / 3 failed.
- test002-watch-review-red.log — new incompatibility tests (`cannot be combined`)
  red without the `test_options` validation (0 passed / 3 failed), green with it.

Green (refreshed on HEAD 4800e1d after audit fix; code HEAD 6a26ccb first green, then audit guard added; `cargo test -p qqq-run`):
- lib 705 passed, doctests 116 passed, cli 139 passed (8 watch).
- gate-fmt.log, gate-clippy.log, gate-deny.log, gate-machete.log — fast gates exit 0.
- gate-test.log — `cargo test --workspace --all-features` exit 0.
- gate-xtask-ci.log — `cargo xtask ci` GATE GREEN 150 steps.

Review (Meta Muse proxy via Copilot CLI, subscription quota exhausted):
- cr-test002-watch-proxy.log — 9 findings (2 HIGH, 3 MED, 4 LOW), all fixed.
- cr-test002-watch-proxy2.log — CLEAN re-review, zero open findings.
