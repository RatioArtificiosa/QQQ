# Gate evidence — TEST-002 parallel execution (`qqqai test --jobs N`)

Committed with the slice. What each file proves:

- `test002-red.log` — red-first end-to-end proof on the pre-implementation
  tree: CLI tests requiring `--jobs`/parallel snapshots fail (unknown flag,
  unplaced snapshots). The fault-injection run below is the sharper proof.
- `test002-faultinject.log` — the parallel dispatch forced to sequential:
  the barrier test (`test_jobs_runs_tests_in_parallel`) fails after its 30 s
  timeout, proving the test guards live concurrency rather than flag parsing.
  Restored byte-identical (fault marker count 0 in diff), suite green.
- `cr-test002-proxy.log` — independent proxy review (Copilot subscription
  quota exhausted), final sweep: no remaining functional bugs; verified
  unreachable!-on-bad-index, hardware-independent worker cap, stop-flag
  semantics, empty-selection early return, combined failure message, flag
  parsing, and all CLI tests pinning the behavior.
- `cr-test002-proxy2.log` — adversarial final audit: 1 real bug found
  (worker count capped by `available_parallelism` would serialize
  `--jobs 2` on a 1-core machine; fixed to an absolute 256-worker
  bomb-guard), everything else audited clean with no new issues.
- `xtask-ci-green.log` — full `cargo xtask ci` on the committed tree.

Behavioral summary: `--jobs N` runs up to N tests concurrently on worker
threads (absolute 256-worker cap, never core-gated); outcomes reassemble in
discovery order; `--fail-fast` stops scheduling while running tests finish;
per-(file,name) isolation dirs and snapshot keys; `--jobs 0`/non-numeric/
missing values are usage errors; default (no flag) stays sequential. Watch
mode is NOT part of this slice — TEST-002 stays open for it.
