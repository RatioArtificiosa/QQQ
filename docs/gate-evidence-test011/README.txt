# Gate evidence — TEST-011 snapshot testing (`qqqai test --snapshot`)

Committed with the slice. What each file proves:

- `test011-red-unit.log` — red-first library proof: the snapshot unit tests
  against the pre-implementation tree fail to compile (missing
  `check_snapshot`, `escape_snapshot_name`, `SnapshotMode`, `SnapshotStatus`).
- `test011-red-cli.log` — red-first end-to-end proof: 6 of 6 CLI snapshot
  tests fail on the pre-implementation binary (unknown `--snapshot` /
  `--snapshot-update` flags).
- `test011-faultinject.log` — the compare path forced to always report
  `Matched`: the mismatch and missing tests fail. Restored byte-identical
  (fault marker count 0 in diff), suite green.
- `cr-test011-proxy.log` — independent proxy review (Copilot subscription
  quota exhausted): 1 HIGH + 4 MED + 4 LOW, all fixed in-tree.
- `cr-test011-proxy2.log` — focused re-review of the 9 fixes: 2 residuals
  (discover() name-only dedup, CLI diff expectation), first real, second
  refuted with the passing e2e as evidence.
- `cr-test011-proxy3.log` — final verification review: everything resolved,
  no new issues.
- `xtask-ci-green.log` — full `cargo xtask ci` on the committed tree.

Behavioral summary: `--snapshot-update` records each passing test's stdout
into `tests/snapshots/`; `--snapshot` compares byte-exact and fails with a
unified diff (missing recording fails naming `--snapshot-update`); the two
flags together are a usage error; failing tests never record; snapshot
failures feed the exit code; file+name keys keep same-named tests apart.
