# Gate evidence — PKG-014 `--offline` from the local store

Committed with the slice. What each file proves:

- `pkg014-red-unit.log` — red-first library proof: the offline unit tests
  against the pre-implementation tree fail to compile (missing
  `install_offline`, `package_dest`, `store_root_from`).
- `pkg014-red-cli.log` — red-first end-to-end proof: 4 of 5 CLI offline tests
  fail on the pre-implementation binary (happy placement, cold store, partial
  store, unpinned naming); the dry-run test passes before and after as the
  rehearsal control.
- `pkg014-faultinject.log` — the presence check (phase 1b) disabled: the
  partial-store test fails because the present package gets placed before the
  missing one errors. Restored byte-identical (fault marker count 0 in diff),
  suite green.
- `cr-pkg014-proxy.log` — independent proxy review (Copilot subscription quota
  exhausted): 3 MED + 3 LOW, all fixed in-tree.
- `cr-pkg014-proxy2.log` — focused re-review of the six fixes: 3 residual
  findings (empty-USERPROFILE shadowing, two doc overclaims), all fixed.
- `xtask-ci-green.log` — full `cargo xtask ci` on the committed tree
  (written by the gate run; GATE GREEN expected).

Behavioral summary: `install_offline` checks every pin (digest present,
parsing, in store, name inside `.qqq/packages`) before placing anything;
cold/partial stores fail naming every missing package with the project
untouched; corrupt entries and mid-loop IO abort loud; `--offline --dry-run`
verifies without placing; `--frozen --offline` verifies without placing by
strictness; `--force` now honors pins (was parsed but ignored).
