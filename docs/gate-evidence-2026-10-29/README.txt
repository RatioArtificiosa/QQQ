Gate and red-proof evidence for the core-runtime closure handoff round
(2026-10-29 work): ARCH-017, SRV-023, SRV-024 recorded as owner
handoffs with red-first boundary pins, handoff dossiers in
docs/runtime-handoff-2026-10-29.md. Tree clean at the gate run
below; the red-proofs mutate one file each and restore it
byte-identical (verified by empty `git diff` after each restore).

HOW TO REPRODUCE (core-runtime round)
  cargo xtask ci                        # full gate, expect GATE GREEN: 148 steps
  python tools/gen_llms_txt.py --self-test   # expect SELF-TEST PASSED
  python tools/check_lifecycle_counts.py --self-test  # expect 19/19

HOW TO REPRODUCE (REG-closure round, this directory's red-* and
xtask-ci-REG-green logs)
  cargo xtask ci                        # full gate, expect GATE GREEN: 150 steps
  python tools/fault_inject_qblock.py   # expect 5/5 DETECTED
  python tools/gen_capability_catalogue.py --check      # expect CATALOGUE OK
  python tools/gen_capability_catalogue.py --self-test # expect SELF-TEST OK
  python tools/check_doc_claims.py      # expect DOC CLAIMS OK

FILES
  xtask-ci-148-green.log
    Full gate on the evidence commit: GATE GREEN, 148 steps, zero
    failures, exit 0.
  xtask-ci-REG-green.log
    Full gate on the REG-closure tree (this round): replaced by the final
    committed gate log for the slice; during the run it recorded the
    mid-tree state. Do not cite step counts from it — cite the final log.
  red-hostkey.log
    Red proof 1: with `deny_unknown_fields` removed from `Route`, a
    `host` key parses silently and
    `a_route_with_a_host_key_is_refused_at_parse_time` FAILS. Restored
    byte-identical; the test passes (path-only router pinned at the
    manifest boundary for ARCH-017).
  red-ws-fallthrough.log
    Red proof 2: with a WebSocket entry wired into the flat test server,
    the upgrade returns `101` and
    `an_upgrade_without_a_websocket_entry_falls_through_to_flat` FAILS.
    Restored byte-identical; the test passes (production dispatch stays
    flat-only for SRV-024 until a guest ABI exists).
  red-install-nosubprocess.log
    Red proof 3: with `std::process::Command::new("true")` injected into
    `read_lockfile`, the scan finds ``Command::new(`` in `src/install.rs`
    and `install_path_spawns_no_subprocess` FAILS. Restored with
    0 deletions; the install suite passes 23/23 (REG-015).
  red-lock-unknownfield.log
    Red proof 4: with `deny_unknown_fields` removed from `LockPackage`,
    an unknown `bogus = true` field slides past and
    `an_unknown_package_field_is_refused` FAILS. Restored with
    0 deletions; the `lock::` suite passes 45/45 (REG-011).
  red-audit-twopackage-prov.log
    Red proof 5: with the `provenance` loop truncated to the first
    package, only `a@1.0.0` is reported and the per-rule assertion
    requiring both names FAILS. Restored with 0 deletions (PKG-021).
  red-audit-twopackage-supply.log
    Red proof 6: with the `supply_chain` loop truncated to the first
    package, only `a@1.0.0 [dns.resolve]` is reported and the per-rule
    assertion FAILS. Restored with 0 deletions (PKG-021).
  det009-full-10000.log
    DET-009 re-run on tree 0658cde (runtime-identical to this commit;
    only checklist prose and generated docs changed after): 10000/10000
    byte-identical replay logs, 0 failed, 0 diverged, 28.6 ms/trial,
    reference REFERENCE_SHA256
    aed4cd719c0feec5ad66822f9d48fb69a6144d4773acc851e682a18c960e074e
    (pinned guest artifact unchanged: ARTIFACT_SHA 2a9c3fb3…).
    Cited by DET-009's Done line.
