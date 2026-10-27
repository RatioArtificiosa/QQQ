Gate and red-proof evidence for commit 1ff2e24 (2026-10-27 round 2).

Commit: 1ff2e24 "det: close DET-005/DET-006 with red-first proofs; triage
ARCH-009/S52 (DET-003..006, SEC-020/027, CON-020)" on main. Tree clean at
both gate runs below; the red-proofs mutate one file each and restore it
byte-identical (verified by empty `git status` after each restore).

HOW TO REPRODUCE
  cargo xtask ci                        # full gate, expect GATE GREEN: 148 steps
  python tools/check_ordered_maps.py --self-test    # expect 19/19
  python tools/check_checklist_counts.py --self-test # expect 19/19

FILES
  xtask-ci-148-green.log
    Second full-gate run on the committed tree: GATE GREEN, 148 steps
    (146 + check_ordered_maps bare + --self-test), zero failures, exit 0.
    A first run on the same bytes went RED on exactly one timing-sensitive
    self-test case ("live progress.py agrees with the checker"):
    .scratch/progress.py shells `graf check-update` (7s on a quiet tree)
    and starved past the 120s deadline under that run's saturated parallel
    lane (self_test_xrefs alone took 565s vs 146s on rerun). No gate or
    product file changed between runs; the rerun is green throughout.
  checklist-counts-selftest-19-19.log
    Standalone re-proof of the flaked step: 19/19, ~9s, on the committed tree.
  det005-nan-red.log
    Red proof 1: cranelift_nan_canonicalization flipped true->false in the
    deterministic arm only; the guest's 0.0/0.0 reads back 0xFFF8... (x86
    hardware indefinite QNaN) instead of canonical 0x7FF8.... Restored after.
  det005-relaxed-red.log
    Red proof 2: wasm_relaxed_simd flipped false->true in the deterministic
    arm only; the relaxed-madd fixture compiles when the item forbids it.
    Restored after.
  det006-checker-red.log
    Red proof 3: one injected function using HashMap::new, HashSet::new and
    RandomState::new in shipped code; the checker names all three with
    remedies and exits 1. Restored byte-identical (empty git diff), green
    after (UNORDERED-MAP RULE PASSED).
