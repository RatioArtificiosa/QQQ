#!/usr/bin/env python3
"""Fault-injection harness for tools/check_xrefs.py.

Proves the validator actually detects the failure modes it claims to detect.
A validator that never fires is worse than no validator, because it manufactures
false confidence. Run this after any change to check_xrefs.py.

Usage:  python tools/self_test_xrefs.py
Exit:   0 = all fault injections were correctly detected, 1 = a check is dead
"""

from __future__ import annotations

import re
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECK = ROOT / "tools" / "check_xrefs.py"
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"
CHECKLIST = ROOT / "QQQ-Checklist-V1.md"
OBS = ROOT / "QQQ-Observations-and-Memories.md"


def run_validator() -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(CHECK)],
        capture_output=True, text=True, cwd=ROOT,
    )
    return p.returncode, p.stdout + p.stderr


def expect_failure(name: str, target: Path, mutate) -> bool:
    """Apply mutate(text)->text, run the validator, restore, report.

    # Why the restore is a `try`/`finally` AND a `SIGTERM` handler

    Found by running it: a `qqqdev checks` invocation was **killed by a timeout**
    while this function had the corpus mutated, and `finally` never ran. The
    repository was left with `CAP-011`'s citation stripped and a `§99.9` marker in
    `HOST-001`, so the *next* validator run failed on faults that were **the test
    harness's leftovers rather than real problems**. Two failures, from one
    interruption, in a file the harness had modified on purpose.

    `finally` covers an exception. It does not cover `SIGTERM`/`SIGKILL` from
    outside, which is exactly what a timeout or a `Ctrl-C` in a container
    produces. So:

      * `SIGTERM`/`SIGINT` are handled and restore before exiting, and
      * the mutations are **verified absent** at the start of `main`, so a
        `SIGKILL` — which cannot be caught — is detected on the next run rather
        than silently invalidating results.

    The second mechanism is the one that matters, because no handler can run after
    `SIGKILL`. `assert_clean_corpus` is what makes the failure loud.
    """
    original = target.read_text(encoding="utf-8")
    mutated = mutate(original)
    if mutated == original:
        print(f"  SKIP  {name}: mutation was a no-op (the test itself is wrong)")
        return False

    # Register the restore so a signal during a slow validator run unwinds it.
    pending.append((target, original))
    try:
        target.write_text(mutated, encoding="utf-8")
        code, out = run_validator()
        detected = code != 0 and "FAIL" in out
        marker = "\n".join(l for l in out.splitlines() if "FAIL" in l)[:200]
        if detected:
            print(f"  OK    {name}")
            if marker:
                print(f"        -> {marker.strip().splitlines()[0].strip()}")
            return True
        print(f"  DEAD  {name}: validator did NOT detect this fault")
        return False
    finally:
        target.write_text(original, encoding="utf-8")
        pending.remove((target, original))


# Mutations currently applied, so a signal handler can undo them.
pending: list[tuple[Path, str]] = []


def restore_all(*_args) -> None:
    """Undo every pending mutation, then exit.

    Installed for `SIGTERM`/`SIGINT` so a timeout or a `Ctrl-C` leaves the corpus
    as it found it. Cannot help with `SIGKILL`, which is why
    `assert_clean_corpus` also exists.
    """
    for target, original in list(pending):
        try:
            target.write_text(original, encoding="utf-8")
        except OSError:
            pass
    pending.clear()
    print("\nrestored the corpus after a signal", file=sys.stderr)
    sys.exit(130)


# The markers every injection leaves. If one is present at startup, a previous run
# was killed and the corpus is dirty.
#
# # Why this list must cover EVERY injection
#
# The first version listed only three of the nine. That was enough to catch a
# leftover from three of them and useless for the rest, and the gap cost real time:
# an interrupted run left `### §C-006 —` renamed to `### REMOVED —`, the *next*
# validator run failed with "Appendix A row A-6 has no matching §C-006 entry", and
# the natural reading — "the documents have drifted" — pointed at three correct
# documents. The actual cause was a dead harness, again (`§O-070`).
#
# A partial marker list is worse than none, because it makes the guard look like it
# covers the harness when it covers a third of it.
#
# # Why each entry is (marker, file, description)
#
# Some markers legitimately occur in prose: `HOST-999` and `§D-099` are named in
# the Observations document's own table describing this harness. Scanning every
# file for them produced FALSE POSITIVES — the guard would have "repaired" the
# Observations document on every clean run, destroying the very table that explains
# it.
#
# So each marker names the single file its injection targets, and `§99.9` is
# checked with its distinguishing suffix so it cannot match a latency percentile.
INJECTION_MARKERS = [
    ("§99.9 Nonexistent section", CHECKLIST, "check [1]: a checklist item citing a bad section"),
    ("`HOST-999`", PROPOSAL, "check [2]: the Proposal citing a dangling checklist ID"),
    (
        "- [ ] **CAP-011** Implement the restricted policy expression language.\n",
        CHECKLIST,
        "check [4]: CAP-011's citation line stripped",
    ),
    ("### REMOVED — The \"Wasm is near-native\"", OBS, "check [8]: the Observations §C-006 entry renamed away"),
    ("**OQ-099**", CHECKLIST, "check [9]: a checklist open question renamed"),
    ("`§D-099`", PROPOSAL, "check [10]: the Proposal citing a bad Observations decision"),
    ("§REMOVED", PROPOSAL, "check [10b]: a decision's citations stripped from the Proposal"),
    ("## (heading deleted)", OBS, "check [12]: the MISTAKES AND FIXES heading deleted"),
    ("**CAP-011** duplicate", CHECKLIST, "check [6]: a duplicate checklist ID"),
    # A safety net for the check [2] variant: the harness renames HOST-001 inside
    # the *checklist* too, and both files must be restored.
    ("`HOST-999`", CHECKLIST, "check [2]: a checklist ID renamed to a dangling value"),
]


# The exact inverse of every injection above, so the harness can undo its own
# leftovers *surgically*: `marker -> (injected_text, original_text)`.
#
# # Why this table exists at all
#
# The obvious repair — `git checkout HEAD -- <file>` — throws away every uncommitted
# change to that file. During this session it nearly destroyed a 269-line entry that
# had been written but not committed. A self-healing harness that eats work is worse
# than one that reports a confusing error.
#
# Reversing the substitution touches only the mutated bytes, so uncommitted work
# elsewhere in the same file survives by construction.
#
# Every marker in `INJECTION_MARKERS` must have an entry here. When one is missing,
# `assert_clean_corpus` refuses to repair and says which reversal to add, rather
# than falling back to something destructive.
#
# An entry whose original text is `None` means the injection *deleted* text rather
# than replacing it, so the repair cannot be derived from the marker alone; the
# harness reports that instead of guessing.
REVERSALS = {
    "§99.9 Nonexistent section": (
        "→ §99.9 Nonexistent section",
        "→ §6.1 `qqq-host` — the execution engine",
    ),
    "`HOST-999`": ("`HOST-999`", "`HOST-001`"),
    "- [ ] **CAP-011** Implement the restricted policy expression language.\n": (
        "- [ ] **CAP-011** Implement the restricted policy expression language.\n",
        "- [ ] **CAP-011** Implement the restricted policy expression language with "
        "static analysability and termination proofs.\n"
        "  → §6.2 `qqq-cap` — the capability engine\n",
    ),
    '### REMOVED — The "Wasm is near-native"': (
        '### REMOVED — The "Wasm is near-native"',
        '### §C-006 — The "Wasm is near-native"',
    ),
    "**OQ-099**": ("**OQ-099**", "**OQ-012**"),
    "`§D-099`": ("`§D-099`", "`§D-003`"),
    "§REMOVED": ("§REMOVED", "§D-005"),
    "## (heading deleted)": ("## (heading deleted)", "## 4. MISTAKES AND FIXES"),
    # The injection prepends a whole bogus item line; the repair removes it. The
    # original text is empty because nothing was replaced, only inserted.
    "**CAP-011** duplicate": ("- [ ] **CAP-011** duplicate\n", ""),
}


def assert_clean_corpus(autofix: bool = True) -> bool:
    """Fail loudly if a previous run left an injection applied.

    # Why this is the important guard

    `SIGKILL` cannot be caught, so a container timeout can always leave the corpus
    mutated. Without this check the *next* validator run reports failures that are
    the harness's leftovers, and the natural conclusion — "the documents are
    broken" — sends the reader to edit three documents that were fine. That is the
    `§O-070` shape: a tooling artifact that reads as a real defect.

    # Why it *repairs* rather than only refusing

    Refusing was not enough. This exact situation recurred three times in one
    session, and each time a human had to notice a confusing failure, work out that
    the cause was a dead harness rather than a broken document, and restore by
    hand — once restoring the wrong thing because a *different* injection had also
    been left behind by an earlier kill.

    The marker tells us precisely which mutation is present, and the original text
    is in git. So the harness now reverses its own leftovers automatically and says
    so. A tool that leaves a mess and then declines to clean it, three times, is
    not a guard — it is a hazard.

    `autofix=False` keeps the pure detection available for tests.
    """
    dirty = []
    for marker, path, source in INJECTION_MARKERS:
        if not path.exists():
            continue
        if marker in path.read_text(encoding="utf-8"):
            dirty.append((path, marker, source))

    if not dirty:
        return True

    # A leftover marker means a killed run, not a broken document. Say so before
    # touching anything, so the log explains the repair rather than hiding it.
    print(
        "WARNING: the corpus contains left-over fault injections from a killed run.",
        file=sys.stderr,
    )
    for path, marker, source in dirty:
        print(f"  {path.name}: contains {marker!r}  (left by {source})", file=sys.stderr)

    if not autofix:
        print("", file=sys.stderr)
        print("Restore with `git checkout HEAD -- QQQ-Checklist-V1.md`.", file=sys.stderr)
        return False

    # # Why the repair REVERSES the substitution instead of checking out the file
    #
    # `git checkout HEAD -- <file>` is the obvious repair and it is wrong: it
    # discards **every** uncommitted change to that file, not just the injection.
    # That is real data loss, and it very nearly cost this session a 269-line
    # Observations entry that was written but not yet committed.
    #
    # The injections are all known text substitutions, so each marker can be
    # reversed exactly, leaving everything else in the file untouched. The repair is
    # therefore *surgical*: it edits the mutated bytes back to their original text
    # and nothing more.
    #
    # `REVERSALS` is the inverse of every mutation in `run_all`. If an injection is
    # added without its inverse, the marker check below still fires and the harness
    # reports that it could not repair — loudly, rather than silently truncating a
    # developer's work.
    repaired_paths = []
    for path, marker, source in dirty:
        text = path.read_text(encoding="utf-8")
        reversal = REVERSALS.get(marker)
        if reversal is None:
            print(
                f"  !! no reversal is defined for {marker!r} ({source})",
                file=sys.stderr,
            )
            print(
                "     Add it to REVERSALS so the harness can undo its own damage.",
                file=sys.stderr,
            )
            return False
        injected, original = reversal
        if injected not in text:
            print(
                f"  !! {path.name} names {marker!r} but does not contain the mutated "
                "text, so the repair cannot be applied safely",
                file=sys.stderr,
            )
            return False
        path.write_text(text.replace(injected, original, 1), encoding="utf-8")
        repaired_paths.append(path.name)

    print("  repaired:", ", ".join(sorted(set(repaired_paths))) or "(nothing)", file=sys.stderr)

    # **Verify the repair.** A restore that is assumed to have worked is the very
    # failure mode this file exists to catch, so the markers are re-checked.
    for path in targets:
        text = path.read_text(encoding="utf-8")
        for marker, marker_path, source in INJECTION_MARKERS:
            if marker_path == path and marker in text:
                print(
                    f"  !! {path.name} still contains {marker!r} after the repair",
                    file=sys.stderr,
                )
                return False

    print("  repaired; the corpus is clean again", file=sys.stderr)
    return True


def main() -> int:
    # Install the signal handlers FIRST, so a timeout during any later step still
    # restores. `SIGKILL` cannot be caught, which is why the check below exists.
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, restore_all)

    # **Before anything else: is the corpus clean?**
    #
    # A previous run killed with `SIGKILL` cannot restore, so this is the only
    # mechanism that catches it. Without it the validator's baseline fails and the
    # error points at the *documents* rather than at the harness that mutilated
    # them — and the natural response is to edit three files that were correct.
    if not assert_clean_corpus():
        return 1

    # Baseline must be clean first; otherwise everything below is meaningless.
    code, out = run_validator()
    if code != 0:
        print("FATAL: baseline corpus does not validate. Fix that first.")
        print(out[-2000:])
        return 1
    print("baseline: PASSED\n")

    results: list[bool] = []

    print("check [2] dangling checklist ID cited by the Proposal")
    results.append(expect_failure(
        "proposal cites HOST-999",
        PROPOSAL,
        lambda t: t.replace("`HOST-001`", "`HOST-999`", 1),
    ))

    print("check [1] dangling Proposal section cited by a checklist item")
    results.append(expect_failure(
        "checklist cites §99.9",
        CHECKLIST,
        lambda t: t.replace(
            "→ §6.1 `qqq-host` — the execution engine",
            "→ §99.9 Nonexistent section", 1),
    ))

    print("check [4] checklist item with no Proposal citation")
    results.append(expect_failure(
        "strip CAP-011's citation line",
        CHECKLIST,
        # # Why CAP-011 and not CAP-001
        #
        # This injection used CAP-001, which has since been ticked `- [x]` and
        # gained a `→ Done:` line. The old pattern anchored on `- [ ]` and
        # stopped matching, so the mutation became a no-op and the harness
        # reported SKIP — which is the harness working correctly: it noticed its
        # own injection had gone stale rather than silently passing.
        #
        # The fix is to use an item that is still open, and to match either
        # checkbox state so a future tick does not silently disable it again.
        lambda t: re.sub(
            r"(?m)^- \[[ x]\] \*\*CAP-011\*\*.*?\r?\n\s*→ §[^\r\n]*",
            "- [ ] **CAP-011** Implement the restricted policy expression language.",
            t,
            count=1,
        ),
    ))

    print("check [8] Appendix A <-> Observations correction parity")
    results.append(expect_failure(
        "remove Observations §C-006",
        OBS,
        lambda t: t.replace("### §C-006 —", "### REMOVED —", 1),
    ))

    print("check [9] §Q-nnn <-> OQ-nnn open-question parity")
    results.append(expect_failure(
        "rename checklist OQ-012",
        CHECKLIST,
        lambda t: t.replace("**OQ-012**", "**OQ-099**", 1),
    ))

    print("check [10] Proposal citing a nonexistent Observations decision")
    results.append(expect_failure(
        "proposal cites §D-099 everywhere",
        PROPOSAL,
        lambda t: t.replace("§D-003", "§D-099"),
    ))

    print("check [10b] Observations decision never cited from the Proposal")
    results.append(expect_failure(
        "strip every §D-005 citation from the proposal",
        PROPOSAL,
        # `§D-005` is the Tokio decision. Removing its citations from the
        # Proposal must be caught: a decision that is defined and never
        # referenced is a decorative identifier, and the reverse check exists
        # because six of the nine decisions were once write-only while check
        # [10] -- which only knows about citations that exist -- reported clean.
        lambda t: t.replace("§D-005", "§REMOVED"),
    ))

    print("check [12] Observations keeps its nine-section skeleton")
    results.append(expect_failure(
        "delete the `## 4. MISTAKES AND FIXES` heading",
        OBS,
        # The exact mistake that happened four times: an `edit` anchored on this
        # heading, used it as trailing context, and did not reproduce it.
        #
        # Anchored on the *line*, not on the bare string. The bare string appears
        # four times in the document — this entry and several others quote the
        # heading while explaining the mistake — so replacing the first
        # occurrence left the check still able to find the text, and the harness
        # reported the injection as dead. It was the injection that was wrong,
        # not the check: which is precisely what a self-test is for.
        lambda t: re.sub(
            r"(?m)^#+ 4\. MISTAKES AND FIXES[ \t]*$",
            "## (heading deleted)",
            t,
            count=1,
        ),
    ))

    print("check [6] duplicate checklist ID")
    results.append(expect_failure(
        "duplicate CAP-011",
        CHECKLIST,
        # Matches either checkbox state, so ticking the item later cannot turn
        # this injection into a silent no-op the way it did before.
        lambda t: re.sub(
            r"(?m)^- \[[ x]\] \*\*CAP-012\*\*",
            "- [ ] **CAP-011** duplicate",
            t,
            count=1,
        ),
    ))

    # Final state must be clean again.
    code, out = run_validator()
    restored = code == 0
    print(f"\nrestored: {'PASSED' if restored else 'STILL BROKEN'}")
    if not restored:
        print(out[-2000:])

    passed = sum(results)
    total = len(results)
    print(f"\n{passed}/{total} fault injections detected")
    if passed != total or not restored:
        print("SELF-TEST FAILED — a validator check is dead")
        return 1
    print("SELF-TEST PASSED — every check is live")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
