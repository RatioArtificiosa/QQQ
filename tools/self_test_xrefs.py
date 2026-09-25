#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Fault-injection harness for tools/check_xrefs.py.

Proves the validator actually detects the failure modes it claims to detect.
A validator that never fires is worse than no validator, because it manufactures
false confidence. Run this after any change to check_xrefs.py.

Two phases, one entry point:

  1. `check_xrefs.py --self-test` -- the hermetic matrix. It builds a small synthetic
     corpus in a temporary directory, injects each numbered check's defect into a
     fresh copy of it, and never touches this repository. Some rules can only be
     violated by a source file or a repeated heading, so this is where [3], [7] and
     [11] are covered at all.
  2. The in-place cases below -- the integration proof. They mutate the three real
     documents, run the validator, and restore. This is the phase that can leave a
     defect behind if it is killed, and the reason for the signal handlers and for
     `--check-clean`.

Usage:  python tools/self_test_xrefs.py
Exit:   0 = all fault injections were correctly detected, 1 = a check is dead

# checklist-citations-exempt
# observation-citations-exempt
#
# Both are declared because this file fabricates references by design: it injects
# **OQ-099**, ` HOST-999 `, §D-099 and §O-999 into a copy of the corpus to prove
# the validators reject them. Check [13] would report §O-999 as a citation of an
# undefined observation, which it is -- and that is the point of the fixture.

This file is exempt from `tools/check_checklist_citations.py`, in full: fabricating
references that resolve to nothing is *what it is for*. It writes `HOST-999` and
`OQ-099` into documents to prove `check_xrefs.py` catches them, so every one of those
identifiers is deliberate. The declaration is here rather than repeated on each line
— nine copies of the same comment would be nine places to keep right, and the tenth
fabricated marker added later would be missed.
"""

from __future__ import annotations

import importlib.util
import re
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
import os
import time

ROOT = Path(__file__).resolve().parent.parent
CHECK = ROOT / "tools" / "check_xrefs.py"
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"
CHECKLIST = ROOT / "QQQ-Checklist-V1.md"
OBS = ROOT / "QQQ-Observations-and-Memories.md"


def run_validator() -> tuple[int, str]:
    args = [sys.executable, str(CHECK)]
    if SANDBOX is not None:
        args.append(str(SANDBOX))
    p = subprocess.run(args, capture_output=True, text=True, cwd=ROOT)
    return p.returncode, p.stdout + p.stderr


# --------------------------------------------------------------------------
# The sandbox Phase 2 injects into
# --------------------------------------------------------------------------
#
# Phase 2's injections rewrite the three canonical documents. Until this existed
# they were rewritten **in the repository**, with the restore in a `finally` and a
# `SIGTERM` handler as the only defence -- and neither runs after the process-group
# termination a build tool applies to a command that overruns its deadline. The
# harness's own docstring above `expect_failure` records that happening: a killed
# run left `CAP-011`'s citations stripped and a `\u00a799.9` marker in `HOST-001`, and
# the next validator run reported faults that were **the harness's leftovers rather
# than real problems**.
#
# A `SIGKILL`-proof `finally` does not exist, so the guard is not the fix. Redirecting
# the write target is: Phase 2 now injects into a copy, and a copy left mutated by a
# signal is discarded with its temporary directory. The audited tree is never written
# to, so it cannot be left dirty by a signal it cannot catch.
#
# # Why rebinding globals is enough, and why the guard still watches the real tree
#
# `expect_failure` takes the target document as an argument and every Phase 2 call
# site passes one of `PROPOSAL` / `CHECKLIST` / `OBS`. Rebinding those three names
# therefore redirects every injection at once, and keeps the restore logic, the
# `REVERSALS` table and the marker checks exactly as they were -- only the write
# target moves.
#
# `INJECTION_MARKERS` is the one thing that must NOT move: it is built at import time
# from the original `Path` objects, so it keeps pointing at the repository. That is
# deliberate. `assert_clean_corpus` exists to catch a leftover from a *previous, killed*
# run, which is a property of the audited tree rather than of this run's copy; a guard
# that watched the copy would answer a question nobody asked.
SANDBOX: Path | None = None
_SANDBOX_HOLDER: tempfile.TemporaryDirectory | None = None


def activate_sandbox() -> Path:
    """Copy the tree and point every injection target at the copy.

    Called once, after the hermetic matrix has passed and immediately before the
    first injection. Returns the sandbox root, which is also passed to the validator
    so it judges the injected copy rather than the tree.
    """
    global SANDBOX, _SANDBOX_HOLDER, PROPOSAL, CHECKLIST, OBS
    _SANDBOX_HOLDER = tempfile.TemporaryDirectory(prefix="qqq-xrefs-sandbox-")
    SANDBOX = check_xrefs.sandbox_copy(ROOT, Path(_SANDBOX_HOLDER.name) / "root")
    PROPOSAL = SANDBOX / "QQQ-Proposal-V1.md"
    CHECKLIST = SANDBOX / "QQQ-Checklist-V1.md"
    OBS = SANDBOX / "QQQ-Observations-and-Memories.md"
    return SANDBOX


def prove_isolation() -> int:
    """Prove a killed sweep cannot dirty the audited tree.

    The failure this file lost two rounds to is precise: **a mutation applied to the
    real documents and never restored**. `finally` cannot run after a `SIGKILL`, so the
    only honest test is to leave a mutation un-restored on purpose and show the audited
    tree is still clean.

    So this injects into the sandbox, deliberately does **not** undo it, and then
    checks the repository's own documents for the marker. If the sandbox default ever
    regresses -- if a target escapes back to the worktree -- this goes red, because the
    real `QQQ-Checklist-V1.md` would carry `**OQ-099**`.
    """
    marker, injected = "**OQ-099**", "**OQ-012**"
    # Read the flag from the table rather than restating it. A hard-coded `True` here
    # was how this proof first disagreed with the validator: the proof was checking for
    # a line-anchored marker against a mid-line occurrence. The durable version of that
    # mistake is a second hand-written copy of a derived value (`§O-261`).
    line_start = next(ls for m, _p, _s, ls in INJECTION_MARKERS if m == marker)
    sandbox = activate_sandbox()
    real_checklist = ROOT / "QQQ-Checklist-V1.md"
    copy_checklist = sandbox / "QQQ-Checklist-V1.md"

    print(f"sandbox root      : {sandbox}")
    print(f"injection target  : {copy_checklist}")
    print(f"real document     : {real_checklist}")

    # The default must be the copy, and the copy must be inside the temporary
    # directory rather than anywhere near the repository.
    under_sandbox = copy_checklist.resolve().is_relative_to(sandbox.resolve())
    targets_are_copies = all(
        p.resolve().is_relative_to(sandbox.resolve()) for p in (PROPOSAL, CHECKLIST, OBS)
    )
    print(f"all three targets are inside the copy : {targets_are_copies}")
    print(f"the copy is inside the temp root      : {under_sandbox}")

    # Inject and DO NOT restore: this is the killed-run state, reproduced on purpose.
    original = copy_checklist.read_text(encoding="utf-8")
    assert original.count(injected) >= 1, f"{injected} must exist in the copy"
    copy_checklist.write_text(original.replace(injected, marker, 1), encoding="utf-8")
    print(f"\ninjected {injected} -> {marker} into the copy and left it un-restored")

    copy_dirty = marker_is_present(copy_checklist, marker, line_start)
    real_dirty = marker_is_present(real_checklist, marker, line_start)
    print(f"the copy carries the mutation         : {copy_dirty}")
    print(f"the real document carries it          : {real_dirty}")

    # The validator reads the sandbox, so it sees the injected copy.
    code, out = run_validator()
    tag_present = "[9]" in out
    print(f"the validator rejects the injected copy: {code != 0 and tag_present}")

    ok = targets_are_copies and under_sandbox and copy_dirty and not real_dirty and code != 0
    print()
    if ok:
        print("ISOLATION PROVEN -- a sweep killed mid-injection cannot dirty the "
              "audited tree")
        return 0
    print("ISOLATION FAILED -- an injection reached the audited tree", file=sys.stderr)
    return 1


def markers_match_their_mutations() -> bool:
    """Derive every marker's `line_start` flag from the mutation it guards.

    # Why this is derived rather than declared

    The `line_start` flag says *where in a line* an applied injection puts its marker.
    A wrong flag does not make the guard loud; it makes it **silent**, which is the one
    failure a guard must not have. A `True` on a mutation that lands mid-line means the
    check looks for the marker at the start of a line, does not find it, and reports the
    corpus clean while the corpus is not.

    That is not hypothetical: the entry for `**OQ-099**` was declared `True` while check
    [9] replaces a mid-line occurrence, so `assert_clean_corpus` was blind to the exact
    leftover that refuted two rounds of this goal (`§O-261`). The flag was a hand-written
    claim about behaviour, and the comment above the table cited a test that had never
    been written -- so nothing executed it.

    This applies each mutation to the sandbox copy, asks the **shipped**
    `marker_is_present` with the declared flag, and fails when the answer is no. The
    flag is now measured rather than asserted, and the derived value is what a reader
    should trust.
    """
    if SANDBOX is None:
        print("  !! marker agreement needs an active sandbox", file=sys.stderr)
        return False

    print("marker table -> the mutations it guards")
    failures = 0
    # marker text -> the states of every entry carrying that text
    coverage: dict[str, list[str]] = {}

    for marker, path, source, line_start in INJECTION_MARKERS:
        copy = SANDBOX / path.name
        reversal = REVERSALS.get(marker)
        if reversal is None:
            print(f"  !!  {source}: no REVERSALS entry for {marker!r}")
            failures += 1
            continue
        injected, original = reversal
        text = copy.read_text(encoding="utf-8")
        if original is None or original not in text:
            # Text shared with another entry that carries the mutation; that entry
            # is the one that applies, and this one is the safety net.
            coverage.setdefault(marker, []).append("anchor-absent")
            print(f"  --  {source}: anchor absent here; a shared-text safety net")
            continue
        copy.write_text(text.replace(original, injected, 1), encoding="utf-8")
        detected = marker_is_present(copy, marker, line_start)
        copy.write_text(text, encoding="utf-8")
        coverage.setdefault(marker, []).append("ok" if detected else "blind")
        if detected:
            print(f"  OK  {source}: line_start={line_start} detects its own mutation")
        else:
            print(f"  !!  {source}: line_start={line_start} does NOT detect its "
                  f"mutation -- the guard would miss this leftover")
            failures += 1

    # A marker no applying entry can see is dead weight: it can never fire.
    for marker, states in coverage.items():
        if "ok" not in states:
            print(f"  !!  {marker!r} is not detected by any entry whose anchor applies")
            failures += 1

    if failures:
        print(f"\nmarker table is wrong: {failures} problem(s), so the guard would miss "
              f"its own leftovers", file=sys.stderr)
        return False
    print("  every marker detects the mutation it guards\n")
    return True


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
        _write_text_lf(target, mutated)
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
        _write_text_lf(target, original)
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
            _write_text_lf(target, original)
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
# Some markers legitimately occur in prose: `HOST-999` (not-a-checklist-item) and
# `§D-099` are named in the Observations document's own table describing this harness.
# Scanning every file for them produced FALSE POSITIVES — the guard would have
# "repaired" the Observations document on every clean run, destroying the very table
# that explains it.
#
# So each marker names the single file its injection targets, and `§99.9` is
# checked with its distinguishing suffix so it cannot match a latency percentile.
#
# # Why every marker is anchored to the START OF A LINE
#
# Because the Observations document describes this harness, and in doing so it
# *quotes* the markers — `## (heading deleted)` and `HOST-999` both appear in prose
# explaining what the injections do. An unanchored `in` test therefore fired on the
# documentation, and the guard "repaired" a document that was correct. That is the
# same false-positive class as the earlier `HOST-999` case, arriving one level up:
# the detector could not tell a mutation from a description of one.
#
# An applied injection is always a whole line (or the start of one), because every
# mutation in `run_all` anchors on `(?m)^`. Prose quoting a marker puts it mid-line,
# inside backticks. So `line_start=True` separates them exactly, and the flag is per
# entry rather than global because the two cases genuinely differ.
INJECTION_MARKERS = [
    ("§99.9 Nonexistent section", CHECKLIST, "check [1]: a checklist item citing a bad section", False),
    ("`HOST-999`", PROPOSAL, "check [2]: the Proposal citing a dangling checklist ID", False),
    # The text here must equal the mutation's replacement verbatim, or the guard
    # reports a leftover on the next clean run. Both are checked against each
    # other by `markers_match_their_mutations`, which derives each `line_start`
    # flag from the mutation it guards rather than trusting the value written here.
    (
        "- [ ] **CAP-011** Implement the restricted policy expression language.",
        CHECKLIST,
        "check [4]: CAP-011's citations stripped",
        True,
    ),
    ("### REMOVED — The \"Wasm is near-native\"", OBS, "check [8]: the Observations §C-006 entry renamed away", True),
    # `False`, and it was `True` until a test derived it. This mutation is the one
    # that is *not* line-anchored: check [9] does
    # `t.replace("**OQ-012**", "**OQ-099**", 1)` and `**OQ-012**` occurs mid-line, in
    # `- [ ] **OQ-012** Decide the deprecation window: ...`. So the applied leftover
    # reads `- [ ] **OQ-099** ...` and a start-of-line test cannot see it.
    #
    # Declared `True`, this entry was **blind to the exact leftover that refuted two
    # rounds of this goal** (`§O-261`). A sweep killed during check [9] left
    # `**OQ-099**` in the checklist; `assert_clean_corpus` scanned for it, found
    # nothing, reported the corpus clean, and the next validator run reported three
    # errors against documents that were correct apart from the harness's own damage.
    # The guard existed, ran, and could not see the one thing it was built for.
    #
    # The reason it could drift is the next defect: the comment at the head of this
    # table promised a test named `test_the_markers_match_their_mutations`, and no
    # such test was ever written. The flag was therefore a hand-written claim about
    # behaviour that nothing exercised -- the same shape as `ARCH-011`'s three counts,
    # in the harness rather than in the artifact. `markers_match_their_mutations`
    # now derives every flag from the mutation it guards.
    ("**OQ-099**", CHECKLIST, "check [9]: a checklist open question renamed", False),
    ("`§D-099`", PROPOSAL, "check [10]: the Proposal citing a bad Observations decision", False),
    ("§REMOVED", PROPOSAL, "check [10b]: a decision's citations stripped from the Proposal", False),
    ("§O-999", CHECKLIST, "check [13]: a citation of an undefined observation", False),
    ("## (heading deleted)", OBS, "check [12]: the MISTAKES AND FIXES heading deleted", True),
    ("**CAP-011** duplicate", CHECKLIST, "check [6]: a duplicate checklist ID", False),
    # A safety net for the check [2] variant: the harness renames HOST-001 inside
    # the *checklist* too, and both files must be restored.
    ("`HOST-999`", CHECKLIST, "check [2]: a checklist ID renamed to a dangling value", False),
]


def marker_is_present(path: Path, marker: str, line_start: bool) -> bool:
    """Whether `marker` is applied to `path`, as opposed to merely mentioned.

    A line-anchored marker is matched only where it begins a line, which is how an
    applied injection looks and how prose quoting it does not.
    """
    text = path.read_text(encoding="utf-8")
    if not line_start:
        return marker in text
    return any(line.startswith(marker) for line in text.splitlines())


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
#
# # Why the check [4] original is CAPTURED from the checklist rather than typed
#
# The entry used to hard-code the original as the heading plus one `→` line. That
# was correct when `CAP-011` had one citation and silently wrong once it had
# seven: the reversal would have restored one line and left the item different
# from before the injection, which is exactly the defect the check [6] comment
# below describes — *"a repair table is code, and code that is never executed
# against the thing it repairs is a guess."*
#
# So the original is read from the real checklist at import time. A document
# change is picked up automatically, and if the anchor stops matching, the capture
# is `None` and the harness reports that rather than guessing.
# # Why this pattern is shaped the way it is, having been wrong twice
#
# The item has a heading line and then zero or more **continuation block** lines:
# each `  → ...` line, plus any further-indented lines belonging to it. The first
# version matched only the heading and the FIRST `→` line, because a repetition
# like `(?:  → [^\r\n]*\r?\n?)*` stops at the four-space continuation lines
# that follow every arrow -- so six arrows survived, the item still cited §6.2,
# and check [4] correctly did not fire while the harness reported DEAD.
#
# The robust form does not count arrows or their widths. It consumes the heading
# and then **every following line that is indented and is not itself a new list
# item**. That is exactly what "part of this item" means in this document, and it
# cannot go stale when an entry gains another paragraph.
CAP_011_BLOCK = re.compile(
    r"(?m)^- \[[ x]\] \*\*CAP-011\*\*[^\r\n]*\r?\n"
    r"(?:(?!- \[[ x!]\])[ \t]+[^\r\n]*\r?\n)*"
)


def _capture_cap_011_original() -> str | None:
    """The real `CAP-011` block, exactly as the checklist holds it."""
    text = CHECKLIST.read_text(encoding="utf-8")
    found = CAP_011_BLOCK.search(text)
    return found.group(0) if found else None


CAP_011_ORIGINAL = _capture_cap_011_original()


REVERSALS = {
    "§99.9 Nonexistent section": (
        "→ §99.9 Nonexistent section",
        "→ §6.1 `qqq-host` — the execution engine",
    ),
    "`HOST-999`": ("`HOST-999`", "`HOST-001`"),
    # The injected text is the mutation's replacement verbatim; the original is
    # the block captured from the live checklist, so the reversal restores every
    # citation line rather than a transcribed subset. `None` means the anchor did
    # not match, and the harness refuses to guess.
    "- [ ] **CAP-011** Implement the restricted policy expression language.": (
        "- [ ] **CAP-011** Implement the restricted policy expression language.",
        CAP_011_ORIGINAL,
    ),
    '### REMOVED — The "Wasm is near-native"': (
        '### REMOVED — The "Wasm is near-native"',
        '### §C-006 — The "Wasm is near-native"',
    ),
    "**OQ-099**": ("**OQ-099**", "**OQ-012**"),
    "`§D-099`": ("`§D-099`", "`§D-003`"),
    "§REMOVED": ("§REMOVED", "§D-005"),
    "§O-999": ("§O-999", "§O-248"),
    "## (heading deleted)": ("## (heading deleted)", "## 4. MISTAKES AND FIXES"),
    # # Why this reversal was WRONG the first time, and how it was found
    #
    # Check [6]'s injection does `re.sub` on the `CAP-012` **line**, replacing its
    # `- [x] **CAP-012**` prefix with `- [ ] **CAP-011** duplicate`, so the injected
    # text keeps CAP-012's description. The original revision of this entry claimed
    # the injection "prepends a whole bogus item line" and set the original to the
    # empty string — which is not what the injection does at all.
    #
    # The repair therefore deleted a line that was not there, left the injected
    # line in place, and reported success. The result was a corpus that had *lost*
    # `CAP-012` and gained a duplicate `CAP-011`. On the next run the injection's
    # own pattern no longer matched anything, so the harness reported
    # `SKIP duplicate CAP-011: mutation was a no-op` — a real defect in the
    # self-repair, surfaced as flakiness across consecutive runs.
    #
    # The lesson is one this session keeps relearning: **a repair table is code, and
    # code that is never executed against the thing it repairs is a guess.** This
    # entry was written from reading the injection rather than from running it.
    "**CAP-011** duplicate": (
        "- [ ] **CAP-011** duplicate Implement `qqqai why <resource>` producing the complete resolution chain.",
        "- [x] **CAP-012** Implement `qqqai why <resource>` producing the complete resolution chain.",
    ),
}


# The byte-faithful writer lives with the other corpus writers, in `check_xrefs.py`.
# Loading it as a module rather than copying the function keeps one definition, so
# the rule cannot drift between the two files.
_spec = importlib.util.spec_from_file_location("check_xrefs", CHECK)
check_xrefs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_xrefs)
_write_text_lf = check_xrefs.write_text_lf


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
    for marker, path, source, line_start in INJECTION_MARKERS:
        if not path.exists():
            continue
        if marker_is_present(path, marker, line_start):
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
        _write_text_lf(path, text.replace(injected, original, 1))
        repaired_paths.append(path.name)

    print("  repaired:", ", ".join(sorted(set(repaired_paths))) or "(nothing)", file=sys.stderr)

    # **Verify the repair.** A restore that is assumed to have worked is the very
    # failure mode this file exists to catch, so the markers are re-checked.
    #
    # Only the paths this function actually repaired. `repaired_paths` holds the
    # names it wrote, so the set is the repair's own record rather than a
    # re-derivation that could disagree with it.
    #
    # This loop read `for path in targets:` and `targets` was never assigned anywhere
    # in the file, so the self-healing path repaired the corpus and then died with
    # `NameError: name 'targets' is not defined` on a corpus it had just made clean.
    # The harness exited 1 and the Linux bridge's `checks` command failed for a
    # reason unrelated to the corpus. Found by using it: a killed bridge run left
    # `§REMOVED` in the Proposal and this path was what handled it (`§O-191`).
    for path, _marker, _source in dirty:
        if path.name not in repaired_paths:
            continue
        for marker, marker_path, source, line_start in INJECTION_MARKERS:
            if marker_path == path and marker_is_present(path, marker, line_start):
                print(
                    f"  !! {path.name} still contains {marker!r} after the repair",
                    file=sys.stderr,
                )
                return False

    print("  repaired; the corpus is clean again", file=sys.stderr)
    return True


def check_clean_only() -> int:
    """Refuse if the corpus carries an injection. Does NOT self-heal.

    # Why a separate mode, and why it does not repair
    #
    # `assert_clean_corpus` self-heals, which is right when a developer runs the
    # harness and wrong at the point of commit. A commit gate that silently edits
    # the tree is a commit gate that commits something other than what was
    # reviewed — and `git commit -a` would capture the repair without anyone seeing
    # it.
    #
    # So this mode only **reports**, with a non-zero exit, and names the exact
    # repair to apply. It exists because a real failure got through: commit
    # `2546546` shipped the corpus with a renamed `OQ-012` and a deleted
    # `## 4. MISTAKES AND FIXES` heading, both left by an interrupted harness run,
    # and CI's xref job failed on the pushed commit. The working tree looked clean
    # because the harness had not yet been re-run since the kill.
    #
    # A checker that only runs *after* the damage is a postmortem, not a gate.
    """
    dirty = []
    for marker, path, source, line_start in INJECTION_MARKERS:
        if path.exists() and marker_is_present(path, marker, line_start):
            dirty.append((path, marker, source))

    if not dirty:
        print("corpus is clean: no fault injection is applied")
        return 0

    print("FATAL: refusing to proceed — the corpus contains a left-over injection.")
    print("")
    print("A previous harness run was killed before it could restore. These are NOT")
    print("real defects in the documents:")
    print("")
    for path, marker, source in dirty:
        print(f"  {path.name}: contains {marker!r}  (left by {source})")
    print("")
    print("Repair with:  python tools/self_test_xrefs.py")
    print("(it reverses the exact substitution), then re-check with `git diff`.")
    return 1


LOCK = ROOT / ".self_test_xrefs.lock"


class _Lock:
    """An exclusive marker that only one mutating harness run may hold.

    # Why a lock file and not `flock`

    `O_CREAT | O_EXCL` behaves the same on Windows and Linux, and this harness runs on
    both: the bridge runs it under Linux and a developer runs it under Windows. `flock`
    is POSIX-only; `msvcrt.locking` is Windows-only.

    # Why a stale lock is reclaimed rather than obeyed

    A `SIGKILL` or a container stop cannot run a handler, so the file outlives its owner.
    A lock that refuses forever would make the harness permanently unusable, and one that
    is ignored is not a lock. So the file carries the owner's PID, a lock whose PID is
    gone is reclaimed with a message, and the reclaim race is accepted as smaller than
    the corruption it prevents.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.held = False

    def acquire(self) -> bool:
        """Take the lock, or report that a live run holds it."""
        if self._reclaim_if_stale():
            pass
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            owner = self._owner()
            print(
                f"FATAL: another harness run holds the corpus ({owner}).\n"
                f"  The lock is {self.path.name}. It mutates the three documents, so two\n"
                f"  runs cannot overlap: the second would restore the first's injection\n"
                f"  mid-flight and leave the corpus in a state that reads as document\n"
                f"  drift (\u00a7O-193).\n"
                f"  Wait for the other run, or, if it is gone, run with `--break-lock`.",
                file=sys.stderr,
            )
            return False
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(self._describe())
        self.held = True
        return True

    def _describe(self) -> str:
        return f"pid={os.getpid()} started={time.strftime('%Y-%m-%dT%H:%M:%S')}"

    def _owner(self) -> str:
        try:
            return self.path.read_text(encoding="utf-8").strip() or "unknown owner"
        except OSError:
            return "unreadable lock file"

    def _pid_alive(self, pid: int) -> bool:
        """Whether `pid` is a live process. Best-effort and platform-split.

        On POSIX, signal 0 asks the kernel whether the process exists without
        delivering anything. On Windows there is no such probe without a handle, so
        `tasklist` output is the check; if that fails the lock is treated as live,
        which errs toward refusing rather than toward two mutators.
        """
        if pid <= 0:
            return False
        if os.name == "nt":
            try:
                out = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                    capture_output=True, text=True, timeout=15, check=False,
                ).stdout
                return str(pid) in out
            except (OSError, subprocess.SubprocessError):
                return True
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _reclaim_if_stale(self) -> bool:
        if not self.path.exists():
            return False
        owner = self._owner()
        pid = 0
        for part in owner.split():
            if part.startswith("pid="):
                try:
                    pid = int(part[4:])
                except ValueError:
                    pid = 0
        if pid and self._pid_alive(pid):
            return False
        print(
            f"note: reclaiming a stale harness lock ({owner}); its process is gone.",
            file=sys.stderr,
        )
        try:
            self.path.unlink()
        except OSError:
            return False
        return True

    def break_lock(self) -> None:
        """Remove the lock unconditionally, for `--break-lock`."""
        try:
            self.path.unlink()
            print(f"broke the lock at {self.path}", file=sys.stderr)
        except OSError as e:
            print(f"could not remove {self.path}: {e}", file=sys.stderr)

    def release(self) -> None:
        if not self.held:
            return
        try:
            self.path.unlink()
        except OSError:
            pass
        self.held = False


def main() -> int:
    # `--check-clean` is the commit gate: report only, change nothing.
    if len(sys.argv) > 1 and sys.argv[1] == "--check-clean":
        return check_clean_only()
    if len(sys.argv) > 1 and sys.argv[1] == "--break-lock":
        _Lock(LOCK).break_lock()
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "--prove-isolation":
        return prove_isolation()

    # **One mutator at a time.** This harness rewrites the three real documents, and a
    # second run overlapping the first restores an injection mid-flight and leaves a
    # corpus that reads as document drift (`\u00a7O-193`: `\u00a7C-006` renamed to `REMOVED` by
    # one run while a repair was in progress in another).
    lock = _Lock(LOCK)
    if not lock.acquire():
        return 1
    try:
        return _run(lock)
    finally:
        lock.release()


def _run(lock: _Lock) -> int:
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

    # ------------------------------------------------------------------
    # Phase 1: the hermetic rule matrix
    # ------------------------------------------------------------------
    #
    # Why both phases exist, and which one owns which rule
    #
    # The cases below mutate the three canonical documents and restore them. That is
    # the integration proof -- it shows the rules fire against the corpus as it
    # actually is. They mutate a **copy** of it, made immediately before the first
    # case below, so the audited tree is not written to; the restore still runs, and
    # is still what makes a successful sweep leave no trace, but what it protects is
    # now a temporary directory.
    #
    # That distinction is the whole of `§O-260`. In the repository, a sweep killed
    # mid-injection left a mutation behind that read as a real document defect on
    # every later run, and the guard built to catch it (`assert_clean_corpus`) could
    # only detect the damage after the fact. Against a copy there is no damage to
    # detect. `--prove-isolation` demonstrates it by leaving a mutation un-restored
    # on purpose and showing the audited tree is clean.
    #
    # It is not, and cannot be, the whole proof. Three numbered checks need a source
    # file or a repeated heading to violate, and mutating those in place risks more
    # than it proves:
    #
    #   [3]  an anchor defined twice            -- needs a repeated heading
    #   [7]  a stub marker naming no checklist item, and markers with no stub section
    #   [11] stub sections with no inline marker
    #
    # `check_xrefs.py --self-test` builds its own corpus in a temporary directory and
    # covers those three plus every other numbered check. Running it FIRST means a
    # dead rule is reported by the cheap, safe harness before anything touches the
    # tree, and it is the same `--self-test` interface every other checker in `tools/`
    # exposes.
    #
    # Not a duplicate of the cases below: this phase asserts each rule on a corpus
    # built to violate exactly one of them; the cases below assert the same rules
    # against the documents that will actually be committed.
    hermetic = subprocess.run(
        [sys.executable, str(CHECK), "--self-test"],
        capture_output=True, text=True, errors="replace", cwd=ROOT,
    )
    if hermetic.returncode != 0:
        print("FATAL: check_xrefs.py --self-test failed -- a rule is dead.")
        print((hermetic.stdout or hermetic.stderr)[-4000:])
        return 1
    # The count is read from the subprocess rather than written here. It was the
    # literal `16` until this line was fixed, while the subprocess had reached 17:
    # a message asserting another program's output that nothing compares to that
    # output drifts silently, and this one had already drifted.
    hermetic_out = hermetic.stdout or hermetic.stderr or ""
    _m = re.search(r"SELF-TEST PASSED -- (\d+)/(\d+) case", hermetic_out)
    if _m is None:
        print("FATAL: check_xrefs.py --self-test printed no case total to read.")
        print(hermetic_out[-4000:])
        return 1
    hermetic_cases = int(_m.group(2))
    print(
        f"hermetic rule matrix: PASSED ({hermetic_cases} cases over every "
        f"numbered check)\n"
    )

    results: list[bool] = []

    # Phase 2 injects, so redirect every write target at a copy first. This is the
    # line that makes a killed sweep harmless: a mutation left un-restored lands in a
    # temporary directory rather than in the audited tree (`§O-260`).
    sandbox = activate_sandbox()
    print(f"Phase 2 injects into a copy: {sandbox}")
    print("the audited tree is not written to\n")

    # Before using the marker table, prove it can see its own mutations. A guard whose
    # flags have drifted is worse than no guard, because it reports the corpus clean.
    if not markers_match_their_mutations():
        return 1

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
        # # Why this strips *every* continuation line and not just one
        #
        # This injection has now gone stale twice, both times for the same
        # reason, and the second time is the instructive one.
        #
        # * First it anchored on `- [ ]`, and CAP-011 was ticked `- [x]`, so the
        #   pattern stopped matching.
        # * Fixed by matching `\[[ x]\]` -- and then CAP-011 gained a `→ Done:`
        #   line plus six further `→` evidence lines, while the mutation stripped
        #   only the *first* one. Six citations remained, the item still had a
        #   Proposal citation, check [4] correctly did not fire, and the harness
        #   correctly reported SKIP.
        #
        # **The pattern removed one syntactic instance of the thing the check
        # tests for, rather than the thing itself.** Check [4] asks "does this
        # item cite a Proposal section"; the injection must therefore remove
        # every citation, not the line after the heading. An anchor that has to
        # grow every time the document gets richer is the wrong anchor.
        #
        # So: match the heading line and then consume the whole continuation
        # block -- every following line that starts with `  →` -- and replace the
        # lot with a bare item. The checkbox state is matched as `[ x]` so a
        # future tick does not disable this again, which is the half of the
        # earlier fix that was right.
        lambda t: re.sub(
            CAP_011_BLOCK,
            "- [ ] **CAP-011** Implement the restricted policy expression language.\n",
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

    print("check [13] a citation of an observation that does not exist")
    results.append(expect_failure(
        "checklist cites O-999",
        CHECKLIST,
        lambda t: t.replace("§O-248", "§O-999", 1),
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
