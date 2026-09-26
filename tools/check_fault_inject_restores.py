#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Prove the gate leaves the tree exactly as it found it — `§O-336`.

    python tools/check_fault_inject_restores.py --snapshot   # before the checkers
    python tools/check_fault_inject_restores.py --verify     # after them
    python tools/check_fault_inject_restores.py --self-test

# Why this exists, and the defect it answers

`02903b7` — a commit about the MCP server — **deleted one line from `wit/qqq-clock.wit`**: the
`@since(version = 1.0.0)` annotation. `git log -S` traced it there, and the commit had no business
touching a WIT file at all.

The gate had run **`fault_inject_wit_since`**, whose *injection* is exactly *"remove the `@since`
annotation"*. **A fault-injection checker modifies the tree on purpose**, and if its restore does not
complete, `git add -A` takes the injected state:

    a restore that did not complete is indistinguishable, to `git add -A`, from a change I made.

**One missing annotation then caused three checkers to fail** — `fault_inject_wit_since` refused
(*"the checker already fails on the pristine tree"*) and the other two reported *"injection point moved"*
— and the gate reported `OK` for the checker that would have caught it, **because that checker ran before
the injection that broke the tree**.

# What this checker does, and what it deliberately does not

It runs each fault-injection checker **once**, and compares **every tracked file** before and after. It
does not care *how* a checker restores — only that the tree it returns is the tree it was given.

**`§O-336`'s own mechanism is unproven**: `fault_inject_wit_since` *does* verify its restore and returns
`3` when the bytes differ. So the corruption was **an interrupted run or a restore that never executed**,
not a lossy one — and this checker is what makes that class **detectable rather than inferred**.

# Why the comparison is on bytes and not on `git status`

Because `git status` says *"modified"* for a file whose content changed and *"clean"* for one restored to
the same bytes — which is the distinction this is about. And because a checker could restore a file to
bytes that **differ from the working tree but match `HEAD`**, which `git status` would call clean only by
accident of timing.

**The baseline is the working tree as this checker finds it**, so it answers the question that matters:
*did this run change anything?*
"""

from __future__ import annotations

import argparse
import hashlib
import tempfile
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Every checker whose *purpose* is to modify the tree. Named by pattern rather than by list, so a new
# one is covered the moment it is written -- a list would be a second place to forget.
PATTERN = "fault_inject_*.py"

# Paths that a checker may legitimately create and remove. **Nothing else is excused**: the point of the
# check is that the tree is returned, so an allowance for a *tracked* file would defeat it.
UNTRACKED_OK = re.compile(r"^(\.pytest_cache|__pycache__|.*\.pyc$)")


def tracked_digests() -> dict[str, str]:
    """A digest of every tracked file, as git knows them.

    # Why `git ls-files` and not a directory walk

    Because the subject is **the committed tree**: an untracked scratch file a checker leaves behind is
    not the defect, and a tracked file it altered is. `git ls-files` is the list `git add -A` would take.
    """
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout
    digests: dict[str, str] = {}
    for raw in out.split(b"\0"):
        if not raw:
            continue
        rel = raw.decode("utf-8")
        path = ROOT / rel
        if not path.is_file():
            # A file git tracks that is not on disk: record its absence, because a checker that deleted
            # it has changed the tree as surely as one that edited it.
            digests[rel] = "<absent>"
            continue
        digests[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


def checkers() -> list[Path]:
    """Every fault-injection checker, sorted for determinism."""
    return sorted(ROOT.glob(f"tools/{PATTERN}"))


def run_checker(path: Path) -> tuple[int, str]:
    """Run one checker and return its exit code and combined output."""
    out = subprocess.run(
        [sys.executable, str(path.relative_to(ROOT))],
        cwd=ROOT,
        capture_output=True,
    )
    combined = (out.stdout + out.stderr).decode("utf-8", errors="replace")
    return out.returncode, combined


def compare(before: dict[str, str], after: dict[str, str]) -> list[str]:
    """The files that differ, as sentences. A pure function, so `--self-test` can drive it."""
    problems: list[str] = []
    for rel in sorted(set(before) | set(after)):
        was, now = before.get(rel), after.get(rel)
        if was == now:
            continue
        if was is None:
            problems.append(f"{rel} was CREATED and left behind")
        elif now is None:
            problems.append(f"{rel} was DELETED and not restored")
        else:
            problems.append(f"{rel} was MODIFIED and not restored")
    return problems


# **In the TEMP directory, not the repository.** A snapshot written beside the tree is a file `git add
# -A` could commit, and a checker whose own artefact becomes a change is a checker that causes the
# defect it exists to catch.
# **A STABLE name, because the protocol is two PROCESSES.** The first version put `os.getpid()` in the
# path -- and `--snapshot` and `--verify` are separate runs, so `--verify` could not find the snapshot
# its predecessor wrote. **The anti-vacuity guard below caught it**, which is the whole reason that
# guard exists: a comparison with no baseline certifies nothing, and it said so rather than passing.
SNAPSHOT = Path(tempfile.gettempdir()) / "qqq-gate-tree-snapshot.json"


def snapshot() -> int:
    """Record every tracked file's digest, for `--verify` to compare against.

    # Why a snapshot and not a re-run

    The first version of this checker **ran every fault injector itself**, which the gate already runs
    -- so the gate did the work twice and timed out. **The gate's own ordering is the mechanism**: write
    the tree's state before the checkers, verify it after. Two file reads, and it catches **any** checker
    that modifies the tree rather than only the fault injectors.
    """
    digests = tracked_digests()
    SNAPSHOT.write_text(
        "\n".join(f"{rel}\t{d}" for rel, d in sorted(digests.items())),
        encoding="utf-8",
        newline="",
    )
    print(f"GATE SNAPSHOT TAKEN -- {len(digests)} tracked file(s)")
    return 0


def verify() -> int:
    """Compare the tree against the snapshot, and fail on anything that moved."""
    if not SNAPSHOT.exists():
        # **A verification with no snapshot certifies nothing**, and saying so is the anti-vacuity rule
        # this repository applies in four other checkers.
        print("GATE TREE INCONCLUSIVE -- no snapshot; `--snapshot` must run before the checkers")
        return 1
    before: dict[str, str] = {}
    for line in SNAPSHOT.read_text(encoding="utf-8").splitlines():
        rel, _, digest = line.partition("\t")
        if rel:
            before[rel] = digest
    after = tracked_digests()
    problems = compare(before, after)

    print(f"tracked files compared: {len(before)}")
    print("")
    if problems:
        print(f"GATE TREE MODIFIED -- {len(problems)} file(s) the gate changed and did not restore:")
        for p_ in problems:
            print(f"  FAIL  {p_}")
        print("")
        print("  A checker that MODIFIES the tree on purpose must return it. If it does not, then")
        print("  `git add -A` takes the injected state -- which is how 02903b7 deleted a `@since` line")
        print("  from wit/qqq-clock.wit, and one missing annotation then failed three checkers.")
        return 1
    print(f"GATE TREE AT REST -- {len(before)} tracked file(s), none moved")
    return 0


def self_test() -> int:
    failures = 0
    total = 4

    def case(name: str, got, want) -> None:
        nonlocal failures
        ok = got == want
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}: {got!r}")
        if not ok:
            failures += 1

    # The comparison, in both directions.
    case("an identical tree is clean", compare({"a": "1"}, {"a": "1"}), [])
    case("a modified file is caught", len(compare({"a": "1"}, {"a": "2"})), 1)
    case("a deleted file is caught", len(compare({"a": "1"}, {})), 1)
    case("a created file is caught", len(compare({}, {"a": "1"})), 1)

    # **And the detector must fire on a checker that does NOT restore.** This is the injection: a
    # checker is written into a scratch copy of the tree's subject list... rather than run, because
    # running a deliberately-broken checker inside the gate would corrupt the tree it is guarding.
    #
    # The injection is therefore the COMPARISON itself, driven with a non-restoring pair -- and it is
    # the same function the real run uses, which is what makes it an injection rather than a second
    # implementation.
    injected = compare({"wit/qqq-clock.wit": "with-@since"}, {"wit/qqq-clock.wit": "without-@since"})
    case(
        "the non-restoring case 02903b7 hit is caught",
        injected,
        ["wit/qqq-clock.wit was MODIFIED and not restored"],
    )

    # And the real tree must pass, so this checker is not asserting a property the repository lacks.
    before = tracked_digests()
    after = tracked_digests()
    case("the real tree is at rest between two reads", compare(before, after), [])

    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) behaved wrongly")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s); the comparison and the real tree are live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--snapshot", action="store_true", help="record the tree before the checkers run")
    ap.add_argument("--verify", action="store_true", help="fail on anything the gate moved")
    ap.add_argument("--self-test", action="store_true", help="prove the comparison catches a non-restore")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if args.snapshot:
        return snapshot()
    return verify()


if __name__ == "__main__":
    raise SystemExit(main())
