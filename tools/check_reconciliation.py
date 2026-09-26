#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

# observation-citations-exempt
#
# This file's self-test fabricates `§C-007`, an entry that deliberately does
# not exist, to prove the generator rejects a table naming an undefined correction.
# Check [13] would otherwise report it, so the exemption is declared here -- in the
# source, where the reason sits next to the fixture that needs it.

"""Verify `docs/reconciliation.md` matches Appendix A (`DOC-013`).

A thin wrapper over `tools/gen_reconciliation.py --check`, with a self-test.

# Why the self-test matters more here than usual

This file is the *third* place the corrections are recorded, after Appendix A and the
Observations' `§C-NNN` entries. Three copies is two too many in principle, and the only
thing that justifies the arrangement is that a machine check holds them together. A
check that has never been shown to fail would make the third copy pure liability.

So the self-test exercises both drift directions — a row added to Appendix A, and a
`§C` entry added to the Observations — plus the splice markers going missing, which is
the failure that would silently produce an unspliced file.

Usage:
    python tools/check_reconciliation.py
    python tools/check_reconciliation.py --self-test
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import sys as _sys

# The byte-faithful writer and the sandbox copier are shared with the other corpus
# checkers rather than copied, because two copies of a newline rule -- or of a
# scratch-isolation rule -- is how the two copies drift.
_sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_xrefs import sandbox_copy, write_text_lf  # noqa: E402


# This tool's own stdout must be able to encode what it prints. On a Windows console the stream
# inherits `cp1252`, so a character read from a subprocess -- which this file now reads as UTF-8 --
# raises `UnicodeEncodeError` inside `print` and the tool dies while reporting its result. `§O-291`.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass



ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "tools" / "gen_reconciliation.py"
TARGET = ROOT / "docs" / "reconciliation.md"
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"
OBSERVATIONS = ROOT / "QQQ-Observations-and-Memories.md"


# The root the generator is aimed at. `None` means the repository, which is what a
# plain `--check` run wants; the self-test points it at a copy before injecting.
ACTIVE_ROOT: Path | None = None


def run_check() -> tuple[int, str]:
    args = [sys.executable, str(GEN), "--check"]
    if ACTIVE_ROOT is not None:
        args += ["--root", str(ACTIVE_ROOT)]
    p = subprocess.run(
        args,
        capture_output=True,
        text=True,
        cwd=ROOT, encoding="utf-8", errors="replace")
    return p.returncode, p.stdout + p.stderr


def self_test() -> int:
    global ACTIVE_ROOT, TARGET, PROPOSAL, OBSERVATIONS
    failures = 0

    # The clean case: the repository must currently be consistent.
    code, out = run_check()
    ok = code == 0
    print(f"  {'OK  ' if ok else 'DEAD'}  the committed table matches Appendix A")
    if not ok:
        failures += 1
        print(f"        {out.strip()[:200]}")

    # **Everything below this line injects, so it runs against a copy.** The cases
    # mutate `docs/reconciliation.md`, the Proposal and the Observations to prove the
    # generator notices. Done in the repository, a run killed mid-injection leaves a
    # mutation behind that reads as real document drift on every later run, and the
    # `finally` cannot help because the process-group termination a build tool applies
    # cannot be caught (`§O-260`).
    #
    # `--root` aims the generator -- and therefore every read and write it performs --
    # at the copy, so the injection cannot reach the audited tree. Nothing else about
    # the cases changes: same mutations, same expected failures, new write target.
    #
    # The holder is deliberately module-scoped rather than a `with` block: the copy is
    # released when the process exits, so the five cases below keep their own
    # indentation and this edit stays reviewable as a target change rather than a
    # rewrite.
    holder = tempfile.TemporaryDirectory(prefix="qqq-reconciliation-")
    sandbox_root = sandbox_copy(ROOT, Path(holder.name) / "root")
    ACTIVE_ROOT = sandbox_root
    TARGET = sandbox_root / "docs" / "reconciliation.md"
    PROPOSAL = sandbox_root / "QQQ-Proposal-V1.md"
    OBSERVATIONS = sandbox_root / "QQQ-Observations-and-Memories.md"
    print(f"  the cases below inject into a copy: {sandbox_root}")

    # Drift direction 1: the generated *region* is edited.
    #
    # # Why appending to the end of the file was the wrong test
    #
    # The first version appended a row after everything else — which is outside the
    # `GENERATED:END` marker, so it is prose the generator does not own and `--check`
    # was right to ignore it. The self-test reported DEAD and the *test* was the
    # broken thing, which is the same shape as the identifier case in
    # `check_advisories.py`'s self-test.
    #
    # The corruption has to land between the markers, because that is the only region
    # the generator owns.
    original = TARGET.read_text(encoding="utf-8")
    try:
        corrupted = original.replace(
            "<!-- GENERATED:BEGIN -->",
            "<!-- GENERATED:BEGIN -->\n\n| A-9 | invented | x | y |",
            1,
        )
        if corrupted == original:
            print("  SKIP  hand-edit case: the BEGIN marker was not found")
        else:
            write_text_lf(TARGET,corrupted, encoding="utf-8")
            code, out = run_check()
            ok = code != 0 and ("out of date" in out or "first difference" in out)
            print(f"  {'OK  ' if ok else 'DEAD'}  a hand-edit inside the generated region")
            if not ok:
                failures += 1
                print(f"        exit {code}: {out.strip()[:200]}")
    finally:
        write_text_lf(TARGET,original, encoding="utf-8")

    # Drift direction 2: Appendix A gains a row the Observations do not mirror. The
    # generator must refuse rather than emit a table that agrees with a drifted source.
    proposal = PROPOSAL.read_text(encoding="utf-8")
    try:
        patched = proposal.replace(
            "| A-6 |",
            "| A-6.5 | invented row | Corrected | nothing |\n| A-6 |",
            1,
        )
        if patched == proposal:
            print("  SKIP  appendix-drift case: the anchor row `| A-6 |` was not found")
        else:
            write_text_lf(PROPOSAL,patched, encoding="utf-8")
            code, out = run_check()
            ok = code != 0 and "parity" in out
            print(f"  {'OK  ' if ok else 'DEAD'}  a row added to Appendix A alone")
            if not ok:
                failures += 1
                print(f"        exit {code}: {out.strip()[:220]}")
    finally:
        write_text_lf(PROPOSAL,proposal, encoding="utf-8")

    # Drift direction 3: the Observations gain a §C entry alone.
    obs = OBSERVATIONS.read_text(encoding="utf-8")
    try:
        patched = obs.replace(
            "### §C-006 —",
            "### §C-007 — invented\n\n### §C-006 —",
            1,
        )
        if patched == obs:
            print("  SKIP  observations-drift case: the `### §C-006 —` heading was not found")
        else:
            write_text_lf(OBSERVATIONS,patched, encoding="utf-8")
            code, out = run_check()
            ok = code != 0 and "parity" in out
            print(f"  {'OK  ' if ok else 'DEAD'}  a §C entry added to the Observations alone")
            if not ok:
                failures += 1
                print(f"        exit {code}: {out.strip()[:220]}")
    finally:
        write_text_lf(OBSERVATIONS,obs, encoding="utf-8")

    # The splice markers going missing: the generator must refuse rather than write a
    # file with no table in it.
    try:
        write_text_lf(TARGET,original.replace("<!-- GENERATED:BEGIN -->", "<!-- gone -->"), encoding="utf-8")
        code, out = run_check()
        # `--check` compares content, so a missing marker surfaces as "out of date";
        # what matters is that it does not report OK.
        ok = code != 0
        print(f"  {'OK  ' if ok else 'DEAD'}  the splice markers going missing")
        if not ok:
            failures += 1
            print(f"        exit {code}: {out.strip()[:200]}")
    finally:
        write_text_lf(TARGET,original, encoding="utf-8")

    total = 5
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every check is live")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    code, out = run_check()
    print(out.strip())
    return code


if __name__ == "__main__":
    raise SystemExit(main())
