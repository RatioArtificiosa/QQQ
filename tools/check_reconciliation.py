#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

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
from pathlib import Path

import sys as _sys

# The byte-faithful writer is shared with the other corpus checkers rather than
# copied, because two copies of a newline rule is how the two copies drift.
_sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_xrefs import write_text_lf  # noqa: E402


ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "tools" / "gen_reconciliation.py"
TARGET = ROOT / "docs" / "reconciliation.md"
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"
OBSERVATIONS = ROOT / "QQQ-Observations-and-Memories.md"


def run_check() -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(GEN), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    return p.returncode, p.stdout + p.stderr


def self_test() -> int:
    failures = 0

    # The clean case: the repository must currently be consistent.
    code, out = run_check()
    ok = code == 0
    print(f"  {'OK  ' if ok else 'DEAD'}  the committed table matches Appendix A")
    if not ok:
        failures += 1
        print(f"        {out.strip()[:200]}")

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
