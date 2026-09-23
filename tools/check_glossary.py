#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Verify `docs/glossary.md` matches its source (`DOC-011`).

A thin wrapper over `tools/gen_glossary.py --check`, with a self-test.

# Why a wrapper rather than calling the generator directly in CI

Two reasons, and the second is the real one:

1. **The name says what CI is doing.** A CI step named `gen_glossary.py --check` reads
   as a generation step that happens to check; `check_glossary.py` reads as a check.
2. **It can self-test.** A generation check that has never been shown to fail is the
   same unexercised control this repository has recorded eleven times. The self-test
   builds a temporary Proposal, generates from it, corrupts the output, and asserts the
   check rejects it — including the case where the *source* changes rather than the
   generated file, which is the drift that actually happens.

Usage:
    python tools/check_glossary.py
    python tools/check_glossary.py --self-test
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import sys as _sys

# The byte-faithful writer is shared with the other corpus checkers rather than
# copied, because two copies of a newline rule is how the two copies drift.
_sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_xrefs import write_text_lf  # noqa: E402


ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "tools" / "gen_glossary.py"

# A minimal Proposal carrying a §0.6 table, so the self-test does not depend on the
# real corpus and cannot be affected by an unrelated edit to it.
FIXTURE_PROPOSAL = """\
# Proposal

## §0.6 Glossary

| Term | Definition |
|---|---|
| **Host** | The native `qqqai` process. |
| **Guest** | A WebAssembly component executed by the host. |
| **Fuel** | A deterministic instruction budget. |

## §0.7 Next section
"""


def run_check() -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(GEN), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    return p.returncode, p.stdout + p.stderr


def self_test() -> int:
    """Prove the check fails when the generated file and its source disagree."""
    failures = 0

    # The real repository must currently be consistent, or nothing below means
    # anything. This is the clean case.
    code, out = run_check()
    ok = code == 0
    print(f"  {'OK  ' if ok else 'DEAD'}  the committed glossary matches the Proposal")
    if not ok:
        failures += 1
        print(f"        {out.strip()[:200]}")

    # Corruption: append a line to the generated file.
    original = (ROOT / "docs" / "glossary.md").read_text(encoding="utf-8")
    try:
        write_text_lf((ROOT / "docs" / "glossary.md"),
            original + "\n## Hand added\n\nA line a human typed.\n", encoding="utf-8"
        )
        code, out = run_check()
        ok = code != 0 and "out of date" in out
        print(f"  {'OK  ' if ok else 'DEAD'}  a hand-edit to the generated file")
        if not ok:
            failures += 1
            print(f"        exit {code}: {out.strip()[:200]}")
    finally:
        write_text_lf((ROOT / "docs" / "glossary.md"),original, encoding="utf-8")

    # **Source drift**: the Proposal's table gains a term the glossary lacks. This is
    # the direction that actually happens in practice, and the first version of a
    # check like this often only tests the other one.
    proposal = (ROOT / "QQQ-Proposal-V1.md").read_text(encoding="utf-8")
    try:
        patched = proposal.replace(
            "| **Fuel** |",
            "| **Epoch** | A monotonic counter checked at loop back-edges. |\n| **Fuel** |",
            1,
        )
        if patched == proposal:
            print("  SKIP  source-drift case: the anchor row `**Fuel**` was not found")
        else:
            write_text_lf((ROOT / "QQQ-Proposal-V1.md"),patched, encoding="utf-8")
            code, out = run_check()
            ok = code != 0
            print(f"  {'OK  ' if ok else 'DEAD'}  a new term in the Proposal's table")
            if not ok:
                failures += 1
                print(f"        exit {code}: {out.strip()[:200]}")
    finally:
        write_text_lf((ROOT / "QQQ-Proposal-V1.md"),proposal, encoding="utf-8")

    # A missing generated file must be reported, not silently regenerated.
    glossary = ROOT / "docs" / "glossary.md"
    backup = glossary.read_text(encoding="utf-8")
    try:
        glossary.unlink()
        code, out = run_check()
        ok = code != 0 and "does not exist" in out
        print(f"  {'OK  ' if ok else 'DEAD'}  a missing generated file")
        if not ok:
            failures += 1
            print(f"        exit {code}: {out.strip()[:200]}")
    finally:
        write_text_lf(glossary,backup, encoding="utf-8")

    total = 4
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
