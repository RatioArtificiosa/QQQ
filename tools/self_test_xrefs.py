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
    """Apply mutate(text)->text, run the validator, restore, report."""
    original = target.read_text(encoding="utf-8")
    mutated = mutate(original)
    if mutated == original:
        print(f"  SKIP  {name}: mutation was a no-op (the test itself is wrong)")
        return False
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


def main() -> int:
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
        "strip CAP-001's citation line",
        CHECKLIST,
        lambda t: re.sub(
            r"(?m)^- \[ \] \*\*CAP-001\*\*.*?\r?\n\s*→ §[^\r\n]*",
            "- [ ] **CAP-001** Implement the three capability kinds.",
            t, count=1),
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

    print("check [6] duplicate checklist ID")
    results.append(expect_failure(
        "duplicate CAP-001",
        CHECKLIST,
        lambda t: t.replace(
            "- [ ] **CAP-002**",
            "- [ ] **CAP-001** duplicate", 1),
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
