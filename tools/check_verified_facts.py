#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Verify `docs/verified-facts.md` matches Appendix B (`DOC-016`).

A wrapper over `tools/gen_verified_facts.py --check`, with a self-test.

# The property that matters

Every fact must be **classified** — assigned a re-verification cadence. An unclassified
fact is one nobody will think to re-check, which is the failure the whole register
exists to prevent: a value quietly wrong, in the document whose purpose is to say which
values are trustworthy.

The generator reports unclassified rows rather than guessing, and this checker turns
that report into a failure. Two rules were added because of that report while building
it — the first pass left 8 of 30 facts unclassified, all of them API and specification
properties.

Usage:
    python tools/check_verified_facts.py
    python tools/check_verified_facts.py --self-test
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "tools" / "gen_verified_facts.py"
TARGET = ROOT / "docs" / "verified-facts.md"
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"

sys.path.insert(0, str(ROOT / "tools"))
import gen_verified_facts as gen  # noqa: E402


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

    def case(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            if detail:
                print(f"        {detail[:220]}")

    # Each cadence class must be reachable, or a rule is dead.
    samples = [
        ("perishable", "Wasmtime latest stable", "crates.io API"),
        ("volatile", "`qqq` on npm", "npm registry API"),
        ("local", "Local toolchain: rustc 1.97.1", "`rustc --version`"),
        ("stable", "Wasmtime licence", "GitHub API `license`"),
    ]
    for expected, fact, method in samples:
        cls, cadence, _why = gen.classify(fact, method)
        case(
            f"classifies {fact[:40]!r} as {expected}",
            cls == expected and bool(cadence),
            f"got class={cls!r} cadence={cadence!r}",
        )

    # The referral case, which was added because two rows use "Same document".
    cls, _cadence, _why = gen.classify("some fact", "Same document")
    case("classifies a `Same document` referral", cls != "", f"got {cls!r}")

    # **No unclassified rows in the real register.** This is the substantive check.
    rows = gen.parse_appendix_b(PROPOSAL.read_text(encoding="utf-8"))
    unclassified = [
        r["id"] for r in rows if not gen.classify(r["fact"], r["method"])[0]
    ]
    case(
        "every Appendix B fact has a cadence",
        not unclassified,
        f"unclassified: {unclassified} — an unclassified fact is one nobody will "
        f"think to re-check",
    )

    # Every fact must reach the generated page.
    text = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
    missing = [r["id"] for r in rows if f"`{r['id']}`" not in text]
    case("every fact appears in the register", not missing, f"missing: {missing}")

    # **One section per cadence class.** `CLASSES` holds *rules*, and a class may need
    # more than one (`volatile` has two, `stable` has two). Both emitters iterated
    # `CLASSES` directly, so a two-rule class printed its summary row twice and its whole
    # section twice, with every one of its facts listed under each. The page claimed "30 of
    # 30 facts classified" while rendering 48 rows.
    #
    # Nothing else could see it. `check_verified_facts.py` compares the page against
    # Appendix B, and a duplicated section agrees with Appendix B exactly as well as a
    # single one — so the one checker whose job is this page was blind to a page that
    # contradicted itself. Counting the headings is what catches it.
    names = [c[0] for c in gen.distinct_classes()]
    case(
        "each cadence class is emitted once",
        len(names) == len(set(names)) and len(names) > 0,
        f"distinct_classes returned {names}",
    )
    headings = [
        line for line in text.splitlines() if line.startswith("## ") and "re-verify" in line
    ]
    case(
        "no cadence section is duplicated in the register",
        len(headings) == len(set(headings)),
        f"headings: {headings}",
    )

    # The committed file matches the source.
    code, out = run_check()
    case("the committed register matches Appendix B", code == 0, out.strip())

    # A hand-edit must be caught.
    original = text
    try:
        if original:
            TARGET.write_text(original + "\n### `B-99` — invented\n", encoding="utf-8")
            code, out = run_check()
            case("a hand-edit to the register", code != 0, out.strip())
    finally:
        if original:
            TARGET.write_text(original, encoding="utf-8")

    total = len(samples) + 8
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(
        f"SELF-TEST PASSED -- {total}/{total} case(s), every check is live "
        f"({len(rows)} fact(s), all classified)"
    )
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    code, out = run_check()
    print(out.strip())
    return code


if __name__ == "__main__":
    raise SystemExit(main())
