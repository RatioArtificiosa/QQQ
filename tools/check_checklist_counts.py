#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The checklist's own arithmetic, checked against the checklist.

# Why this exists

`QQQ-Checklist-V1.md` states its size three times, and all three were wrong:

| Place | Said | Truth |
|---|---|---|
| §1 area table, `Total:` line | 578 | 586 |
| §1 area table, its own rows | summed to 587 | 586 |
| §14 phase table, `Total` row | 586 | 586, but its rows summed to 568 |

Five per-area counts disagreed with the document they summarise (`DOC` 20 vs 21,
`AGENT` 24 vs 25, `PERF` 26 vs 27, `SUP` 14 vs 12, `CON` 20 vs 18). Nothing checked
any of it, so it drifted the way every hand-maintained total drifts.

# Why it matters beyond tidiness

This file is the project's progress metric. A percentage against a total nothing
measures is not a measurement, and the two directions of error are not symmetric:
a total that is *too low* makes the project look further along than it is, which is
the direction that stops work. It is also the number a reader quotes when they want
to know how much is left.

# What is checked

1. Every area's declared `Count` equals the number of `- [x] **AREA-NNN**` items in
   that area.
2. The §1 `**Total: N items.**` line equals the sum of the declared counts, which by
   (1) equals the number of items.
3. Every phase's declared `Items` equals the sum of the areas §2 assigns to it.
4. The §14 `**Total**` row equals the sum of the phase rows.

The phase-to-area map is read from §2 rather than hard-coded, so adding an area to a
phase is one edit in one place — and an area that appears in **no** phase is an error,
because its items would silently vanish from the phase table.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKLIST = ROOT / "QQQ-Checklist-V1.md"

ITEM = re.compile(r"^- \[[ x~!-]\] \*\*([A-Z]+)-(\d{3})\*\*", re.MULTILINE)
AREA_ROW = re.compile(r"^\| `([A-Z]+)` \| ([^|]+?) \| (\d+) \| ([^|]+?) \|$", re.MULTILINE)
TOTAL_ITEMS = re.compile(r"^\*\*Total: (\d+) items\.\*\*$", re.MULTILINE)
PHASE_ROW = re.compile(r"^\| \*{0,2}(P\d+) ([^|*]+?)\*{0,2} \| ([^|]+?) \| (\d+) \|$", re.MULTILINE)
PHASE_MAP_ROW = re.compile(r"^\| \*\*(P\d+)\*\* \| ([^|]+?) \| ([^|]+?) \| ([^|]+?) \|$", re.MULTILINE)
PHASE_TOTAL = re.compile(r"^\| \*\*Total\*\* \| \| \*\*(\d+)\*\* \|$", re.MULTILINE)


def counts_by_area(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for area, _num in ITEM.findall(text):
        out[area] = out.get(area, 0) + 1
    return out


def declared_areas(text: str) -> dict[str, int]:
    return {area: int(n) for area, _meaning, n, _owner in AREA_ROW.findall(text)}


def phase_map(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for phase, _name, _milestone, areas in PHASE_MAP_ROW.findall(text):
        out[phase] = [a.strip() for a in areas.split(",") if a.strip()]
    return out


def declared_phases(text: str) -> dict[str, int]:
    return {phase: int(n) for phase, _name, _milestone, n in PHASE_ROW.findall(text)}


def analyse(text: str) -> list[str]:
    """Return a list of problems. Empty means the document agrees with itself."""
    problems: list[str] = []
    actual = counts_by_area(text)
    declared = declared_areas(text)
    total_line = TOTAL_ITEMS.search(text)

    for area in sorted(set(actual) | set(declared)):
        want = declared.get(area)
        got = actual.get(area, 0)
        if want is None:
            problems.append(f"`{area}` has {got} item(s) but no row in the §1 area table")
        elif want != got:
            problems.append(f"§1 says `{area}` has {want}, the document has {got}")

    if total_line is None:
        problems.append("the §1 `**Total: N items.**` line is missing")
    else:
        stated = int(total_line.group(1))
        if stated != sum(declared.values()):
            problems.append(
                f"§1 states `Total: {stated}` but its own rows sum to {sum(declared.values())}"
            )
        if stated != sum(actual.values()):
            problems.append(
                f"§1 states `Total: {stated}` but the document has {sum(actual.values())} items"
            )

    mapping = phase_map(text)
    phases = declared_phases(text)
    covered = {a for areas in mapping.values() for a in areas}

    for area in sorted(set(actual) - covered):
        problems.append(f"`{area}` is in no phase in §2, so its items vanish from §14")

    for phase in sorted(set(mapping) | set(phases)):
        areas = mapping.get(phase)
        if areas is None:
            problems.append(f"§14 lists `{phase}` but §2 does not map it to any area")
            continue
        want = sum(actual.get(a, 0) for a in areas)
        got = phases.get(phase)
        if got is None:
            problems.append(f"§2 maps `{phase}` but §14 has no row for it")
        elif got != want:
            problems.append(
                f"§14 says `{phase}` has {got}, its areas ({', '.join(areas)}) sum to {want}"
            )

    total_row = PHASE_TOTAL.search(text)
    if total_row is None:
        problems.append("the §14 `**Total**` row is missing")
    else:
        stated = int(total_row.group(1))
        if stated != sum(phases.values()):
            problems.append(
                f"§14 states `Total = {stated}` but its phase rows sum to {sum(phases.values())}"
            )
        if stated != sum(actual.values()):
            problems.append(
                f"§14 states `Total = {stated}` but the document has {sum(actual.values())} items"
            )

    return problems


def fix(text: str) -> str:
    """Rewrite both tables from the items themselves."""
    actual = counts_by_area(text)

    def area_row(m: re.Match[str]) -> str:
        area, meaning, _n, owner = m.groups()
        return f"| `{area}` | {meaning} | {actual.get(area, 0)} | {owner} |"

    text = AREA_ROW.sub(area_row, text)
    text = TOTAL_ITEMS.sub(
        lambda m: f"**Total: {sum(actual.values())} items.**", text
    )

    mapping = phase_map(text)

    def phase_row(m: re.Match[str]) -> str:
        phase, name, milestone, _n = m.groups()
        areas = mapping.get(phase, [])
        return f"| {phase} {name} | {milestone} | {sum(actual.get(a, 0) for a in areas)} |"

    text = PHASE_ROW.sub(phase_row, text)
    text = PHASE_TOTAL.sub(
        lambda m: f"| **Total** | | **{sum(actual.values())}** |", text
    )
    return text


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()

    text = CHECKLIST.read_text(encoding="utf-8")

    if "--fix" in sys.argv:
        fixed = fix(text)
        if fixed == text:
            print("nothing to fix: the checklist already agrees with itself")
            return 0
        write_text_lf(CHECKLIST,fixed, encoding="utf-8")
        print("rewrote the §1 area table and the §14 phase table from the items")
        problems = analyse(fixed)
        if problems:
            print("STILL INCONSISTENT:")
            for p in problems:
                print(f"  {p}")
            return 1
        return 0

    problems = analyse(text)
    if problems:
        for p in problems:
            print(f"  DRIFT: {p}")
        print("  Run `python tools/check_checklist_counts.py --fix` to regenerate both tables.")
        return 1

    actual = counts_by_area(text)
    print(
        f"CHECKLIST COUNTS OK -- {len(actual)} area(s), {sum(actual.values())} item(s), "
        f"§1 and §14 agree with the document"
    )
    return 0


def self_test() -> int:
    """Prove each check can fail, by breaking a copy of the real document."""
    failures = 0
    total = 0

    def case(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures, total
        total += 1
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            if detail:
                print(f"        {detail[:220]}")

    real = CHECKLIST.read_text(encoding="utf-8")

    case("the real checklist is consistent", not analyse(real), "; ".join(analyse(real)))

    # 1. A per-area count that disagrees with the items.
    broken = real.replace("| `CAP` | Capability resolution pipeline | 16 |", "| `CAP` | Capability resolution pipeline | 99 |", 1)
    case(
        "a wrong per-area count is caught",
        any("CAP" in p for p in analyse(broken)),
        "; ".join(analyse(broken)),
    )

    # 2. A total line that disagrees with the rows.
    broken = TOTAL_ITEMS.sub("**Total: 578 items.**", real, count=1)
    case(
        "a wrong §1 total is caught",
        any("§1 states" in p for p in analyse(broken)),
        "; ".join(analyse(broken)),
    )

    # 3. A phase row that disagrees with its areas.
    broken = re.sub(r"^\| P2 Capability engine \| M2 \| 46 \|$", "| P2 Capability engine | M2 | 7 |", real, count=1, flags=re.MULTILINE)
    case(
        "a wrong §14 phase count is caught",
        any("P2" in p for p in analyse(broken)),
        "; ".join(analyse(broken)),
    )

    # 4. The §14 total row.
    broken = PHASE_TOTAL.sub("| **Total** | | **1** |", real, count=1)
    case(
        "a wrong §14 total is caught",
        any("§14 states" in p for p in analyse(broken)),
        "; ".join(analyse(broken)),
    )

    # 5. An area assigned to no phase — its items would vanish from §14.
    broken = real.replace("| **P10** | Beyond V1 | post-1.0 | FUT, AI, OQ |", "| **P10** | Beyond V1 | post-1.0 | FUT, AI |", 1)
    case(
        "an area in no phase is caught",
        any("no phase" in p for p in analyse(broken)),
        "; ".join(analyse(broken)),
    )

    # 6. `--fix` must produce a document that passes, and must not be a no-op on a broken
    #    one. Without this the fixer could be silently writing nothing.
    fixed = fix(real)
    case("--fix leaves a correct document unchanged", fixed == real)
    broken = TOTAL_ITEMS.sub("**Total: 578 items.**", real, count=1)
    case(
        "--fix repairs a broken total",
        not analyse(fix(broken)) and fix(broken) != broken,
    )

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} of {total} case(s) not detected")
        return 1
    # `total` rather than a literal. The first version hard-coded "6/6" and printed it
    # under a list of eight cases -- a summary that disagreed with the thing it summarised,
    # which is precisely the defect this checker exists to catch in the checklist.
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every check is live")
    return 0


if __name__ == "__main__":
    sys.exit(main())
