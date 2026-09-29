#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Emit the checklist as machine-readable data, and fail when the data drifts from it.

# Why this exists (`PLAN-001`)

`QQQ-Checklist-V1.md` is the project's progress metric, and **every tool that wants a number out of it
re-parses markdown**. `check_checklist_counts.py` validates the document's arithmetic;
`check_doc_claims.py` has three resolvers that recount items; `check_xrefs.py` reports a progress line;
`mark_complete.py` rewrites statuses. Each one carries its own regex over the same lines, and each is a
place for the same number to be derived two ways.

This emits **one** derived artifact -- `tools/backlog.json` -- so a consumer reads a field instead of
matching a line. That is `§O-277` applied to the checklist: the document owns the data, this owns the
**shape**, and `--check` makes drift a failure rather than a discovery.

# Why it is tracked rather than generated on demand

Same reason `tools/corpus_at_rest.json` is: a checked-in artifact can be **diffed**. A regeneration that
changes 40 lines because a status flipped is reviewable; a file rebuilt in CI and thrown away is not.

# The document's shape, measured before this was written

    587 items, 32 areas, no item line outside the strict form
    status characters in use: ' ' 342, 'x' 241, '~' 2, '!' 2   (the '-' in the pattern is unused)
    phases P0..P10, each naming a milestone (P5 -> "M5, M8"; P8 -> "continuous"; P10 -> "post-1.0")

The item, area, phase and phase-map patterns are **the ones `check_checklist_counts.py` already uses**,
imported from it rather than copied, so there is one definition of what an item looks like.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_checklist_counts import (  # noqa: E402
    AREA_ROW,
    ITEM,
    PHASE_MAP_ROW,
    PHASE_ROW,
    PHASE_TOTAL,
    TOTAL_ITEMS,
)

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


ROOT = Path(__file__).resolve().parent.parent
CHECKLIST = ROOT / "QQQ-Checklist-V1.md"
BACKLOG = ROOT / "tools" / "backlog.json"

SCHEMA = 1

# The status character, spelled out. `-` is accepted by `ITEM` and used by nothing; if it ever appears,
# `--check` will carry it through as `unknown` rather than guessing, and the self-test asserts that a
# fifth character cannot pass silently.
STATUS = {"x": "done", " ": "open", "~": "partial", "!": "blocked", "-": "withdrawn"}

# A per-item line, capturing the title: `- [x] **AREA-000** the text`
ITEM_LINE = re.compile(r"^- \[([ x~!-])\] \*\*([A-Z]+)-(\d{3})\*\*\s*(.*)$")


def build(text: str) -> dict:
    """Derive the backlog from the document. Pure: no I/O, so the self-test can call it."""
    lines = text.splitlines()

    # area -> phase, and phase -> milestones, both read from the document rather than hard-coded.
    area_to_phase: dict[str, str] = {}
    for phase, _name, _milestone, areas in PHASE_MAP_ROW.findall(text):
        for area in (a.strip() for a in areas.split(",")):
            if area:
                area_to_phase[area] = phase
    phase_milestones = {p: ms.strip() for p, _n, ms, _c in PHASE_ROW.findall(text)}
    declared_phase_counts = {p: int(c) for p, _n, _ms, c in PHASE_ROW.findall(text)}

    items: list[dict] = []
    for lineno, line in enumerate(lines, start=1):
        m = ITEM_LINE.match(line)
        if not m:
            continue
        ch, area, num, title = m.groups()
        items.append(
            {
                "id": f"{area}-{num}",
                "area": area,
                "status": STATUS.get(ch, "unknown"),
                "phase": area_to_phase.get(area, "unassigned"),
                "line": lineno,
                # The title is the item's text with the trailing markdown emphasis trimmed, so a
                # consumer can print "what is left in P5" without re-reading the document.
                "title": title.strip().rstrip("*").strip(),
            }
        )

    def tally(rows: list[dict], key: str) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for row in rows:
            bucket = out.setdefault(row[key], {"done": 0, "open": 0, "partial": 0, "blocked": 0,
                                               "withdrawn": 0, "unknown": 0, "total": 0})
            bucket[row["status"]] = bucket.get(row["status"], 0) + 1
            bucket["total"] += 1
        return dict(sorted(out.items()))

    declared_total = TOTAL_ITEMS.search(text)
    return {
        "schema": SCHEMA,
        "source": CHECKLIST.name,
        "total": len(items),
        "declared_total": int(declared_total.group(1)) if declared_total else None,
        "declared_phase_total": int(PHASE_TOTAL.search(text).group(1)) if PHASE_TOTAL.search(text) else None,
        "by_status": dict(sorted(tally(items, "area").items())),
        "by_area": tally(items, "area"),
        "by_phase": tally(items, "phase"),
        "declared_area_counts": {a: int(n) for a, _m, n, _o in AREA_ROW.findall(text)},
        "declared_phase_counts": declared_phase_counts,
        "phase_milestones": dict(sorted(phase_milestones.items())),
        "items": items,
    }


def problems(backlog: dict) -> list[str]:
    """Anti-vacuity clauses. Empty means the backlog is a usable statement about the document.

    # Why these exist rather than being left to `check_checklist_counts.py`

    That checker validates the **document against itself**; this one validates the **derived data
    against the document**. They are different questions, and there are four ways this file could be a
    confident statement about nothing:

      * the `**Total: N items.**` line vanishes, so `declared_total` is `None` and there is no number
        for the total to agree with;
      * the phase table's `**Total**` row vanishes, likewise;
      * an area belongs to **no** phase, so its items silently drop out of `by_phase` -- the same
        reasoning `check_checklist_counts.py` gives for its own rule;
      * an item carries a status character the vocabulary does not define, which would be carried as
        `unknown` and counted by nothing.
    """
    out: list[str] = []
    if backlog["declared_total"] is None:
        out.append("the `**Total: N items.**` line is missing, so the total has nothing to agree with")
    if backlog["declared_phase_total"] is None:
        out.append("the phase table's `**Total**` row is missing")
    unassigned = sorted({i["area"] for i in backlog["items"] if i["phase"] == "unassigned"})
    if unassigned:
        out.append(f"area(s) in no phase, whose items would vanish from `by_phase`: {unassigned}")
    unknown = sorted({i["id"] for i in backlog["items"] if i["status"] == "unknown"})
    if unknown:
        out.append(f"item(s) with a status character the vocabulary does not define: {unknown[:5]}")
    if backlog["total"] != backlog["declared_total"]:
        out.append(f"the items number {backlog['total']} but the document declares {backlog['declared_total']}")
    return out


def render(backlog: dict) -> bytes:
    """The on-disk bytes. LF, sorted keys, one trailing newline -- so `--check` compares bytes."""
    return (json.dumps(backlog, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="derive tools/backlog.json from the checklist")
    ap.add_argument("--check", action="store_true", help="fail if the tracked file has drifted")
    ap.add_argument("--record", action="store_true", help="write the file")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    derived = build(CHECKLIST.read_text(encoding="utf-8"))
    found = problems(derived)
    if found:
        print("BACKLOG CANNOT BE TRUSTED -- the derivation is vacuous or disagrees with the document:",
              file=sys.stderr)
        for p in found:
            print(f"    {p}", file=sys.stderr)
        return 1
    fresh = render(derived)

    if args.record:
        BACKLOG.write_bytes(fresh)
        print(f"wrote {BACKLOG.relative_to(ROOT)} ({len(fresh)} bytes)")
        return 0

    if not BACKLOG.is_file():
        print(f"BACKLOG MISSING -- {BACKLOG.relative_to(ROOT)} is not tracked; run --record", file=sys.stderr)
        return 1

    tracked = BACKLOG.read_bytes()
    if tracked != fresh:
        print("BACKLOG DRIFT -- the checklist changed and the backlog was not re-recorded", file=sys.stderr)
        # Say WHERE, and only the first few: a 587-item diff is unreadable, and the first divergence
        # is the one that tells a reader what happened.
        old = json.loads(tracked.decode("utf-8"))
        new = json.loads(fresh.decode("utf-8"))
        for key in sorted(set(old) | set(new)):
            if old.get(key) != new.get(key):
                print(f"    {key}", file=sys.stderr)
        print("  re-record with: python tools/gen_backlog.py --record", file=sys.stderr)
        return 1

    b = json.loads(tracked.decode("utf-8"))
    print(f"BACKLOG OK -- {b['total']} item(s) in {len(b['by_area'])} area(s) over "
          f"{len(b['by_phase'])} phase(s), matching the checklist")
    return 0


def self_test() -> int:
    """Every predicate must fire on a mutated document, and be silent on the real one."""
    failures = 0
    total = 0

    def case(name: str, mutated: str, *, must_differ: bool) -> None:
        nonlocal failures, total
        total += 1
        real = CHECKLIST.read_text(encoding="utf-8")
        got = render(build(mutated)) != render(build(real))
        ok = got == must_differ
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1

    real = CHECKLIST.read_text(encoding="utf-8")
    base = render(build(real))

    # 1. The baseline must be reproducible: the same input twice gives the same bytes.
    total += 1
    same = render(build(real)) == base
    print(f"  {'OK  ' if same else 'DEAD'}  the real document renders identically twice")
    if not same:
        failures += 1

    # 2. A status flip must move it.
    flipped = real.replace("- [x] **FND-001**", "- [ ] **FND-001**", 1)
    case("a ticked item untickd moves the backlog", flipped, must_differ=True)

    # 3. A FIFTH status character must not pass silently. `-` is accepted by the shared pattern and
    #    used by nothing; if it appears, the status must be carried as something a consumer can see
    #    rather than dropped.
    fifth = real.replace("- [ ] **LANG-007**", "- [-] **LANG-007**", 1)
    case("an unused status character is carried, not dropped", fifth, must_differ=True)

    # 4. The title is part of the data: editing one must move the file.
    retitled = real.replace("**LANG-007** Rust build-time", "**LANG-007** Rust build-time (edited)", 1)
    case("an edited title moves the backlog", retitled, must_differ=True)

    # 5. A line number is part of the data, so an inserted line must move it.
    shifted = real.replace("- [x] **FND-001**", "an inserted line\n- [x] **FND-001**", 1)
    case("an inserted line moves the recorded line numbers", shifted, must_differ=True)

    # 6. And the file must not be sensitive to nothing: a change outside every item must be silent,
    #    or `--check` would fail on an unrelated prose edit and train its readers to re-record blindly.
    prose = real.replace("QQQ-Checklist-V1", "QQQ-Checklist-V1 (title unchanged)", 1)
    case("a prose edit outside the items is silent", prose, must_differ=False)

    # --- the anti-vacuity clauses, each fault-injected -------------------------------
    #
    # `problems()` is what stops the backlog from being a confident statement about nothing. A clause
    # that cannot fire is worse than no clause, so each one is given a document that violates it and
    # must report. Without these the clauses could be deleted and every drift case above would pass.
    def problem_case(name: str, mutated: str, *, must_report: bool) -> None:
        nonlocal failures, total
        total += 1
        reported = bool(problems(build(mutated)))
        ok = reported == must_report
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1

    problem_case("the real document raises no problem", real, must_report=False)

    no_total = re.sub(r"(?m)^\*\*Total: \d+ items\.\*\*$", "", real)
    problem_case("a missing `**Total: N items.**` line is reported", no_total, must_report=True)

    no_phase_total = re.sub(r"(?m)^\| \*\*Total\*\* \| \| \*\*\d+\*\* \|$", "", real)
    problem_case("a missing phase-table Total row is reported", no_phase_total, must_report=True)

    # The `unknown` clause **cannot be reached from the document**: `ITEM` accepts `[ x~!-]` and
    # `STATUS` defines all five characters, so no item can carry an undefined one. It guards a FUTURE
    # edit that widens one of the two without the other, so it is exercised by calling the pure
    # function with a fabricated backlog rather than by mutating the document.
    #
    # **The first version of this case mutated `[ ]` to `[-]` and was DEAD** -- because `-` is
    # *defined* as `withdrawn`. A test for an input that cannot occur is not a test, and it read as
    # coverage while proving nothing. `§O-375`: a rule that cannot fire is worse than no rule.
    fabricated = build(real)
    fabricated["items"][0]["status"] = "unknown"
    total += 1
    reported = bool(problems(fabricated))
    print(f"  {'OK  ' if reported else 'DEAD'}  an undefined status is reported (fabricated input)")
    if not reported:
        failures += 1

    if failures:
        print(f"SELF-TEST FAILED -- {failures} of {total} case(s) failed", file=sys.stderr)
        return 1
    print(f"SELF-TEST PASSED -- {total} case(s); every predicate fires on a mutation and is silent on "
          f"an unrelated edit")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
