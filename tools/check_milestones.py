#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Decide whether a milestone's exit criteria are met, instead of asserting it in prose.

# Why this exists (`PLAN-003`)

The Proposal states each milestone's deliverable in a sentence -- *"AssemblyScript and Go pass the
conformance suite"*, *"Security audit #1 complete; benchmark suite published; first external users"* --
and nothing could decide whether one had been reached. A milestone that is "done" because someone says
so is the same defect as a count with no owner (`§O-277`), one level up.

`tools/milestones.json` turns each sentence into named checklist items, and this decides them against
`tools/backlog.json` (`PLAN-001`). The two are a pair: that one makes the checklist readable as data,
this one asks a question of it.

# The three answers, and why there are three

    MET       every criterion is `done`, and nothing external is outstanding
    OPEN      criteria remain, and nothing external is outstanding
    EXTERNAL  the milestone needs a party outside this repository

**`EXTERNAL` is not a polite way of saying `OPEN`.** M7 and M10 each require a *commissioned security
audit*, and `DOD-004` and `DOD-020` exist precisely so that no amount of local work can close them. A
checker that let those pass once their item lists were ticked would manufacture the false confidence
those items guard against -- so `--milestone M7` **fails while any `external` entry is declared**, and
says which one.

# The declaration is validated, not trusted

`check_checklist_counts.py` validates the arithmetic *and* the declaration; the same shape applies here.
A criterion that names an item the backlog does not contain is a failure, not a line that quietly does
nothing -- and a milestone with **no** criteria is a failure too, because `--milestone M0` on an empty
list would pass while deciding nothing. That is `§O-375`: a rule that cannot fire is worse than no rule.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


ROOT = Path(__file__).resolve().parent.parent
BACKLOG = ROOT / "tools" / "backlog.json"
DECLARED = ROOT / "tools" / "milestones.json"

# `M0` .. `M11`. The phase table also names `continuous` and `post-1.0`, which are not milestones.
MILESTONE = re.compile(r"\bM(\d{1,2})\b")


def load() -> tuple[dict, dict]:
    backlog = json.loads(BACKLOG.read_text(encoding="utf-8"))
    declared = json.loads(DECLARED.read_text(encoding="utf-8"))
    return backlog, declared


def phases_per_milestone(backlog: dict) -> dict[str, list[str]]:
    """Which phases the checklist assigns to each milestone. Read, never hard-coded."""
    out: dict[str, list[str]] = {}
    for phase, milestones in backlog["phase_milestones"].items():
        for m in MILESTONE.findall(milestones):
            out.setdefault(f"M{m}", []).append(phase)
    return out


def status_of(name: str, entry: dict, by_id: dict) -> tuple[str, list[str], list[str]]:
    """`(verdict, remaining criteria, external blockers)` for one milestone."""
    remaining = [c for c in entry["criteria"] if by_id.get(c, {}).get("status") != "done"]
    external = [f"{e['what']} -- {e['why']}" for e in entry.get("external", [])]
    if external:
        return "EXTERNAL", remaining, external
    if remaining:
        return "OPEN", remaining, external
    return "MET", remaining, external


def declaration_problems(backlog: dict, declared: dict) -> list[str]:
    """Everything wrong with `milestones.json` itself, before any milestone is judged."""
    problems: list[str] = []
    by_id = {i["id"]: i for i in backlog["items"]}
    entries = declared.get("milestones", {})

    # 1. Every milestone the phase table references must have an entry, or a release gate would be
    #    silently absent from the report.
    referenced = set(phases_per_milestone(backlog))
    for m in sorted(referenced - set(entries)):
        problems.append(f"{m} is referenced by a phase but has no declared criteria")

    # 2. Every criterion must name an item the backlog contains. A typo here is a criterion that
    #    decides nothing, and it would read as satisfied in a report.
    for m, entry in sorted(entries.items()):
        if not entry.get("criteria"):
            problems.append(f"{m} declares no criteria, so `--milestone {m}` would pass while deciding nothing")
        for c in entry.get("criteria", []):
            if c not in by_id:
                problems.append(f"{m} names `{c}`, which is not an item in the backlog")
            elif by_id[c]["status"] == "withdrawn":
                problems.append(f"{m} names `{c}`, which is withdrawn -- a stale criterion")
        for e in entry.get("external", []):
            if not e.get("what") or not e.get("why"):
                problems.append(f"{m} has an external entry without both a `what` and a `why`")

    # 3. A milestone the Proposal names but no phase assigns is a NOTICE, not a failure: a release
    #    gate's work is legitimately spread across the phases that precede it. It is reported because
    #    it is the kind of gap that goes unnoticed otherwise.
    return problems


def notices(backlog: dict, declared: dict) -> list[str]:
    referenced = set(phases_per_milestone(backlog))
    return [
        f"{m} is declared but no phase assigns items to it -- its work is spread across other phases"
        for m in sorted(set(declared.get("milestones", {})) - referenced)
    ]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="decide whether a milestone's exit criteria are met")
    ap.add_argument("--report", action="store_true", help="print every milestone and exit 0")
    ap.add_argument("--milestone", metavar="MX", help="exit 0 only if MX's criteria are met")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    backlog, declared = load()
    by_id = {i["id"]: i for i in backlog["items"]}
    entries = declared["milestones"]

    problems = declaration_problems(backlog, declared)
    if problems:
        print("MILESTONE DECLARATION INVALID -- the criteria cannot be trusted:", file=sys.stderr)
        for p in problems:
            print(f"    {p}", file=sys.stderr)
        return 1

    if args.milestone:
        m = args.milestone.upper()
        if m not in entries:
            print(f"unknown milestone `{m}`; declared: {', '.join(sorted(entries))}", file=sys.stderr)
            return 1
        verdict, remaining, external = status_of(m, entries[m], by_id)
        if verdict == "MET":
            print(f"{m} MET -- {len(entries[m]['criteria'])} criterion(a) satisfied, nothing external outstanding")
            return 0
        print(f"{m} NOT MET -- {verdict}", file=sys.stderr)
        for c in remaining:
            print(f"    remaining  {c}: {by_id[c]['title'][:80]}", file=sys.stderr)
        for e in external:
            print(f"    external   {e}", file=sys.stderr)
        return 1

    # The report. Exit 0 by design: most milestones are not met, and a gate that fails on that would
    # be switched off within a week. The executable form is `--milestone`.
    width = max(len(m) for m in entries)
    for m in sorted(entries, key=lambda k: int(k[1:])):
        entry = entries[m]
        verdict, remaining, external = status_of(m, entry, by_id)
        total = len(entry["criteria"])
        met = total - len(remaining)
        extra = f", {len(external)} external" if external else ""
        print(f"  {m:<{width}}  {verdict:<8} {met}/{total} criteria{extra}")
        if verdict != "MET":
            print(f"      {entry['delivers'][:96]}")

    for n in notices(backlog, declared):
        print(f"  NOTICE  {n}")

    met_count = sum(1 for m in entries if status_of(m, entries[m], by_id)[0] == "MET")
    print(f"MILESTONES OK -- {met_count} of {len(entries)} met; the rest report their real position")
    return 0


def self_test() -> int:
    """Every predicate fires on a mutation, and is silent on the real declaration."""
    failures = 0
    total = 0
    backlog, declared = load()
    by_id = {i["id"]: i for i in backlog["items"]}

    def case(name: str, fn) -> None:
        nonlocal failures, total
        total += 1
        ok = fn()
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1

    # 1. The real declaration must be clean, or every other case is measuring a broken baseline.
    case("the real declaration raises no problem", lambda: not declaration_problems(backlog, declared))

    # 2. An empty criteria list is a failure -- `--milestone MX` would pass while deciding nothing.
    def empty_criteria() -> bool:
        import copy
        d = copy.deepcopy(declared)
        d["milestones"]["M0"]["criteria"] = []
        return bool(declaration_problems(backlog, d))
    case("a milestone with no criteria is rejected", empty_criteria)

    # 3. A criterion naming an item that does not exist is a failure.
    def invented_id() -> bool:
        import copy
        d = copy.deepcopy(declared)
        d["milestones"]["M0"]["criteria"] = ["NOPE-999"]
        return any("NOPE-999" in p for p in declaration_problems(backlog, d))
    case("a criterion naming a non-existent item is rejected", invented_id)

    # 4. An external entry without a `why` is a failure -- the reason is the part a reader needs.
    def external_no_why() -> bool:
        import copy
        d = copy.deepcopy(declared)
        d["milestones"]["M7"]["external"] = [{"what": "an audit"}]
        return bool(declaration_problems(backlog, d))
    case("an external entry with no `why` is rejected", external_no_why)

    # 5. THE IMPORTANT ONE: a milestone with a satisfied criterion list but an outstanding external
    #    must NOT be MET. This is what stops M7 and M10 passing on local work alone.
    def external_blocks() -> bool:
        import copy
        d = copy.deepcopy(declared)
        d["milestones"]["M7"]["criteria"] = [i for i, it in by_id.items() if it["status"] == "done"][:3]
        verdict, _, external = status_of("M7", d["milestones"]["M7"], by_id)
        return verdict == "EXTERNAL" and len(external) == 2
    case("a satisfied criterion list does not let an external milestone pass", external_blocks)

    # 6. And the opposite: a milestone with no externals and no remaining criteria IS met.
    def met_works() -> bool:
        import copy
        d = copy.deepcopy(declared)
        d["milestones"]["M0"]["criteria"] = [i for i, it in by_id.items() if it["status"] == "done"][:3]
        verdict, _, _ = status_of("M0", d["milestones"]["M0"], by_id)
        return verdict == "MET"
    case("a satisfied criterion list with no externals is MET", met_works)

    if failures:
        print(f"SELF-TEST FAILED -- {failures} of {total} case(s) failed", file=sys.stderr)
        return 1
    print(f"SELF-TEST PASSED -- {total} case(s); the declaration is validated and the external gate holds")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
