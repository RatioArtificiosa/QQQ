#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render the tracked milestone dashboard from the canonical checklist backlog.

`tools/gen_backlog.py` owns the checklist-to-data transformation and
`tools/check_milestones.py` owns milestone exit semantics.  This tool is the
read-only presentation layer between them: it validates the tracked backlog,
reuses the milestone declaration checker, and emits a deterministic Markdown
artifact suitable for humans, reviews, and release evidence.

The dashboard deliberately counts only `done` items as complete.  `partial`,
`blocked`, `open`, `withdrawn`, and `unknown` remain visible so a percentage
cannot manufacture progress by collapsing non-done states.  `--check` fails
on either aggregate drift or a stale tracked document; `--self-test` exercises
both failure paths and the external milestone gate.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
from pathlib import Path

from check_milestones import (  # noqa: E402
    declaration_problems,
    notices,
    status_of,
)

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


ROOT = Path(__file__).resolve().parent.parent
BACKLOG = ROOT / "tools" / "backlog.json"
DECLARED = ROOT / "tools" / "milestones.json"
OUTPUT = ROOT / "docs" / "milestone-dashboard.md"

SCHEMA = 1
STATUS_ORDER = ("done", "partial", "open", "blocked", "withdrawn", "unknown")
REQUIRED_ITEM_FIELDS = {"area", "id", "phase", "status", "title"}


def load() -> tuple[dict, dict]:
    backlog = json.loads(BACKLOG.read_text(encoding="utf-8"))
    declared = json.loads(DECLARED.read_text(encoding="utf-8"))
    return backlog, declared


def phase_key(phase: str) -> tuple[int, str]:
    """Sort P0..P10 numerically, with non-phase labels after them."""
    if phase.startswith("P") and phase[1:].isdigit():
        return int(phase[1:]), ""
    return 10_000, phase


def tally(items: list[dict], key: str) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for item in items:
        bucket = out.setdefault(item[key], {status: 0 for status in STATUS_ORDER} | {"total": 0})
        status = item["status"]
        bucket[status] = bucket.get(status, 0) + 1
        bucket["total"] += 1
    return dict(sorted(out.items()))


def validate_backlog(backlog: dict) -> list[str]:
    """Validate the shape and all redundant aggregates before rendering."""
    problems: list[str] = []
    if backlog.get("schema") != SCHEMA:
        problems.append(f"unsupported backlog schema: {backlog.get('schema')!r}")

    items = backlog.get("items")
    if not isinstance(items, list):
        return ["backlog `items` is not a list"]
    if not items:
        problems.append("backlog `items` is empty")

    ids: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            problems.append(f"item {index} is not an object")
            continue
        missing = sorted(REQUIRED_ITEM_FIELDS - set(item))
        if missing:
            problems.append(f"item {index} is missing fields: {', '.join(missing)}")
            continue
        item_id = item["id"]
        if item_id in ids:
            problems.append(f"duplicate item id: {item_id}")
        ids.add(item_id)
        if item["status"] not in STATUS_ORDER:
            problems.append(f"{item_id} has unsupported status {item['status']!r}")
        if not isinstance(item["title"], str) or not item["title"].strip():
            problems.append(f"{item_id} has an empty title")

    expected_total = len(items)
    if backlog.get("total") != expected_total:
        problems.append(f"backlog total is {backlog.get('total')}, items contain {expected_total}")

    if isinstance(items, list) and all(isinstance(item, dict) and REQUIRED_ITEM_FIELDS <= set(item) for item in items):
        expected_area = tally(items, "area")
        expected_phase = tally(items, "phase")
        if backlog.get("by_area") != expected_area:
            problems.append("by_area does not equal the item-level status tally")
        if backlog.get("by_phase") != expected_phase:
            problems.append("by_phase does not equal the item-level status tally")

    for field in ("by_area", "by_phase", "phase_milestones"):
        if not isinstance(backlog.get(field), dict):
            problems.append(f"backlog `{field}` is not an object")
    return problems


def complete_percent(bucket: dict[str, int]) -> str:
    total = bucket["total"]
    return f"{(100 * bucket['done'] / total):.1f}%" if total else "0.0%"


def count_cells(bucket: dict[str, int]) -> str:
    return " | ".join(str(bucket[status]) for status in STATUS_ORDER) + f" | {bucket['total']} | {complete_percent(bucket)}"


def phase_rows(backlog: dict) -> list[tuple[str, dict[str, int]]]:
    return sorted(backlog["by_phase"].items(), key=lambda row: phase_key(row[0]))


def area_rows(backlog: dict) -> list[tuple[str, str, dict[str, int]]]:
    phase_by_area: dict[str, set[str]] = {}
    for item in backlog["items"]:
        phase_by_area.setdefault(item["area"], set()).add(item["phase"])
    rows: list[tuple[str, str, dict[str, int]]] = []
    for area, bucket in backlog["by_area"].items():
        phases = phase_by_area.get(area, set())
        phase = ", ".join(sorted(phases, key=phase_key))
        rows.append((phase, area, bucket))
    return sorted(rows, key=lambda row: (phase_key(row[0].split(", ")[0]), row[1]))


def render(backlog: dict, declared: dict) -> bytes:
    problems = validate_backlog(backlog)
    if problems:
        raise ValueError("cannot render an invalid backlog: " + "; ".join(problems))
    declaration = declaration_problems(backlog, declared)
    if declaration:
        raise ValueError("cannot render invalid milestone declarations: " + "; ".join(declaration))

    # Normalize the item-level statuses so the table uses exactly the same
    # columns as area and phase rows.
    overall_bucket = {status: 0 for status in STATUS_ORDER} | {"total": len(backlog["items"])}
    for item in backlog["items"]:
        overall_bucket[item["status"]] += 1

    lines = [
        "# Milestone dashboard",
        "",
        "> Generated from `tools/backlog.json` and `tools/milestones.json`; do not edit this file by hand.",
        "> `done` is the only complete state. Partial, blocked, open, withdrawn, and unknown items remain visible.",
        "",
        "## Overall",
        "",
        "| Scope | Done | Partial | Open | Blocked | Withdrawn | Unknown | Total | Complete |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        f"| All checklist items | {count_cells(overall_bucket)} |",
        "",
        "## By phase",
        "",
        "| Phase | Milestone(s) | Done | Partial | Open | Blocked | Withdrawn | Unknown | Total | Complete |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for phase, bucket in phase_rows(backlog):
        lines.append(f"| {phase} | {backlog['phase_milestones'].get(phase, 'unassigned')} | {count_cells(bucket)} |")

    lines.extend(
        [
            "",
            "## By area",
            "",
            "| Phase | Area | Done | Partial | Open | Blocked | Withdrawn | Unknown | Total | Complete |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for phase, area, bucket in area_rows(backlog):
        lines.append(f"| {phase} | {area} | {count_cells(bucket)} |")

    lines.extend(
        [
            "",
            "## Milestone gates",
            "",
            "| Milestone | Criteria done | Criteria total | Remaining | External blockers | Verdict |",
            "| --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    by_id = {item["id"]: item for item in backlog["items"]}
    entries = declared["milestones"]
    for milestone in sorted(entries, key=lambda name: int(name[1:])):
        entry = entries[milestone]
        verdict, remaining, external = status_of(milestone, entry, by_id)
        done = len(entry["criteria"]) - len(remaining)
        lines.append(f"| {milestone} | {done} | {len(entry['criteria'])} | {len(remaining)} | {len(external)} | {verdict} |")

    outstanding_notices = notices(backlog, declared)
    if outstanding_notices:
        lines.extend(["", "### Declaration notices", ""])
        lines.extend(f"- {notice}" for notice in outstanding_notices)

    lines.extend(
        [
            "",
            "### Reading the dashboard",
            "",
            "- A percentage is `done / total`; partial work is not silently credited as complete.",
            "- `OPEN` means checklist criteria remain. `EXTERNAL` means a repository-local checklist cannot close the gate by itself.",
            "- CI and the container gate run `--check` and `--self-test`; stale aggregates or stale Markdown fail both readers.",
            "",
        ]
    )
    return ("\n".join(lines)).encode("utf-8")


def self_test() -> int:
    failures = 0
    total = 0
    backlog, declared = load()

    def case(name: str, condition: bool) -> None:
        nonlocal failures, total
        total += 1
        print(f"  {'OK  ' if condition else 'DEAD'}  {name}")
        if not condition:
            failures += 1

    case("the real backlog validates", not validate_backlog(backlog))
    baseline = render(backlog, declared)
    case("the real dashboard renders identically twice", baseline == render(backlog, declared))

    with tempfile.TemporaryDirectory() as temporary:
        probe = Path(temporary) / "dashboard.md"
        probe.write_bytes(baseline + b"stale\n")
        case(
            "--check rejects stale Markdown through the CLI",
            main(["--check", "--output", str(probe)]) != 0,
        )
        probe.write_bytes(baseline)
        case(
            "--check accepts exact Markdown through the CLI",
            main(["--check", "--output", str(probe)]) == 0,
        )

    changed = copy.deepcopy(backlog)
    changed["items"][0]["status"] = "open" if changed["items"][0]["status"] == "done" else "done"
    changed["by_area"] = tally(changed["items"], "area")
    changed["by_phase"] = tally(changed["items"], "phase")
    case("a valid item status change changes the dashboard", baseline != render(changed, declared))

    aggregate_drift = copy.deepcopy(backlog)
    aggregate_drift["by_area"]["FND"]["done"] += 1
    case("aggregate drift is rejected", any("by_area" in problem for problem in validate_backlog(aggregate_drift)))

    unknown_status = copy.deepcopy(backlog)
    unknown_status["items"][0]["status"] = "surprise"
    case("an unknown status is rejected", any("unsupported status" in problem for problem in validate_backlog(unknown_status)))

    duplicate_id = copy.deepcopy(backlog)
    duplicate_id["items"][1]["id"] = duplicate_id["items"][0]["id"]
    case("a duplicate item id is rejected", any("duplicate item id" in problem for problem in validate_backlog(duplicate_id)))

    empty_backlog = copy.deepcopy(backlog)
    empty_backlog["items"] = []
    empty_backlog["total"] = 0
    empty_backlog["by_area"] = {}
    empty_backlog["by_phase"] = {}
    case("an empty item list is rejected", any("items` is empty" in problem for problem in validate_backlog(empty_backlog)))

    by_id = {item["id"]: item for item in backlog["items"]}
    m7_verdict, _remaining, external = status_of("M7", declared["milestones"]["M7"], by_id)
    case("an external milestone stays EXTERNAL", m7_verdict == "EXTERNAL" and len(external) == 2)

    if failures:
        print(f"SELF-TEST FAILED -- {failures} of {total} case(s) failed", file=sys.stderr)
        return 1
    print(f"SELF-TEST PASSED -- {total} case(s); dashboard and failure predicates are live")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="render the tracked QQQ milestone dashboard")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--record", action="store_true", help="write the generated dashboard")
    mode.add_argument("--check", action="store_true", help="fail if the tracked dashboard is stale")
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT,
        help="dashboard path for --record/--check (default: docs/milestone-dashboard.md)",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    backlog, declared = load()
    try:
        fresh = render(backlog, declared)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"DASHBOARD INVALID -- {error}", file=sys.stderr)
        return 1

    output = args.output if args.output.is_absolute() else ROOT / args.output
    if args.record:
        output.write_bytes(fresh)
        display = output.relative_to(ROOT) if output.is_relative_to(ROOT) else output
        print(f"wrote {display} ({len(fresh)} bytes)")
        return 0

    if not output.is_file():
        display = output.relative_to(ROOT) if output.is_relative_to(ROOT) else output
        print(f"DASHBOARD MISSING -- {display} is not tracked; run --record", file=sys.stderr)
        return 1
    tracked = output.read_bytes()
    if tracked != fresh:
        print("DASHBOARD DRIFT -- the tracked Markdown is stale", file=sys.stderr)
        print("  re-record with: python tools/milestone_dashboard.py --record", file=sys.stderr)
        return 1
    print(f"DASHBOARD OK -- {backlog['total']} item(s), {len(backlog['by_area'])} area(s), {len(backlog['by_phase'])} phase(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
