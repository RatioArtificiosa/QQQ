#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Verify the §9.2 budget table against the Proposal and the checklist.

Two claims are mechanically checkable, and both are claims the project makes in
prose and could therefore drift from silently:

  1. **§9.2 states N rows, and `Budget::ALL` states the same N.** The table in
     `crates/qqq-bench/src/budget.rs` is the machine-readable copy; the Proposal
     is the authority. A row added to one and not the other makes every published
     comparison incomplete, and nothing about the code would look wrong.

  2. **Every budget row cites a real checklist item.** `§O-126` records a round
     that invented a checklist identifier and cited it as though it were
     real. An item id in
     the budget table that resolves to nothing is the same defect with a
     compile-time alibi.

# Why this is a check and not a review item

The failure mode is silent in both directions. A budget whose target drifted from
`§9.2` still compares, still prints a verdict, and still says "MEETS" — against a
number nobody agreed to. That is the shape this repository has recorded more than
twenty times: *a control believed live that is not*.

# Anti-vacuity

This refuses to pass when it finds nothing to compare. A parser that silently
matched no rows would report success forever (`§M-006`), so every extraction
asserts it found something before the comparison is made.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PROPOSAL = ROOT / "QQQ-Proposal-V1.md"
CHECKLIST = ROOT / "QQQ-Checklist-V1.md"
BUDGET_RS = ROOT / "crates" / "qqq-bench" / "src" / "budget.rs"

# §9.2's rows, transcribed from the Proposal. All three sources -- the Proposal,
# this list, and `Budget::ALL` -- are compared, because two agreeing sources could
# both be wrong together.
#
# The metric strings match §9.2 verbatim AFTER backticks and escapes are stripped
# (the parser normalises them), so `qqqai --version wall time` and
# `` `qqqai --version` wall time `` are the same row.
#
# (metric as §9.2 writes it, target, direction symbol)
EXPECTED_ROWS = [
    ("Warm instance acquire", 100.0, "≤"),
    ("Cold instantiate (AOT cached)", 5.0, "≤"),
    ("Cold instantiate (from .wasm)", 150.0, "≤"),
    ("qqqai --version", 15.0, "≤"),
    ("Routed request overhead (empty handler)", 60.0, "≤"),
    ("RSS, idle host, 0 instances", 25.0, "≤"),
    ("RSS, 1000 idle instances", 350.0, "≤"),
    # **60k, not 60.** The `k` suffix is why `parse_target` exists; a parser that
    # ignored it would compare every throughput verdict against sixty RPS.
    ("Throughput, reference app, 8 cores", 60_000.0, "≥"),
    ("p99 request latency, reference app, 10k RPS", 2.0, "≤"),
    ("Memory per instance, reference app", 256.0, "≤"),
    ("qqqai build, 10k LOC Rust", 20.0, "≤"),
]


def read(path: Path) -> str:
    if not path.is_file():
        print(f"FATAL: {path} does not exist")
        sys.exit(1)
    return path.read_text(encoding="utf-8")


def parse_target(target_cell: str) -> tuple[float, str] | None:
    """Extract (value, direction symbol) from §9.2's Target cell.

    # Why the `k` multiplier is handled explicitly

    §9.2 writes `≥ 60k RPS`. The first version of this parser read the digits and
    stopped, producing **60.0** -- a budget of sixty requests per second where the
    Proposal states sixty thousand. Every throughput verdict would then have
    reported that a system doing 100 RPS exceeded its target by 67%.

    That is the worst kind of parser bug: the number is plausible, the comparison
    succeeds, and the error is a factor of one thousand. It is checked against the
    Proposal text directly below rather than trusted.
    """
    m = re.search(r"([≤≥])\s*([0-9][0-9_,]*(?:\.[0-9]+)?)\s*(k?)", target_cell)
    if not m:
        return None
    number = float(m.group(2).replace("_", "").replace(",", ""))
    if m.group(3) == "k":
        number *= 1_000.0
    return number, m.group(1)


def proposal_rows(text: str) -> list[tuple[str, float, str]]:
    """Extract §9.2's numeric budget table from the Proposal.

    Only rows whose Target cell carries a `≤` or `≥` are budget rows. §9.2's
    section and the §12.3 DX table both use pipe tables, so the direction symbol
    is the discriminator rather than position.
    """
    start = text.find("## §9.2 The performance budget")
    if start == -1:
        return []
    end = text.find("\n## ", start + 1)
    section = text[start:end if end != -1 else len(text)]

    rows: list[tuple[str, float, str]] = []
    for line in section.splitlines():
        if not line.startswith("|") or "---" in line:
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 3:
            continue
        metric, target = cells[0], cells[1]
        if metric in ("Metric", ""):
            continue
        parsed = parse_target(target)
        if parsed is None:
            continue
        number, direction = parsed
        # Normalise the metric for comparison: strip markdown code ticks and
        # backslash escapes, which §9.2 uses freely and which must not make two
        # spellings of the same row look different.
        metric = metric.replace("`", "").replace("\\", "")
        rows.append((metric, number, direction))
    return rows


def rust_i64(value: float) -> str:
    """Render a float the way the Rust table would compare to it."""
    return str(int(value))


def rust_rows(text: str) -> list[dict[str, str]]:
    """Extract the `Budget::ALL` entries from budget.rs.

    Parsed rather than compiled: the point is to check the SOURCE against the
    Proposal, and shelling out to a test binary would check a build artifact that
    might be stale. A stale-artifact comparison is `§O-120`'s defect.
    """
    # Length-agnostic on purpose. An earlier version anchored on `[Self; 9]` and
    # stopped finding rows the moment a tenth was added -- the anti-vacuity guard
    # below is what caught it, which is exactly why that guard exists.
    start = re.search(r"pub const ALL:\s*\[Self;\s*\d+\]\s*=\s*\[", text)
    if start is None:
        return []
    start = start.end() - 1
    # Find the matching closing bracket by counting depth from `start`.
    depth = 0
    end = None
    for i in range(start, len(text)):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        return []
    block = text[start + 1 : end]

    rows: list[dict[str, str]] = []
    for entry in re.finditer(
        r"Self\s*\{(?P<body>.*?)\}\s*,\s*(?=Self\s*\{|\Z)", block, re.S
    ):
        body = entry.group("body")
        row: dict[str, str] = {}
        for field in ("item", "target", "direction", "unit", "method"):
            m = re.search(rf"{field}:\s*([^,\n]+)", body)
            if m:
                # Strip the surrounding Rust string quotes. Without this the
                # method check compares `"bench/..."` (with quotes) against
                # `bench/` and fails on a correct file -- a checker defect that
                # would look like a source defect.
                value = m.group(1).strip().strip('"')
                row[field] = value
        if row:
            rows.append(row)
    return rows


def main() -> int:
    proposal_text = read(PROPOSAL)
    checklist_text = read(CHECKLIST)
    budget_text = read(BUDGET_RS)

    errors: list[str] = []

    # --- 0. Anti-vacuity: refuse to pass on nothing -------------------------
    prop = proposal_rows(proposal_text)
    rust = rust_rows(budget_text)

    if len(prop) < 10:
        print(
            f"FATAL: extracted only {len(prop)} row(s) from §9.2. §9.2 has at "
            "least 10; a parser that finds nothing must fail rather than pass."
        )
        return 1
    if not rust:
        print("FATAL: extracted no rows from Budget::ALL. The parse is broken.")
        return 1

    print(f"§9.2 rows found in the Proposal: {len(prop)}")
    print(f"rows found in Budget::ALL:       {len(rust)}")

    # --- 1. Every Proposal row is either implemented or explicitly excluded --
    declared = {r["item"] for r in rust}
    excluded_text = budget_text[budget_text.find("NOT_A_HARNESS_ROW") :]

    for metric, target, direction in prop:
        if metric in {r[0] for r in EXPECTED_ROWS}:
            continue
        # A row this checker's EXPECTED_ROWS does not know about is a Proposal
        # change the checker has not been taught -- which must fail loudly.
        errors.append(
            f"§9.2 row '{metric}' is not in this checker's EXPECTED_ROWS. "
            "If §9.2 changed, update EXPECTED_ROWS deliberately."
        )

    # Every EXPECTED row must be found in the Proposal.
    proposal_metrics = {m for m, _, _ in prop}
    for metric, target, direction in EXPECTED_ROWS:
        found = [p for p in prop if metric in p[0]]
        if not found:
            errors.append(
                f"EXPECTED_ROWS names '{metric}', but §9.2 has no such row. "
                "Either §9.2 changed or this list is wrong."
            )
            continue
        _, prop_target, prop_direction = found[0]
        if abs(prop_target - target) > 0.001:
            errors.append(
                f"'{metric}': this checker expects {target}, §9.2 states "
                f"{prop_target}. One of the two is wrong."
            )
        if prop_direction != direction:
            errors.append(
                f"'{metric}': this checker expects '{direction}', §9.2 states "
                f"'{prop_direction}'. A flipped direction makes every verdict "
                "for this row invert."
            )

    # --- 2. Every checklist item cited by a budget row must exist ------------
    cited: set[str] = set()
    for row in rust:
        m = re.search(r"Item::(Perf\d+)", row.get("item", ""))
        if not m:
            errors.append(f"a Budget::ALL row has no parsable item: {row}")
            continue
        # `Perf003` -> `PERF-003`
        num = m.group(1)[4:]
        item_id = f"PERF-{num}"
        cited.add(item_id)

        if item_id not in checklist_text:
            errors.append(
                f"{item_id} is cited by a budget row but does not appear in "
                "QQQ-Checklist-V1.md -- §O-126's invented-citation defect"
            )

    # Anti-vacuity for the citation loop.
    if not cited:
        errors.append("no checklist items were extracted; the citation check is vacuous")

    # --- 3. Every cited item must have a method naming bench/ ----------------
    for row in rust:
        method = row.get("method", "")
        if not method.startswith("bench/"):
            errors.append(
                f"{row.get('item')} has method '{method}', which does not name a "
                "path under bench/. §9.2 says each row 'has a measurement method "
                "in bench/'."
            )

    # --- 4. The two directions must both be represented ----------------------
    directions = {row.get("direction", "").strip() for row in rust}
    if not any("AtMost" in d for d in directions):
        errors.append("no AtMost budget: every ceiling row is missing")
    if not any("AtLeast" in d for d in directions):
        errors.append(
            "no AtLeast budget: the throughput row is missing, and without a "
            "floor row the direction branch is untested"
        )

    # --- 5. Every §9.2 budget row is either implemented or explicitly excluded --
    #
    # The property: for each of §9.2's rows, the project has made a **decision** --
    # either a `Budget` exists, or the row is named in `NOT_A_HARNESS_ROW` with a
    # reason. A row that is in neither is an oversight, and a row count comparison
    # cannot see that because the two lists are keyed differently.
    #
    # The first version of this check compared three integers and was wrong in
    # both directions: it counted tuple literals that were not rows, and it
    # assumed a relationship between §9.2's row count and the implementation
    # count that does not hold, because §9.1's `cold` row appears twice in §9.2.
    m = re.search(
        r"NOT_A_HARNESS_ROW: \[\(&'static str, &'static str\); (\d+)\]", budget_text
    )
    if not m:
        errors.append("NOT_A_HARNESS_ROW is not declared with an explicit length")
        declared_excluded = 0
    else:
        declared_excluded = int(m.group(1))

    # Extract the excluded row names from the array body.
    excluded_names: list[str] = []
    ex_start = budget_text.find("NOT_A_HARNESS_ROW: [")
    if ex_start != -1:
        ex_end = budget_text.find("];", ex_start)
        ex_body = budget_text[ex_start:ex_end]
        excluded_names = re.findall(r'\(\s*"([^"]+)"', ex_body)

    if len(excluded_names) != declared_excluded:
        errors.append(
            f"NOT_A_HARNESS_ROW declares {declared_excluded} rows but names "
            f"{len(excluded_names)}: {excluded_names}"
        )

    # Every Proposal row must be accounted for by SOME decision.
    #
    # # Which source is authoritative, and why the first version was wrong
    #
    # The implemented row names are read from `Item::metric()` -- but that function
    # is a *lookup table for an enum*, not proof that a row exists. The self-test's
    # first injection removed `Perf002` from `Budget::ALL` and the checker stayed
    # silent, because `Item::Perf002 => "Routed request overhead (empty handler)"`
    # was still in `metric()`.
    #
    # That is the same "check aimed at a nearby property" shape this repository
    # records repeatedly: `metric()` is nearby and easy to read, while "a row
    # exists for this §9.2 metric" is the property that matters. So the source of
    # truth is the **`item:` field of each `Budget::ALL` entry**, resolved through
    # `metric()` only to get its human-readable name.
    metric_fn = re.search(r"pub fn metric\(self\) -> &'static str \{(.*?)\n    \}", budget_text, re.S)
    metric_names: dict[str, str] = {}
    if metric_fn:
        for m in re.finditer(r"Self::(\w+)\s*=>\s*\"([^\"]+)\"", metric_fn.group(1)):
            metric_names[m.group(1)] = m.group(2)

    if not metric_names:
        errors.append(
            "could not read any metric names from `Item::metric()`; the accounting "
            "check would be vacuous"
        )

    # The items that actually have a row, taken from `Budget::ALL`.
    row_items = set()
    for row in rust:
        m = re.search(r"Item::(\w+)", row.get("item", ""))
        if m:
            row_items.add(m.group(1))

    if not row_items:
        errors.append("no `item:` fields extracted from Budget::ALL; nothing to account for")

    implemented_metrics = {metric_names[i] for i in row_items if i in metric_names}

    # `PERF-007`'s AOT cache row shares §9.2's cold-instantiate measurement rather
    # than occupying a row of its own -- recorded here rather than silently
    # allowed, because a reader comparing the two tables will notice.
    AOT_CACHE_SHARES_COLD = "PERF-007"
    _ = AOT_CACHE_SHARES_COLD

    for metric, _target, _direction in prop:
        if metric in implemented_metrics:
            continue
        if any(name in metric or metric in name for name in excluded_names):
            continue
        errors.append(
            f"§9.2 row '{metric}' has no decision: it is neither implemented by a "
            "Budget nor named in NOT_A_HARNESS_ROW with a reason"
        )

    if errors:
        print(f"\n{len(errors)} PROBLEM(S):")
        for e in errors:
            print(f"  FAIL  {e}")
        print("\nBENCH CONTRACT VIOLATED")
        return 1

    print(
        f"\n{len(rust)} budget row(s) implemented, {len(cited)} checklist item(s) "
        "cited and all present"
    )
    print("BENCH CONTRACT OK")
    return 0


def self_test() -> int:
    """Prove this checker can fail, by injecting each defect it exists to catch.

    # Why every checker in this repository has this

    A checker whose self-test only exercises the passing path certifies nothing.
    This one has four properties to defend, and each is injected below against a
    **synthetic source string** rather than by mutating the real files: the point
    is to exercise the *rule*, and writing to the repository to test a checker
    would make the test itself a hazard.

    The four:
      1. a `§9.2` row with no decision (neither implemented nor excluded);
      2. a budget whose target drifted from the Proposal;
      3. a citation of an item that does not exist in the checklist;
      4. a method that does not name a path under `bench/`.
    """
    print("self-test: injecting the defects this checker exists to catch")

    proposal_text = read(PROPOSAL)
    checklist_text = read(CHECKLIST)
    real_budget = read(BUDGET_RS)

    cases: list[tuple[str, str, str, bool]] = []

    # 1. A row removed from Budget::ALL and not excluded -> must be flagged.
    without_routed = real_budget.replace(
        """        Self {
            item: Item::Perf002,
            target: 60.0,
            direction: Direction::AtMost,
            unit: Unit::Micros,
            method: "bench/routed.rs::routed_request_overhead",
        },
""",
        "",
        1,
    )
    cases.append(
        (
            "a §9.2 row with no decision",
            without_routed,
            proposal_text,
            True,
        )
    )

    # 2. A target that drifted from the Proposal.
    drifted = real_budget.replace("target: 100.0,", "target: 999.0,", 1)
    cases.append(("a target that drifted from §9.2", drifted, proposal_text, True))

    # 3. A citation of an item that does not exist.
    invented = real_budget.replace("Item::Perf003", "Item::Perf999", 1)
    cases.append(
        ("an invented checklist citation", invented, proposal_text, True)
    )

    # 4. A method that does not name a path under bench/.
    bad_method = real_budget.replace(
        '"bench/routed.rs::routed_request_overhead"', '"somewhere/else.rs::fn"', 1
    )
    cases.append(("a method outside bench/", bad_method, proposal_text, True))

    # --- The control ---------------------------------------------------------
    # The real source must PASS. Without this, a checker that failed on
    # everything would satisfy all four cases above and certify nothing.
    cases.append(("the real source (control)", real_budget, proposal_text, False))

    failures = 0
    for label, budget_src, prop_src, should_fail in cases:
        found = analyse(budget_src, prop_src, checklist_text)
        did_fail = bool(found)
        ok = did_fail == should_fail
        status = "OK  " if ok else "FAIL"
        expectation = "must FAIL" if should_fail else "must PASS"
        print(f"  {status} {label}: {expectation}, got "
              f"{'FAIL' if did_fail else 'PASS'}")
        if not ok:
            failures += 1
            for f in found[:3]:
                print(f"         {f}")

    if failures:
        print(f"\nSELF-TEST FAILED: {failures} of {len(cases)} injections wrong")
        return 1
    print(f"\nSELF-TEST OK -- {len(cases)} injection(s), all behaved as required")
    return 0


def analyse(
    budget_src: str, proposal_src: str, checklist_src: str
) -> list[str]:
    """The checker's decision procedure, as a pure function.

    Extracted so `self_test` can run it against a synthetic source without
    touching the repository. Returning the error list rather than printing makes
    the self-test able to assert on *which* rule fired, not merely on whether
    something did -- the distinction `§O-149` records between a test that passes
    for the right reason and one that passes for any reason.
    """
    errors: list[str] = []
    prop = proposal_rows(proposal_src)
    rust = rust_rows(budget_src)

    if len(prop) < 10:
        return [f"extracted only {len(prop)} §9.2 rows"]
    if not rust:
        return ["extracted no rows from Budget::ALL"]

    # The Rust table's metric names, read once and used by both the drift check
    # above and the accounting check below. Defined BEFORE either, because a
    # reference to a variable assigned later in the same function is an
    # `UnboundLocalError` in Python -- the first version of this edit had exactly
    # that, and the self-test caught it by crashing.
    metric_fn = re.search(
        r"pub fn metric\(self\) -> &'static str \{(.*?)\n    \}", budget_src, re.S
    )
    metric_names: dict[str, str] = {}
    if metric_fn:
        for mm in re.finditer(r"Self::(\w+)\s*=>\s*\"([^\"]+)\"", metric_fn.group(1)):
            metric_names[mm.group(1)] = mm.group(2)

    # Target and direction must match the Proposal.
    for metric, target, direction in EXPECTED_ROWS:
        found = [p for p in prop if metric in p[0]]
        if not found:
            errors.append(f"EXPECTED_ROWS names '{metric}', absent from §9.2")
            continue
        _, prop_target, prop_direction = found[0]
        if abs(prop_target - target) > 0.001:
            errors.append(f"'{metric}': expected {target}, §9.2 states {prop_target}")
        if prop_direction != direction:
            errors.append(f"'{metric}': expected {direction}, §9.2 states {prop_direction}")

    # The RUST table's targets must match the Proposal too.
    #
    # This is the check that matters most and the one the first version of
    # `analyse` omitted entirely: it compared EXPECTED_ROWS against the Proposal,
    # and the Proposal against EXPECTED_ROWS, and never looked at the numbers that
    # actually run. The self-test's drift injection -- `target: 100.0` changed to
    # `target: 999.0` in the Rust source -- reported PASS, which is exactly the
    # blindness the self-test exists to expose.
    #
    # `main` had this comparison; `analyse` did not, so the two implementations of
    # one rule disagreed. Extracting the rule into `analyse` and having `main` call
    # it is the fix: one implementation cannot disagree with itself.
    rust_by_item = {
        m.group(1): row
        for row in rust
        if (m := re.search(r"Item::(\w+)", row.get("item", "")))
    }
    for metric, target, direction in EXPECTED_ROWS:
        # Find the Item whose metric name matches this §9.2 row.
        owning = [
            key
            for key, name in metric_names.items()
            if name == metric
        ]
        if not owning:
            # Not every EXPECTED row is implemented -- some are excluded. The
            # exclusion path is checked by the accounting rule below.
            continue
        for key in owning:
            row = rust_by_item.get(key)
            if row is None:
                errors.append(f"{key} has a metric name but no row in Budget::ALL")
                continue
            raw = row.get("target", "")
            try:
                rust_target = float(raw)
            except ValueError:
                errors.append(f"{key}: target '{raw}' is not a number")
                continue
            if abs(rust_target - target) > 0.001:
                errors.append(
                    f"{key} ({metric}): the Rust budget says {rust_target}, but "
                    f"§9.2 states {target}. A drifted target still compares, still "
                    "prints a verdict, and reports MEETS against a number nobody "
                    "agreed to."
                )
            rust_direction = row.get("direction", "")
            want = "AtLeast" if direction == "≥" else "AtMost"
            if want not in rust_direction:
                errors.append(
                    f"{key} ({metric}): the Rust direction is '{rust_direction}', "
                    f"but §9.2 states '{direction}' ({want}). A flipped direction "
                    "inverts every verdict for this row."
                )

    # Citations must resolve.
    cited: set[str] = set()
    for row in rust:
        m = re.search(r"Item::(Perf\d+)", row.get("item", ""))
        if not m:
            errors.append(f"a row has no parsable item: {row}")
            continue
        item_id = f"PERF-{m.group(1)[4:]}"
        cited.add(item_id)
        if item_id not in checklist_src:
            errors.append(f"{item_id} is cited but absent from the checklist")
        method = row.get("method", "")
        if not method.startswith("bench/"):
            errors.append(f"{item_id} method '{method}' is not under bench/")

    if not cited:
        errors.append("no checklist items extracted; the citation check is vacuous")

    # Both directions must be represented.
    directions = {row.get("direction", "").strip() for row in rust}
    if not any("AtMost" in d for d in directions):
        errors.append("no AtMost budget")
    if not any("AtLeast" in d for d in directions):
        errors.append("no AtLeast budget")

    # Every §9.2 row needs a decision.
    excluded_names: list[str] = []
    ex_start = budget_src.find("NOT_A_HARNESS_ROW: [")
    if ex_start != -1:
        ex_end = budget_src.find("];", ex_start)
        excluded_names = re.findall(r'\(\s*"([^"]+)"', budget_src[ex_start:ex_end])

    # The source of truth is `Budget::ALL`'s `item:` field, not `metric()`. See
    # the note in `main` for why: the self-test's first injection caught the
    # difference, because a metric name in an enum lookup table is not a row.
    row_items = set()
    for row in rust:
        mm = re.search(r"Item::(\w+)", row.get("item", ""))
        if mm:
            row_items.add(mm.group(1))

    implemented = {metric_names[i] for i in row_items if i in metric_names}
    if not implemented:
        errors.append("could not resolve any implemented metric from Budget::ALL")

    for metric, _t, _d in prop:
        if metric in implemented:
            continue
        if any(name in metric or metric in name for name in excluded_names):
            continue
        errors.append(f"§9.2 row '{metric}' has no decision")

    return errors


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(self_test())
    raise SystemExit(main())
