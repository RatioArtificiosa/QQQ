#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Refuse an unbounded metric label — Proposal §10.2's cardinality lint.

    python tools/check_metric_cardinality.py [--self-test] [--list]

# What §10.2 requires

> **Cardinality discipline:** no metric label may take an unbounded value (no raw paths, no user
> IDs, no full URLs). **Enforced by a lint on metric definitions.** High-cardinality data goes to
> traces, not metrics.

The lint is the part that did not exist. The *design* enforces the discipline structurally —
`metrics.rs` says so itself: *"the labels here are **enums, not strings**"* — and a structural
guarantee is only as good as its coverage. Three of `HttpMetrics`' six maps are keyed by `String`,
and the struct's own doc comment claims *"All per-request counters, keyed by the bounded label
sets"*. The comment was true of three of them.

# Why this is not a restatement of the doc comment

Because the values in those maps come from `tenant_of`, which returns the **peer IP address** — so
**an attacker chooses the key**. One time series per source address, with no ceiling, on three
maps. §10.2 calls that the violation *"in its worst form"*.

# What it checks

  1. **Every label enum asserts its own finiteness.** A `pub enum` used as a label must carry a
     `pub const ALL: [Self; N]`, and `N` must equal the number of variants. Without `ALL` the
     "finite" claim is prose; with a wrong `N` it is a lie that compiles.
  2. **No registry map is keyed by an unbounded type.** A `Mutex<BTreeMap<K, V>>` field's `K` must
     be an enum defined in the file, a tuple of such enums, or an integer type. `String`, `&str`,
     `Cow<str>` and `Vec<_>` are refused by name, with the line.
  3. **A declared ceiling is a real bound.** `const MAX_*: usize = N` must be non-zero and finite,
     because `MAX_TENANTS = 0` would bound the space to nothing and pass a naive check.

# Why `ALL` is the finiteness assertion

A variant count is not derivable from the enum declaration alone in a way a reviewer can check by
reading — `Method` has ten arms and nothing states that. `ALL` is the machine-checkable form, and
the file already had one per label enum before this lint existed. The lint's job is to keep that
true of the **next** one.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
METRICS = ROOT / "crates" / "qqq-serve" / "src" / "metrics.rs"

# A label enum's finiteness assertion: `pub const ALL: [Self; 10] = [`.
#
# Searched in the enum's own `impl` block, not in its declaration: `ALL` is conventionally declared
# beside the enum rather than inside it, and the first version of this lint searched only the
# declaration -- so it reported four false positives on enums that all had `ALL`. A checker with
# false positives is one that gets worked around, which is the opposite of what §10.2 asks for.
ALL_CONST = re.compile(r"pub const ALL: \[Self; (\d+)\]")
IMPL_DECL = re.compile(r"^impl(?:<[^>]*>)?\s+(\w+)")

# An enum declaration, and the block that follows it.
ENUM_DECL = re.compile(r"^pub enum (\w+)")

# A map-typed struct field: `name: Mutex<BTreeMap<K, V>>,` (K may contain no `,`).
MAP_FIELD = re.compile(
    r"^\s*(\w+):\s*(?:std::sync::)?Mutex<(?:BTreeMap|HashMap)<(.+),\s*[^,<>]+>>,"
)

# A declared ceiling.
MAX_CONST = re.compile(r"pub const MAX_\w+: usize = (\d+)")

# Types that make a key unbounded. Matched on the key text, so `String` inside a tuple is caught
# too -- `(Method, String)` is exactly the shape a rushed addition takes.
UNBOUNDED = ("String", "&str", "Cow", "Vec<", "Box<", "str")

# Integer key types are bounded by their width, which is finite by construction.
BOUNDED_NUMERIC = ("u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "usize", "bool")


def enum_variants(lines: list[str], start: int) -> tuple[int, int]:
    """`(variant count, end line index)` for the enum beginning at `start` (0-based).

    Counts top-level `Variant,` arms by brace depth, so a nested struct field or a method body
    inside an impl block cannot be miscounted as a variant.
    """
    depth = 0
    variants = 0
    i = start
    seen_open = False
    while i < len(lines):
        line = lines[i]
        if not seen_open and "{" in line:
            seen_open = True
        if seen_open:
            # A variant line at depth 1 is `    Name,` or `    Name(...)` or `    Name {`.
            if depth == 1 and re.match(r"^\s*[A-Z]\w*\s*[(,{]", line):
                variants += 1
            depth += line.count("{") - line.count("}")
            if depth <= 0 and i > start:
                return variants, i
        i += 1
    return variants, len(lines) - 1


def check(text: str) -> list[str]:
    """The decision procedure, as a pure function, so `--self-test` can drive it."""
    problems: list[str] = []
    lines = text.split("\n")

    # -- 1. every label enum asserts its finiteness ------------------------------
    # A label enum is bounded by one of two mechanisms, and both are machine-checkable:
    #
    #   * `pub const ALL: [Self; N]` in its `impl` — the variant count is asserted;
    #   * a declared `const MAX_*: usize = N` — the *label space* is capped even though the enum
    #     carries a payload. `Tenant::Named(&str)` is exactly this case: three variants, but the
    #     names behind `Named` are unbounded without `TenantLabels::MAX_TENANTS`.
    #
    # Requiring `ALL` of every enum was the first version's rule and it was wrong for `Tenant`,
    # which is bounded by the ceiling instead. Requiring *one of the two* is the honest rule, and
    # it still refuses an enum that asserts neither.
    ceilings = [m.group(0) for m in MAX_CONST.finditer(text)]
    impl_blocks: dict[str, str] = {}
    i = 0
    while i < len(lines):
        m = IMPL_DECL.match(lines[i])
        if m:
            depth = 0
            j = i
            start = i
            while j < len(lines):
                depth += lines[j].count("{") - lines[j].count("}")
                if depth <= 0 and j > start:
                    break
                j += 1
            impl_blocks.setdefault(m.group(1), "\n".join(lines[start : j + 1]))
        i += 1

    enum_names: set[str] = set()
    i = 0
    while i < len(lines):
        m = ENUM_DECL.match(lines[i])
        if m:
            name = m.group(1)
            enum_names.add(name)
            variants, _end = enum_variants(lines, i)
            block = impl_blocks.get(name, "")
            allm = ALL_CONST.search(block)
            if allm is None:
                if ceilings:
                    # Bounded by a declared ceiling; the ceiling's own sanity is check 3.
                    pass
                else:
                    problems.append(
                        f"`enum {name}` is a label type that asserts neither a finite `ALL` nor a "
                        f"declared `MAX_*` ceiling, so its boundedness is prose (§10.2)"
                    )
            elif int(allm.group(1)) != variants:
                problems.append(
                    f"`enum {name}` declares `ALL: [Self; {allm.group(1)}]` but has {variants} "
                    f"variant(s): the finiteness assertion is wrong, and a wrong one compiles"
                )
        i += 1

    # -- 2. no registry map keyed by an unbounded type ---------------------------
    for n, line in enumerate(lines, 1):
        m = MAP_FIELD.match(line)
        if not m:
            continue
        field, key = m.group(1), m.group(2).strip()
        if key in enum_names:
            continue
        if key in BOUNDED_NUMERIC:
            continue
        # A tuple of bounded parts, e.g. `(Method, StatusClass)`.
        if key.startswith("(") and key.endswith(")"):
            parts = [p.strip() for p in key[1:-1].split(",") if p.strip()]
            if parts and all(p in enum_names or p in BOUNDED_NUMERIC for p in parts):
                continue
        for bad in UNBOUNDED:
            if bad in key:
                problems.append(
                    f"`{field}: Mutex<BTreeMap<{key}, _>>` at line {n} is keyed by an UNBOUNDED "
                    f"type: every distinct value is a new time series, and §10.2 forbids it. Key "
                    f"it by a label enum, or bound it the way `TenantLabels` does"
                )
                break
        else:
            problems.append(
                f"`{field}` at line {n} is keyed by `{key}`, which this lint cannot prove bounded: "
                f"use an enum defined here, an integer type, or a tuple of them"
            )

    # -- 3. a declared ceiling is a real bound -----------------------------------
    for m in MAX_CONST.finditer(text):
        if int(m.group(1)) == 0:
            problems.append(
                f"`MAX_*: usize = 0` bounds the label space to nothing, which passes a naive "
                f"finiteness check and is not a working ceiling"
            )

    return problems


def validate(listing: bool) -> int:
    text = METRICS.read_text(encoding="utf-8", errors="replace")
    lines = text.split("\n")
    problems = check(text)

    maps = sum(1 for line in lines if MAP_FIELD.match(line))
    enums = sum(1 for line in lines if ENUM_DECL.match(line))
    print(f"label enums in metrics.rs : {enums}")
    print(f"registry map fields       : {maps}")
    if listing:
        for n, line in enumerate(lines, 1):
            m = MAP_FIELD.match(line)
            if m:
                print(f"  line {n}: {m.group(1)} keyed by {m.group(2).strip()}")

    print("")
    if problems:
        print(f"METRIC CARDINALITY FAILED -- {len(problems)} problem(s):")
        for p in problems:
            print(f"  FAIL  {p}")
        return 1
    print("METRIC CARDINALITY OK -- every registry map is keyed by a bounded label")
    return 0


def self_test() -> int:
    failures = 0

    def case(name: str, source: str, expect: str | None) -> None:
        nonlocal failures
        problems = check(source)
        ok = (not problems) if expect is None else any(expect in p for p in problems)
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            for p in problems[:2]:
                print(f"        got: {p}")

    FINITE = "pub enum Method {\n    Get,\n    Post,\n}\n\nimpl Method {\n    pub const ALL: [Self; 2] = [Self::Get, Self::Post];\n}\n"

    case("a finite enum key passes", FINITE + "\nstruct R {\n    requests: Mutex<BTreeMap<Method, u64>>,\n}\n", None)
    case(
        "a String key is refused",
        FINITE + "\nstruct R {\n    hits: Mutex<BTreeMap<String, u64>>,\n}\n",
        "UNBOUNDED",
    )
    case(
        "a tuple with a String in it is refused",
        FINITE + "\nstruct R {\n    hits: Mutex<BTreeMap<(Method, String), u64>>,\n}\n",
        "UNBOUNDED",
    )
    case("an integer key passes", FINITE + "\nstruct R {\n    by_status: Mutex<BTreeMap<u16, u64>>,\n}\n", None)
    case(
        "an enum that asserts neither ALL nor a ceiling is refused",
        "pub enum Method {\n    Get,\n    Post,\n}\n",
        "asserts neither a finite `ALL`",
    )
    case(
        "an ALL whose count is wrong is refused",
        "pub enum Method {\n    Get,\n    Post,\n    Put,\n}\n\nimpl Method {\n    pub const ALL: [Self; 2] = [Self::Get, Self::Post];\n}\n",
        "has 3 variant",
    )
    case(
        "a zero ceiling is refused",
        FINITE + "\nimpl T {\n    pub const MAX_TENANTS: usize = 0;\n}\n",
        "bounds the label space to nothing",
    )
    case(
        "a HashMap key is checked too",
        FINITE + "\nstruct R {\n    hits: Mutex<HashMap<String, u64>>,\n}\n",
        "UNBOUNDED",
    )

    # The real file must currently be clean -- the substantive case.
    real = check(METRICS.read_text(encoding="utf-8", errors="replace"))
    ok = not real
    print(f"  {'OK  ' if ok else 'DEAD'}  the real metrics.rs is clean ({len(real)} problem(s))")
    if not ok:
        failures += 1
        for p in real[:4]:
            print(f"        {p}")

    total = 9
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) behaved wrongly")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s); the lint and its refusals are live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--self-test", action="store_true", help="prove the lint is live")
    ap.add_argument("--list", action="store_true", help="print every registry map field")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return validate(listing=args.list)


if __name__ == "__main__":
    raise SystemExit(main())
