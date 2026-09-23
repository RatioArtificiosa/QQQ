#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Generate `docs/verified-facts.md` from the Proposal's Appendix B (`DOC-016`).

Appendix B is the register of external facts the project depends on, each with the
method that verified it. This renders it as a live document with a **re-verification
cadence** attached to every row.

# Why a cadence rather than a date

A register of facts with a single "verified on" date rots as a whole: nobody knows which
rows still hold, and the only way to find out is to re-verify everything — which is
expensive enough that it does not happen.

So each fact carries a **class**, and the class determines how fast it goes stale:

  * `perishable` — a version number, a star count, a download count. Changes weekly.
  * `volatile`   — a registry or DNS fact. Changes monthly, unpredictably.
  * `stable`     — a licence, a specification's content. Changes rarely.
  * `local`      — a property of a development machine. Changes whenever anyone works.

The class is derived from the fact's own text rather than assigned by hand, so a new row
gets a plausible cadence without anyone remembering to classify it — and
`check_verified_facts.py` reports a row it cannot classify rather than guessing.

Usage:
    python tools/gen_verified_facts.py           # write docs/verified-facts.md
    python tools/gen_verified_facts.py --check   # fail if it is out of date
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"
TARGET = ROOT / "docs" / "verified-facts.md"

# The date Appendix B's values were read. Kept here rather than in the Proposal because
# the Proposal states the *values*; this register states when they were last checked,
# and those are different facts. Bumping it is how a re-verification is recorded.
LAST_VERIFIED = "2026-09-20"

# Classification rules, applied in order. Each maps a fact's text to a cadence class.
# Anchored on the *verification method* where possible, because that is the stable part
# of a row — the value changes and the method does not.
CLASSES: list[tuple[str, str, str, str]] = [
    # (class, pattern, cadence, why)
    #
    # # Why `local` comes first, found by the self-test
    #
    # Order matters, and the first version got it wrong: `Local toolchain: rustc 1.97.1`
    # was classified **perishable**, because the `perishable` rule matches a version
    # number and fires before anything else. The cadence happened to be right (7 days
    # either way) and the class was wrong, which is the worse outcome — a reader losing
    # a local fact among the perishable ones cannot tell that it is a *machine*
    # property rather than a published one.
    #
    # The lesson is about rule ordering, not about the regexes: a broad rule placed
    # first silently wins every overlap. The narrowest, most specific rule has to come
    # first, and "given the choice, which class is more informative?" is the tiebreak.
    (
        "local",
        r"(?i)(local|dev machine|world-readable|auxiliary tooling|installed on the dev)",
        "every 7 days",
        "a property of a development machine changes whenever anyone works",
    ),
    (
        "perishable",
        r"(?i)(latest|newest|version|stars|downloads|open issues|activity|rc\b)",
        "every 7 days",
        "a version number or a popularity metric changes without notice",
    ),
    (
        "volatile",
        r"(?i)(crates\.io|npm|registry|DNS|github\.com/|SOA)",
        "every 30 days",
        "a registry or DNS fact changes unpredictably, and the change is not announced",
    ),
    (
        "stable",
        r"(?i)([Ll]icence|license|README|stability-tiers|repo)",
        "every 180 days",
        "a licence or a specification's content changes rarely, and loudly when it does",
    ),
    # # Why this rule was added after the first run
    #
    # Eight facts came out unclassified, and every one was the same kind: an **API or
    # specification property** rather than a value that drifts.
    #
    #   B-12  `wasmtime` exposes `Config::epoch_interruption`, `StoreLimitsBuilder`, …
    #   B-14  WASIp2 opts out of Tokio's per-task cooperative budget
    #   B-29  a component may not export a memory
    #   B-30  Component Model enables static analysis of component graphs
    #
    # These are the facts a design *rests* on, so they need a cadence more than the
    # version numbers do — a version bump is noticed immediately, while an API
    # property disappearing in a major release is exactly what a re-check catches.
    #
    # The `unclassified` report is what surfaced them. A classifier that silently
    # guessed would have filed eight load-bearing facts under a wrong cadence.
    (
        "volatile",
        # # Why this is not anchored with `^`/`$`
        #
        # `classify` searches the fact and the method joined by a space, so an anchored
        # `^(same|...)$` can never match — the string always has the fact in front of
        # it. The first version of this rule was anchored and silently never fired,
        # which is why B-8 and B-11 stayed unclassified after it was added.
        #
        # A rule that cannot match is worse than a missing rule, because the
        # `unclassified` report stops mentioning it.
        r"(?i)\b(same document|same|ibid)\b",
        "every 30 days",
        "the row defers to the method above it — a spec's stability tiers, which move "
        "when a proposal advances rather than on a schedule",
    ),
    (
        "stable",
        r"(?i)(API|exposes|documentation|release notes|structural|enables|requires "
        r"`?\*?_?async|opts out|specification)",
        "every 180 days",
        "an API or specification property: it changes only with a major release, and "
        "a design that rests on it must notice when it does",
    ),
]


def classify(fact: str, method: str) -> tuple[str, str, str]:
    """Return `(class, cadence, why)` for a fact row."""
    haystack = f"{fact} {method}"
    for name, pattern, cadence, why in CLASSES:
        if re.search(pattern, haystack):
            return name, cadence, why
    return "", "", ""


def distinct_classes() -> list[tuple[str, str, str]]:
    """One `(name, cadence, why)` per class, in first-appearance order.

    # Why this exists, and what it fixed

    `CLASSES` is a list of **rules**, and a class may need more than one: `volatile`
    covers both "same document / ibid" rows and the Component Model API properties, and
    `stable` covers both API prose and specification text. That is correct for
    classification — `classify` returns on the first rule that matches, so ordering is
    what decides.

    It is wrong for *emission*, and the two loops below used to iterate `CLASSES`
    directly. A class with two rules therefore printed its summary row twice and its
    whole section twice, with the same facts under each. The page said "30 of 30 facts
    classified" while listing 48 rows, and `check_verified_facts.py` could not see it:
    that checker compares the page against Appendix B, and a duplicated section agrees
    with Appendix B just as well as a single one.

    The cadence and reason reported for a class are the **first** rule's, which is the
    one the module docstring at the top of `CLASSES` names for each class.
    """
    seen: dict[str, tuple[str, str, str]] = {}
    for name, _pattern, cadence, why in CLASSES:
        if name not in seen:
            seen[name] = (name, cadence, why)
    return list(seen.values())


def parse_appendix_b(text: str) -> list[dict[str, str]]:
    """Extract the Appendix B rows."""
    marker = "# Appendix B — Verified external facts"
    start = text.find(marker)
    if start == -1:
        raise ValueError("the Proposal has no Appendix B heading")

    rest = text[start + len(marker) :]
    nxt = re.search(r"(?m)^# ", rest)
    section = rest[: nxt.start()] if nxt else rest

    rows: list[dict[str, str]] = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if len(cells) < 4:
            continue
        if cells[0] == "#" or set(cells[0]) <= set("-: "):
            continue
        rows.append(
            {
                "id": cells[0],
                "fact": cells[1],
                "value": cells[2],
                "method": cells[3],
            }
        )
    if not rows:
        raise ValueError("Appendix B has no data rows")
    return rows


HEADER = f"""\
<!--
  GENERATED FILE -- DO NOT EDIT BY HAND.

  Source:       QQQ-Proposal-V1.md, Appendix B
  Generated by: python tools/gen_verified_facts.py
  Verified by:  python tools/check_verified_facts.py  (runs in CI)

  The VALUES live in the Proposal's Appendix B table. This file adds the cadence each
  fact carries, so a reader can tell which rows are still likely to hold.
-->

# Verified external facts

Every external fact QQQ depends on, with the method that verified it and **how fast it
goes stale**. Generated from Appendix B.

The Proposal states the values. This page adds the part the Proposal's table cannot
express at a glance: which of those values is still likely to be true.

## Why a cadence per fact rather than one date

A register with a single "verified on" date rots as a whole. Nobody knows which rows
still hold, and finding out means re-verifying everything — expensive enough that it
does not happen, so the register quietly becomes history.

Attaching a **class** to each fact makes the decay visible per row. The class is derived
from the fact's own text, not assigned by hand, so a new row gets a plausible cadence
without anyone remembering to classify it.

| Class | Cadence | Why |
|---|---|---|
| **perishable** | every 7 days | A version number or a popularity metric changes without notice |
| **volatile** | every 30 days | A registry or DNS fact changes unpredictably, and not announced |
| **local** | every 7 days | A property of a development machine changes whenever anyone works |
| **stable** | every 180 days | A licence or a specification's content changes rarely, and loudly |

**Last verified: {LAST_VERIFIED}.** That date is stored in `tools/gen_verified_facts.py`
rather than in this generated file, because bumping it is how a re-verification is
recorded — and a re-verification is an action, not an edit to a document.

"""


def render(rows: list[dict[str, str]]) -> str:
    """Render the register markdown."""
    classified: list[tuple[dict[str, str], str, str, str]] = []
    unclassified: list[dict[str, str]] = []

    for row in rows:
        cls, cadence, why = classify(row["fact"], row["method"])
        if not cls:
            unclassified.append(row)
            continue
        classified.append((row, cls, cadence, why))

    parts = [HEADER]

    # Summary counts first, because the number that matters is how many rows are
    # *overdue*, and that is only computable once each has a cadence.
    counts: dict[str, int] = {}
    for _row, cls, _cadence, _why in classified:
        counts[cls] = counts.get(cls, 0) + 1
    parts.append("## Summary\n")
    parts.append("| Class | Facts | Cadence |")
    parts.append("|---|---|---|")
    for cls, cadence, _why in distinct_classes():
        if counts.get(cls):
            parts.append(f"| **{cls}** | {counts[cls]} | {cadence} |")
    parts.append(f"\n**{len(classified)} of {len(rows)} facts classified.**\n")

    if unclassified:
        parts.append(
            "### Unclassified facts\n\n"
            "These rows matched no cadence rule, so nothing says how fast they rot. "
            "**This is a gap rather than a detail**: an unclassified fact is one nobody "
            "will think to re-check.\n"
        )
        for row in unclassified:
            parts.append(f"* `{row['id']}` — {row['fact']}")
        parts.append("")

    for cls, cadence, why in distinct_classes():
        group = [c for c in classified if c[1] == cls]
        if not group:
            continue
        # `cadence` already reads "every 7 days", so the heading must not prefix another
        # "every": the first version produced "re-verify every every 7 days", which is the
        # kind of thing a reader notices and a checker cannot.
        parts.append(f"## {cls.capitalize()} — re-verify {cadence}\n")
        parts.append(f"*{why}.*\n")
        for row, _cls, _cadence, _why in group:
            parts.append(f"### `{row['id']}` — {row['fact']}\n")
            parts.append(f"**Value at {LAST_VERIFIED}.** {row['value']}\n")
            parts.append(f"**Verified by.** `{row['method']}`\n")

    parts.append(
        "---\n\n"
        "## Re-verifying\n\n"
        "When a fact is re-checked:\n\n"
        "1. Update its value in the Proposal's Appendix B table.\n"
        "2. Bump `LAST_VERIFIED` in `tools/gen_verified_facts.py`.\n"
        "3. Regenerate this page: `python tools/gen_verified_facts.py`.\n\n"
        "`tools/check_verified_facts.py` fails CI when this page and Appendix B\n"
        "disagree, so a value change without a regeneration is caught rather than\n"
        "shipping a register that contradicts its own source.\n"
    )
    return "\n".join(parts)


def main() -> int:
    check_only = "--check" in sys.argv

    if not PROPOSAL.exists():
        print(f"FATAL: {PROPOSAL} does not exist")
        return 1

    try:
        rows = parse_appendix_b(PROPOSAL.read_text(encoding="utf-8"))
    except ValueError as e:
        print(f"FATAL: {e}")
        return 1

    generated = render(rows)

    if check_only:
        if not TARGET.exists():
            print(f"FATAL: {TARGET} does not exist; run tools/gen_verified_facts.py")
            return 1
        current = TARGET.read_text(encoding="utf-8")
        if current != generated:
            print(
                "FATAL: docs/verified-facts.md is out of date with Appendix B. Run "
                "`python tools/gen_verified_facts.py`."
            )
            for i, (a, b) in enumerate(
                zip(current.splitlines(), generated.splitlines()), start=1
            ):
                if a != b:
                    print(f"  first difference at line {i}:")
                    print(f"    committed: {a[:110]}")
                    print(f"    generated: {b[:110]}")
                    break
            else:
                print(
                    f"  the committed file has {len(current.splitlines())} lines and "
                    f"the generated one has {len(generated.splitlines())}"
                )
            return 1
        print(
            f"VERIFIED FACTS OK -- {len(rows)} fact(s) from Appendix B, all classified"
        )
        return 0

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(generated, encoding="utf-8")
    unclassified = [
        r["id"] for r in rows if not classify(r["fact"], r["method"])[0]
    ]
    print(f"wrote {TARGET.relative_to(ROOT)} with {len(rows)} fact(s)")
    if unclassified:
        print(f"  unclassified (no cadence): {', '.join(unclassified)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
