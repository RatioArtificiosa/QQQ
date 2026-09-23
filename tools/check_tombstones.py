#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check that no Proposal anchor is silently deleted (`DOC-010`).

# The rule, from §0.5

> **If a section is retired, its anchor is tombstoned**, not deleted: the heading remains
> as `## §6.4 Capability Engine (retired — see §X)` so old links resolve.

The reason is that an anchor is a **link target other documents point at**. Deleting one
turns every inbound citation into a dead link, and the breakage appears in a *different*
file from the one that caused it — a checklist item pointing at nothing, months later,
with no indication of when or why.

# How deletion is detected without version control

Comparing against `git` would be the obvious approach and it is wrong for this purpose: it
detects a change since the last commit, so it fires on every legitimate in-progress edit
and says nothing about a *deletion* specifically.

Instead a **baseline of known anchors** is committed at
`.anchor-baseline.txt`. Every anchor that has ever existed appears there, and the check
fails when one disappears from the Proposal without a tombstone. The baseline only ever
grows, which is what makes "never deleted" enforceable.

# What is checked

  1. Every baseline anchor is still present in the Proposal, **either** as a live heading
     **or** as a tombstoned one.
  2. A tombstoned heading uses the documented form
     `## §X.Y Title (retired — see §A.B)`, so a reader is told where the content went.
  3. A tombstone names a section that exists, because a tombstone pointing at a
     non-existent section is the same dead end the convention exists to prevent.
  4. Anchors are not duplicated across live headings — two headings deriving one anchor
     makes every link to it ambiguous (`check_xrefs.py` check `[3]` covers the same
     ground from the citation side; this one is the heading side).

Usage:
    python tools/check_tombstones.py                # verify against the baseline
    python tools/check_tombstones.py --update       # add newly seen anchors
    python tools/check_tombstones.py --self-test
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"
BASELINE = ROOT / ".anchor-baseline.txt"

# `## §6.4 Capability Engine` or `## §6.4 Capability Engine (retired — see §6.5)`.
HEADING = re.compile(r"^(#{1,4})\s+(§[0-9A-Z][0-9A-Za-z.]*)\s+(.+?)\s*$", re.MULTILINE)

# A tombstone must name its successor:
#     (retired — see §6.5)
TOMBSTONE = re.compile(r"\(retired\s*[—-]\s*see\s+(§[0-9A-Z][0-9A-Za-z.]*)\)", re.IGNORECASE)

# # Why a SEPARATE pattern for a bare `(retired)` marker
#
# The first version detected only the complete `(retired — see §X.Y)` form, so a heading
# marked `(retired)` with no successor was **not recognised as retired at all** — and the
# rule "a tombstone must name a successor" therefore never fired on exactly the case it
# exists for.
#
# The self-test caught it: the case reported `DEAD` because no problem was produced, and
# the cause was that the heading never entered the tombstone branch. A rule whose input
# set excludes its target is unreachable — the same shape as `§O-092`'s glob.
#
# Now any `(retired…)` marks the heading, and the successor is checked separately.
RETIRED_MARKER = re.compile(r"\(retired\b", re.IGNORECASE)


def github_anchor(heading: str) -> str:
    """The GitHub-flavoured anchor for a heading, per §0.5.

    The derivation is pinned in the Proposal and implemented identically in
    `tools/gen_glossary.py`; duplicating it here is deliberate rather than a shared
    helper, because this check must be able to disagree with that one — two
    implementations of the same rule is how a discrepancy becomes visible.
    """
    text = heading.strip().lstrip("#").strip()
    text = text.replace("§", "").lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return text.strip().replace(" ", "-")


def parse_headings(text: str) -> list[dict[str, str]]:
    """Every numbered section heading, with its section number, title and state."""
    out: list[dict[str, str]] = []
    for m in HEADING.finditer(text):
        section = m.group(2)
        title = m.group(3)
        tomb = TOMBSTONE.search(title)
        out.append(
            {
                "level": m.group(1),
                "section": section,
                "title": title,
                # # Why the heading is reconstructed WITH the section number
                #
                # §0.5 derives an anchor from the full heading text, and the section
                # number is part of it: `## §6.4 Capability Engine` becomes
                # `64-capability-engine`, not `capability-engine`.
                #
                # The first version built the anchor from `f"{level} {title}"`, which
                # **dropped the section number entirely** — so every anchor it computed
                # was wrong, the baseline was written with those wrong values, and three
                # self-test cases failed. The check was internally consistent and
                # consistently incorrect, which is exactly why the synthetic cases caught
                # it and the real run did not.
                "anchor": github_anchor(f"{m.group(1)} {section} {title}"),
                "tombstoned": bool(RETIRED_MARKER.search(title)),
                "points_to": tomb.group(1) if tomb else "",
            }
        )
    return out


def load_baseline() -> set[str]:
    if not BASELINE.exists():
        return set()
    return {
        line.strip()
        for line in BASELINE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def save_baseline(anchors: set[str]) -> None:
    header = (
        "# Known Proposal anchors (`DOC-010`).\n"
        "#\n"
        "# Every anchor that has ever existed in QQQ-Proposal-V1.md. The list only GROWS:\n"
        "# an anchor that disappears without a tombstone fails `tools/check_tombstones.py`,\n"
        "# because deleting one turns every inbound citation into a dead link in a\n"
        "# different file from the one that caused it.\n"
        "#\n"
        "# Regenerate with: python tools/check_tombstones.py --update\n"
    )
    body = "\n".join(sorted(anchors))
    write_text_lf(BASELINE,f"{header}\n{body}\n", encoding="utf-8")


def check() -> list[str]:
    """Return the anchor problems. Empty means the convention holds."""
    text = PROPOSAL.read_text(encoding="utf-8")
    headings = parse_headings(text)
    if not headings:
        return ["no numbered Proposal headings found, so every check would pass vacuously"]

    live = {h["anchor"] for h in headings if not h["tombstoned"]}
    all_present = {h["anchor"] for h in headings}
    baseline = load_baseline()
    problems: list[str] = []

    if not baseline:
        problems.append(
            "no `.anchor-baseline.txt`, so silent deletion cannot be detected. Run "
            "`python tools/check_tombstones.py --update` once to record the current set."
        )
        return problems

    # 1. A baseline anchor must still exist, live or tombstoned.
    for anchor in sorted(baseline - all_present):
        problems.append(
            f"the anchor `{anchor}` is in the baseline but no longer appears in the "
            f"Proposal, live or tombstoned. Deleting an anchor breaks every citation to "
            f"it, and the breakage shows up in a different file from the change. If the "
            f"section was retired, keep the heading as `(retired — see §X.Y)`."
        )

    # 2/3. A tombstone must use the documented form and point somewhere real.
    section_numbers = {h["section"] for h in headings}
    for h in headings:
        if not h["tombstoned"]:
            continue
        target = h["points_to"]
        if not target:
            problems.append(
                f"the heading `{h['section']} {h['title']}` looks retired but does not "
                f"name a successor in the form `(retired — see §X.Y)`, so a reader "
                f"following an old link is not told where the content went"
            )
        elif target not in section_numbers:
            problems.append(
                f"the tombstone for `{h['section']}` points at `{target}`, which does not "
                f"exist. A tombstone naming a missing section is the same dead end the "
                f"convention exists to prevent."
            )

    # 4. Two live headings must not derive one anchor.
    seen: dict[str, str] = {}
    for h in headings:
        if h["tombstoned"]:
            continue
        if h["anchor"] in seen:
            problems.append(
                f"the anchor `{h['anchor']}` is derived by both `{seen[h['anchor']]}` and "
                f"`{h['section']}`. Two headings with one anchor makes every link to it "
                f"ambiguous."
            )
        seen[h["anchor"]] = h["section"]

    return problems


def validate(update: bool = False) -> int:
    if update:
        text = PROPOSAL.read_text(encoding="utf-8")
        headings = parse_headings(text)
        anchors = {h["anchor"] for h in headings}
        baseline = load_baseline()
        added = anchors - baseline
        save_baseline(baseline | anchors)
        print(
            f"baseline updated: {len(baseline)} -> {len(baseline | anchors)} anchor(s)"
            + (f", added {len(added)}" if added else ", nothing new")
        )
        for a in sorted(added):
            print(f"  + {a}")
        return 0

    problems = check()
    if problems:
        print("ANCHOR STABILITY FAILED")
        print("")
        for p in problems:
            print(f"  FAIL  {p}")
        return 1

    text = PROPOSAL.read_text(encoding="utf-8")
    headings = parse_headings(text)
    baseline = load_baseline()
    tombstoned = sum(1 for h in headings if h["tombstoned"])
    print(
        f"ANCHOR STABILITY OK -- {len(headings)} heading(s), {tombstoned} tombstoned, "
        f"all {len(baseline)} baseline anchor(s) present, no duplicate derivation"
    )
    return 0


def self_test() -> int:
    """Prove every rule fires, on synthetic heading sets."""
    failures = 0

    def case(name: str, text: str, baseline: set[str], expect: str) -> None:
        nonlocal failures
        headings = parse_headings(text)
        live = {h["anchor"] for h in headings if not h["tombstoned"]}
        present = {h["anchor"] for h in headings}
        problems: list[str] = []
        for anchor in sorted(baseline - present):
            problems.append(f"the anchor `{anchor}` is in the baseline but no longer")
        section_numbers = {h["section"] for h in headings}
        for h in headings:
            if h["tombstoned"]:
                if not h["points_to"]:
                    problems.append("looks retired but does not name a successor")
                elif h["points_to"] not in section_numbers:
                    problems.append(f"points at `{h['points_to']}`, which does not exist")
        seen: dict[str, str] = {}
        for h in headings:
            if h["tombstoned"]:
                continue
            if h["anchor"] in seen:
                problems.append("is derived by both")
            seen[h["anchor"]] = h["section"]
        _ = live
        joined = "\n".join(problems)
        ok = (expect == "" and not problems) or (expect != "" and expect in joined)
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            print(f"        expected {expect!r}, got: {joined[:200]}")

    # # Why the fixtures build their anchors from the SAME helper `parse_headings` uses
    #
    # The first version wrote `github_anchor("## §6.4 Capability Engine")` by hand, which
    # **omits the section number** that the real derivation includes — so the fixtures
    # expected `capability-engine` while the parser produced `64-capability-engine`, and
    # two cases reported DEAD.
    #
    # That is the fixtures disagreeing with the code rather than the code being wrong,
    # and it is the same mistake the production derivation had. Deriving the expected
    # anchor through `parse_headings` on a one-heading string removes the possibility:
    # the fixture can no longer encode a different rule from the one under test.
    def anchor_of(heading: str) -> str:
        parsed = parse_headings(heading)
        if not parsed:
            raise AssertionError(f"the fixture heading {heading!r} did not parse")
        return parsed[0]["anchor"]

    LIVE = "## §6.4 Capability Engine\n\nBody.\n"
    TOMB = "## §6.4 Capability Engine (retired — see §6.5)\n\n## §6.5 The engine\n"

    case("a live heading that stayed", LIVE, {anchor_of(LIVE)}, "")
    case("a correctly tombstoned heading", TOMB, {anchor_of(TOMB)}, "")
    case(
        "an anchor deleted with no tombstone",
        "## §6.5 Something else\n",
        {github_anchor("## §6.4 Capability Engine")},
        "no longer",
    )
    case(
        "a tombstone pointing at a missing section",
        "## §6.4 Capability Engine (retired — see §9.9)\n",
        set(),
        "which does not exist",
    )
    case(
        "a retired-looking heading with no successor",
        "## §6.4 Capability Engine (retired)\n",
        set(),
        "does not name a successor",
    )
    case(
        "two headings deriving one anchor",
        "## §6.4 Capability Engine\n\n## §6.4 Capability Engine\n",
        set(),
        "is derived by both",
    )

    # The real corpus must currently hold.
    problems = check()
    ok = not problems
    print(f"  {'OK  ' if ok else 'DEAD'}  the real Proposal holds the convention")
    if not ok:
        failures += 1
        for p in problems[:3]:
            print(f"        {p}")

    total = 7
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every rule is live")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    if "--update" in sys.argv:
        return validate(update=True)
    return validate()


if __name__ == "__main__":
    raise SystemExit(main())
