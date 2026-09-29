#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare the checklist-item claims in source module docs against the backlog's status.

    python tools/check_source_claims.py [--report] [--check] [--self-test]

# The claim this checks

Source files state which checklist items they implement, in their own module docs:

    crates/qqq-pkg/src/store.rs    //! Implements `PKG-001` (layout and verification) and `PKG-014` ...
    crates/qqq-core/src/lib.rs     //! Implements `ARCH-007`, `ARCH-008`, `CON-009`, `CON-016`, ...
    crates/qqq-io/src/shard.rs     //! Implements `ARCH-011`'s step 1 and the sharding half of ...

and `tools/backlog.json` states each item's status. **Nothing compared the two**, which is how seven
briefed "unbuilt" items turned out to be built during the goal that produced this file. `§O-415` proposed
this checker; `§O-276` is why it is written as a tool rather than a note.

# Why the vocabulary is two patterns and not one

Both were measured, and each is blind in a different direction:

  * `Implements <ID>` -- **misses comma lists.** `qqq-core/src/lib.rs` names six items in one claim and
    the singular form caught one, leaving five claimed and never compared.
  * backtick-list-after-`Implements` -- **misses `the versioning half of \\`PKG-003\\``**, which has no
    backtick immediately after the verb.

The union is what this file implements. `§O-282` -- *a guard is only as narrow as its pattern* -- applies
to a grammar as much as to a regex, and the fix for one blind spot opened the other.

# Why the failure condition is narrower than "a claim disagrees with the checklist"

Measured on the real tree: **29 items claimed, 26 agreeing, 3 disagreeing** -- and **two of the three
disagreements are honest partials** that the checklist is right to leave open:

    store.rs   "Implements `PKG-001` (layout and verification)"   -- the item also asks for materialisation
    shard.rs   "Implements `ARCH-011`'s step 1"                   -- the item asks for fifteen steps
    semver.rs  "the versioning half of `PKG-003`"                 -- the item asks for a solver

So a checker that failed on every disagreement would produce **two false defects out of three**, which is
the failure `--trials`' own doc names: *"a determinism check that fires on a stable suite is worse than no
check, because it teaches the reader to ignore the one signal it exists to give."*

**The failure condition is therefore: a TOTAL claim against an item the backlog reports as not done.** A
claim is partial when it carries one of a closed set of markers -- `the <x> half of`, `'s step <n>`, a
parenthetical scope after the id, or the word `partial` in the same doc paragraph. Everything else is
total, and a total claim that the checklist contradicts is a defect in one of the two documents.

# What this deliberately does NOT check

A `[x]` item whose implementing file has been deleted. That direction needs the checklist to name the
file, and it does not. Reporting it as covered would be `§O-375` -- a rule that cannot fire.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

BACKLOG = pathlib.Path("tools/backlog.json")
CRATES = pathlib.Path("crates")

ID = r"[A-Z]{2,6}-\d{3}"
BACKTICKED = re.compile(rf"`({ID})`")

# Two patterns, unioned. See the module doc for the measurement that made both necessary -- and note
# the third blind spot the fault injection found: `CLAIM_LIST` must tolerate a parenthetical scope
# BETWEEN ids, because `store.rs` writes
#
#     //! Implements `PKG-001` (layout and verification) and `PKG-014`
#
# and a list pattern that expects only ids separated by `,`/`and` stops at the parenthesis -- reading
# `PKG-001` and silently skipping `PKG-014`. Removing that scope and re-running `--check` reported no
# change, which is what exposed it: **the injection was inert because the id it made total was already
# invisible.**
CLAIM_SINGULAR = re.compile(rf"[Ii]mplements\s+(?:the\s+[\w-]+\s+half\s+of\s+)?`?({ID})`?")
CLAIM_LIST = re.compile(rf"[Ii]mplements\s+((?:`{ID}`(?:\s*\([^)]*\))?[,\s]*(?:and\s+)?)+)", re.S)

# A closed vocabulary of partiality. Each entry was observed on the real tree.
PARTIAL_MARKERS = (
    re.compile(rf"the\s+[\w-]+\s+half\s+of\s+`?{ID}"),      # "the versioning half of `PKG-003`"
    re.compile(rf"`?{ID}`?'s\s+step\s+\d+"),                 # "`ARCH-011`'s step 1"
    re.compile(rf"`?{ID}`?\s*\("),                           # "`PKG-001` (layout and verification)"
    re.compile(r"(?i)\bpartial\b"),
)


def module_head(text: str) -> str:
    """The module doc: everything before the first `use`, which is where claims are written.

    A claim later in the file is prose about something else, and including it made the first version of
    this parse report `ARCH-007` from a doc comment that was describing a different item.
    """
    return text.split("\nuse ", 1)[0][:6000]


def claims_in(head: str) -> set[str]:
    """Every id this head claims, from both patterns."""
    out: set[str] = set()
    for m in CLAIM_LIST.finditer(head):
        out.update(BACKTICKED.findall(m.group(1)))
    for m in CLAIM_SINGULAR.finditer(head):
        out.add(m.group(1))
    return out


# A heading that weakens the claim beneath it. See `is_partial` for the measurement that added it.
WEAKER_HEADINGS = re.compile(r"(?im)^\s*//!\s*#+\s*.*(coverage|contributes|related)")


def is_partial(head: str, iid: str) -> bool:
    """Whether the claim about `iid` is scoped rather than total."""
    # A claim under a weaker heading is scoped by its own heading. `qqq-core/src/lib.rs` writes
    #
    #     //! ## Checklist coverage
    #     //!
    #     //! Implements `ARCH-007`, `ARCH-008`, `CON-009`, `CON-016`, `AGENT-021`, `AGENT-022`.
    #
    # and `ARCH-007` is "Create **all crates** listed in the topology" -- which one crate cannot
    # complete. **"Coverage" is a weaker claim than "implements"**, and the first version of this file
    # read it as the stronger one and reported a defect. That was a false positive found by reading the
    # finding rather than counting it: the id list was right, and the verb in the heading was not the
    # verb in the sentence.
    if WEAKER_HEADINGS.search(head):
        return True
    # Otherwise, only the sentence or two around the id, so a distant `partial` cannot excuse a total
    # claim -- **and the marker must be about THIS id.**
    #
    # The first version of this loop matched the marker patterns as written, and those patterns use
    # `{ID}`, which is the *class* `[A-Z]{2,6}-\d{3}` rather than the id under test. So
    # `PKG-001`'s own parenthetical, sitting inside `DIST-001`'s 440-character window, excused
    # `DIST-001` -- and the fault injection that appended a deliberately total `Implements \`DIST-001\``
    # to `store.rs` was classified `scoped-and-open` and `--check` stayed green.
    #
    # That is the fourth blind spot this file has had, and the only one found by injecting a defect
    # rather than by reading the output. `§O-280`: confirm the premises, not the exit code.
    for m in re.finditer(re.escape(iid), head):
        window = head[max(0, m.start() - 220) : m.end() + 220]
        for p in PARTIAL_MARKERS:
            for hit in p.finditer(window):
                # A marker that names an id must name *THIS* id, or it is a neighbour's scope.
                #
                # The first attempt at this line tested `BACKTICKED.search(hit.group(0))`, which accepts
                # any backticked id at all -- so `PKG-001`'s parenthetical still excused `DIST-001` and
                # the injection stayed green. Narrowing a check by one clause is not narrowing it to the
                # thing being checked; that is `§O-282` for the fifth time in this file.
                if re.search(rf"`?{re.escape(iid)}`?", hit.group(0)):
                    return True
    return False


def scan() -> tuple[dict[str, set[str]], dict[str, bool]]:
    """(id -> files claiming it, id -> whether every claim about it is partial)."""
    where: dict[str, set[str]] = {}
    partial: dict[str, bool] = {}
    for path in sorted(CRATES.rglob("*.rs")):
        try:
            head = module_head(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, OSError):
            continue
        for iid in claims_in(head):
            where.setdefault(iid, set()).add(path.as_posix())
            partial[iid] = partial.get(iid, True) and is_partial(head, iid)
    return where, partial


def load_status() -> dict[str, str]:
    b = json.loads(BACKLOG.read_text(encoding="utf-8"))
    return {i["id"]: i["status"] for i in b["items"]}


def report() -> int:
    where, partial = scan()
    status = load_status()
    agree = disagree_total = disagree_partial = unknown = 0
    for iid in sorted(where):
        st = status.get(iid, "MISSING")
        if st == "MISSING":
            unknown += 1
            print(f"  UNKNOWN  {iid:<10} claimed by {sorted(where[iid])}")
        elif st == "done":
            agree += 1
        elif partial[iid]:
            disagree_partial += 1
            print(f"  partial  {iid:<10} claimed by {sorted(where[iid])} -- scoped claim, item open")
        else:
            disagree_total += 1
            print(f"  TOTAL    {iid:<10} claimed by {sorted(where[iid])} -- claim is total, item is {st}")
    print()
    print(f"  {len(where)} item(s) claimed | agreeing {agree} | scoped-and-open {disagree_partial} "
          f"| TOTAL-and-open {disagree_total} | unknown {unknown}")
    return disagree_total + unknown


def self_test() -> int:
    """Fault injection: the total claim must be caught, the scoped claim must not.

    `want_claimed` is `True` for every case that names the id, **including the scoped ones** -- the first
    version of this self-test asserted `False` for those, which is wrong: a scoped claim is still a claim,
    and `claims_in()` and `is_partial()` answer two independent questions. The three cases failed and
    named the *code* as broken when the *assertion* was. `§O-411` from the other side: a test is a claim
    about what is possible, and this one claimed the impossible.
    """
    cases = [
        ("a total claim against an unticked item is a defect",
         "//! Implements `PKG-001` and `PKG-014`.", "PKG-001", False, True),
        ("a scoped claim is still a claim, and is scoped",
         "//! Implements `PKG-001` (layout and verification).", "PKG-001", True, True),
        ("a half-of claim is scoped",
         "//! Implements the versioning half of `PKG-003`.", "PKG-003", True, True),
        ("a step claim is scoped",
         "//! Implements `ARCH-011`'s step 1 and the sharding half.", "ARCH-011", True, True),
        ("a comma list is read in full",
         "//! Implements `ARCH-007`, `ARCH-008`, `CON-009`.", "CON-009", False, True),
        ("a claim under a coverage heading is scoped",
         "//! ## Checklist coverage\n//!\n//! Implements `ARCH-007`.", "ARCH-007", True, True),
        ("a claim under a related-work heading is scoped",
         "//! ## Related items\n//!\n//! Implements `ARCH-008`.", "ARCH-008", True, True),
    ]
    bad = 0
    for name, head, iid, want_partial, want_claimed in cases:
        got_claimed = iid in claims_in(head)
        got_partial = is_partial(head, iid)
        ok = got_claimed == want_claimed and got_partial == want_partial
        if not ok:
            bad += 1
        print(f"  {'ok ' if ok else 'FAIL'}  {name}")
        print(f"        claimed={got_claimed} (want {want_claimed})  partial={got_partial} (want {want_partial})")

    # And the anti-vacuity clause: a head with no claim at all must yield nothing, or every pattern
    # above could be matching something other than what it names.
    if claims_in("//! A module about nothing in particular.") :
        bad += 1
        print("  FAIL  a head with no claim yields no ids")
    else:
        print("  ok    a head with no claim yields no ids")

    print()
    if bad:
        print(f"SELF-TEST FAILED -- {bad} case(s)")
        return 1
    print(f"SELF-TEST PASSED -- {len(cases) + 1} case(s); both patterns and the partiality vocabulary are live")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    if "--report" in argv or not argv:
        n = report()
        return 0
    if "--check" in argv:
        n = report()
        print()
        if n:
            print(f"SOURCE CLAIMS FAILED -- {n} claim(s) need an owner")
            return 1
        print("SOURCE CLAIMS OK -- every total claim agrees with the backlog")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
