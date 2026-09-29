# SPDX-License-Identifier: Apache-2.0
"""Every ticked checklist item must carry evidence, and no `→ Done:` block may repeat a line.

# Why this exists, in the three defects that motivated it

**A duplicated clause, which nothing could see.** `TEST-008`'s `→ Done:` block held the same
seventy-nine-character sentence twice, because an edit's anchor ended mid-sentence and its replacement
reproduced past the end. **`check_checklist_counts` counts items and `check_doc_claims` resolves numerals —
neither reads prose** — so it rendered as a repeated clause and passed every gate. That is the prose form
of the defect this corpus names for figures: *a number that cannot be compared is a number with no owner.*

**A tick with no evidence.** Measured when this file was written: **248 items are ticked and 53 of them
have no `→ Done:` line.** They are not wrong — they were ticked before the convention existed — but the
count only ever went one way, and nothing said so.

**And a fabricated list, by the agent who wrote this file.** The first version of `KNOWN_WITHOUT_DONE` held
eight ids measured from a truncated print and **forty-five invented to fill the count**. `SEC-007`,
`SEC-022`, `DET-001`, `TEST-009` and a whole `LANG-` tail were made up. **That is `§O-126` exactly** — the
observation `check_checklist_citations.py` was written after: *"the identifier was invented, a quotation was
wrapped around it to look like a citation, and the same claim was repeated in a commit message."*

**And the fabrication was not harmless.** A list that is too **large** fails loudly; a list that is wrong
in *membership* is silent, because an evidence-less item outside it is never reported. **The failure is in
the quiet direction**, which is why check [3] below refuses a list that disagrees with the corpus in
**either** direction.

# Check [1] — no block repeats a substantial line

**Certain, and the reason it is a line rather than a phrase.** A repeated line of forty characters or more,
within one item's block, is always a mistake: prose that says the same thing twice says it once too many.
Forty is chosen so that a short shared fragment — an em-dash clause, a citation, a backticked identifier —
is not flagged, because **a guard that fires on legitimate repetition is a guard people turn off.**

# Check [2] — a ticked item with no `→ Done:` line and no entry in the list fails

**And only a *ticked* item.** The first version filtered every item, so the 249 unticked ones were each
reported as lacking evidence — **a check that fires on the majority is not a check.** The self-test caught
it because one of its cases asserts that an unticked item needs no evidence.

# Check [3] — the list must agree with the corpus **both ways**

An id in the list that now *has* a `→ Done:` line is a failure, so the list ratchets **downward** and an
item cannot stay listed after gaining evidence. **Without this the set could be refreshed to the same size
while changing membership**, which is how a list stops describing anything.

# Escape hatch

A block may contain a repeated substantial line if it carries `done-lines-exempt` on its own line, beside
the reason. **Like `check_checklist_citations.py`'s `not-a-checklist-item`, a checker must be able to
describe the class it forbids without being an instance of it** — and this file's self-test fabricates
both defects to prove it detects them.

Exit: 0 ok, 1 a defect, 2 the corpus could not be read.
"""

from __future__ import annotations

import pathlib
import re
import sys

CHECKLIST = pathlib.Path("QQQ-Checklist-V1.md")

# The shortest repeated line worth reporting. Below this, a shared fragment is more likely to be a
# citation, an em-dash clause or a backticked identifier than a duplicated sentence.
SUBSTANTIAL = 40

EXEMPT = "done-lines-exempt"

ITEM = re.compile(r"^- \[([x~! ])\] \*\*([A-Z]+-\d+)\*\*")

# **Measured at `6abb86e`, by the command in this file's own header rather than by hand.** Explicit rather
# than counted: the set is what a reader checks, and a number cannot be checked against anything. Each was
# ticked before `→ Done:` became the convention, and each was ticked at a commit that has evidence of its
# own -- this list records that the *line* is absent, not that the *work* is.
KNOWN_WITHOUT_DONE = frozenset(
    """
    FND-010 DOC-018 ARCH-010 HOST-009 HOST-020 CON-006 CON-011 SEC-003 SEC-009 SEC-012 SEC-015
    SEC-016 SEC-017 SEC-018 SEC-019 SEC-020 SEC-027 SRV-001 SRV-002 SRV-003 SRV-004 SRV-005 SRV-006
    SRV-009 SRV-020 DX-001 DX-002 DX-003 DX-009 DX-016 CLI-003 CLI-004 CLI-008 CLI-009 CLI-010 CLI-011
    CLI-014 CLI-016 CLI-017 CLI-019 CLI-021 OBS-001 OBS-002 OBS-003 OBS-004 OBS-006 OBS-007 OBS-008
    OBS-011 OBS-013 OBS-014 OBS-016 OQ-007
    """.split()
)


def blocks(text: str) -> list[tuple[str, str, list[str]]]:
    """Every checklist item as `(status, id, its body lines)`.

    The body runs to the next item, which is what makes a `→ Done:` line belong to its own item rather
    than to the file.
    """
    lines = text.split("\n")
    out: list[tuple[str, str, list[str]]] = []
    for i, line in enumerate(lines):
        m = ITEM.match(line)
        if not m:
            continue
        j = i + 1
        while j < len(lines) and not re.match(r"^- \[", lines[j]):
            j += 1
        out.append((m.group(1), m.group(2), lines[i + 1 : j]))
    return out


def duplicates(body: list[str]) -> list[str]:
    """Substantial lines that appear more than once, in order of second appearance."""
    if any(EXEMPT in l for l in body):
        return []
    seen: set[str] = set()
    repeated: list[str] = []
    for line in body:
        s = line.strip()
        if len(s) < SUBSTANTIAL:
            continue
        if s in seen and s not in repeated:
            repeated.append(s)
        seen.add(s)
    return repeated


def has_done(body: list[str]) -> bool:
    return any(l.strip().startswith("→ Done:") for l in body)


def audit(text: str) -> tuple[list[tuple[str, str]], list[str], list[str], str | None]:
    """Return `(duplications, newly evidenceless, stale list entries, fatal)`.

    Separated from `main` so the self-test drives the same code the check does, rather than a copy of it
    that could drift.
    """
    parsed = blocks(text)
    if not parsed:
        return [], [], [], "no checklist items were found -- the file was not read"

    dups = [(oid, d) for _, oid, body in parsed for d in duplicates(body)]
    present = {oid for _, oid, _ in parsed}
    evidenceless = {oid for status, oid, body in parsed if status == "x" and not has_done(body)}
    # **Both directions, and only over what the file actually holds.** `new` is evidence-less and
    # unlisted; `stale` is listed and now has evidence.
    #
    # The first version computed `stale` as `KNOWN_WITHOUT_DONE - evidenceless`, which reads *"absent from
    # the file"* as *"stale"* -- so a fixture holding one id reported all fifty-three as stale, and the
    # self-test caught it in four cases. **A pattern wider than the thing it describes is not a guard.**
    # Intersecting with `present` first is what makes the rule about the file rather than about the list.
    new = sorted(evidenceless - KNOWN_WITHOUT_DONE)
    stale = sorted(KNOWN_WITHOUT_DONE & (present - evidenceless))
    return dups, new, stale, None


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    try:
        text = CHECKLIST.read_text(encoding="utf-8")
    except OSError as e:
        print(f"DONE LINES: cannot read {CHECKLIST}: {e}")
        return 2

    dups, new, stale, fatal = audit(text)
    if fatal:
        print(f"DONE LINES: {fatal}")
        return 2

    if dups:
        print(f"DONE LINES: {len(dups)} -> Done: block(s) repeat a substantial line\n")
        for oid, line in dups[:10]:
            print(f"  {oid}: {line[:96]!r}")
        print(
            "\n  A repeated line in one item's block is always a mistake -- an edit whose anchor ended "
            "mid-sentence and whose replacement reproduced past the end produces exactly this."
        )

    if new:
        print(f"\n{len(new)} newly ticked item(s) carry no evidence\n")
        for oid in new[:10]:
            print(f"  {oid}")
        print(
            "\n  A tick is the strongest claim the checklist makes. Add a `→ Done:` line naming the code, "
            "the test and the measured value."
        )

    if stale:
        print(f"\n{len(stale)} listed item(s) now carry evidence, so the list is stale\n")
        for oid in stale[:10]:
            print(f"  {oid}")
        print(
            "\n  The list ratchets downward: an item that gains a `→ Done:` line must be removed, or the "
            "set can be refreshed to the same size while changing membership."
        )

    if dups or new or stale:
        return 1

    print(
        f"DONE LINES OK -- no block repeats a substantial line; "
        f"{len(KNOWN_WITHOUT_DONE)} known item(s) without evidence, and the list agrees both ways"
    )
    return 0


def self_test() -> int:
    """Fabricate each defect and require detection, then require a clean corpus to pass.

    The fabricated id is `ZZ-001`, which is not a checklist item and cannot collide with one -- the same
    escape `check_checklist_citations.py` needed for `DX-029`.
    """
    long = "y" * 50
    cases: list[tuple[str, bool]] = []

    def case(name: str, text: str, caught: bool) -> None:
        dups, new, stale, fatal = audit(text)
        got = bool(dups) or bool(new) or bool(stale) or fatal is not None
        cases.append((name, got == caught))

    case("no item at all fails loudly rather than passing", "nothing here", True)
    case(
        "a block repeating a substantial line is caught",
        f"- [x] **ZZ-001** something.\n  → Done: ran.\n  {long}\n  {long}\n",
        True,
    )
    case(
        "a short repeated fragment is not",
        "- [x] **ZZ-001** something.\n  → Done: short.\n  short.\n",
        False,
    )
    case(
        "the exemption suppresses the duplicate",
        f"- [x] **ZZ-001** something.\n  → Done: {EXEMPT}\n  {long}\n  {long}\n",
        False,
    )
    case(
        "a ticked item with no evidence and no entry is caught",
        "- [x] **ZZ-001** something.\n  → §1\n",
        True,
    )
    case(
        "a ticked item with a → Done: line passes",
        "- [x] **ZZ-001** something.\n  → Done: measured.\n",
        False,
    )
    # **The case the first version got wrong.** It filtered every item, so a corpus of unticked items was
    # reported as entirely evidence-less -- a check that fires on the majority is not a check.
    case(
        "an unticked item needs no evidence",
        "- [ ] **ZZ-001** something.\n  → §1\n",
        False,
    )
    case(
        "an item in the list that gained evidence is caught",
        f"- [x] **{next(iter(sorted(KNOWN_WITHOUT_DONE)))}** something.\n  → Done: measured.\n",
        True,
    )

    bad = [n for n, ok in cases if not ok]
    for name, ok in cases:
        print(f"  {'OK  ' if ok else 'FAIL'} {name}")
    if bad:
        print(f"\nSELF-TEST FAILED -- {len(bad)} of {len(cases)}")
        return 5
    print(f"\nSELF-TEST PASSED -- {len(cases)} of {len(cases)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
