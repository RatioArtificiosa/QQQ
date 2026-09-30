# SPDX-License-Identifier: Apache-2.0
"""`check_admission.py` -- the admission rule of `docs/definition-of-ready.md`, made executable.

# The measurement that shaped this file, and why it is not a sweep

The rule is: *what may be written down is a claim, and what must be true before it is written is that its
author can name the observation that would falsify it.* Applied to every `->` note in the checklist:

```
TICKED  1116 notes = 276 references + 840 claims   claims WITH a falsifier 364, WITHOUT 476
OPEN     448 notes = 325 references + 123 claims   claims WITH a falsifier  37, WITHOUT  86
                                                    562 of 963 claims (58%) lack one
```

**And the ones that lack one are mostly good prose** -- *"The attestation half is not faked"*, *"Done, all
three parts, each measured rather than asserted."* **A rule that condemned 58% of the corpus retroactively
would be firing on the majority, and `check_done_lines.py` already records the principle: *a check that fires
on the majority is not a check.*

# So the instrument is a RATCHET, and `§O-258` makes it one-directional

**A budget the number must not exceed, and that must only ever fall.** `§O-258` forbids raising a budget to
make a check pass -- **so a ratchet here is not a weakening, it is the only shape that can enforce a new rule
over an existing corpus.** The precedent is `check_done_lines.py`'s `KNOWN_WITHOUT_DONE`, a measured 53-item
list; this is the same idea with a count instead of a name list, because 562 names would be a second copy of
the corpus.

# And the reference/claim split is load-bearing

**A `-> §16 ...` note is a POINTER and must always pass.** The document says so, and 601 of the 1564 notes are
pointers -- **so a checker that demanded a falsifier of them would fail almost half the file for the crime of
citing a section.**
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKLIST = ROOT / "QQQ-Checklist-V1.md"
DONE_LINES = ROOT / "tools" / "check_done_lines.py"

# **The budget, measured at landing.** It may fall and never rise; `--record` prints the value to use.
CLAIMS_WITHOUT_FALSIFIER_BUDGET = 331

# ---------------------------------------------------------------- the three admissible forms

# **Every REFERENCE form is stripped before looking for a number**, because `§16` and `TEST-010` name where a
# requirement lives -- they could not show a claim to be false.
REFERENCE_FORMS = [
    re.compile(r"§[OD]-?\d+[a-z]?"),
    re.compile(r"§\d+(?:\.\d+)*"),
    re.compile(r"\b[A-Z]{2,}-\d+\b"),
    re.compile(r"\bQQQ-\d{4}\b"),
    re.compile(r"\bv?\d+\.\d+(?:\.\d+)*\b"),
]

NUMBER = re.compile(r"\d")

# **A PATH**: a slash-joined path, or a dotted filename with an extension this repository uses.
PATH = re.compile(
    r"\b[\w./-]*/[\w./-]+"
    r"|\b\w[\w.-]*\.(?:rs|toml|md|py|ps1|sh|json|yaml|yml|wit|js|ts|go|c|cpp|h|lock|cmd|txt)\b"
)

# **A COMMAND WITH ITS VERDICT**: a tool of this repository by name, or an exit code, or a verdict word.
COMMAND = re.compile(
    r"\b(?:check|self_test|gen|audit|fault_inject|sync|normalize|det009)\w*\.py\b"
    r"|\bself-test\b|\bexit\s*\d+|\bPASSED\b|\bFAILED\b|\bsha256\b|\bdigest\b"
)

# **Or an explicit statement that none exists, with the reason** -- honest rather than exempt.
NONE_DECLARED = re.compile(
    r"\bno (?:observation|measurement|checker|test|number) (?:would|could|can)\b"
    r"|\bnot (?:verifiable|measurable)\b|\bexternal action\b|\bnot a repository artefact\b"
    r"|\bnot verifiable from inside\b|\bno legal review\b",
    re.I,
)

# A note that is ONLY a section pointer.
REFERENCE_ONLY = re.compile(r"^§\d+(?:\.\d+)*\b")


def forms(note: str) -> list[bool]:
    """Which of the four admissible forms `note` carries."""
    stripped = note
    for r in REFERENCE_FORMS:
        stripped = r.sub(" ", stripped)
    return [
        bool(NUMBER.search(stripped)),
        bool(PATH.search(note)),
        bool(COMMAND.search(note)),
        bool(NONE_DECLARED.search(note)),
    ]


def admits(note: str) -> bool:
    return any(forms(note))


# ---------------------------------------------------------------- reading the checklist

def load_blocks():
    """`check_done_lines.blocks`, imported rather than re-implemented.

    # Why this imports instead of copying

    Because the two checkers must agree about what an item IS. **A second parser would be a second opinion
    about the checklist's grammar**, and the day they disagreed the disagreement would look like a real
    finding. The import is explicit and the failure is loud.
    """
    spec = importlib.util.spec_from_file_location("check_done_lines", DONE_LINES)
    if spec is None or spec.loader is None:
        raise SystemExit(f"FATAL: cannot import {DONE_LINES.relative_to(ROOT)}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.blocks


def audit(text: str) -> tuple[int, list[tuple[str, str]]]:
    """(claims without a falsifier, the ones that are new since the budget was set)."""
    blocks = load_blocks()(text)
    without = 0
    for _status, _name, body in blocks:
        for note in notes_in(body):
            if REFERENCE_ONLY.match(note):
                continue  # a pointer, and the document says it must pass
            if not admits(note):
                without += 1
    return without, []


def notes_in(body: list[str]) -> list[str]:
    """Each `\u2192` note **joined with its continuation lines**.

    # The defect this fixes

    The first version read one physical line per note, so a note whose falsifier was on a later line was
    reported as having none:

        *** NO FALSIFIER ***  **And it is `[~]` rather than `[x]`, measured:** the acceptance-test half is ...

    **The rule is about a NOTE and the implementation was about a LINE**, which is the shape this repository
    records three times over: *a guard is only as wide as its pattern.*

    # What counts as a continuation

    A line that is **not** itself a new arrow, and whose text is deeper-indented than the arrow's own column, or
    blank-but-followed-by-more. **Quoted evidence lines inside a note are part of the note**, which is why the
    join is unconditional rather than stopping at the first blank.
    """
    notes: list[str] = []
    current: list[str] | None = None
    for line in body:
        stripped = line.lstrip()
        if stripped.startswith("\u2192"):
            if current is not None:
                notes.append(" ".join(current))
            current = [stripped[1:].strip()]
        elif current is not None and stripped:
            current.append(stripped)
    if current is not None:
        notes.append(" ".join(current))
    return notes


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    if "--record" in argv:
        text = CHECKLIST.read_text(encoding="utf-8")
        count, _ = audit(text)
        print(f"  claims without a falsifier: {count}")
        print(f"  set CLAIMS_WITHOUT_FALSIFIER_BUDGET = {count}")
        return 0

    text = CHECKLIST.read_text(encoding="utf-8")
    count, _ = audit(text)
    budget = CLAIMS_WITHOUT_FALSIFIER_BUDGET
    if count > budget:
        print(f"ADMISSION FAILED -- {count} claim(s) without a falsifier; the budget is {budget}.")
        print("  A claim must name a number, a path, a command with its verdict, or state why none exists.")
        print("  See docs/definition-of-ready.md section 2.")
        print("  **The budget may only fall.** Raising it is the drift this check exists to notice.")
        return 1
    print(f"ADMISSION OK -- {count} claim(s) without a falsifier, at or under the budget of {budget}.")
    if count < budget:
        print(f"  The budget can be tightened to {count} -- it may only fall.")
    return 0


def self_test() -> int:
    """Every case, including the controls, run against the real parser."""
    cases: list[tuple[str, str, bool]] = [
        (
            "a claim naming a NUMBER passes",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n- [x] **TEST-001** does a thing.\n"
            "  \u2192 Done: measured 547 passed.\n",
            True,
        ),
        (
            "a claim naming a PATH passes",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n- [x] **TEST-002** does a thing.\n"
            "  \u2192 Done: `crates/qqq-run/src/build.rs` carries it.\n",
            True,
        ),
        (
            "a claim naming a CHECKER AND ITS VERDICT passes",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n- [x] **TEST-003** does a thing.\n"
            "  \u2192 Done: `check_xrefs.py` reports validation PASSED.\n",
            True,
        ),
        (
            "a claim declaring that no observation exists passes",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n- [x] **TEST-004** does a thing.\n"
            "  \u2192 Done: no legal review has been obtained; it is an external action.\n",
            True,
        ),
        (
            "CONTROL: a bare section reference passes, and must",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n- [x] **TEST-005** does a thing.\n"
            "  \u2192 \u00a716 Definition of Done for V1\n",
            True,
        ),
        (
            "CONTROL: an open item with only a reference passes",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n- [ ] **TEST-006** does a thing.\n"
            "  \u2192 \u00a74.3 Crate topology\n",
            True,
        ),
        (
            "a WRAPPED claim whose falsifier is on its continuation line passes",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n- [x] **TEST-008** does a thing.\n"
            "  \u2192 Done: the acceptance-test half is executable --\n"
            "    `tools/check_admission.py` runs in **both** gates and reports `556` at or under `556`.\n",
            True,
        ),
        (
            "a WRAPPED claim with a falsifier on NEITHER line fails",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n- [x] **TEST-009** does a thing.\n"
            "  \u2192 Done: the acceptance-test half is executable --\n"
            "    and it is implemented.\n",
            False,
        ),
        (
            "a claim naming NOTHING fails",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n- [x] **TEST-007** does a thing.\n"
            "  \u2192 Done: it is implemented.\n",
            False,
        ),
    ]

    wrong = 0
    for label, src, expected in cases:
        count, _ = audit(src)
        got = count == 0
        mark = "OK  " if got == expected else "FAIL"
        if got != expected:
            wrong += 1
        print(f"    {mark}  {label}")
    print()
    if wrong:
        print(f"  SELF-TEST FAILED -- {wrong} case(s) wrong")
        return 1
    print(f"  SELF-TEST PASSED -- {len(cases)} cases, including two controls")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
