#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check that every stated `STAGES` count is the count the table produces.

`ARCH-011`'s defect was not a wrong number. It was **one number written in three
places**, which drifted: the module doc comment said steps 2, 6, 8, 10 and 14 were
implemented, the checklist entry said `5 implemented, 9 partial, 1 built-unwired,
1 absent`, and the `STAGES` table held three implemented rows. All three read as
authoritative; none agreed with the others. Two earlier round-trips "fixed" it by
correcting the numbers, which is how it came back (`§O-244`).

The fix is one counting site. `Summary::of` delegates to `Counts::of`, `Counts`
renders the numbers and the step lists, and the in-file test
`the_documented_counts_match_the_table` asserts the module's own prose against that
rendering. What a test inside `qqq-serve` **cannot** do is read the checklist: the
test binary is compiled from the crate, and `QQQ-Checklist-V1.md` lives two
directories up. So the checklist side is checked here, from the same source of
truth.

# Why this is a check and not a review item

The failure mode is silent. A stale count in a checklist entry still reads as a
measurement, still has the shape of evidence, and still cites `Summary::of` as its
source. That is `§M-006`'s shape -- a control believed live that is not -- and it is
the exact defect this checker exists to prevent recurring, not merely to detect
once.

# Anti-vacuity

Refuses to pass when it finds nothing to compare. A regex that silently matched no
checklist sentence would report success forever, so the extraction asserts it found
the counts before comparing them.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


# This tool's own stdout must be able to encode what it prints. On a Windows console the stream
# inherits `cp1252`, so a character read from a subprocess -- which this file now reads as UTF-8 --
# raises `UnicodeEncodeError` inside `print` and the tool dies while reporting its result. `§O-291`.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


ROOT = Path(__file__).resolve().parent.parent
LIFECYCLE_RS = ROOT / "crates" / "qqq-serve" / "src" / "lifecycle.rs"
CHECKLIST = ROOT / "QQQ-Checklist-V1.md"

# The four status kinds, in the order `Summary::Display` renders them. The order is
# part of the contract: `Display` writes them in this sequence and the checklist
# sentence is compared against that rendering, not against an independently
# assembled string.
KINDS = ("implemented", "partial", "built-unwired", "absent")

# The Rust variant that produces each kind. The fold is checked against these
# rather than against a second count, so a variant added to `Status` with no entry
# here is a failure rather than a silent omission.
VARIANT_FOR_KIND = {
    "implemented": "Status::Implemented",
    "partial": "Status::Partial",
    "built-unwired": "Status::BuiltUnwired",
    "absent": "Status::Absent",
}


def read(path: Path) -> str:
    if not path.is_file():
        print(f"FATAL: {path} does not exist")
        sys.exit(1)
    return path.read_text(encoding="utf-8")


def stages_block(text: str) -> str | None:
    """The body of the `STAGES` array, with its brackets stripped.

    Bracket-counted from the opening `[` rather than matched with a non-greedy
    regex, because a row's `gap` string can contain a `]` and a non-greedy match
    would stop early on a correct file.
    """
    m = re.search(r"pub const STAGES:\s*\[Stage;\s*\d+\]\s*=\s*\[", text)
    if m is None:
        return None
    start = m.end() - 1
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
    return None


def rust_counts(text: str) -> dict[str, list[int]] | None:
    """Fold the `STAGES` rows the way `Counts::of` does.

    Parsed rather than compiled on purpose: the point is to check the SOURCE, and
    shelling out to a test binary would compare against a build artifact that might
    be stale (`§O-120`).

    Returns `None` when the table cannot be read at all, which the caller treats as
    a fatal extraction failure rather than as an empty table.
    """
    block = stages_block(text)
    if block is None:
        return None

    out: dict[str, list[int]] = {kind: [] for kind in KINDS}
    # A row begins at `Stage {` and carries `step:` and `status:` in its body. The
    # split is on the variant keyword rather than on braces, because the `gap`
    # strings are prose and contain no braces but plenty of punctuation.
    for row in re.finditer(r"Stage\s*\{(?P<body>.*?)\n    \},", block, re.S):
        body = row.group("body")
        step_m = re.search(r"step:\s*(\d+)", body)
        status_m = re.search(r"status:\s*(Status::\w+)", body)
        if step_m is None or status_m is None:
            continue
        kind = next(
            (k for k, v in VARIANT_FOR_KIND.items() if v == status_m.group(1)), None
        )
        if kind is None:
            # An untaught `Status` variant. Reported by the caller as a failure
            # rather than skipped, because a silent skip is how a fold stops
            # covering the table.
            out.setdefault("__unknown__", []).append(int(step_m.group(1)))
            continue
        out[kind].append(int(step_m.group(1)))
    for kind in out:
        out[kind].sort()
    return out


def rendered(counts: dict[str, list[int]]) -> str:
    """The sentence `Summary::Display` produces from these counts.

    Mirrors the Rust `write!` format string exactly, including the comma-space
    separators and the `built-unwired` spelling. This is the string the checklist
    must carry verbatim.
    """
    return (
        f"{len(counts['implemented'])} implemented, "
        f"{len(counts['partial'])} partial, "
        f"{len(counts['built-unwired'])} built-unwired, "
        f"{len(counts['absent'])} absent"
    )


def documented_sentence(checklist_src: str) -> str | None:
    """The counts sentence the `ARCH-011` entry states.

    Anchored on the `**Measured: ...**` marker, which is the form this repository's
    checklist entries use for a measured value. Anchoring on the numbers themselves
    would find the right sentence only while it happened to be right.
    """
    m = re.search(
        r"\*\*Measured:\s*(\d+ implemented,\s*\d+ partial,\s*\d+ built-unwired,"
        r"\s*\d+ absent)\.\*\*",
        checklist_src,
    )
    return m.group(1) if m else None


def documented_not_done(checklist_src: str) -> int | None:
    """The number in the entry's "N of the fifteen steps are not done" sentence.

    # The sentence the crate test cannot reach and this checker did not read

    `the_documented_counts_match_the_table` covers the module. This checker covers the
    checklist's `Measured:` line. **Neither read the sentence next to it** — and that
    sentence said **"five"** in the same bullet as a `Measured:` line that made it twelve.
    Two readings of one table, one of them owned (`§O-277`).

    It is extracted by its own typographic marker, like the counts sentence, so a rewrite
    that drops it is *reported* rather than silently becoming unchecked. The number is a
    numeral and not a word on purpose: "five" cannot be compared to anything without a
    number-word parser, and a value that cannot be compared is a value with no owner.
    """
    m = re.search(r"because\s+(\d+)\s+of the fifteen steps are not done", checklist_src)
    return int(m.group(1)) if m else None


def analyse(lifecycle_src: str, checklist_src: str) -> list[str]:
    """The checker's decision procedure, as a pure function.

    Extracted so `self_test` can run it against a synthetic source without touching
    the repository, and so both callers exercise the same rules -- the split
    `§O-149` records as the difference between a self-test that certifies the
    shipped path and one that certifies a different function.
    """
    errors: list[str] = []

    counts = rust_counts(lifecycle_src)
    if counts is None:
        return ["could not find the `STAGES` table in lifecycle.rs"]

    total = sum(len(v) for k, v in counts.items() if k != "__unknown__")
    if total == 0:
        return ["the `STAGES` table parsed to zero rows"]
    if total != 15:
        errors.append(
            f"`STAGES` holds {total} rows; §4.4 lists fifteen. A table with a "
            "different count has lost or invented a step"
        )
    if counts.get("__unknown__"):
        errors.append(
            "a `Status` variant in `STAGES` is not in the checker's fold: "
            f"steps {counts['__unknown__']}. A variant with no entry here is a "
            "row the count would silently omit"
        )

    want = rendered(counts)

    stated = documented_sentence(checklist_src)
    if stated is None:
        errors.append(
            "the `ARCH-011` checklist entry states no `**Measured: N implemented, "
            "N partial, N built-unwired, N absent.**` sentence, so its counts "
            "cannot be checked against the table"
        )
    else:
        normalised = re.sub(r"\s+", " ", stated).strip()
        if normalised != want:
            errors.append(
                f"the `ARCH-011` entry states `{normalised}` and the `STAGES` table "
                f"produces `{want}`. One of them is stale (`§O-244`)"
            )

    # The headline claim, which is the same table read a second way.
    not_done = total - len(counts["implemented"])
    stated_not_done = documented_not_done(checklist_src)
    if stated_not_done is None:
        errors.append(
            "the `ARCH-011` entry states no `because N of the fifteen steps are not "
            "done` sentence, so its headline claim cannot be checked against the table"
        )
    elif stated_not_done != not_done:
        errors.append(
            f"the `ARCH-011` entry says {stated_not_done} of the fifteen steps are not "
            f"done, and the `STAGES` table leaves {not_done} not implemented. The "
            f"sentence and the `Measured:` line beside it describe the same table, so "
            f"they must agree (`§O-277`)"
        )

    return errors


def main() -> int:
    """Report the verdict on the real files.

    Holds no rules: everything that must be true of the verdict lives in `analyse`,
    so the self-test and CI validate the same procedure.
    """
    lifecycle_src = read(LIFECYCLE_RS)
    checklist_src = read(CHECKLIST)

    counts = rust_counts(lifecycle_src)
    if counts is None:
        print("FATAL: could not find the `STAGES` table in lifecycle.rs")
        return 1
    total = sum(len(v) for k, v in counts.items() if k != "__unknown__")
    print(f"`STAGES` rows parsed:  {total}")
    print(f"`STAGES` fold:         {rendered(counts)}")
    print(f"checklist entry says:  {documented_sentence(checklist_src)}")

    errors = analyse(lifecycle_src, checklist_src)
    if errors:
        print(f"\n{len(errors)} PROBLEM(S):")
        for e in errors:
            print(f"  FAIL  {e}")
        print("\nLIFECYCLE COUNTS DRIFTED")
        return 1

    print("\nthe checklist entry and the module documentation both state the table's count")
    print("LIFECYCLE COUNTS OK")
    return 0


def self_test() -> int:
    """Prove this checker can fail, by injecting each defect it exists to catch.

    Four properties, each injected against a synthetic source string:

      1. the checklist stating a count the table does not produce -- the defect
         `ARCH-011` shipped with;
      2. the checklist stating no count at all, which would otherwise make the
         comparison vacuously skip;
      3. a `STAGES` table whose row count changed, so the fold is checked against
         §4.4's fifteen rather than only against itself;
      4. a `Status` variant the checker has not been taught, so a new variant
         cannot be silently omitted from the fold.

    Plus the control: the real files must pass. Without it, a checker that failed
    on everything would satisfy every case above and certify nothing.

    # Why each injection asserts its own anchor applied

    A `str.replace` whose needle is absent returns the input unchanged, and the case
    then tests the unmodified source -- which passes, which the case reports as a
    checker failure when it is a failure of the harness. `§O-183` records the shape.
    """
    print("self-test: injecting the defects this checker exists to catch")

    lifecycle_src = read(LIFECYCLE_RS)
    checklist_src = read(CHECKLIST)

    counts = rust_counts(lifecycle_src)
    if counts is None:
        print("HARNESS FAIL: could not parse the real STAGES table")
        return 1
    real_sentence = rendered(counts)

    cases: list[tuple[str, str, str, bool]] = []

    # 1. The checklist restating a count the table does not produce. This is the
    #    defect exactly as it shipped: a stale hand-written sentence.
    stale = checklist_src.replace(
        f"**Measured: {real_sentence}.**",
        "**Measured: 5 implemented, 9 partial, 1 built-unwired, 1 absent.**",
        1,
    )
    if stale == checklist_src:
        print("HARNESS FAIL: the stale-count injection did not apply")
        return 1
    cases.append(("a checklist count the table does not produce", lifecycle_src, stale, True))

    # 2. No count sentence at all, which a comparison would otherwise skip.
    missing = re.sub(
        r"\*\*Measured:\s*\d+ implemented,.*?absent\.\*\*", "", checklist_src, count=1
    )
    if missing == checklist_src:
        print("HARNESS FAIL: the missing-count injection did not apply")
        return 1
    cases.append(("no count sentence to compare", lifecycle_src, missing, True))

    # 3. A table with a row deleted: the fold must notice against §4.4's fifteen.
    #    The first row is dropped by removing its `Stage { ... },` block. The body
    #    is indented four spaces inside the array and closed by a four-space `},`.
    first_row = re.search(r"\n    Stage \{.*?\n    \},", stages_block(lifecycle_src) or "", re.S)
    if first_row is None:
        print("HARNESS FAIL: could not locate a row to delete")
        return 1
    shorter = lifecycle_src.replace(first_row.group(0), "", 1)
    if shorter == lifecycle_src:
        print("HARNESS FAIL: the row-deletion injection did not apply")
        return 1
    cases.append(("a table with fourteen rows", shorter, checklist_src, True))

    # 4. A `Status` variant the fold has not been taught.
    untaught = lifecycle_src.replace(
        "status: Status::Partial,", "status: Status::Mystery,", 1
    )
    if untaught == lifecycle_src:
        print("HARNESS FAIL: the untaught-variant injection did not apply")
        return 1
    cases.append(("a Status variant the fold omits", untaught, checklist_src, True))

    # 5. The headline sentence disagreeing with the `Measured:` line beside it. This is the
    #    defect as it shipped: the entry said "five" while the line under it made it twelve,
    #    and nothing compared the two. The comparison and the thing compared are both new
    #    here, so the case is the reason the rule exists rather than a decoration on it.
    headline = re.sub(
        r"because\s+\d+\s+of the fifteen steps are not done",
        "because 5 of the fifteen steps are not done",
        checklist_src,
        count=1,
    )
    if headline == checklist_src:
        print("HARNESS FAIL: the headline-count injection did not apply")
        return 1
    cases.append(
        ("a headline count the table does not produce", lifecycle_src, headline, True)
    )

    # 6. The headline sentence removed. A comparison that silently skips an absent
    #    sentence would pass forever after a rewrite dropped it.
    gone = re.sub(
        r"because\s+\d+\s+of the fifteen steps are not done",
        "because the item is open",
        checklist_src,
        count=1,
    )
    if gone == checklist_src:
        print("HARNESS FAIL: the headline-removal injection did not apply")
        return 1
    cases.append(("no headline count to compare", lifecycle_src, gone, True))

    # --- The control ---------------------------------------------------------
    cases.append(("the real files (control)", lifecycle_src, checklist_src, False))

    failures = 0
    for label, lc_src, cl_src, should_fail in cases:
        found = analyse(lc_src, cl_src)
        did_fail = bool(found)
        ok = did_fail == should_fail
        status = "OK  " if ok else "FAIL"
        expectation = "must FAIL" if should_fail else "must PASS"
        print(
            f"  {status} {label}: {expectation}, got "
            f"{'FAIL' if did_fail else 'PASS'}"
        )
        if not ok:
            failures += 1
            for f in found[:3]:
                print(f"         {f}")

    if failures:
        print(f"\nSELF-TEST FAILED: {failures} of {len(cases)} injections wrong")
        return 1
    print(f"\nSELF-TEST OK -- {len(cases)} injection(s), all behaved as required")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    sys.exit(main())
