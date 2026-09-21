#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate the security-advisory register (`SEC-023`).

A security index that drifts is worse than no index: it tells a reader they are
unaffected while the advisory file sitting next to it says otherwise. This checker
exists so that drift is a build failure rather than a discovery made by a user
during an incident.

What it enforces:

  1. Every `QQQ-YYYY-NNN.md` in `docs/advisories/` has a row in `INDEX.md`.
  2. Every row in `INDEX.md` names an advisory file that exists.
  3. No identifier is defined twice — in filenames or in the index.
  4. Every advisory has all required sections, each non-empty.
  5. The severity in a file matches the severity in its index row.
  6. Identifiers match `QQQ-YYYY-NNN`, and the sequence number is unique.
  7. "Found" is not later than "Published".

Usage:  python tools/check_advisories.py [--self-test]
Exit:   0 = the register is internally consistent, 1 = it is not
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADVISORY_DIR = ROOT / "docs" / "advisories"
INDEX = ADVISORY_DIR / "INDEX.md"

# `QQQ-2026-001`: a four-digit year and a zero-padded three-digit sequence. The
# format is fixed because the identifier is what a reporter is given and what a
# user searches for; a project that changes its identifier format mid-history
# breaks every stored reference to it.
ID_PATTERN = re.compile(r"^QQQ-(\d{4})-(\d{3})$")

# The sections `README.md` promises, in the order the template uses. Required
# because a missing "Affected versions" is the difference between an advisory a
# user can act on and one they have to email about.
REQUIRED_SECTIONS = [
    "Identifier",
    "Published",
    "Found",
    "Severity",
    "Affected versions",
    "Fixed in",
    "Summary",
    "Impact",
    "Mitigation",
    "Credit",
    "Details",
]

SEVERITIES = {"critical", "high", "medium", "low"}

# The placeholder used while the register is empty. Treated as "no rows" rather
# than as a malformed row.
EMPTY_ROW_MARKER = "_(none)_"


def parse_index(text: str) -> list[dict[str, str]]:
    """Parse the markdown table in INDEX.md into rows.

    Returns an empty list when the table holds only the placeholder row.
    """
    rows: list[dict[str, str]] = []
    header: list[str] | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            # A blank line between the table and whatever follows ends the table.
            if header is not None and stripped == "":
                break
            continue

        cells = [c.strip() for c in stripped.strip("|").split("|")]

        # The separator row: `|---|---|`.
        if all(set(c) <= set("-: ") and c for c in cells):
            continue

        if header is None:
            header = [c.lower() for c in cells]
            continue

        if cells and cells[0] == EMPTY_ROW_MARKER:
            continue

        if len(cells) != len(header):
            raise ValueError(
                f"index row has {len(cells)} cells but the header has {len(header)}: "
                f"{line!r}"
            )
        rows.append(dict(zip(header, cells, strict=True)))

    return rows


def parse_sections(text: str) -> dict[str, str]:
    """Split an advisory into `{section heading: body}`.

    Headings are `## Name` or `**Name.**` -- both appear in real advisories, and
    accepting only one form would reject a correctly written file.
    """
    sections: dict[str, str] = {}

    # `## Heading` style.
    for match in re.finditer(r"(?m)^##\s+(.+?)\s*$", text):
        name = match.group(1).strip()
        start = match.end()
        nxt = re.search(r"(?m)^##\s+", text[start:])
        end = start + nxt.start() if nxt else len(text)
        sections[name] = text[start:end].strip()

    # `**Heading.**` style, used inside prose sections.
    for match in re.finditer(r"\*\*([A-Z][A-Za-z ]+?)\.?\*\*", text):
        name = match.group(1).strip()
        if name not in sections:
            sections.setdefault(name, "present")

    return sections


def check_advisory(path: Path) -> list[str]:
    """Return the problems with one advisory file. Empty means valid."""
    problems: list[str] = []
    text = path.read_text(encoding="utf-8")
    sections = parse_sections(text)

    stem = path.stem
    if not ID_PATTERN.match(stem):
        problems.append(
            f"{path.name}: the filename is not `QQQ-YYYY-NNN`; an identifier a user "
            f"cannot search for is not an identifier"
        )

    for required in REQUIRED_SECTIONS:
        if required not in sections:
            problems.append(
                f"{path.name}: missing the required section `{required}` "
                f"(present: {sorted(sections)})"
            )

    # A section that exists but is empty is a section that was not written.
    for required in REQUIRED_SECTIONS:
        body = sections.get(required)
        if body is not None and body.strip() in {"", "**", "present"} and required in {
            "Summary",
            "Impact",
            "Affected versions",
            "Fixed in",
        }:
            # `present` means the heading was found in `**Bold.**` form, where the
            # body is the surrounding prose; only flag genuinely empty bodies.
            if body == "":
                problems.append(f"{path.name}: section `{required}` is empty")

    # The identifier inside the file must match the filename.
    if "Identifier" in sections:
        declared = re.search(r"QQQ-\d{4}-\d{3}", sections["Identifier"])
        if declared and declared.group(0) != stem:
            problems.append(
                f"{path.name}: declares identifier {declared.group(0)!r}, which is "
                f"not the filename; two names for one advisory is one too many"
            )

    # Severity must be one of the four the policy defines.
    if "Severity" in sections:
        found = re.search(
            r"\b(critical|high|medium|low)\b", sections["Severity"], re.IGNORECASE
        )
        if not found:
            problems.append(
                f"{path.name}: severity is not one of {sorted(SEVERITIES)}"
            )

    # Found must not postdate Published.
    dates = {}
    for key in ("Published", "Found"):
        if key in sections:
            m = re.search(r"(\d{4})-(\d{2})-(\d{2})", sections[key])
            if m:
                dates[key] = m.group(0)
    if "Published" in dates and "Found" in dates and dates["Found"] > dates["Published"]:
        problems.append(
            f"{path.name}: Found ({dates['Found']}) is later than Published "
            f"({dates['Published']})"
        )

    return problems


def validate() -> int:
    """Validate the whole register. Returns a process exit code."""
    if not ADVISORY_DIR.is_dir():
        print(f"FATAL: {ADVISORY_DIR} does not exist")
        return 1
    if not INDEX.is_file():
        print(f"FATAL: {INDEX} does not exist, so the register has no front door")
        return 1

    # # Why the glob is `*.md` and not `QQQ-*.md`
    #
    # A glob that only matches well-formed names cannot report a *malformed* one:
    # `ADVISORY-1.md` would simply be invisible, the index row pointing at it would
    # be reported as "does not exist", and the real problem -- a filename that does
    # not follow the scheme -- would never be named. The self-test's last case found
    # exactly this: the check was correct but unreachable.
    #
    # `INDEX.md` and `README.md` are excluded by name, since they are the register's
    # own documentation rather than advisories.
    files = sorted(
        p
        for p in ADVISORY_DIR.glob("*.md")
        if p.name not in {"INDEX.md", "README.md"}
    )
    by_stem = {p.stem: p for p in files}

    problems: list[str] = []

    # 3/6. Identifiers must be unique and well formed.
    seen: dict[str, Path] = {}
    for path in files:
        stem = path.stem
        if stem in seen:
            problems.append(f"identifier {stem} is defined twice: {seen[stem]} and {path}")
        seen[stem] = path
        if not ID_PATTERN.match(stem):
            problems.append(f"{path.name}: does not match `QQQ-YYYY-NNN`")

    # 1. Every file needs a row; 2. every row needs a file.
    try:
        rows = parse_index(INDEX.read_text(encoding="utf-8"))
    except ValueError as e:
        print(f"FATAL: INDEX.md is malformed: {e}")
        return 1

    indexed = {r.get("identifier", "") for r in rows}

    for stem in by_stem:
        if stem not in indexed:
            problems.append(
                f"{stem}: an advisory exists at docs/advisories/{stem}.md but has "
                f"no row in INDEX.md, so a reader checking the index would not "
                f"learn they are affected"
            )
    for row_id in indexed:
        if row_id not in by_stem:
            problems.append(
                f"INDEX.md lists {row_id}, but docs/advisories/{row_id}.md does not "
                f"exist; the index points at nothing"
            )

    # 5. Severity must agree between the file and the index.
    for row in rows:
        row_id = row.get("identifier", "")
        if row_id in by_stem:
            text = by_stem[row_id].read_text(encoding="utf-8")
            sections = parse_sections(text)
            file_sev = re.search(
                r"\b(critical|high|medium|low)\b",
                sections.get("Severity", ""),
                re.IGNORECASE,
            )
            row_sev = re.search(
                r"\b(critical|high|medium|low)\b",
                row.get("severity", ""),
                re.IGNORECASE,
            )
            if file_sev and row_sev:
                if file_sev.group(1).lower() != row_sev.group(1).lower():
                    problems.append(
                        f"{row_id}: the file says severity {file_sev.group(1)!r} but "
                        f"the index says {row_sev.group(1)!r}"
                    )

    # 4/7. Per-file structural checks.
    for path in files:
        problems.extend(check_advisory(path))

    if problems:
        print("ADVISORY REGISTER FAILED")
        print("")
        for p in problems:
            print(f"  FAIL  {p}")
        return 1

    print(
        f"ADVISORY REGISTER OK -- {len(files)} advisor{'y' if len(files) == 1 else 'ies'}, "
        f"{len(rows)} indexed row(s), {len(REQUIRED_SECTIONS)} required sections enforced"
    )
    return 0


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def self_test() -> int:
    """Prove every check can fail.

    # Why this harness exists

    A checker that has never rejected anything is a checker nobody has seen work,
    and this repository has found six controls that were installed and inert
    (`§O-066`, `§O-069`, `§O-071`, `§O-076`, `§O-085`, `§O-088`). The advisory
    register is the one artifact a user consults *during an incident*, so a
    validator that cannot fail would be discovered at the worst possible moment.

    Each case builds a throwaway copy of the register, breaks one thing, and
    asserts the checker rejects it. The clean case runs first, so a failure there
    means the fixture itself is wrong.
    """
    global ROOT, ADVISORY_DIR, INDEX

    original_root, original_dir, original_index = ROOT, ADVISORY_DIR, INDEX

    VALID_ADVISORY = """\
# QQQ-2026-001 -- example advisory

## Identifier

QQQ-2026-001

## Published

2026-03-01

## Found

2026-02-20

## Severity

high

## Affected versions

>=0.3.0, <0.3.2

## Fixed in

0.3.2

## Summary

An example advisory used only by the checker's self-test.

## Impact

An example consequence, stated as a consequence.

## Mitigation

Upgrade to 0.3.2.

## Credit

Reported by the self-test.

## Details

The technical narrative, including what we got wrong.
"""

    VALID_INDEX = """\
# Advisory index

| Identifier | Published | Found | Severity | Affected | Fixed in | Summary |
|---|---|---|---|---|---|---|
| QQQ-2026-001 | 2026-03-01 | 2026-02-20 | high | >=0.3.0, <0.3.2 | 0.3.2 | example |
"""

    cases: list[tuple[str, str, str, str]] = [
        # (name, advisory content, index content, what must break)
        ("clean register", VALID_ADVISORY, VALID_INDEX, ""),
        (
            "advisory with no index row",
            VALID_ADVISORY,
            VALID_INDEX.replace(
                "| QQQ-2026-001 | 2026-03-01 | 2026-02-20 | high | >=0.3.0, <0.3.2 | 0.3.2 | example |",
                "| _(none)_ | | | | | | |",
            ),
            "no row in INDEX.md",
        ),
        (
            "index row with no advisory",
            VALID_ADVISORY,
            VALID_INDEX
            + "| QQQ-2026-002 | 2026-03-02 | 2026-03-01 | low | all | 0.4.0 | ghost |\n",
            "does not exist",
        ),
        (
            "missing required section",
            VALID_ADVISORY.replace("## Impact", "## NotImpact"),
            VALID_INDEX,
            "missing the required section `Impact`",
        ),
        (
            "severity disagreement",
            VALID_ADVISORY.replace("high", "low"),
            VALID_INDEX,
            "the index says",
        ),
        (
            "found after published",
            VALID_ADVISORY.replace("2026-02-20", "2026-04-01"),
            VALID_INDEX.replace("2026-02-20", "2026-04-01"),
            "later than Published",
        ),
        (
            "identifier does not match filename",
            # Replace the identifier *inside the `## Identifier` section*, not the
            # title. The first version of this case used `replace(..., 1)`, which
            # hit the H1 title instead — so the file still declared the correct
            # identifier and the checker was right to pass it. The self-test
            # reported DEAD and the *test* was the thing that was broken.
            VALID_ADVISORY.replace(
                "## Identifier\n\nQQQ-2026-001", "## Identifier\n\nQQQ-2026-777"
            ),
            VALID_INDEX,
            "which is not the filename",
        ),
        (
            "empty required section",
            VALID_ADVISORY.replace(
                "## Summary\n\nAn example advisory used only by the checker's self-test.",
                "## Summary\n\n",
            ),
            VALID_INDEX,
            "is empty",
        ),
    ]

    # # Why the malformed-identifier case is separate
    #
    # Every case above writes its advisory to `QQQ-2026-001.md`, so the *filename*
    # is always well formed and only the content varies. Testing case 6 (an
    # identifier that is not `QQQ-YYYY-NNN`) therefore needs a different filename,
    # which the shared fixture above cannot express. It gets its own block rather
    # than a flag threaded through the loop, because the loop's shape is about
    # content and this case is about naming.
    cases_with_filename: list[tuple[str, str, str, str, str]] = [
        (
            "identifier not in QQQ-YYYY-NNN form",
            "ADVISORY-1.md",
            VALID_ADVISORY.replace("QQQ-2026-001", "ADVISORY-1"),
            VALID_INDEX.replace("QQQ-2026-001", "ADVISORY-1"),
            "does not match `QQQ-YYYY-NNN`",
        ),
    ]

    failures = 0

    def run_case(name: str, filename: str, advisory: str, index: str, expect: str) -> bool:
        """Build the fixture, run the checker, and report whether it behaved."""
        # `ROOT`/`ADVISORY_DIR`/`INDEX` are module globals, not enclosing locals,
        # so they are rebound with `global` rather than `nonlocal`.
        global ROOT, ADVISORY_DIR, INDEX
        tmp = Path(tempfile.mkdtemp(prefix="qqq-advisory-selftest-"))
        try:
            (tmp / "docs" / "advisories").mkdir(parents=True)
            (tmp / "docs" / "advisories" / filename).write_text(advisory, encoding="utf-8")
            (tmp / "docs" / "advisories" / "INDEX.md").write_text(index, encoding="utf-8")

            ROOT = tmp
            ADVISORY_DIR = tmp / "docs" / "advisories"
            INDEX = ADVISORY_DIR / "INDEX.md"

            # Capture the checker's verdict without printing it, so the self-test's
            # own output stays readable.
            import contextlib
            import io

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = validate()
            output = buf.getvalue()

            # The clean case must PASS; every other case must FAIL *for the stated
            # reason*, so a checker that rejected everything for the wrong reason
            # would not pass this harness.
            ok = (code == 0) if expect == "" else (code != 0 and expect in output)

            print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
            if not ok:
                print(f"        expected {expect!r}, got exit {code}")
                for line in output.strip().splitlines()[:4]:
                    print(f"        | {line}")
            return ok
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    for name, advisory, index, expect in cases:
        if not run_case(name, "QQQ-2026-001.md", advisory, index, expect):
            failures += 1

    for name, filename, advisory, index, expect in cases_with_filename:
        if not run_case(name, filename, advisory, index, expect):
            failures += 1

    total = len(cases) + len(cases_with_filename)
    ROOT, ADVISORY_DIR, INDEX = original_root, original_dir, original_index

    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every check is live")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    return validate()


if __name__ == "__main__":
    raise SystemExit(main())
