#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Every checklist identifier cited in code must exist in the checklist.

See Observations ``§O-126``: a docstring in ``tools/`` cited a Checklist item that
does not exist -- the ``DX`` series ends at ``DX-020``, and the cited number was
``DX-029`` (not-a-checklist-item). The identifier was invented, a quotation was
wrapped around it to look like a citation, and the same claim was repeated in a
commit message. Nothing caught it; it surfaced by luck when the item was being ticked
and ``grep`` found nothing.

That paragraph is the first exercise of this checker's own escape hatch: the marker
``not-a-checklist-item`` exempts the number, because this file's whole subject is
identifiers that point at nothing and it cannot cite the real one without mentioning
the fake one.

# Why a checker and not a resolution to be careful

This project has a rule for prose claims about the code: *verify with a real
command*. It applies to ``§O-…`` references, which are looked up rather than
recalled. It did not apply to the checklist, because a docstring reads as
commentary rather than as a claim. That is exactly the blind spot this file
records, and the cheap structural fix is this checker.

# What it checks

Every token shaped like a Checklist identifier -- ``PREFIX-NNN``, where ``PREFIX``
is one of the series the checklist actually uses -- that appears in a tracked source
file must appear as a real item in ``QQQ-Checklist-V1.md``.

# What it deliberately does not check

- **It does not guess the prefix set.** The prefixes are read from the checklist
  itself, so adding a series does not require editing this file. A hard-coded list
  would go stale and start producing false negatives -- the failure mode this whole
  exercise is about.
- **It does not check `§O-…` / `§D-…` / `§M-…` / `§C-…` references.** Those are
  already covered by ``tools/check_xrefs.py``, and duplicating the rule would create
  two places to keep right.

Usage::

    python tools/check_checklist_citations.py
    python tools/check_checklist_citations.py --self-test
"""

from __future__ import annotations

import argparse
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
CHECKLIST = ROOT / "QQQ-Checklist-V1.md"

# Where citations are looked for. Source and tooling, not prose: the narrative
# documents legitimately *discuss* identifiers -- `§O-126` quotes `DX-029`
# (not-a-checklist-item) as a mistake -- so scanning them would flag the record of the
# defect as the defect.
SCAN_DIRS = ["crates", "tools", "docker", ".github"]
SCAN_SUFFIXES = {".rs", ".py", ".sh", ".yml", ".yaml", ".toml"}

# `DX-029` (not-a-checklist-item), `SRV-013`, `CAP-004`. The prefix is upper-case
# letters, 2-5 long, to avoid matching prose like `UTF-8` or a version like `HTTP-2`
# -- and the item must be zero-padded to three digits, the checklist's own convention.
CITATION = re.compile(r"\b([A-Z]{2,5})-(\d{3})\b")

# A real item line: `- [ ] **DX-020** ...`, `- [x] **SRV-013** ...`, or
# `- [!] **SEC-024** ...`.
#
# `[!]` is the **blocked** marker, and leaving it out was the first bug in this
# checker: `SEC-024` and `SEC-025` exist in exactly that form, so every citation of
# them was reported as pointing at nothing. A checker that flags two real items is
# worse than no checker, because the two false positives are what a reader remembers
# when the next, real finding arrives.
# The marker set is the checklist's documented legend: `[ ]`, `[x]`, `[~]`,
# `[!]`, `[-]`. `[~]` was missing until `SRV-020` became the first item marked in
# progress, at which point every citation of it was reported as "not in the
# checklist" -- a false failure across nine files, caused by this grammar being
# narrower than the legend and narrower than `check_xrefs.py`'s identical regex.
ITEM = re.compile(r"^-\s*\[[ x~!-]\]\s*\*\*([A-Z]{2,5}-\d{3})\*\*", re.MULTILINE)

# A citation is *allowed* to point at nothing when the source says so nearby.
#
# This replaces the hand-written allow-list the first version used (which held
# `UTF-16` and a placeholder). A list of blessed identifiers is wrong here for a
# reason worth stating: two of the flagged sites are **deliberate** fabrications.
# `self_test_xrefs.py` writes `HOST-999` (not-a-checklist-item) into a document to
# prove `check_xrefs.py` catches a reference that resolves to nothing, and
# `fix_corpus.py` names `LANG-048` (not-a-checklist-item) while explaining that the
# real series stops at `LANG-040`. Those must never be flagged: flagging them would
# mean the tool that tests a control fails the build by doing its job.
#
# So the exemption is a **marker in the source**, not a list in this file. It is
# adjacent to the citation, greppable, self-documenting at the site, and cannot drift
# out of sync with reality the way a central list does. `ALLOWED_MARKER` is the
# spelling; `DELIBERATE` is what the reader sees.
ALLOWED_MARKER = "not-a-checklist-item"
DELIBERATE = ALLOWED_MARKER  # the token written in the source

# A file may also declare the exemption for **all** of its contents, when fabricating
# references is what the file is for.
#
# `self_test_xrefs.py` is the case that forced this: it writes fake references into
# documents to prove `check_xrefs.py` catches them, so it contains nine deliberate
# fabrications (`HOST-999`, `OQ-099` — not-a-checklist-item) spread through constants,
# comparisons and assertions. Per-line markers would mean nine edits saying the same
# thing, and the tenth fabricated marker added later would be missed — which is how a
# per-line scheme decays into a checker that is silently wrong.
#
# So the declaration is once per file, in a comment, and it names the reason. It is
# still greppable and still adjacent to the code it covers, and adding it to a new
# file is a deliberate act with a visible diff.
FILE_MARKER = "checklist-citations-exempt"

# A short window after the citation to look for the marker: the same line, or the
# next few, because a docstring wraps.
MARKER_WINDOW = 3


def checklist_items() -> set[str]:
    text = CHECKLIST.read_text(encoding="utf-8")
    items = set(ITEM.findall(text))
    if not items:
        raise SystemExit(
            "FAIL: no checklist items found in QQQ-Checklist-V1.md -- the item "
            "pattern is wrong, and a checker that finds nothing must not pass"
        )
    return items


def prefixes(items: set[str]) -> set[str]:
    return {i.split("-")[0] for i in items}


def citations() -> list[tuple[Path, int, str]]:
    """Every citation found, with file and line, in deterministic order."""
    found: list[tuple[Path, int, str]] = []
    for directory in SCAN_DIRS:
        base = ROOT / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix not in SCAN_SUFFIXES:
                continue
            if "target" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            # A file-level exemption, declared once. See `FILE_MARKER`.
            if FILE_MARKER in text:
                continue

            lines = text.splitlines()
            for lineno, line in enumerate(lines, 1):
                # A deliberate non-item is exempt when the marker is nearby. The
                # window is small and the marker must be spelled out, so it cannot
                # be added by accident or applied to a wide span of code.
                window = "\n".join(lines[lineno - 1 : lineno - 1 + MARKER_WINDOW])
                if DELIBERATE in window:
                    continue
                for match in CITATION.finditer(line):
                    # Only prefixes the checklist actually uses are candidates. This
                    # keeps `UTF-16` and a hypothetical `HTTP-200` out without
                    # listing every standard that happens to share the shape.
                    if match.group(1) in KNOWN_PREFIXES:
                        found.append(
                            (path.relative_to(ROOT), lineno, f"{match.group(1)}-{match.group(2)}")
                        )
    return found


# Filled by `main`/`run`, so the prefix set always comes from the checklist.
KNOWN_PREFIXES: set[str] = set()


def check() -> list[str]:
    """Return the citations that point at nothing."""
    global KNOWN_PREFIXES

    items = checklist_items()
    KNOWN_PREFIXES = prefixes(items)

    if not KNOWN_PREFIXES:
        raise SystemExit("FAIL: the checklist has items but no prefixes -- impossible")

    bad: list[str] = []
    for path, lineno, token in citations():
        if token in items:
            continue
        bad.append(f"{path}:{lineno}: cites `{token}`, which is not in the checklist")
    return bad


def self_test() -> int:
    """Prove the check fails on a fabricated citation.

    The defect this checker exists for was a single invented identifier, so the
    injection is exactly that: a temporary source file citing an item that cannot
    exist, in a prefix the checklist does use.
    """
    global KNOWN_PREFIXES

    items = checklist_items()
    KNOWN_PREFIXES = prefixes(items)
    real = sorted(KNOWN_PREFIXES)[0]
    fabricated = f"{real}-999"

    probe = ROOT / "crates" / "qqq-core" / "src" / "_citation_probe.rs"
    if probe.exists():
        print(f"SELF-TEST FAILED: {probe} already exists")
        return 1

    failures: list[str] = []
    try:
        probe.write_text(
            f"// SPDX-License-Identifier: Apache-2.0\n// {fabricated}\n",
            encoding="utf-8",
        )
        if fabricated in items:
            failures.append(f"the fixture `{fabricated}` is a real item; pick another")
        bad = check()
        if not any(fabricated in b for b in bad):
            failures.append(
                f"a fabricated citation `{fabricated}` was not caught (found {bad})"
            )
        else:
            print(f"  caught a fabricated citation: {fabricated}")

        # --- The exemptions themselves must be proven not to blind the check ---
        #
        # An escape hatch that can swallow anything is the obvious failure mode of
        # the mechanism above, so three cases are exercised. Each is a way the
        # exemption could be wrong rather than a way the citation check could be.

        # 1. The per-line marker on a *different* line must not exempt this one.
        probe.write_text(
            f"// SPDX-License-Identifier: Apache-2.0\n"
            f"// {DELIBERATE}\n"
            f"// padding\n// padding\n// padding\n// padding\n"
            f"// {fabricated}\n",
            encoding="utf-8",
        )
        if not any(fabricated in b for b in check()):
            failures.append(
                "the per-line marker exempted a citation outside its window -- the "
                "exemption is too wide and would hide real defects"
            )
        else:
            print("  the per-line marker does not reach past its window")

        # 2. The file marker must exempt the whole file.
        probe.write_text(
            f"// SPDX-License-Identifier: Apache-2.0\n"
            f"// {FILE_MARKER}\n// {fabricated}\n",
            encoding="utf-8",
        )
        if any(fabricated in b for b in check()):
            failures.append("the file-level marker did not exempt the file")
        else:
            print("  the file-level marker exempts the file it is declared in")

        # 3. A real citation must never be flagged, whichever form it takes --
        #    including the `[!]` blocked marker that the first version's regex missed.
        probe.write_text(
            f"// SPDX-License-Identifier: Apache-2.0\n// {real}-001\n",
            encoding="utf-8",
        )
        genuine = [b for b in check() if "citation_probe" in b]
        if genuine:
            failures.append(
                f"a real citation was flagged, which is a false positive: {genuine}"
            )
        else:
            print(f"  a real citation ({real}-001) is not flagged")
    finally:
        probe.unlink(missing_ok=True)

    # And the real tree must be clean, or every injection above proved nothing.
    bad_after = check()
    if bad_after:
        failures.append(f"the real tree is not clean: {bad_after[:3]}")

    if failures:
        print(f"SELF-TEST FAILED: {failures}")
        return 1

    print("SELF-TEST OK -- a fabricated citation is caught; the real tree passes")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="inject a fabricated citation and assert it is caught",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    bad = check()
    if bad:
        print(f"FAIL: {len(bad)} citation(s) point at no checklist item:")
        for entry in bad[:20]:
            print(f"  {entry}")
        if len(bad) > 20:
            print(f"  ... and {len(bad) - 20} more")
        return 1

    n = len(citations())
    print(
        f"CHECKLIST CITATIONS OK -- {n} citation(s) across "
        f"{len(SCAN_DIRS)} source trees all resolve to a real item"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
