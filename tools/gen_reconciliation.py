#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Generate the corrections table in `docs/reconciliation.md` (`DOC-013`).

Reads the Proposal's Appendix A table and the Observations' `§C-NNN` headings, and
writes the table between the `GENERATED:BEGIN`/`GENERATED:END` markers.

# Why markers rather than whole-file generation

`docs/reconciliation.md` carries prose the generator does not produce — the "what each
correction has in common" section, which is the part worth reading. Replacing the whole
file on every run would discard it.

So the generator owns the *table* and nothing else, and the markers say exactly where.
A generator that owns everything is easier to write and forces all commentary into its
templates, where nobody edits it.

Usage:
    python tools/gen_reconciliation.py           # rewrite the table in place
    python tools/gen_reconciliation.py --check   # fail if it is out of date
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"
OBSERVATIONS = ROOT / "QQQ-Observations-and-Memories.md"
TARGET = ROOT / "docs" / "reconciliation.md"

BEGIN = "<!-- GENERATED:BEGIN -->"
END = "<!-- GENERATED:END -->"


def parse_appendix_a(text: str) -> list[dict[str, str]]:
    """Extract the Appendix A rows as dicts with `id`, `claim`, `status`, `correction`."""
    marker = "# Appendix A — Source document reconciliation"
    start = text.find(marker)
    if start == -1:
        raise ValueError("the Proposal has no Appendix A heading")

    rest = text[start:]
    nxt = re.search(r"(?m)^# ", rest[len(marker) :])
    section = rest[: len(marker) + nxt.start()] if nxt else rest

    rows: list[dict[str, str]] = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if len(cells) < 4:
            continue
        # Header row and separator row.
        if cells[0] == "#" or set(cells[0]) <= set("-: "):
            continue
        rows.append(
            {
                "id": cells[0],
                "claim": cells[1],
                "status": cells[2],
                "correction": cells[3],
            }
        )
    if not rows:
        raise ValueError("Appendix A has no data rows")
    return rows


def correction_headings(text: str) -> list[str]:
    """The Observations' `§C-NNN` headings, in order."""
    return re.findall(r"(?m)^### (§C-\d{3})\b", text)


def render_table(rows: list[dict[str, str]]) -> str:
    """Render the markdown table the markers delimit."""
    lines = [
        "| # | Source claim | Status | What changed |",
        "|---|---|---|---|",
    ]
    for row in rows:
        # The Proposal's cells can contain escaped pipes; keep them escaped so the
        # table does not gain a column.
        cells = [row["id"], row["claim"], row["status"], row["correction"]]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def splice(current: str, table: str) -> str:
    """Replace the region between the markers, leaving everything else alone."""
    begin = current.find(BEGIN)
    end = current.find(END)
    if begin == -1 or end == -1 or end < begin:
        raise ValueError(
            f"docs/reconciliation.md must contain both {BEGIN} and {END}, in that order"
        )
    return current[: begin + len(BEGIN)] + "\n\n" + table + "\n\n" + current[end:]


def main() -> int:
    check_only = "--check" in sys.argv

    try:
        rows = parse_appendix_a(PROPOSAL.read_text(encoding="utf-8"))
        corrections = correction_headings(OBSERVATIONS.read_text(encoding="utf-8"))
    except (ValueError, OSError) as e:
        print(f"FATAL: {e}")
        return 1

    # # Why the count is cross-checked here as well as in check [8]
    #
    # Check `[8]` proves A↔§C parity. This generator would otherwise happily emit a
    # table from a *drifted* Proposal, producing a third document that agrees with the
    # wrong one. Failing here means the generator cannot be the thing that launders a
    # disagreement into a generated file.
    if len(rows) != len(corrections):
        print(
            f"FATAL: Appendix A has {len(rows)} row(s) but the Observations define "
            f"{len(corrections)} §C entry/entries ({', '.join(corrections)}). Fix the "
            f"parity before regenerating: a generated file must not agree with a "
            f"drifted source."
        )
        return 1

    table = render_table(rows)

    if not TARGET.exists():
        print(f"FATAL: {TARGET} does not exist; it holds prose the generator does not own")
        return 1

    current = TARGET.read_text(encoding="utf-8")
    try:
        updated = splice(current, table)
    except ValueError as e:
        print(f"FATAL: {e}")
        return 1

    if check_only:
        if current != updated:
            print(
                "FATAL: docs/reconciliation.md is out of date with the Proposal's "
                "Appendix A. Run `python tools/gen_reconciliation.py`."
            )
            for i, (a, b) in enumerate(
                zip(current.splitlines(), updated.splitlines()), start=1
            ):
                if a != b:
                    print(f"  first difference at line {i}:")
                    print(f"    committed: {a[:110]}")
                    print(f"    generated: {b[:110]}")
                    break
            else:
                print(
                    f"  the committed file has {len(current.splitlines())} lines and "
                    f"the generated one has {len(updated.splitlines())}"
                )
            return 1
        print(
            f"RECONCILIATION OK -- {len(rows)} correction(s), matching Appendix A and "
            f"the Observations"
        )
        return 0

    TARGET.write_text(updated, encoding="utf-8")
    print(f"wrote {TARGET.relative_to(ROOT)} with {len(rows)} correction(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
