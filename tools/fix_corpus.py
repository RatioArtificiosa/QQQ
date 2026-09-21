#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""One-shot repair tool for the QQQ corpus.

Fixes two defect classes found by tools/check_xrefs.py:

  A. Checklist items whose citation line points at an *appendix* rather than a
     numbered Proposal section. The validator (correctly) requires a numeric
     section, so each is repointed at the numbered section that actually
     creates the question. This is more useful than citing an appendix anyway.

  B. The Proposal cites checklist ID *ranges* that overstate the real count
     (e.g. "LANG-001 … LANG-048" when LANG stops at 040). Ranges are rewritten
     to close on the highest ID that actually exists in that area.

Idempotent: running it twice changes nothing the second time.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKLIST = ROOT / "QQQ-Checklist-V1.md"
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"

RE_ITEM_DEF = re.compile(r"^\s*-\s*\[[ x~!-]\]\s*\*\*([A-Z]{2,5}-\d{3})\*\*")
RE_TOKEN_ID = re.compile(r"`([A-Z]{2,5}-\d{3})`")
RE_RANGE = re.compile(r"`([A-Z]{2,5})-(\d{3})`\s*…\s*`([A-Z]{2,5})-(\d{3})`")

# --------------------------------------------------------------------------
# A. Repoint appendix citations at numbered sections
# --------------------------------------------------------------------------
CITATION_FIXES = {
    "OQ-001": "§13.2 The licence model, and why NN-8 still holds",
    "OQ-002": "§6.10 Language toolchains — one per target language",
    "OQ-003": "§6.10 Language toolchains — one per target language",
    "OQ-004": "§6.10 Language toolchains — one per target language",
    "OQ-005": "§4.7 Concurrency model for guests",
    "OQ-006": "§6.5 `qqq-pkg` — package manager and registry",
    "OQ-007": "§6.4 `qqq-serve` — the HTTP and application server",
    "OQ-008": "§13.2 The licence model, and why NN-8 still holds",
    "OQ-009": "§2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship",
    "OQ-010": "§10.1 The three signals, plus one unique to QQQ",
    "OQ-011": "§6.9 `qqq:ai` — local inference as a capability",
    "OQ-012": "§2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship",
    "LANG-008": "§6.10 Language toolchains — one per target language",
    "LANG-016": "§6.10 Language toolchains — one per target language",
    "LANG-024": "§6.10 Language toolchains — one per target language",
    "LANG-031": "§6.10 Language toolchains — one per target language",
    "LANG-032": "§6.10 Language toolchains — one per target language",
    "ABI-016": "§6.3 `qqq-abi` — WIT interfaces as the single source of truth",
    "DOC-013": "§0.4 How to read the cross-references",
    "DOC-015": "§3.4 Positioning statement and the language we use",
    "DOC-016": "§0.4 How to read the cross-references",
    "DIST-020": "§11.1 Install channels, in priority order",
    "FND-011": "§0.4 How to read the cross-references",
    "HOST-024": "§6.1 `qqq-host` — the execution engine",
    "OBS-017": "§10.4 Distributed tracing",
    "SRV-006": "§6.4 `qqq-serve` — the HTTP and application server",
    "POS-006": "§6.10 Language toolchains — one per target language",
    "MKT-014": "§3.2 The competitive set, honestly",
    "LIC-005": "§13.2 The licence model, and why NN-8 still holds",
    "PKG-005": "§6.5 `qqq-pkg` — package manager and registry",
    "GOV-010": "§2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship",
}


def fix_citations() -> int:
    lines = CHECKLIST.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    i = 0
    changed = 0
    while i < len(lines):
        line = lines[i]
        m = RE_ITEM_DEF.match(line)
        if m and m.group(1) in CITATION_FIXES:
            out.append(line)
            i += 1
            new = "  → " + CITATION_FIXES[m.group(1)]
            if i < len(lines) and lines[i].strip().startswith("→ §"):
                if lines[i].rstrip() != new.rstrip():
                    changed += 1
                out.append(new)
                i += 1
            else:
                out.append(new)
                changed += 1
            continue
        out.append(line)
        i += 1
    CHECKLIST.write_text("\n".join(out) + "\n", encoding="utf-8")
    return changed


# --------------------------------------------------------------------------
# B. Rewrite overstated ID ranges in the proposal
# --------------------------------------------------------------------------
def collect_area_maxima() -> dict[str, int]:
    maxima: dict[str, int] = {}
    for line in CHECKLIST.read_text(encoding="utf-8").splitlines():
        m = RE_ITEM_DEF.match(line)
        if not m:
            continue
        area, num = m.group(1).split("-")
        maxima[area] = max(maxima.get(area, 0), int(num))
    return maxima


def fix_ranges() -> int:
    maxima = collect_area_maxima()
    text = PROPOSAL.read_text(encoding="utf-8")
    changes = 0

    def repl(m: re.Match) -> str:
        nonlocal changes
        a1, n1, a2, n2 = m.group(1), m.group(2), m.group(3), m.group(4)
        if a1 != a2:
            return m.group(0)
        real = maxima.get(a1)
        if real is None:
            return m.group(0)
        if int(n2) > real:
            changes += 1
            return f"`{a1}-{n1}` … `{a1}-{real:03d}`"
        return m.group(0)

    text = RE_RANGE.sub(repl, text)
    PROPOSAL.write_text(text, encoding="utf-8")
    return changes


# --------------------------------------------------------------------------
# C. Drop unresolvable single-ID citations that name no existing item
# --------------------------------------------------------------------------
def fix_single_ids() -> int:
    defined = set()
    for line in CHECKLIST.read_text(encoding="utf-8").splitlines():
        m = RE_ITEM_DEF.match(line)
        if m:
            defined.add(m.group(1))

    text = PROPOSAL.read_text(encoding="utf-8")
    lines = text.splitlines()
    out: list[str] = []
    changes = 0
    for line in lines:
        if "→ **Checklist:**" in line:
            ids = RE_TOKEN_ID.findall(line)
            bad = [i for i in ids if i not in defined and "-" in i]
            if bad:
                # Drop only the offending tokens, keep the rest of the line.
                newline = line
                for b in bad:
                    newline = newline.replace(f"`{b}`, ", "").replace(f", `{b}`", "")
                    newline = newline.replace(f"`{b}`", "")
                newline = newline.replace("  ", " ").rstrip()
                newline = newline.replace("Checklist:** ,", "Checklist:**")
                if newline != line:
                    changes += 1
                out.append(newline)
                continue
        out.append(line)
    PROPOSAL.write_text("\n".join(out) + "\n", encoding="utf-8")
    return changes


def main() -> int:
    a = fix_citations()
    b = fix_ranges()
    c = fix_single_ids()
    print(f"citation fixes      : {a}")
    print(f"range rewrites      : {b}")
    print(f"single-ID removals  : {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
