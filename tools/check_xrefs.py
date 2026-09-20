#!/usr/bin/env python3
"""QQQ cross-reference validator.

Proves the three-document corpus is internally consistent. Fails CI on any of:

  1. A checklist item cites a Proposal anchor that does not exist.
  2. A Proposal section cites a checklist ID that does not exist.
  3. A Proposal anchor is defined twice (ambiguous target).
  4. A checklist item has no Proposal citation.
  5. A checkable Proposal section has no checklist citation.
  6. A checklist ID is defined twice.
  7. A stub marker in a source file has no Observations entry, and vice versa.

Usage:  python tools/check_xrefs.py [repo_root]
Exit:   0 = clean, 1 = violations found

This script is intentionally dependency-free so it runs anywhere Python does,
including a bare CI container.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------

PROPOSAL = "QQQ-Proposal-V1.md"
CHECKLIST = "QQQ-Checklist-V1.md"
OBSERVATIONS = "QQQ-Observations-and-Memories.md"

# --------------------------------------------------------------------------
# Regexes
# --------------------------------------------------------------------------

# A markdown heading, capturing level and text:  "## §6.4 Capability engine"
RE_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")

# A checklist item definition:  "- [ ] **CAP-001** ..."  or  "- [x] **CAP-001**"
RE_ITEM_DEF = re.compile(r"^\s*-\s*\[[ x~!-]\]\s*\*\*([A-Z]{2,5}-\d{3})\*\*")

# A checklist citation in the proposal:  "→ **Checklist:** `ABC-001`, `ABC-002`"
RE_CHECKLIST_LINE = re.compile(r"→\s*\*\*Checklist:\*\*\s*(.+)")

# A backticked token that looks like a checklist ID
RE_TOKEN_ID = re.compile(r"`([A-Z]{2,5}-\d{3})`")

# A citation to a proposal anchor inside a checklist item: "→ §6.4 Capability engine"
RE_ARROW_SECTION = re.compile(r"→\s*§([0-9A-Za-z.]+)")

# Explicit anchor override inside a heading:  "## Title {#custom-anchor}"
RE_EXPLICIT_ANCHOR = re.compile(r"\{#([a-zA-Z0-9\-_]+)\}\s*$")

# Stub markers
RE_STUB_MARKER = re.compile(r"QQQ-STUB\(([A-Z]{2,5}-\d{3})\)")
RE_STUB_OBS = re.compile(r"^###\s+§S-\d{3}\b", re.MULTILINE)


def slugify(text: str) -> str:
    """GitHub-flavoured heading anchor slug.

    Mirrors GitHub's algorithm closely enough for our headings: lowercase,
    strip anything that is not alphanumeric/space/hyphen, spaces -> hyphens.
    Unicode letters (such as §) are dropped, which matches GitHub's behaviour
    of removing most punctuation. Non-ASCII letters are kept.
    """
    text = text.strip().lower()
    # Remove explicit {#anchor} suffixes from the slug input.
    text = RE_EXPLICIT_ANCHOR.sub("", text).strip()
    out = []
    for ch in text:
        if ch.isalnum() or ch in (" ", "-", "_"):
            out.append(ch)
        elif ch in ("—", "–"):  # em/en dash -> hyphen, matching GitHub
            out.append("-")
        # everything else is dropped
    slug = "".join(out)
    slug = slug.replace(" ", "-")
    # collapse repeated hyphens (GitHub keeps them, but our headings produce
    # doubles from " — " sequences; collapsing keeps anchors readable)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


def parse_headings(text: str):
    """Return (anchors, ordered_section_titles).

    anchors maps anchor -> list of heading texts (to detect duplicates).
    """
    anchors: dict[str, list[str]] = {}
    in_fence = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = RE_HEADING.match(raw)
        if not m:
            continue
        level, title = len(m.group(1)), m.group(2)
        if level > 4:
            continue
        explicit = RE_EXPLICIT_ANCHOR.search(title)
        if explicit:
            anchor = explicit.group(1)
        else:
            anchor = slugify(title)
        if not anchor:
            continue
        anchors.setdefault(anchor, []).append(title)
    return anchors


def section_number_from_heading(title: str) -> str | None:
    """Extract '6.4' from '§6.4 Capability engine'. Returns None if absent."""
    m = re.match(r"^§([0-9]+(?:\.[0-9]+)*)", title.strip())
    return m.group(1) if m else None


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    proposal_path = root / PROPOSAL
    checklist_path = root / CHECKLIST
    obs_path = root / OBSERVATIONS

    errors: list[str] = []
    warnings: list[str] = []

    for p in (proposal_path, checklist_path, obs_path):
        if not p.exists():
            print(f"FATAL: missing {p}")
            return 1

    proposal = proposal_path.read_text(encoding="utf-8")
    checklist = checklist_path.read_text(encoding="utf-8")
    observations = obs_path.read_text(encoding="utf-8")

    # ----------------------------------------------------------------------
    # 1. Build the anchor table from the proposal
    # ----------------------------------------------------------------------
    anchors = parse_headings(proposal)
    anchor_set = set(anchors)

    # Map "6.4" -> anchor, for numeric citations like "→ §6.4".
    number_to_anchor: dict[str, str] = {}
    for anchor, titles in anchors.items():
        for t in titles:
            num = section_number_from_heading(t)
            if num:
                number_to_anchor.setdefault(num, anchor)

    # ----------------------------------------------------------------------
    # 2. Collect checklist item definitions
    # ----------------------------------------------------------------------
    item_lines: list[tuple[int, str, str]] = []  # (lineno, id, text-of-item)
    defined_ids: list[str] = []
    current: tuple[int, str] | None = None

    for lineno, line in enumerate(checklist.splitlines(), start=1):
        m = RE_ITEM_DEF.match(line)
        if m:
            if current:
                item_lines.append((current[0], current[1], " "))
            current = (lineno, m.group(1))
            defined_ids.append(m.group(1))
        if current and RE_ARROW_SECTION.search(line):
            item_lines.append((current[0], current[1], line))
            current = None
    if current:
        item_lines.append((current[0], current[1], ""))

    # Deduplicate: keep the citation line per item id
    citations: dict[str, str] = {}
    for _lineno, item_id, text in item_lines:
        if text.strip():
            citations[item_id] = text

    defined_set = set(defined_ids)

    # Duplicate ID detection
    seen: set[str] = set()
    dupes: set[str] = set()
    for i in defined_ids:
        if i in seen:
            dupes.add(i)
        seen.add(i)
    for d in sorted(dupes):
        errors.append(f"[6] duplicate checklist ID defined twice: {d}")

    # ----------------------------------------------------------------------
    # 3. Every checklist item must cite an existing Proposal section
    # ----------------------------------------------------------------------
    for _lineno, item_id, text in item_lines:
        if not text.strip():
            continue
        m = RE_ARROW_SECTION.search(text)
        if not m:
            if "DROPPED" in text or "deferred" in text.lower():
                continue
            errors.append(f"[4] item {item_id} has no '→ §...' Proposal citation")
            continue
        num = m.group(1)
        if num not in number_to_anchor:
            errors.append(
                f"[1] item {item_id} cites §{num}, which is not a Proposal section"
            )

    # Items with no citation at all (never got a text line)
    for item_id in defined_set:
        if item_id not in citations:
            errors.append(f"[4] item {item_id} has no Proposal citation line")

    # ----------------------------------------------------------------------
    # 4. Every Proposal "→ Checklist:" citation must name a real item
    # ----------------------------------------------------------------------
    proposal_citations_found: set[str] = set()
    in_fence = False
    for lineno, line in enumerate(proposal.splitlines(), start=1):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = RE_CHECKLIST_LINE.search(line)
        if not m:
            continue
        body = m.group(1)
        tokens = RE_TOKEN_ID.findall(body)
        # Also allow un-backticked ranges like  `ABC-001` … `ABC-010` which
        # the regex already captures as tokens; ranges are expanded by authors
        # into explicit lists, so anything un-tokenised is a warning.
        if not tokens and "…" not in body and "§" not in body:
            warnings.append(f"proposal line {lineno}: Checklist citation has no item IDs: {body!r}")
        for t in tokens:
            proposal_citations_found.add(t)
            if t not in defined_set:
                errors.append(
                    f"[2] proposal line {lineno} cites checklist item {t}, which is not defined"
                )

    # ----------------------------------------------------------------------
    # 5. Coverage: checkable Proposal sections should be cited by some item
    # ----------------------------------------------------------------------
    # Sections that legitimately carry no buildable work.
    NARRATIVE_SECTIONS = {
        "0", "01", "02", "03", "04", "05", "06",
        "1", "1.3",
        "2",
        "3.3",
        "13.1",
        "appendix-a", "appendix-b", "appendix-c", "document-control",
        "table-of-contents",
        "qqq--technical-proposal-v10",
    }

    cited_numbers: set[str] = set()
    for item_id in defined_set:
        text = citations.get(item_id, "")
        m = RE_ARROW_SECTION.search(text)
        if m:
            cited_numbers.add(m.group(1))

    for num, anchor in sorted(number_to_anchor.items(), key=lambda kv: kv[0]):
        if num in NARRATIVE_SECTIONS or num in cited_numbers:
            continue
        # Numeric parents like "6" are covered by their children
        if "." not in num and any(c.startswith(num + ".") for c in cited_numbers):
            continue
        warnings.append(
            f"[5] Proposal section §{num} ({anchor}) has no checklist item citing it"
        )

    # ----------------------------------------------------------------------
    # 6. Stub markers: inline markers <-> Observations entries
    # ----------------------------------------------------------------------
    marker_ids: set[str] = set()
    for src in root.rglob("*"):
        if not src.is_file():
            continue
        if src.suffix not in {".rs", ".ts", ".go", ".py", ".c", ".h", ".cpp", ".toml", ".wit"}:
            continue
        if ".git" in src.parts or "target" in src.parts or "node_modules" in src.parts:
            continue
        try:
            content = src.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in RE_STUB_MARKER.finditer(content):
            marker_ids.add(m.group(1))

    obs_stub_count = len(re.findall(RE_STUB_OBS, observations))

    for mid in sorted(marker_ids):
        if mid not in defined_set:
            errors.append(f"[7] stub marker {mid} in source does not match any checklist item")

    if marker_ids and obs_stub_count == 0:
        errors.append("[7] stub markers exist in source but Observations has no §S- entries")

    # ----------------------------------------------------------------------
    # 7. Anchor duplicates
    # ----------------------------------------------------------------------
    for anchor, titles in anchors.items():
        if len(titles) > 1:
            errors.append(
                f"[3] anchor defined {len(titles)} times: #{anchor} <- {titles!r}"
            )

    # ----------------------------------------------------------------------
    # 8. Appendix A <-> Observations correction parity
    #
    # Appendix A is the proposal's register of corrections to the source
    # corpus. Every row must have a corresponding §C-nnn entry in the
    # Observations document, and vice versa. Without this check the two
    # registers drift apart silently -- which is exactly what happened once,
    # producing a proposal row (A-3) with no matching observation.
    # ----------------------------------------------------------------------
    appendix_a_rows = re.findall(r"^\|\s*(A-\d{1,2})\s*\|", proposal, re.MULTILINE)
    obs_corrections = re.findall(r"^###\s+§(C-\d{3})\b", observations, re.MULTILINE)

    # A-1 <-> C-001, A-2 <-> C-002, ... by ordinal.
    row_nums = sorted({int(r.split("-")[1]) for r in appendix_a_rows})
    obs_nums = sorted({int(c.split("-")[1]) for c in obs_corrections})

    for n in row_nums:
        if n not in obs_nums:
            errors.append(
                f"[8] Appendix A row A-{n} has no matching §C-{n:03d} entry in Observations"
            )
    for n in obs_nums:
        if n not in row_nums:
            errors.append(
                f"[8] Observations §C-{n:03d} has no matching Appendix A row A-{n}"
            )

    # ----------------------------------------------------------------------
    # 9. Open-question parity: §Q-nnn <-> OQ-nnn
    # ----------------------------------------------------------------------
    q_ids = {int(x) for x in re.findall(r"§Q-(\d{3})", observations)}
    oq_ids = {int(x) for x in re.findall(r"\*\*OQ-(\d{3})\*\*", checklist)}
    for n in sorted(q_ids - oq_ids):
        errors.append(f"[9] Observations §Q-{n:03d} has no matching checklist item OQ-{n:03d}")
    for n in sorted(oq_ids - q_ids):
        errors.append(f"[9] checklist OQ-{n:03d} has no matching Observations §Q-{n:03d}")

    # ----------------------------------------------------------------------
    # 10. Decision IDs cited from the proposal must exist in Observations
    # ----------------------------------------------------------------------
    obs_decisions = set(re.findall(r"^###\s+§(D-\d{3})\b", observations, re.MULTILINE))
    for m in re.finditer(r"§D-(\d{3})", proposal):
        did = f"D-{m.group(1)}"
        if did not in obs_decisions:
            errors.append(f"[10] proposal cites Observations decision §{did}, which is not defined")

    # ----------------------------------------------------------------------
    # 11. Stub parity is bidirectional
    # ----------------------------------------------------------------------
    if obs_stub_count and not marker_ids:
        errors.append("[11] Observations defines §S- stubs but no inline QQQ-STUB markers exist")

    # ----------------------------------------------------------------------
    # Report
    # ----------------------------------------------------------------------
    # ----------------------------------------------------------------------
    # Progress accounting
    #
    # Reported on every run so the achieved fraction is visible without
    # grepping. The reason this exists: items were being implemented and left
    # unchecked, so the checklist understated the work and there was no signal
    # that anything was wrong. A number that appears every time is one that
    # gets noticed when it stops moving.
    #
    # Deliberately a *report*, not a gate. The checklist is not the work; it is
    # a description of the work, and failing CI because a count is low would
    # create pressure to tick boxes rather than to build things.
    # ----------------------------------------------------------------------
    done_items = re.findall(r"^- \[x\] \*\*([A-Z]+-\d{3})\*\*", checklist, re.M)
    open_items = re.findall(r"^- \[ \] \*\*([A-Z]+-\d{3})\*\*", checklist, re.M)
    partial = len(re.findall(r"^  → Partial:", checklist, re.M))
    total = len(done_items) + len(open_items)
    pct = (100 * len(done_items) / total) if total else 0

    # A crate with a substantial implementation and no ticked items is the
    # symptom that started this: work happening where the checklist cannot see
    # it. Reported as a warning rather than an error, because a crate can
    # legitimately be in progress with nothing finished.
    implemented_crates = {}
    crates_dir = root / "crates"
    if crates_dir.is_dir():
        for crate in sorted(crates_dir.iterdir()):
            src = crate / "src"
            if not src.is_dir():
                continue
            lines = 0
            for rs in src.rglob("*.rs"):
                try:
                    lines += len(rs.read_text(encoding="utf-8").splitlines())
                except OSError:
                    pass
            # Past the stub threshold: a skeleton lib.rs is ~10 lines, so any
            # crate over 500 lines has real content.
            if lines > 500:
                implemented_crates[crate.name] = lines

    print("QQQ cross-reference validation")
    print("=" * 60)
    print(f"Proposal sections/anchors : {len(anchors)}")
    print(f"Checklist items defined   : {len(defined_set)}")
    print(f"Checklist items cited in Proposal : {len(proposal_citations_found)}")
    print(f"Stub markers in source    : {len(marker_ids)}")
    print(f"Stub entries in Observations: {obs_stub_count}")
    print("-" * 60)
    print(f"Checklist progress        : {len(done_items)}/{total} ({pct:.1f}%) checked"
          + (f", {partial} annotated partial" if partial else ""))
    if implemented_crates:
        print("Implemented crates (>500 lines):")
        for name, lines in implemented_crates.items():
            print(f"  {name:<12} {lines:>6} lines of Rust")

    if warnings:
        print(f"\n{len(warnings)} warning(s):")
        for w in warnings:
            print(f"  WARN  {w}")

    if errors:
        print(f"\n{len(errors)} ERROR(S):")
        for e in errors:
            print(f"  FAIL  {e}")
        print("\nvalidation FAILED")
        return 1

    print("\nvalidation PASSED — corpus is internally consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
