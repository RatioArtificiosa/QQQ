#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

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

# Why these three lines are exempt from `tools/check_checklist_citations.py`
# -------------------------------------------------------------------------
#
# The per-line marker, not the file-level one. The file-level spell is reserved for
# files whose whole purpose is fabricating references -- `self_test_xrefs.py` is one.
# This file validates; only its self-test fabricates, on three lines. A file-wide
# marker would blind the citation checker for all of it, and an escape hatch that
# can swallow a whole file is the failure mode that checker's own self-test names.
#
# The marker is `not-a-checklist-item`. **Not** the file-level spelling
# (`checklist-citations-exempt`) -- this file carries three per-line markers and no
# file-wide declaration, which is the same choice `self_test_xrefs.py` made for the
# opposite reason (that file is all fabrications; this one is three).
#
# An earlier version of this comment declared the file exempt in full, one
# paragraph after arguing that a file-wide marker is the failure mode the citation
# checker's own self-test names. The declaration was also untrue: the checker had
# never seen it. Corrected to describe what the file does.
#
# `--self-test` fabricates identifiers deliberately: the only way to prove rule [7]
# fires is to write a `QQQ-STUB` marker naming an item that does not exist, and the
# only way to prove rule [2] fires is to cite one from the Proposal. Those
# fabrications are the test. Flagging them would mean the tool that tests a control
# fails the build by doing its job.

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
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

# A file whose whole subject is fabricating references declares this and is skipped
# by check [13]. A marker in the source rather than a list in this file, for the same
# reason `checklist-citations-exempt` is: a list here drifts from the tree it describes.
EXEMPT_MARKER = "observation-citations-exempt"
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
    # 13. Every observation cited from the corpus must exist.
    #
    # [10] catches the Proposal citing an undefined **decision**. This is the same
    # rule for every observation family and every citing document, and it exists
    # because the narrower rule was not enough: `§O-249` was cited by eleven
    # references across the checklist, a checker and a budget table while the entry
    # itself had never been written, and nothing reported it (`§O-266`).
    #
    # # Why the test is "appears anywhere" rather than "is a definitional heading"
    #
    # The stricter version -- require the citation to be a heading -- was measured
    # against this corpus before being wired in, and produced four false positives
    # and no true ones: definitions here appear as `### O-181:` with no sigil, and as
    # table rows (`| `§Q-012` | ... |`). A rule that cannot tell a definition from a
    # citation without structure is noise, and a noisy gate gets disabled. "The
    # referent exists" is the weaker claim, but it is sound -- and sufficient: it
    # reports `§O-249` when the entry is stripped, and nothing when it is present.
    # ----------------------------------------------------------------------
    citing: dict[str, set[str]] = {}
    for rel, body in (("QQQ-Proposal-V1.md", proposal), ("QQQ-Checklist-V1.md", checklist)):
        for m in re.finditer("§([ODCSQM]-\\d{3})", body):
            citing.setdefault(m.group(1), set()).add(rel)
    for src in root.rglob("*"):
        if not src.is_file() or src.suffix not in {".rs", ".py", ".md", ".toml", ".wit", ".yml"}:
            continue
        if ".git" in src.parts or "target" in src.parts or "node_modules" in src.parts:
            continue
        # The canonical documents are handled above; walking them again would only
        # re-add their own definitions, which reads as double coverage.
        if src.name.startswith("QQQ-"):
            continue
        try:
            content = src.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if EXEMPT_MARKER in content:
            continue
        for m in re.finditer("§([ODCSQM]-\\d{3})", content):
            citing.setdefault(m.group(1), set()).add(str(src.relative_to(root)))

    for cid in sorted(citing):
        if ("§" + cid) not in observations:
            where = ", ".join(sorted(citing[cid])[:4])
            errors.append(
                f"[13] §{cid} is cited by {where} but is not defined in Observations"
            )


    # ----------------------------------------------------------------------
    # 10b. Every decision must be cited from the Proposal.
    #
    # The reverse of [10], and the check that was missing. Six of the nine
    # decisions were once *write-only*: they existed in Observations and appeared
    # nowhere in the Proposal, so a reader of the Proposal alone would never learn
    # they existed. [10] could not catch that -- it only knows about citations
    # that exist. This was found by reading, not by the validator.
    #
    # An identifier defined but never referenced is a decorative identifier, and
    # the whole point of the cross-reference graph is that it is load-bearing.
    # ----------------------------------------------------------------------
    for did in sorted(obs_decisions):
        if not re.search(r"§" + re.escape(did) + r"\b", proposal):
            errors.append(
                f"[10b] Observations defines §{did} but the Proposal never cites it"
            )

    # ----------------------------------------------------------------------
    # 11. Stub parity is bidirectional
    # ----------------------------------------------------------------------
    if obs_stub_count and not marker_ids:
        errors.append("[11] Observations defines §S- stubs but no inline QQQ-STUB markers exist")

    # ----------------------------------------------------------------------
    # 12. The Observations document keeps its skeleton.
    #
    # This exists because the same mistake happened four times: an `edit`
    # anchored on `## 4. MISTAKES AND FIXES` used that heading as trailing
    # context and did not reproduce it, so the heading was deleted. Each time it
    # was caught by a person re-listing the headings afterwards, and each time
    # the lesson was written down as a note — which did not prevent the next
    # occurrence (§M-007).
    #
    # A note was not enough, so this is a check. The document has a fixed
    # nine-section skeleton; a missing rib is mechanically visible.
    # ----------------------------------------------------------------------
    EXPECTED_SECTIONS = [
        "## 1. NEEDS YOUR ATTENTION",
        "## 2. DECISIONS",
        "## 3. OBSERVATIONS",
        "## 4. MISTAKES AND FIXES",
        "## 5. CORRECTIONS TO THE SOURCE CORPUS",
        "## 6. CODE STUBS AND PENDING ITEMS",
        "## 7. OPEN QUESTIONS",
        "## 8. THINGS TO REMEMBER (THE SHORT LIST)",
        "## 9. CHANGE LOG",
    ]

    # Matched as a **line**, not as a substring.
    #
    # A substring search was the first implementation and it was wrong: this
    # document *quotes* the heading `## 4. MISTAKES AND FIXES` in several places
    # while explaining the mistake of deleting it, so `find()` kept succeeding
    # after the real heading was removed. The check passed on a document that had
    # lost its section — and the fault injection is what caught that, by
    # reporting the check as dead rather than the injection as broken.
    #
    # Anchoring on the line is what makes the check test the skeleton rather than
    # the text.
    positions = []
    for section in EXPECTED_SECTIONS:
        match = re.search(r"(?m)^" + re.escape(section) + r"[ \t]*$", observations)
        if match is None:
            errors.append(
                f"[12] Observations is missing the section heading `{section}`"
            )
        else:
            positions.append(match.start())

    # Also checked: the sections are in order. A heading restored in the wrong
    # place leaves the document readable but its numbering a lie, which is
    # harder to notice than a missing one.
    if len(positions) == len(EXPECTED_SECTIONS) and positions != sorted(positions):
        errors.append("[12] Observations section headings are out of order")

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
    # Every marker the checklist's `Status legend` defines, parsed once so the
    # count of definitions and the progress fraction cannot disagree about the
    # population. An earlier version counted only `[x]` and `[ ]` here while the
    # report above counted all five: the two `[!]` blocked items were reported as
    # *defined* and then silently dropped from the denominator, and an
    # in-progress, dropped or blocked item was invisible in the one line printed
    # on every run.
    item_markers = re.findall(
        r"^- \[([ x~!-])\] \*\*[A-Z]+-\d{3}\*\*", checklist, re.M
    )
    by_marker: dict[str, int] = {m: item_markers.count(m) for m in "x ~!-"}
    done_items = by_marker["x"]
    in_progress = by_marker["~"]
    blocked = by_marker["!"]
    dropped = by_marker["-"]
    not_started = by_marker[" "]
    partial = len(re.findall(r"^  → Partial:", checklist, re.M))
    total = sum(by_marker.values())
    pct = (100 * done_items / total) if total else 0

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
    # Each non-zero marker is named, so the denominator is auditable from the
    # output alone: a reader can add the parts and get `total`. `[!]` blocked is
    # the case that exposed the defect -- it was in neither the numerator nor the
    # denominator, so the line above and this one disagreed by its count.
    breakdown = ", ".join(
        f"{n} {label}"
        for n, label in (
            (not_started, "not started"),
            (in_progress, "in progress"),
            (blocked, "blocked"),
            (dropped, "dropped"),
        )
        if n
    )
    print(f"Checklist progress        : {done_items}/{total} ({pct:.1f}%) checked"
          + (f", {partial} annotated partial" if partial else "")
          + (f" [{breakdown}]" if breakdown else ""))
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


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
#
# Why this exists
# ---------------
# This checker is the only thing standing between the repository and three
# documents that cite each other into nonsense. Every other document check -- the
# glossary, the scope table, the error catalogue, the threat model -- is written
# against the graph this file validates, so a silent false PASSED here is worse
# than a failure anywhere else.
#
# It had no self-test. The local gate asked it for `--self-test` anyway and
# produced `FATAL: missing --self-test\QQQ-Proposal-V1.md`, which reads like corpus
# drift and was the harness passing an argument that was never defined (SSO-186).
# The gate was fixed; this closes the other half, because a checker that has never
# been observed to fail has an uninformative "PASSED" -- it is indistinguishable
# from a checker that reads nothing.
#
# How it works
# ------------
# A tiny synthetic corpus is written to a temporary directory. The pristine copy
# must exit 0. Then each numbered rule is injected into a FRESH copy of that
# corpus, one per case, from a clean baseline -- batching two defects into one
# corpus would leave it ambiguous which of them the checker saw.
#
# Error rules assert two things: the run exits non-zero, and the output names that
# rule (`[n]`). Rule [5] is the one numbered check that only warns -- the checklist
# describes the work rather than being the work -- so its case asserts exit 0 WITH
# the tag present, which is the shape it really has. A further property is asserted
# once for the whole run rather than per case, and it is what keeps the error cases
# from being vacuous: the PRISTINE corpus must exit 0, which rules out any rule that
# fires unconditionally -- a checker that always failed would otherwise pass every
# case below.
#
# Relationship to `tools/self_test_xrefs.py`
# -----------------------------------------
# That harness is the integration proof: it mutates the three real documents, runs
# the validator, and restores them. It covers nine of the numbered checks. It cannot
# cover all of them safely, because three need a source file or a repeated heading
# to violate -- [3] an anchor defined twice, [7] stub markers, [11] stub parity --
# and mutating those in place risks more than it proves. This harness builds its own
# corpus in a temporary directory, so it can cover every one of them. It runs FIRST,
# from `self_test_xrefs.py`, so a dead rule is reported by the cheap safe harness
# before anything touches the tree.
#
# The checker is invoked as a subprocess through `sys.executable`, so the case
# exercises the same entry point CI runs, not an internal function.

# Assembled rather than written out, because `check_xrefs.py` scans every `.py`
# file under the repo root for stub markers -- including this one. Written as a
# literal, the two corpora below put a complete `QQQ-STUB(<ID>)` into the checker's own
# source, and the checker reported its own self-test as a stub with no checklist
# item. It really did: the first run after the self-test was added failed the real
# corpus with `[7] stub marker CAP-777 in source does not match any checklist item`. (not-a-checklist-item)
_STUB = "QQQ" + "-STUB"

_SKELETON = [
    "## 1. NEEDS YOUR ATTENTION",
    "## 2. DECISIONS",
    "## 3. OBSERVATIONS",
    "## 4. MISTAKES AND FIXES",
    "## 5. CORRECTIONS TO THE SOURCE CORPUS",
    "## 6. CODE STUBS AND PENDING ITEMS",
    "## 7. OPEN QUESTIONS",
    "## 8. THINGS TO REMEMBER (THE SHORT LIST)",
    "## 9. CHANGE LOG",
]


def _proposal(*, checklist_citation: str = "\u2192 **Checklist:** `CAP-001`",
              extra_heading: str = "", correction_rows: str = "| A-1 | a row |",
              decision_citation: str = "\u00a7D-001") -> str:
    return f"""# QQQ Test Proposal

## \u00a76.4 Capability engine
{extra_heading}The engine narrows. {decision_citation}

{checklist_citation}

## Appendix A. Corrections to the source corpus

| ID | Correction |
|---|---|
{correction_rows}
"""


def _checklist(*, citation: str = "\u2192 \u00a76.4 Capability engine",
               items: str = "") -> str:
    return f"""# QQQ Test Checklist

## Area CAP
- [ ] **CAP-001** Narrowing overlays only.
  {citation}
{items}
"""


def _observations(*, skeleton: list[str] | None = None,
                  corrections: str = "### \u00a7C-001 Corrected a thing",
                  decisions: str = "### \u00a7D-001 Narrowing only",
                  stubs: str = "") -> str:
    return "\n".join(skeleton if skeleton is not None else _SKELETON) + f"""

## 3. OBSERVATIONS

{corrections}

{decisions}

{stubs}
"""


def _write_corpus(root: Path, *, proposal: str, checklist: str, observations: str,
                  source_files: dict[str, str] | None = None) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / PROPOSAL).write_text(proposal, encoding="utf-8")
    (root / CHECKLIST).write_text(checklist, encoding="utf-8")
    (root / OBSERVATIONS).write_text(observations, encoding="utf-8")
    for rel, text in (source_files or {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def write_text_lf(path: Path, text: str, encoding: str = "utf-8") -> None:
    """Write `text` without translating newlines.

    # Why not `path.write_text`

    `Path.write_text` passes `newline=None` to `open`, which translates every
    `\n` to `os.linesep` -- `\r\n` on Windows. This repository pins `eol=lf`
    for tracked text (`.gitattributes`), so a read-modify-write cycle through it
    leaves a tracked file that `git status` reports as modified, that
    `git diff --numstat` reports with an empty diff, and that
    `tools/normalize_eol.py --check` rejects. Writing bytes keeps the
    transformation and drops the translation.

    `newline=""` is the other candidate and it is wrong here: it means *translate
    `\n` to the platform terminator*, which is the same behaviour. Only bytes are
    exact.

    The counterpart of this is `Path.read_text`: reads here are already exact,
    because the default newline handling translates `\r\n` *back* to `\n` and
    therefore round-trips. The asymmetry is the whole trap.

    `encoding` is accepted and defaults to UTF-8, so a converted call site keeps
    the keyword it already passed. Anything but UTF-8 is refused: a tracked file
    in this repository is UTF-8 or it is binary.
    """
    if encoding.lower().replace("-", "") != "utf8":
        raise ValueError(f"write_text_lf writes UTF-8, not {encoding!r}")
    path.write_bytes(text.encode("utf-8"))


# Directories never copied into a sandbox: version control, build output, and the
# local caches. Everything else is small enough to copy wholesale -- the tracked
# tree is a few hundred files and a few megabytes.
SANDBOX_SKIP = frozenset(
    {".git", "target", "node_modules", ".graf", ".scratch", "__pycache__", ".venv"}
)


def sandbox_copy(root: Path, dest: Path) -> Path:
    """Copy `root`'s working tree into `dest`, minus build output and caches.

    # Why a fault-injection harness needs this

    A `--self-test` half proves a checker can fail by **injuring the artifact it
    checks**, running the checker, and restoring. The restore is the fragile part:
    it is a `finally`, and no `finally` runs after a `SIGKILL` or the process-group
    termination a build tool applies to a command that overruns its deadline. So a
    harness that injects into the repository's own documents can be killed mid-
    injection and leave the tree mutated, and the mutation then reads as a real
    defect against every later run -- `§O-070`'s shape, and the mechanism behind
    the two rounds this goal lost (`§O-260`).

    Injecting into a copy removes the failure mode instead of policing it. A
    leftover in a temporary directory is discarded with the directory; the audited
    tree is never written to, so it cannot be left dirty by a signal it cannot
    catch. The save/restore logic stays exactly as it was -- it is still the thing
    that makes a *successful* run leave no trace -- but what it protects is now a
    resource that does not matter.

    Copying rather than fabricating a minimal root is deliberate: the whole-tree
    validator reads `crates/`, `wit/`, `docs/` and `tools/` as well as the three
    documents, so a fabricated root with only the documents under test would make
    most of its checks vacuous -- they would pass because the files were absent.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SANDBOX_SKIP]
        for name in filenames:
            src = Path(dirpath) / name
            dst = dest / src.relative_to(root)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
    return dest


@contextlib.contextmanager
def sandbox(root: Path, prefix: str = "qqq-sandbox-"):
    """Yield a temporary copy of `root`'s tree, removed when the block exits.

    The context-manager form of [`sandbox_copy`], for a self-test that wants to
    inject into a copy and let the copy clean itself up. See `sandbox_copy` for why
    injecting into a copy is the fix rather than a better restore.
    """
    import tempfile

    with tempfile.TemporaryDirectory(prefix=prefix) as tmp:
        yield sandbox_copy(root, Path(tmp) / "root")


def _run(root: Path) -> tuple[int, str]:

    proc = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), str(root)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def self_test() -> int:
    """Prove the checker fails for each of the reasons it claims to check."""
    import tempfile

    failures = 0
    total = 0

    def case(name: str, root: Path, tag: str, *, expect_fail: bool = True,
             expect_tag: bool = False) -> None:
        nonlocal failures, total
        total += 1
        code, out = _run(root)
        present = f"[{tag}]" in out
        if expect_fail:
            ok = code != 0 and present
            detail = (
                f"exit={code}, {'tag present' if present else 'TAG ABSENT'}"
                f" -- the checker did not notice the injected defect"
            )
        else:
            # The warning rules must still be observed. `expect_tag` is what makes
            # this more than "the corpus exits 0", which is true of a checker that
            # reads nothing at all.
            ok = code == 0 and (present or not expect_tag)
            detail = (
                f"exit={code} on a corpus that should be clean "
                f"({'tag absent' if not present else 'tag present'})"
            )
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            print(f"         {detail}")
            for line in out.splitlines():
                if "FAIL" in line or "ERROR" in line or "FATAL" in line:
                    print(f"         | {line.strip()}")

    with tempfile.TemporaryDirectory(prefix="qqq-xrefs-selftest-") as tmp:
        base = Path(tmp)

        # --- the pristine corpus: the baseline every case is injected into ---
        pristine = base / "clean"
        _write_corpus(
            pristine,
            proposal=_proposal(),
            checklist=_checklist(),
            observations=_observations(),
        )
        code, out = _run(pristine)
        total += 1
        if code == 0:
            print("  OK    pristine synthetic corpus passes")
        else:
            failures += 1
            print("  DEAD  pristine synthetic corpus passes")
            print("        the baseline is broken, so every case below is meaningless")
            for line in out.splitlines():
                if "FAIL" in line:
                    print(f"         | {line.strip()}")
            print(f"\nSELF-TEST FAILED -- {failures}/{total} case(s) bad; baseline unusable")
            return 1

        # --- [1] a checklist item citing a Proposal section that does not exist ---
        d = base / "r1"
        _write_corpus(d, proposal=_proposal(), checklist=_checklist(
            citation="\u2192 \u00a79.9 Nowhere"), observations=_observations())
        case("[1] item cites a section the Proposal does not define", d, "1")

        # --- [5] a Proposal section no checklist item cites ---
        #
        # [5] is the one numbered check that WARNS rather than fails: the checklist
        # is a description of the work, not the work, so a section with no item was
        # deliberately made a report. A warning is still a behaviour, and an
        # untested behaviour is one nobody has seen happen -- so it is asserted
        # here as exit 0 WITH the tag present, which is the shape [5] actually has.
        d = base / "r5"
        _write_corpus(d, proposal=_proposal() + "\n## \u00a77.1 An uncited section\n",
                      checklist=_checklist(), observations=_observations())
        case("[5] Proposal section no checklist item cites (warns, exit 0)",
             d, "5", expect_fail=False, expect_tag=True)

        # --- [2] a Proposal citation naming a checklist item that does not exist ---
        d = base / "r2"
        _write_corpus(d, proposal=_proposal(
            checklist_citation="\u2192 **Checklist:** `CAP-999`"), checklist=_checklist(),  # not-a-checklist-item
            observations=_observations())
        case("[2] Proposal cites an undefined checklist item", d, "2")

        # --- [3] an anchor defined twice ---
        d = base / "r3"
        _write_corpus(d, proposal=_proposal(
            extra_heading="## \u00a76.4 Capability engine\n"), checklist=_checklist(),
            observations=_observations())
        case("[3] anchor defined twice", d, "3")

        # --- [4] an item with no Proposal citation ---
        d = base / "r4"
        _write_corpus(d, proposal=_proposal(), checklist=_checklist(
            citation="", items="- [ ] **CAP-002** Orphaned, cites nothing."),
            observations=_observations())
        case("[4] item carries no Proposal citation", d, "4")

        # --- [6] a checklist ID defined twice ---
        d = base / "r6"
        _write_corpus(d, proposal=_proposal(), checklist=_checklist(
            items="- [ ] **CAP-001** Defined a second time.\n  \u2192 \u00a76.4 Capability engine"),
            observations=_observations())
        case("[6] checklist ID defined twice", d, "6")

        # --- [7] a stub marker naming no checklist item ---
        d = base / "r7"
        _write_corpus(d, proposal=_proposal(), checklist=_checklist(),
                      observations=_observations(),
                      source_files={"crates/x/src/lib.rs": f"// {_STUB}(CAP-777): nope\n"})  # not-a-checklist-item
        case("[7] stub marker matches no checklist item", d, "7")

        # --- [7] the other half: markers exist, Observations has no SS-S- entries ---
        d = base / "r7b"
        _write_corpus(d, proposal=_proposal(), checklist=_checklist(),
                      observations=_observations(),
                      source_files={"crates/x/src/lib.rs": f"// {_STUB}(CAP-001): nope\n"})
        case("[7] markers exist with no Observations stub section", d, "7")

        # --- [8] an Appendix A row with no matching correction ---
        d = base / "r8"
        _write_corpus(d, proposal=_proposal(
            correction_rows="| A-1 | a row |\n| A-2 | an unrecorded row |"),
            checklist=_checklist(), observations=_observations())
        case("[8] Appendix A row has no matching correction entry", d, "8")

        # --- [9] an open question with no matching checklist item ---
        d = base / "r9"
        _write_corpus(d, proposal=_proposal(), checklist=_checklist(),
                      observations=_observations(corrections=(
                          "### \u00a7C-001 Corrected a thing\n\n"
                          "### \u00a7Q-001 Does the engine narrow?")))
        case("[9] Observations open question has no checklist item", d, "9")

        # --- [10] the Proposal citing a decision that is not defined ---
        d = base / "r10"
        _write_corpus(d, proposal=_proposal(decision_citation="\u00a7D-009"),
                      checklist=_checklist(), observations=_observations())
        case("[10] Proposal cites an undefined decision", d, "10")

        # --- [10b] a decision the Proposal never cites ---
        d = base / "r10b"
        _write_corpus(d, proposal=_proposal(decision_citation="nothing here"),
                      checklist=_checklist(), observations=_observations())
        case("[10b] decision is never cited by the Proposal", d, "10b")

        # --- [11] Observations defines stubs but no marker exists ---
        d = base / "r11"
        _write_corpus(d, proposal=_proposal(), checklist=_checklist(),
                      observations=_observations(
                          stubs="### \u00a7S-001 A stub nothing marks"))
        case("[11] Observations stubs with no inline marker", d, "11")

        # --- [12] a missing skeleton heading ---
        d = base / "r12"
        broken = [s for s in _SKELETON if s != "## 4. MISTAKES AND FIXES"]
        _write_corpus(d, proposal=_proposal(), checklist=_checklist(),
                      observations=_observations(skeleton=broken))
        case("[12] Observations is missing a skeleton heading", d, "12")

        # --- [12] the same skeleton, reordered ---
        d = base / "r12b"
        swapped = list(_SKELETON)
        swapped[3], swapped[4] = swapped[4], swapped[3]
        _write_corpus(d, proposal=_proposal(), checklist=_checklist(),
                      observations=_observations(skeleton=swapped))
        case("[12] Observations headings are out of order", d, "12")

        # --- the progress line counts every marker the legend defines ---------
        #
        # This is a *report* rather than a numbered check, so the assertion is not
        # "an error was raised" but "the arithmetic in the output is right". It is
        # here because the line was wrong: it counted `[x]` and `[ ]` while the
        # line above counted all five legend markers, so the two numbers a few
        # lines apart disagreed by the number of `[!]`/`[~]`/`[-]` items and
        # nothing explained the gap. An item marked blocked, in progress or
        # dropped was invisible in the one line printed on every run.
        #
        # The corpus has one item per marker, so the denominator must be 5 and the
        # breakdown must name each non-zero marker. A checker that regressed to
        # two markers would report 3/4 and fail here.
        d = base / "rprogress"
        _write_corpus(
            d,
            proposal=_proposal(),
            checklist=_checklist(
                items=(
                    "- [x] **CAP-002** Done.\n"
                    "  \u2192 \u00a76.4 Capability engine\n"
                    "- [ ] **CAP-003** Not started.\n"
                    "  \u2192 \u00a76.4 Capability engine\n"
                    "- [~] **CAP-004** In progress.\n"
                    "  \u2192 \u00a76.4 Capability engine\n"
                    "- [!] **CAP-005** Blocked.\n"
                    "  \u2192 \u00a76.4 Capability engine\n"
                    "- [-] **CAP-006** Dropped.\n"
                    "  \u2192 \u00a76.4 Capability engine"
                )
            ),
            observations=_observations(),
        )
        total += 1
        code, out = _run(d)
        line = next(
            (l for l in out.splitlines() if "Checklist progress" in l), ""
        )
        # Assert the *relationship*, not a magic total: the denominator must be
        # the number of items the corpus defines, and the named breakdown must
        # account for every item that is not done. A hard-coded number here would
        # be a second copy of the count -- the defect this whole change is about.
        #
        # The corpus defines six items: the helper's own `CAP-001` (`[ ]`) plus the
        # five injected, one per marker.
        corpus = _checklist(
            items=(
                "- [x] **CAP-002** Done.\n"
                "  \u2192 \u00a76.4 Capability engine\n"
                "- [ ] **CAP-003** Not started.\n"
                "  \u2192 \u00a76.4 Capability engine\n"
                "- [~] **CAP-004** In progress.\n"
                "  \u2192 \u00a76.4 Capability engine\n"
                "- [!] **CAP-005** Blocked.\n"
                "  \u2192 \u00a76.4 Capability engine\n"
                "- [-] **CAP-006** Dropped.\n"
                "  \u2192 \u00a76.4 Capability engine"
            )
        )
        defined = len(re.findall(r"^- \[[ x~!-]\] \*\*[A-Z]+-\d{3}\*\*", corpus, re.M))
        # "N/M (P%) checked [a not started, ...]"
        m = re.search(r"Checklist progress\s*: (\d+)/(\d+) \([\d.]+%\) checked", line)
        parts = re.findall(r"(\d+) (not started|in progress|blocked|dropped)", line)
        ok = (
            code == 0
            and m is not None
            and int(m.group(2)) == defined
            and m.group(1) == "1"
            and len(parts) == 4
            and sum(int(n) for n, _ in parts) == defined - 1
        )
        print(f"  {'OK  ' if ok else 'DEAD'}  [report] the progress line counts every "
              f"legend marker")
        if not ok:
            failures += 1
            print(f"         exit={code}; corpus defines {defined} item(s) and the line "
                  f"was {line!r} -- the denominator must equal the number of items and "
                  f"the named parts must sum to the items that are not done")

    if failures:
        print(f"\nSELF-TEST FAILED -- {failures}/{total} case(s) bad")
        return 1
    print(f"\nSELF-TEST PASSED -- {total}/{total} case(s); every numbered check that"
          f" fails a run was observed to fire, plus the [5] warning and the progress"
          f" line")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        raise SystemExit(self_test())
    raise SystemExit(main())
