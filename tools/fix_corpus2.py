#!/usr/bin/env python3
"""Second-pass corpus repair.

1. Removes leftover secondary citation lines that point at appendices
   (the validator counts only one citation per item and reports the first,
   but stale duplicates are still misleading to a reader).
2. Adds the three checklist items needed to close the coverage warnings for
   Proposal sections §0.1, §2.3 and §8.1.

Idempotent.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKLIST = ROOT / "QQQ-Checklist-V1.md"

RE_ITEM_DEF = re.compile(r"^\s*-\s*\[[ x~!-]\]\s*\*\*([A-Z]{2,5}-\d{3})\*\*")


def strip_stale_appendix_citations() -> int:
    """Remove a *second* '→ Appendix ...' line that follows a '→ §...' line."""
    lines = CHECKLIST.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    removed = 0
    for i, line in enumerate(lines):
        if line.strip().startswith("→ Appendix") and out and out[-1].strip().startswith("→ §"):
            removed += 1
            continue
        out.append(line)
    CHECKLIST.write_text("\n".join(out) + "\n", encoding="utf-8")
    return removed


def add_coverage_items() -> int:
    text = CHECKLIST.read_text(encoding="utf-8")
    added = 0

    # --- §0.1 Executive summary -> a documentation task that keeps the public
    #     summary true. Goes into the DOC area.
    anchor_doc = "### DOC — Documentation machinery\n\n"
    new_doc = (
        "- [ ] **DOC-021** Keep the executive summary in the Proposal synchronised with reality: "
        "re-verify its three falsifiable claims against the benchmark suite and the security "
        "artifacts at every milestone, and correct them publicly when they no longer hold.\n"
        "  → §0.1 Executive summary\n"
    )
    if "**DOC-021**" not in text and anchor_doc in text:
        text = text.replace(anchor_doc, anchor_doc + new_doc, 1)
        added += 1

    # --- §2.3 NN-3 -> measurable predictability work belongs to PERF.
    anchor_perf = "### PERF — Performance engineering\n\n"
    new_perf = (
        "- [ ] **PERF-027** Establish and enforce the tail-latency and cold-start budgets as "
        "*contractual* objectives: publish them, alert on regression, and treat a breach as a "
        "release blocker rather than a metric.\n"
        "  → §2.3 NN-3 — Performance and Predictability Over Micro-Benchmarks\n"
    )
    if "**PERF-027**" not in text and anchor_perf in text:
        text = text.replace(anchor_perf, anchor_perf + new_perf, 1)
        added += 1

    # --- §8.1 The four agent relationships -> an AGENT item proving all four
    #     relationships are actually served.
    anchor_agent = "### AGENT — Machine contracts\n\n"
    new_agent = (
        "- [ ] **AGENT-025** Prove all four agent relationships (author, operator, host, adversary) "
        "are genuinely served: run a structured exercise for each and publish the findings, "
        "including any relationship that turns out to be unserved.\n"
        "  → §8.1 The four agent relationships\n"
    )
    if "**AGENT-025**" not in text and anchor_agent in text:
        text = text.replace(anchor_agent, anchor_agent + new_agent, 1)
        added += 1

    CHECKLIST.write_text(text, encoding="utf-8")
    return added


def recount_totals() -> None:
    """Rewrite the summary counter table with the true item counts per phase."""
    text = CHECKLIST.read_text(encoding="utf-8")
    ids = [m.group(1) for m in (RE_ITEM_DEF.match(l) for l in text.splitlines()) if m]
    total = len(ids)
    # Replace the bolded total line in section 14 only.
    text = re.sub(
        r"\| \*\*Total\*\* \| \| \*\*\d+\*\* \|",
        f"| **Total** | | **{total}** |",
        text,
    )
    CHECKLIST.write_text(text, encoding="utf-8")
    print(f"total checklist items: {total}")


if __name__ == "__main__":
    r = strip_stale_appendix_citations()
    a = add_coverage_items()
    print(f"stale citation lines removed: {r}")
    print(f"coverage items added        : {a}")
    recount_totals()
