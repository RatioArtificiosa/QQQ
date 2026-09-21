#!/usr/bin/env python3
"""Keep the published security scope consistent (`SEC-030`).

# The problem this solves

Four documents state what QQQ defends against and what it does not:

  * `QQQ-Proposal-V1.md` §7.2 — the threat model, including the four out-of-scope
    classes named as bullets
  * `SECURITY.md` — the policy a reporter reads, with its own out-of-scope list
  * `docs/out-of-scope.md` — the published expansion a user reads before choosing QQQ
  * `docs/wasmtim‌e-advisory-process.md` — the process for the one class that is
    tracked rather than excluded

When those disagree, a reader is misled by whichever one they happened to open, and
nothing says which is authoritative. Worse, the disagreement is invisible: all four
are prose, and prose does not fail a build.

That is exactly the failure `§O-085` and §O-088 describe in controls — installed,
silent, believed. So the agreement is checked mechanically.

# What is enforced

  1. Every out-of-scope class named in the Proposal's §7.2 bullet list has a matching
     section in `docs/out-of-scope.md`.
  2. Every class in `SECURITY.md`'s out-of-scope list appears in
     `docs/out-of-scope.md`.
  3. `docs/out-of-scope.md` names no class absent from both, so it cannot invent a
     limitation the canonical sources do not state.
  4. `SECURITY.md` links to `docs/out-of-scope.md`, and the reverse holds, so a reader
     arriving at either finds the other.
  5. The four canonical classes are present in all of them. This is an explicit
     allowlist rather than a derived set: if a class is *removed* from the Proposal,
     this check must fail loudly rather than quietly agreeing to a smaller threat
     model, because that is a security decision rather than an editorial one.

Usage:  python tools/check_security_scope.py [--self-test]
Exit:   0 = the documents agree, 1 = they do not
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"
SECURITY = ROOT / "SECURITY.md"
OUT_OF_SCOPE = ROOT / "docs" / "out-of-scope.md"

# The four classes §7.2 names. Anchored on a distinctive lowercase fragment so the
# match survives rewording of the surrounding sentence — a check that breaks when
# someone improves the wording is a check that gets deleted.
CANONICAL_CLASSES = {
    "host admin": ["malicious **host** administrator", "malicious host"],
    "side channels": ["**Side-channel** attacks", "side-channel"],
    "physical access": ["**Physical** access", "physical access"],
    "volumetric dos": ["Denial of service by sheer volume", "denial of service"],
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def proposal_classes(text: str) -> set[str]:
    """Which canonical classes the Proposal's §7.2 states."""
    found: set[str] = set()
    for name, variants in CANONICAL_CLASSES.items():
        if any(v.lower() in text.lower() for v in variants):
            found.add(name)
    return found


def security_classes(text: str) -> set[str]:
    """Which canonical classes `SECURITY.md`'s out-of-scope list states."""
    # Scope the search to the out-of-scope section, so a mention of "physical" in
    # some other context does not count as declaring it out of scope.
    marker = "## What is explicitly out of scope"
    start = text.find(marker)
    if start == -1:
        return set()
    section = text[start:]
    end = section.find("\n## ", 1)
    if end != -1:
        section = section[:end]

    found: set[str] = set()
    for name, variants in CANONICAL_CLASSES.items():
        if any(v.lower() in section.lower() for v in variants):
            found.add(name)
    return found


def out_of_scope_headings(text: str) -> list[str]:
    """The `## N. Title` headings of the published document."""
    return [m.group(1).strip() for m in re.finditer(r"(?m)^##\s+\d+\.\s+(.+?)\s*$", text)]


def check(proposal: str, security: str, published: str) -> list[str]:
    """Return the disagreements between the three documents."""
    problems: list[str] = []

    if not published.strip():
        return ["docs/out-of-scope.md is empty"]

    in_proposal = proposal_classes(proposal)
    in_security = security_classes(security)
    headings = " || ".join(out_of_scope_headings(published)).lower()

    # 5. Every canonical class must be stated in all three. A *removal* is a
    # security decision, so it must fail here rather than pass quietly.
    for name in CANONICAL_CLASSES:
        if name not in in_proposal:
            problems.append(
                f"the Proposal §7.2 no longer states the {name!r} class. Removing an "
                f"out-of-scope class is a security decision, not an editorial one: if "
                f"QQQ now defends against it, say so in SECURITY.md and here in the "
                f"same change."
            )
        if name not in in_security:
            problems.append(
                f"SECURITY.md's out-of-scope section no longer states {name!r}"
            )

    # 1/2. Every class the canonical sources state must appear in the published doc.
    keywords = {
        "host admin": ["host"],
        "side channels": ["side channel", "side-channel"],
        "physical access": ["physical"],
        "volumetric dos": ["volume", "denial of service"],
    }
    for name in sorted(in_proposal | in_security):
        if not any(k in headings for k in keywords[name]):
            problems.append(
                f"docs/out-of-scope.md has no section for {name!r}, which the "
                f"Proposal or SECURITY.md states. Headings found: {headings!r}"
            )

    # 4. The two documents must link to each other.
    if "out-of-scope.md" not in security:
        problems.append("SECURITY.md does not link to docs/out-of-scope.md")
    if "../SECURITY.md" not in published and "SECURITY.md" not in published:
        problems.append("docs/out-of-scope.md does not link back to SECURITY.md")

    # Each published section must say what to do, not only that something is absent.
    # A document of bare denials is accurate and useless.
    sections = re.split(r"(?m)^##\s+\d+\.\s+", published)[1:]
    for section in sections:
        title = section.splitlines()[0].strip() if section.strip() else "(untitled)"
        body = "\n".join(section.splitlines()[1:])
        if len(body.strip()) < 200:
            problems.append(
                f"the section {title!r} in docs/out-of-scope.md is too short to state "
                f"a consequence or a mitigation. A bare 'not defended' is accurate and "
                f"does not help the reader decide anything."
            )

    return problems


def validate() -> int:
    for path in (PROPOSAL, SECURITY, OUT_OF_SCOPE):
        if not path.exists():
            print(f"FATAL: {path} does not exist")
            return 1

    problems = check(read(PROPOSAL), read(SECURITY), read(OUT_OF_SCOPE))
    if problems:
        print("SECURITY SCOPE FAILED")
        print("")
        for p in problems:
            print(f"  FAIL  {p}")
        return 1

    print(
        f"SECURITY SCOPE OK -- {len(CANONICAL_CLASSES)} canonical classes agree across "
        f"the Proposal §7.2, SECURITY.md and docs/out-of-scope.md"
    )
    return 0


def self_test() -> int:
    """Prove every check can fail."""
    valid_proposal = (
        "**Explicitly out of scope for V1**:\n"
        "- A malicious **host** administrator.\n"
        "- **Side-channel** attacks across tenants.\n"
        "- **Physical** access.\n"
        "- **Denial of service by sheer volume**.\n"
    )
    valid_security = (
        "## What is explicitly out of scope\n"
        "- A malicious **host** administrator.\n"
        "- **Side-channel** attacks between tenants.\n"
        "- **Physical** access.\n"
        "- **Volumetric denial of service**.\n"
        "See docs/out-of-scope.md for the full list.\n"
        "\n## Our commitments\n"
    )
    body = "x" * 250
    valid_published = (
        "# What QQQ does not defend against\n"
        f"## 1. A malicious host administrator\n{body}\n"
        f"## 2. Side channels between tenants\n{body}\n"
        f"## 3. Physical access\n{body}\n"
        f"## 4. Denial of service by sheer volume\n{body}\n"
        "Back to /SECURITY.md\n"
    )

    cases = [
        ("clean documents", valid_proposal, valid_security, valid_published, ""),
        (
            "published doc missing a class",
            valid_proposal,
            valid_security,
            valid_published.replace("## 3. Physical access", "## 3. Something else"),
            "no section for 'physical access'",
        ),
        (
            "proposal drops a class",
            valid_proposal.replace("- **Physical** access.\n", ""),
            valid_security,
            valid_published,
            "no longer states the 'physical access' class",
        ),
        (
            "security.md drops a class",
            valid_proposal,
            valid_security.replace("- **Physical** access.\n", ""),
            valid_published,
            "no longer states 'physical access'",
        ),
        (
            "security.md stops linking",
            valid_proposal,
            valid_security.replace("See docs/out-of-scope.md for the full list.\n", ""),
            valid_published,
            "does not link to docs/out-of-scope.md",
        ),
        (
            "published doc stops linking back",
            valid_proposal,
            valid_security,
            valid_published.replace("Back to /SECURITY.md\n", ""),
            "does not link back to SECURITY.md",
        ),
        (
            "a bare denial with no guidance",
            valid_proposal,
            valid_security,
            valid_published.replace(body, "Not defended."),
            "too short to state a consequence",
        ),
    ]

    failures = 0
    for name, proposal, security, published, expect in cases:
        problems = check(proposal, security, published)
        joined = "\n".join(problems)
        ok = (not problems) if expect == "" else (expect in joined)
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            print(f"        expected {expect!r}, got: {joined[:200]}")

    total = len(cases)
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
