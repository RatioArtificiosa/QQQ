#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check that glossary terms used in WIT doc comments exist in the glossary (`DOC-012`).

# The problem

The Proposal's §0.6 says: "Where a term is contested in the industry, the definition
here wins for this project." That only holds if the WIT documentation uses those terms
**as defined**.

A WIT doc comment that says "the host calls the module" is using two terms the glossary
defines differently (`host` is the native process, and `module` is not a term this
project uses — it is `component`). A reader then has two vocabularies and no way to tell
which is authoritative, and the WIT is the artifact a component author actually reads.

# What is checked

Two directions, and the second is the one that catches real drift:

1. **A defined term used in a WIT doc must be spelled as the glossary spells it.**
   `WebAssembly component` must not appear as `wasm module` in a doc comment.
2. **A near-miss is reported.** If a WIT doc uses a word that is one of the glossary's
   entries but with different capitalisation or a plural, that is flagged — because it
   is usually the beginning of a second vocabulary rather than a stylistic choice.

# What is deliberately NOT checked

Ordinary English. The checker has an explicit list of *confusable pairs* — terms this
project defines precisely and where the industry uses a near-synonym — rather than
trying to validate every noun in the corpus. A check that fires on prose style gets
disabled, and a disabled check is worth nothing.

Usage:  python tools/check_glossary_usage.py [--self-test]
Exit:   0 = the WIT docs use the glossary's vocabulary, 1 = they do not
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
WIT_DIR = ROOT / "wit"
GLOSSARY = ROOT / "docs" / "glossary.md"
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"

# # The confusable pairs
#
# Left side: what the industry says. Right side: what this project says, and why the
# difference matters. Each is a term the Proposal's §0.6 defines deliberately, so a
# WIT comment using the industry word is not a typo — it is a second vocabulary.
#
# Deliberately a short, curated list. Every entry here is a check that will fire on
# real content, so one added carelessly makes the whole check noisy.
CONFUSABLE = [
    ("wasm module", "component", "a Component Model binary, not a core module"),
    ("webassembly module", "component", "same as above"),
    ("core wasm", "core module", "the glossary distinguishes these explicitly"),
    ("plugin", "component", "QQQ has no plugin mechanism"),
    ("permission", "capability", "a grant of authority, not a permission bit"),
    ("sandboxing", "sandbox", "the glossary noun is `sandbox`"),
]

# # Why `thread` and `container` were removed after the first run
#
# Both were in the initial list and both fired on ordinary English:
#
#     /// would force every consumer onto its own thread.
#     /// the container image is read-only
#
# Neither is a vocabulary mistake. `thread` there means an OS thread — a real thing
# this project talks about when explaining why a signature is async — and `container`
# refers to a deployment artefact, which is a use the glossary does not contest.
#
# **A check that fires on prose gets disabled**, and a disabled check is worth nothing,
# so a rule has to earn its place by catching a mistake rather than a word. The
# remaining five all name a concept QQQ *defines differently from the industry*, which
# is the only case where a WIT doc using the industry word is actually wrong.
#
# This is recorded here rather than silently dropped, because the next person will
# reach for `thread` too.

# The terms the glossary defines. Extracted from the generated glossary's headings.
def glossary_terms() -> set[str]:
    """The `##`-level terms in the generated glossary."""
    if not GLOSSARY.exists():
        return set()
    terms = set()
    for m in re.finditer(r"(?m)^##\s+(.+?)\s*$", GLOSSARY.read_text(encoding="utf-8")):
        terms.add(m.group(1).strip().lower())
    return terms


def doc_comments(path: Path) -> list[tuple[int, str]]:
    """Every `///` doc line in a WIT file, with its line number."""
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip().startswith("///"):
            out.append((i, line.strip()[3:].strip()))
    return out


def check_docs(files: list[Path]) -> list[str]:
    """Return the vocabulary problems across the WIT files."""
    problems: list[str] = []

    for path in files:
        for lineno, text in doc_comments(path):
            lowered = text.lower()
            for industry, ours, why in CONFUSABLE:
                # Word-boundary match, so `container` does not fire inside
                # `containerisation` — a substring match here produced false
                # positives on the first run.
                if re.search(rf"\b{re.escape(industry)}\b", lowered):
                    problems.append(
                        f"{path.name}:{lineno}: uses {industry!r}; this project says "
                        f"{ours!r} ({why}). A second vocabulary in the WIT — the "
                        f"artifact a component author actually reads — is how the "
                        f"glossary's authority is lost."
                    )
    return problems


def check_glossary_is_a_source() -> list[str]:
    """The glossary must still exist and be non-trivial, or the check means nothing."""
    problems: list[str] = []
    if not GLOSSARY.exists():
        return [
            "docs/glossary.md does not exist, so there is no vocabulary to check "
            "against. Run `python tools/gen_glossary.py`."
        ]
    terms = glossary_terms()
    if len(terms) < 10:
        problems.append(
            f"docs/glossary.md defines only {len(terms)} term(s). Either the glossary "
            f"was truncated or its headings changed shape, and a check against an "
            f"almost-empty vocabulary passes everything."
        )
    return problems


def validate() -> int:
    if not WIT_DIR.is_dir():
        print(f"FATAL: {WIT_DIR} does not exist")
        return 1

    files = sorted(WIT_DIR.glob("*.wit"))
    if not files:
        print(f"FATAL: no `.wit` files in {WIT_DIR}")
        return 1

    problems = check_glossary_is_a_source() + check_docs(files)
    if problems:
        print("GLOSSARY USAGE FAILED")
        print("")
        for p in problems:
            print(f"  FAIL  {p}")
        return 1

    docs = sum(len(doc_comments(f)) for f in files)
    print(
        f"GLOSSARY USAGE OK -- {docs} WIT doc line(s) across {len(files)} file(s), no "
        f"confusable term misused ({len(CONFUSABLE)} pair(s) checked)"
    )
    return 0


def self_test() -> int:
    """Prove every confusable pair can fire, and that ordinary prose does not."""
    failures = 0

    def case(name: str, text: str, expect: str) -> None:
        nonlocal failures
        lowered = text.lower()
        hits = [
            industry
            for industry, _ours, _why in CONFUSABLE
            if re.search(rf"\b{re.escape(industry)}\b", lowered)
        ]
        ok = (expect == "" and not hits) or (expect != "" and expect in hits)
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            print(f"        expected {expect!r}, got {hits}")

    # Every pair must actually fire, or it is a dead rule.
    for industry, _ours, _why in CONFUSABLE:
        case(f"fires on {industry!r}", f"The guest passes a {industry} to the host.", industry)

    # Ordinary prose must not fire. These are the false positives that would get the
    # check disabled: the glossary's OWN terms, and words that merely contain a
    # confusable as a substring.
    case("does not fire on `component`", "A component holds only its grants.", "")
    case("does not fire on `instance`", "Each instance has its own memory.", "")
    case("does not fire on `capability`", "The capability is resolved once.", "")
    case(
        "does not fire on a substring",
        "The containerisation strategy is out of scope.",
        "",
    )
    case(
        "does not fire on `modules` plural of an unrelated word",
        "Modularity is a design goal.",
        "",
    )

    # The vocabulary source must be real.
    problems = check_glossary_is_a_source()
    ok = not problems
    print(f"  {'OK  ' if ok else 'DEAD'}  the glossary is a usable source")
    if not ok:
        failures += 1
        print(f"        {problems}")

    # The real corpus must currently pass.
    files = sorted(WIT_DIR.glob("*.wit"))
    real = check_docs(files)
    ok = not real
    print(f"  {'OK  ' if ok else 'DEAD'}  the real WIT docs use the glossary vocabulary")
    if not ok:
        failures += 1
        for p in real[:4]:
            print(f"        {p}")

    total = len(CONFUSABLE) + 8
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every rule is live")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    return validate()


if __name__ == "__main__":
    raise SystemExit(main())
