#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refuse a Markdown document that contains the *text* of a Unicode escape.

    python tools/check_unicode_escapes.py [--self-test]

`\\u00a7`, `\\u2014`, `\\u2019` and friends are how a source-language string literal spells a
character. When they reach a Markdown file they render as the literal text `\\u00a7`, not as `§`,
because Markdown has no escape processing. The document then reads to a human as noise, and to a
search for `§O-189` it is invisible -- so a cross-reference that *looks* present is absent.

# Why this is a real hazard here rather than a hypothetical one

Editing these documents is done through Python scripts, because the repository's own handbook
records that a shell mangles multi-line strings. A script that builds text with `\\u` escapes must
either use a plain string (where Python decodes them) or an `f`/raw string (where it does not),
and the difference is one character at the call site. The leak has happened: `` `\\u00a7O-189` ``
sat in `QQQ-Observations-and-Memories.md` where `§O-189` belonged, and it was invisible to
`grep '§O-189'` while being plainly wrong to a reader.

# What is a violation and what is not

**Only** the sequence `\\u` followed by four hex digits, standing as text. Everything else that
looks like an escape is legitimate and is left alone:

| Text | Verdict | Why |
|---|---|---|
| `` `\\u00a7O-189` `` | **violation** | the document wants `§O-189` |
| `` `\\0asm\\x0d\\0\\x01\\0` `` | fine | a byte literal shown as source |
| `` `\\x1b[1m` `` | fine | an ANSI escape shown as source |
| `` r"(?m)^- \\[[ x]\\] \\*\\*CAP-012\\*\\*" `` | fine | a regex shown as source |

The discriminator is `\\u` specifically: `\\x` and `\\*` are overwhelmingly used to *quote* source
in this corpus, while a stray `\\uXXXX` in prose is nearly always a leak. The scanner therefore
covers `\\u` and reports `\\x`/`\\n` counts only in `--self-test`, so a rule that cannot be
satisfied is not added.

# Refusing vacuity

The document list is discovered from the repository, and finding **no** documents is a failure
rather than a pass: a checker that scans nothing certifies nothing. This is the same rule
`check_xrefs.py` states for its own corpus.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# `\u` plus exactly four hex digits, captured so the discriminant can be inspected.
ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")

# Markdown the project treats as canonical or generated. Generated files are included on
# purpose: a leak in `llms.txt` reaches every agent that reads the index.
SEARCH_GLOBS = ("*.md", "docs/**/*.md", "skills/**/*.md", "crates/*/*.md")

# Rust doc comments are scanned too, and this is not theoretical: `crates/qqq-run/src/test.rs`
# carried `` (`\u00a7O-188`) `` in a `///` note, where `§O-188` belonged. Same invisibility —
# `grep '§O-188'` did not find it — in a file type the Markdown-only version of this checker
# would have missed entirely.
RUST_GLOB = "crates/**/*.rs"

# Escapes that are *machinery* rather than prose, and must be left alone. A JSON-escape test
# asserts that a NUL byte serializes to the six characters `\u0000`; rewriting that would break
# the test and the format. The discriminators, each with its real instance:
#
#   * `\u0000`-style control escapes — `qqq_cap`'s manifest fixture and `qqq-host`'s
#     `json_escape` assertions;
#   * the literal inside a `\\u` (an escaped backslash, i.e. a string *about* an escape).
PROSE_ESCAPES = {"00a7", "2014", "2019", "201c", "201d", "2018", "2026", "00b7", "2192", "2265"}

# Code blocks are scanned too. A leak inside a fenced block is still a leak -- the
# `\u00a7O-189` instance was inside a code span -- but a *legitimate* byte literal is
# distinguished by not being `\u`.
SKIP_PATHS = {ROOT / "tools" / "check_unicode_escapes.py"}


def documents() -> list[Path]:
    found: list[Path] = []
    for pattern in SEARCH_GLOBS:
        found.extend(sorted(ROOT.glob(pattern)))
    return sorted({p for p in found if p.is_file() and p not in SKIP_PATHS})


def rust_files() -> list[Path]:
    return sorted(p for p in ROOT.glob(RUST_GLOB) if p.is_file())


def _is_prose_leak(hex_digits: str) -> bool:
    """Whether a `\\uXXXX` is a leaked character rather than escape machinery."""
    return hex_digits.lower() in PROSE_ESCAPES


def scan(path: Path) -> list[tuple[int, str]]:
    """Return (line number, the offending line) for each leaked `\\uXXXX` in the file."""
    hits: list[tuple[int, str]] = []
    text = path.read_text(encoding="utf-8")
    for i, line in enumerate(text.split("\n"), 1):
        for m in ESCAPE.finditer(line):
            if _is_prose_leak(m.group(1)):
                hits.append((i, line.strip()))
                break
    return hits


def run(args) -> int:
    docs = documents()
    rust = rust_files()
    if not docs or not rust:
        print(
            f"FAIL -- found {len(docs)} document(s) and {len(rust)} Rust file(s); "
            "a scan of nothing certifies nothing"
        )
        return 1

    total = 0
    for path in [*docs, *rust]:
        for line_no, line in scan(path):
            total += 1
            rel = path.relative_to(ROOT)
            print(f"  {rel}:{line_no}")
            print(f"    {line[:150]}")

    print(f"\nscanned {len(docs)} document(s) and {len(rust)} Rust file(s)")
    if total:
        print(f"UNICODE ESCAPES LEAKED -- {total} occurrence(s)")
        print("These render as the literal text `\\uXXXX`. Replace each with the character it")
        print("spells: `\\u00a7` is `§`, `\\u2014` is an em dash, `\\u2019` is a right quote.")
        return 1
    print("UNICODE ESCAPES OK -- no file contains the text of a prose character escape")
    return 0


def self_test(args) -> int:
    """Prove the scanner fires on a leak and stays silent on legitimate source text."""
    cases = [
        ("the real leak", "see `\\u00a7O-189` for the cause", True),
        ("an em dash leak", "the rule \\u2014 which is load-bearing", True),
        ("a smart quote leak", "the project\\u2019s own words", True),
        ("the Rust doc-comment leak", "/// (`\\u00a7O-188`).", True),
        ("a byte literal", "`\\0asm\\x0d\\0\\x01\\0` is the magic", False),
        ("an ANSI escape", 'never matched `\\x1b[1m\\x1b[92m Blocking\\x1b[0m`', False),
        ("a regex showing stars", r'r"(?m)^- \[[ x]\] \*\*CAP-012\*\*"', False),
        ("a real section sign", "see \u00a7O-189 for the cause", False),
        ("a real em dash", "the rule \u2014 which is load-bearing", False),
        ("a backslash-u in prose that is not an escape", "the path C:\\users\\name", False),
        # The machinery discriminators, each a real instance in this repository.
        ("a JSON-escape test fixture", 'assert_eq!(json_escape("a\\u{0}b"), "a\\\\u0000b");', False),
        ("a manifest fixture with a control escape", 'path = "/tmp/a\\\\u0000b"', False),
    ]

    failures = 0
    for label, text, want_hit in cases:
        got_hit = any(_is_prose_leak(m.group(1)) for m in ESCAPE.finditer(text))
        ok = got_hit == want_hit
        if not ok:
            failures += 1
        print(f"  {'OK  ' if ok else 'FAIL'} {label}: {'fires' if got_hit else 'silent'}")

    # Refusing vacuity must itself be testable: both corpora must be non-empty.
    docs, rust = len(documents()), len(rust_files())
    ok = docs > 0 and rust > 0
    if not ok:
        failures += 1
    print(f"  {'OK  ' if ok else 'FAIL'} both corpora are non-empty ({docs} docs, {rust} Rust)")

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} case(s) behaved wrongly")
        return 1
    print("SELF-TEST PASSED -- every check is live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--self-test", action="store_true", help="prove the scanner fires")
    args = ap.parse_args()
    return self_test(args) if args.self_test else run(args)


if __name__ == "__main__":
    sys.exit(main())
