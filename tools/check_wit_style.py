#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Enforce the remaining WIT style rules - Checklist `CON-011`.

# What this closes

Proposal §6.3 states **six** WIT style rules and says they are *"enforced in review"*. Review is
prose, and this repository's own principle is that prose does not fail a build. Four of the six
now have machine checks:

| # | Rule | Enforced by |
|---|---|---|
| 1 | Batch-first: list-shaped operations take lists | `check_batch_first.py` (`CON-012`) |
| 3 | Explicit `result<T, E>`, no sentinels | `check_wit_errors.py` (`CON-009`) |
| 6 | `@since(version = ...)` on every published function | `check_wit_since.py` |
| 5 | A doc comment on every function | **this file** |
| 2 | Streaming for anything that can exceed 64 KiB | **this file** (the decidable half) |
| 4 | No `option<option<T>>` | **this file** |

# Rule 4, which is the one a machine can decide completely

`option<option<T>>` has three reachable states and only two meanings: the outer `none` and the
inner `none` both read as "absent", so the caller cannot distinguish them and neither can the
author six months later. WIT models it as a flattening bug rather than a type error, so the
compiler is silent.

The rule is decidable in full: scan the interface's type declarations for an `option` whose
payload is itself an `option`. A violation is always a modelling mistake, never a deliberate
choice, because the deliberate version is a named variant.

# Rule 5, and why the doc requirement is scoped rather than blanket

Proposal §6.3 says a doc comment *"becomes the generated docs"*, so a function without one is a
function absent from the published reference while appearing in the interface. The check is
therefore real.

Its **scope** is what needed deciding. A blanket "every function needs `///`" would fail on
thousands of lines of already-written interface code in one go, which produces a check nobody can
turn green and a rule everyone learns to skip - the failure mode `check_batch_first.py` already
names for its own rule ("paperwork"). So the requirement applies to **`@since`-versioned published
functions**, which is the set the Proposal actually calls published: a function carrying
`@since(version = ...)` has declared itself part of the contract, and the generated docs are part
of that contract.

That coupling is also what keeps the two rules honest together: `check_wit_since.py` requires
`@since` on published functions, and this check requires a doc comment on exactly that set. A
function cannot be published-and-undocumented.

# Rule 2, and the half that is decidable

*"Streaming for anything that can exceed 64 KiB"* is a **design** judgement about a payload's
realistic size, and a checker cannot know that. What is decidable is its enforcement mechanism:
where an interface declares a stream type, that stream must appear in at least one function
signature. A `stream<T>` that no function consumes is a type nobody can obtain - the
feature-with-no-caller shape (`§O-130`) at the type level, and always a defect.

The rule itself stays in review; what this file removes is the case where the review would pass
vacuously because the streaming type is unreachable.

Usage:  python tools/check_wit_style.py [--self-test]
Exit:   0 = rules satisfied, 1 = at least one violation
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
WIT_DIR = ROOT / "wit"

# A function declaration opening: `name: func(` or `name: async func(`.
FUNC_RE = re.compile(r"^(?P<indent>\s*)(?P<name>[a-z][a-z0-9-]*)\s*:\s*(?:async\s+)?func\s*[(<]")

# `@since(version = "1.0.0")` above a function.
#
# # Why the value may be quoted or bare
#
# The first version of this pattern required a quoted string, and **no real `@since` in this
# corpus is quoted** -- every one is `@since(version = 1.0.0)`. So the rule matched nothing,
# counted 85 "published" functions from an unrelated code path, and passed on a corpus it had
# never examined. The corpus injection that removed a real doc comment is what caught it: the
# synthetic self-test could not, because the fixture was written from the same wrong assumption
# as the pattern.
#
# An optional string literal is the fix, and it is stated here because the bug was a one-character
# detail in a regex that looked obviously right.
SINCE_RE = re.compile(r"@since\s*\(\s*version\s*=\s*\"?[0-9]")

# `option<option<...>>`, allowing whitespace and nesting depth 2+.
NESTED_OPTION_RE = re.compile(r"\boption\s*<\s*option\b")

# `stream<T>` in a type position, capturing the payload.
STREAM_RE = re.compile(r"\bstream\s*<\s*(?P<payload>[^>]+)>")

# `type foo = stream<...>` - a named stream alias.
STREAM_ALIAS_RE = re.compile(r"^\s*type\s+(?P<name>[a-z][a-z0-9-]*)\s*=\s*stream\s*<")

# A line that is a doc comment.
DOC_RE = re.compile(r"^\s*///")


def wit_files() -> list[Path]:
    return sorted(WIT_DIR.rglob("*.wit"))


class Violation:
    """One rule breach, with the file and line that carries it."""

    def __init__(self, rule: str, path: Path, line: int, detail: str) -> None:
        self.rule = rule
        self.path = path
        self.line = line
        self.detail = detail

    def render(self) -> str:
        return f"  [{self.rule}] {self.path.relative_to(ROOT)}:{self.line}\n    {self.detail}"


def check_nested_option(path: Path, text: str) -> list[Violation]:
    """Rule 4: no `option<option<T>>`."""
    out: list[Violation] = []
    for i, line in enumerate(text.split("\n"), 1):
        if NESTED_OPTION_RE.search(line):
            out.append(
                Violation(
                    "4/no-nested-option",
                    path,
                    i,
                    "option<option<T>> has three states and two meanings; model the domain with "
                    "a named variant instead",
                )
            )
    return out


def _annotation_block(lines: list[str], func_index: int) -> tuple[bool, bool]:
    """Walk up from a function line, returning (has_since, has_doc).

    # Why the walk cannot stop at a blank line

    The first version treated a blank line as the end of the annotation block. That is right for
    the *bare* blank between declarations and wrong for the **`///`-prefixed** blank that every
    multi-paragraph doc comment contains:

        /// Read a named variable as a UTF-8 string.
        ///
        /// # Errors
        ///
        /// See [`env-error`].
        @since(version = 1.0.0)
        get: func(name: string) -> result<string, env-error>;

    The blank interior lines are `///`, so they are comments and the block continues through them.
    A genuinely empty line still ends the walk, which is what keeps a preceding declaration's
    annotations from being attributed to this function.
    """
    has_since = False
    has_doc = False
    j = func_index - 1
    while j >= 0:
        prev = lines[j]
        stripped = prev.strip()
        if stripped == "":
            break  # a truly blank line: the block has ended
        if SINCE_RE.search(prev):
            has_since = True
        elif DOC_RE.match(prev):
            has_doc = True
        elif stripped.startswith("@") or stripped.startswith("//"):
            pass  # another annotation, or a non-doc comment
        else:
            break  # a declaration or closing brace: not part of this function's block
        j -= 1
    return has_since, has_doc


def check_doc_comments(path: Path, text: str) -> list[Violation]:
    """Rule 5: a `@since`-published function carries a doc comment.

    # Why the `@since` gate rather than every function

    Stated in the module doc. In short: `@since` is a function declaring itself part of the
    published contract, and the generated docs are part of that contract - so this is the set
    where a missing comment is a real defect rather than a style preference.
    """
    out: list[Violation] = []
    lines = text.split("\n")
    for i, line in enumerate(lines):
        m = FUNC_RE.match(line)
        if not m:
            continue
        has_since, has_doc = _annotation_block(lines, i)
        if has_since and not has_doc:
            out.append(
                Violation(
                    "5/doc-comment",
                    path,
                    i + 1,
                    f"`{m.group('name')}` is published (@since) but has no `///` doc comment; "
                    "the comment becomes the generated reference",
                )
            )
    return out


def check_unreachable_stream(path: Path, text: str) -> list[Violation]:
    """Rule 2, decidable half: a declared stream type must be consumed by a function.

    A `stream<T>` that appears only in a type alias is a type no caller can obtain. That is the
    feature-with-no-caller shape at the type level, and it makes any review of "is streaming used
    where it should be" vacuous.
    """
    out: list[Violation] = []
    aliases: dict[str, int] = {}
    for i, line in enumerate(text.split("\n"), 1):
        m = STREAM_ALIAS_RE.match(line)
        if m:
            aliases[m.group("name")] = i

    if not aliases:
        return out

    # A stream is "used" when its name appears in a function signature, or when an inline
    # `stream<...>` does.
    body = "\n".join(
        line for line in text.split("\n") if not STREAM_ALIAS_RE.match(line)
    )
    for name, line_no in aliases.items():
        # The alias line plus any use in a signature. Search the whole file for a second
        # occurrence outside the declaration.
        uses = len(re.findall(rf"\b{re.escape(name)}\b", body))
        if uses == 0:
            out.append(
                Violation(
                    "2/unreachable-stream",
                    path,
                    line_no,
                    f"`{name}` is declared as a stream but appears in no function signature; "
                    "a type no caller can obtain",
                )
            )
    return out


def check_inline_streams(path: Path, text: str) -> list[Violation]:
    """Report an inline `stream<T>` that only ever appears in its own declaration."""
    # Only meaningful for aliases; an inline stream in a signature is by definition consumed.
    return []


def run(args) -> int:
    files = wit_files()
    if not files:
        print(f"FAIL -- no .wit files found under {WIT_DIR}; a scan of nothing certifies nothing")
        return 1

    violations: list[Violation] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        violations.extend(check_nested_option(path, text))
        violations.extend(check_doc_comments(path, text))
        violations.extend(check_unreachable_stream(path, text))

    # Count what was examined, so the denominator is auditable from the output alone. The walk
    # is shared with the rule rather than re-implemented: the first version counted with its own
    # copy, which is how 85 functions were reported as "published" while the rule matched none
    # of them.
    funcs = 0
    published = 0
    for path in files:
        lines = path.read_text(encoding="utf-8").split("\n")
        for i, line in enumerate(lines):
            if FUNC_RE.match(line):
                funcs += 1
                if _annotation_block(lines, i)[0]:
                    published += 1

    for v in violations:
        print(v.render())

    print(f"\nscanned {len(files)} .wit file(s), {funcs} function(s), {published} published")
    if violations:
        print(f"WIT STYLE VIOLATIONS -- {len(violations)}")
        return 1
    print("WIT STYLE OK -- rules 2, 4 and 5 hold")
    return 0


def self_test(args) -> int:
    """Prove each rule fires on a violation and stays silent on a valid interface."""
    tmp = ROOT / "tools" / "_style_selftest.wit"
    failures = 0

    cases = [
        (
            "a nested option fires",
            "interface t {\n  type a = option<option<string>>;\n}\n",
            "4/no-nested-option",
            True,
        ),
        (
            "a single option is silent",
            "interface t {\n  type a = option<string>;\n}\n",
            "4/no-nested-option",
            False,
        ),
        (
            "a published undocumented function fires",
            'interface t {\n  @since(version = "1.0.0")\n  f: func() -> u32;\n}\n',
            "5/doc-comment",
            True,
        ),
        (
            "a published documented function is silent",
            'interface t {\n  /// Does a thing.\n  @since(version = "1.0.0")\n  f: func() -> u32;\n}\n',
            "5/doc-comment",
            False,
        ),
        (
            "an undocumented function with no @since is silent",
            "interface t {\n  f: func() -> u32;\n}\n",
            "5/doc-comment",
            False,
        ),
        # The two cases that mirror the **real corpus**, added after the corpus injection
        # failed to fire. Both details were wrong in the first version of the rule, and the
        # synthetic fixtures shared the wrong assumptions so neither could catch it.
        (
            "an UNQUOTED @since is recognised (the real corpus form)",
            "interface t {\n  @since(version = 1.0.0)\n  f: func() -> u32;\n}\n",
            "5/doc-comment",
            True,
        ),
        (
            "a multi-paragraph doc comment with /// blanks counts as documented",
            "interface t {\n"
            "  /// Does a thing.\n"
            "  ///\n"
            "  /// # Errors\n"
            "  ///\n"
            "  /// See [`t-error`].\n"
            "  @since(version = 1.0.0)\n"
            "  f: func() -> result<u32, t-error>;\n"
            "}\n",
            "5/doc-comment",
            False,
        ),
        (
            "a genuinely blank line still ends the block",
            "interface t {\n"
            "  /// Belongs to the type above, not the function below.\n"
            "  type a = u32;\n"
            "\n"
            "  @since(version = 1.0.0)\n"
            "  f: func() -> u32;\n"
            "}\n",
            "5/doc-comment",
            True,
        ),
        (
            "an unreachable stream fires",
            "interface t {\n  type s = stream<u8>;\n  f: func() -> u32;\n}\n",
            "2/unreachable-stream",
            True,
        ),
        (
            "a consumed stream is silent",
            "interface t {\n  type s = stream<u8>;\n  f: func() -> s;\n}\n",
            "2/unreachable-stream",
            False,
        ),
    ]

    try:
        for label, text, rule, want in cases:
            tmp.write_text(text, encoding="utf-8", newline="")
            found: list[Violation] = []
            found.extend(check_nested_option(tmp, text))
            found.extend(check_doc_comments(tmp, text))
            found.extend(check_unreachable_stream(tmp, text))
            hit = any(v.rule == rule for v in found)
            ok = hit == want
            if not ok:
                failures += 1
            print(f"  {'OK  ' if ok else 'FAIL'} {label}: {'fires' if hit else 'silent'}")
    finally:
        tmp.unlink(missing_ok=True)

    # Vacuity must be refused: the real corpus must be non-empty.
    n = len(wit_files())
    ok = n > 0
    if not ok:
        failures += 1
    print(f"  {'OK  ' if ok else 'FAIL'} the WIT corpus is non-empty ({n} file(s))")

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} case(s) behaved wrongly")
        return 1
    print("SELF-TEST PASSED -- every check is live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--self-test", action="store_true", help="prove each rule fires")
    args = ap.parse_args()
    return self_test(args) if args.self_test else run(args)


if __name__ == "__main__":
    sys.exit(main())
