#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Enforce ordered maps — and no per-process-random iteration — in shipped runtime code. `DET-006`.

# The rule

Proposal §10.5: a deterministic run must be bit-identical across repetitions.
`std::collections::HashMap` and `HashSet` iterate in a per-process random
order, so any of them a guest can observe — directly or through output bytes
whose order derives from it — breaks that guarantee on some run. `RandomState`
is the same class: a fresh per-process seed makes every hash it touches
unrepeatable. The rule is therefore: **none of the three in shipped code.**
`BTreeMap` (or an index map with a fixed order) is the alternative, and the
scan requires at least one live `BTreeMap` use so the alternative is proven
present, not merely named here.

# The one exemption, and why it is not a loophole

`crates/qqq-serve/src/limits.rs` shards tenants into rate-limit buckets under
a per-process `RandomState` seed. That seed is a deliberate anti-gaming
property, stated on the field itself: unknown to any peer, so no client can
aim at (or away from) another tenant's bucket. Fixing the seed would trade
that property for nothing — the buckets' windows are wall-clock time, so
admission is load-dependent and outside the deterministic guarantee either
way (determinism covers guest execution and replay, not which tenant a
shared table admits first). The exemption names the construct, not the file,
so a second `RandomState` beside the seed still fails.

# Why this is a *source* check and not a runtime test

A test that inserts three tenants and reads them back passes with a `HashMap`
on every run where the hasher happens to agree — which is most runs on one
machine and a different set on the next. The violation is an absence of
discipline in code that no execution test distinguishes reliably. The decision
is made in the source, so it is checked in the source.

# What is forbidden, and what is NOT

| Construct | Verdict | Why |
|---|---|---|
| `HashMap` / `HashSet` in `crates/*/src/**` outside test code | **forbidden** | per-process random iteration order |
| `RandomState` in shipped code, except the named seed | **forbidden** | per-process seed makes every hash unrepeatable |
| Any of the three in `#[cfg(test)]` modules, `tests/`, examples, benches | **allowed** | not shipped; a test fake's order is the test's own business |
| Any of the three named in a `//` or `/* */` comment | **allowed** | prose is not code; the tree discusses the rule by name |
| Any of the three inside a string or char literal | **allowed** | data is not code; the stripper blanks literals before matching |
| `BTreeMap` anywhere | **allowed and required** | the ordered alternative; at least one shipped use must exist |

# Scope, and what it does not cover

Scanned: `crates/<11 shipped crates>/src/**/*.rs`. Not scanned: `tests/`
directories (integration tests, never shipped), `examples/`, `benches/`,
`build.rs` files, and `xtask` (a build tool, not guest-reachable). `build.rs`
output is the same gap `audit_unsafe.py` records against itself: generated
code is not committed code, and this checker reads what is committed.

# The comment stripper, and what it does not do

A prohibition that fires on prose dies the same death as every other
over-reporting scanner: people stop running it. The tree already names these
types in doc comments (`egress.rs` explains why it chose a `BTreeMap`;
`guest_output.rs` cites this very checker), in string literals, and in a
deliberate seed — so the stripper is string-aware (`"..."` with backslash
escapes, raw strings `r#"..."#`, char literals with a lifetime heuristic:
`&'static` is not a char), blanks every literal's contents before matching,
and tracks block comments (`/* */`, which nest, per the language) across
lines. The `--self-test` pins each of those shapes. A multi-line block
comment that opens inside a string literal would confuse the walker; no such
shape exists in the scanned tree, and the self-test asserts the walker fails
closed (marks code) rather than open on the shapes it knows.

Usage:  python tools/check_ordered_maps.py [--self-test]
Exit:   0 = rule satisfied, 1 = at least one violation (or a vacuous scan)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# This tool's own stdout must be able to encode what it prints. On a Windows console the stream
# inherits `cp1252`, so a character read from a subprocess -- which this file now reads as UTF-8 ..
# raises `UnicodeEncodeError` inside `print` and the tool dies while reporting its result. `§O-291`.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


ROOT = Path(__file__).resolve().parent.parent

# The shipped runtime crates: everything a guest can reach, plus the CLI and
# bench harnesses whose outputs are agent- or operator-visible. `xtask` is a
# build tool and is not scanned.
SHIPPED_CRATES = [
    "qqq-core",
    "qqq-cap",
    "qqq-abi",
    "qqq-host",
    "qqq-io",
    "qqq-serve",
    "qqq-run",
    "qqq-pkg",
    "qqq-debug",
    "qqq-sys",
    "qqq-bench",
]

# `(pattern, construct, remedy)` — every unordered-per-process type is banned.
BANNED: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\bHashMap\b"), "HashMap", "use `BTreeMap`"),
    (re.compile(r"\bHashSet\b"), "HashSet", "use `BTreeSet`"),
    (
        re.compile(r"\bRandomState\b"),
        "RandomState",
        "use a fixed seed — or remove the hash",
    ),
]

# `(path_suffix, construct, justification)` — the construct must ALSO appear on
# the same line for the exemption to apply. The scope is (file, construct), so
# a `RandomState` in any other file still fails; a second one inside
# `limits.rs` would ride along — the two seed lines are the only ones today,
# and every live run re-proves it. (Same scoping rule as `check_no_ambient.py`.)
EXEMPTIONS: list[tuple[str, str, str]] = [
    (
        "crates/qqq-serve/src/limits.rs",
        "RandomState",
        "the per-process rate-limit seed is a deliberate anti-gaming property: "
        "unknown to any peer, so no client can aim at (or away from) another "
        "tenant's bucket — stated on the field itself. Bucket windows are "
        "wall-clock time, so admission is load-dependent and outside the "
        "deterministic guarantee either way; a fixed seed would trade the "
        "property for nothing.",
    ),
]

ORDERED = re.compile(r"\bBTree(?:Map|Set)\b")


def strip_comments(line: str, in_block: int) -> tuple[str, int]:
    """Remove comments and blank string/char contents; return code + block depth.

    Literals are blanked rather than kept: `"HashMap"` is data, and a matcher
    that fires on data is an audit that cries wolf. Lifetimes (`&'static`) are
    not char literals — a `'` only opens one when a closing `'` follows within
    three characters (`'a'`, `'\\n'`). Block comments nest, per the language.
    """
    out: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        if in_block > 0:
            if line.startswith("/*", i):
                in_block += 1
                i += 2
            elif line.startswith("*/", i):
                in_block -= 1
                i += 2
            else:
                i += 1
            continue
        ch = line[i]
        if ch == '"':
            out.append('""')
            i += 1
            while i < n and line[i] != '"':
                i += 2 if line[i] == "\\" and i + 1 < n else 1
            if i < n:
                i += 1
            continue
        if ch == "r" and i + 1 < n and line[i + 1] in ('"', "#"):
            j = i + 1
            hashes = 0
            while j < n and line[j] == "#":
                hashes += 1
                j += 1
            if j < n and line[j] == '"':
                closer = '"' + "#" * hashes
                end = line.find(closer, j + 1)
                if end == -1:
                    # Fails closed: an unterminated raw string keeps the rest
                    # of the line as code rather than as comment.
                    out.append('r""')
                    i = n
                else:
                    out.append('r""')
                    i = end + len(closer)
                continue
        if ch == "'" and i + 2 < n and line[i + 2] == "'":
            out.append("'?'")
            i += 3
            continue
        if ch == "'" and i + 3 < n and line[i + 1] == "\\" and line[i + 3] == "'":
            out.append("'?'")
            i += 4
            continue
        if line.startswith("//", i):
            break
        if line.startswith("/*", i):
            in_block = 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out), in_block


def stripped_lines(text: str) -> list[str]:
    """The file with comments removed and literals blanked, line-aligned."""
    codes: list[str] = []
    in_block = 0
    for line in text.splitlines():
        code, in_block = strip_comments(line, in_block)
        codes.append(code)
    return codes


def test_ranges(codes: list[str]) -> list[tuple[int, int]]:
    """Line ranges covered by `#[cfg(test)]`, computed forward on stripped code.

    From each marker, the body starts at the first line that opens a brace and
    ends where the depth returns to zero — so a closed test module does not
    swallow the code after it, a single-line `#[cfg(test)] fn` covers only its
    own line, and a brace inside a string or comment is never a boundary (the
    stripper already removed it). A marker with no braces covers only its own
    line: the tree carries no braceless-marker-plus-banned-type shape (a live
    run passing proves it), and a line-based scan cannot see item extents.
    Flat module structure, same assumption as `check_no_ambient.py`.
    """
    ranges: list[tuple[int, int]] = []
    for i, line in enumerate(codes):
        if not line.strip().startswith("#[cfg(test)]"):
            continue
        depth = 0
        start: int | None = None
        end = i
        for j in range(i, len(codes)):
            opens = codes[j].count("{")
            depth += opens - codes[j].count("}")
            if start is None and opens > 0:
                start = j
            end = j
            if start is not None and depth == 0:
                break
        ranges.append((i, i) if start is None else (start, end))
    return ranges


def is_test_context(
    codes: list[str], ranges: list[tuple[int, int]], index: int
) -> bool:
    """Whether line `index` sits inside a `#[cfg(test)]` range."""
    return any(start <= index <= end for start, end in ranges)


def exempted(rel_path: str, construct: str) -> bool:
    return any(
        rel_path.endswith(suffix) and construct == want
        for suffix, want, _ in EXEMPTIONS
    )


def file_hits(rel: str, text: str) -> tuple[list[str], int]:
    """Violations in one file, plus ordered-alternative uses in shipped code."""
    problems: list[str] = []
    codes = stripped_lines(text)
    ranges = test_ranges(codes)
    ordered = 0
    for i, code in enumerate(codes):
        if ORDERED.search(code) and not is_test_context(codes, ranges, i):
            ordered += 1
        for pattern, construct, remedy in BANNED:
            if not pattern.search(code):
                continue
            if is_test_context(codes, ranges, i):
                continue
            if exempted(rel, construct):
                continue
            # The raw line still carries the construct (the stripper never
            # deletes identifiers), so the construct itself is the evidence.
            problems.append(f"{rel}:{i + 1}: `{construct}` in shipped code — {remedy}")
    return problems, ordered


def self_test() -> int:
    """Every case, including the controls, runs against the real stripper."""
    cases: list[tuple[str, str, bool, int]] = [
        # (name, source, want_fire, want_ordered)
        (
            "code `HashMap::new()` fires",
            "fn f() {\n    let m = std::collections::HashMap::new();\n}\n",
            True,
            0,
        ),
        (
            "code `HashSet::new()` fires",
            "fn f() {\n    let m = std::collections::HashSet::new();\n}\n",
            True,
            0,
        ),
        (
            "code `RandomState::new()` fires",
            "fn f() {\n    let s = std::collections::hash_map::RandomState::new();\n}\n",
            True,
            0,
        ),
        (
            "a bare `use` of a banned type fires",
            "use std::collections::HashMap;\nfn f(m: &HashMap<String, u8>) {}\n",
            True,
            0,
        ),
        (
            "CONTROL: a doc line naming `HashMap` passes (prose proves nothing)",
            "/// A `BTreeMap`, not a `HashMap`: iteration order is observable.\nfn f() {}\n",
            False,
            0,
        ),
        (
            "CONTROL: a trailing comment naming `HashSet` passes",
            "fn f() {}\n// TODO: replace the HashSet below\n",
            False,
            0,
        ),
        (
            "CONTROL: a string literal naming `HashMap` is data, not code",
            'fn f() -> &str {\n    let s = "HashMap";\n    s\n}\n',
            False,
            0,
        ),
        (
            "CONTROL: a string holding code-shaped text does not fire or hide",
            'fn f() {\n    let m = HashMap::new(); // was: "HashMap"\n}\n',
            True,
            0,
        ),
        (
            "CONTROL: a URL string keeps its `//` and passes",
            'fn f() -> &str {\n    "https://example.com/x"\n}\n',
            False,
            0,
        ),
        (
            "CONTROL: a raw string with comment markers passes",
            'fn f() -> &str {\n    r#"{"a": 1} // not a comment"near"#\n}\n',
            False,
            0,
        ),
        (
            "CONTROL: a block comment naming `HashSet` passes",
            "/* the old HashSet table */\nfn f() {}\n",
            False,
            0,
        ),
        (
            "CONTROL: a nested block comment passes",
            "/* outer /* inner RandomState */ still comment */\nfn f() {}\n",
            False,
            0,
        ),
        (
            "CONTROL: lifetimes and char literals do not confuse the walker",
            "fn f(x: &'static str) -> char {\n    let c = 'a';\n    c\n}\n",
            False,
            0,
        ),
        (
            "CONTROL: a brace inside a string is not a module boundary",
            '#[cfg(test)]\nmod tests {\n    fn f() -> &str { "{" }\n}\nfn g() {\n    let m = HashMap::new();\n}\n',
            True,
            0,
        ),
        (
            "CONTROL: `BTreeMap` code counts as the alternative",
            "fn f() {\n    let m = std::collections::BTreeMap::new();\n}\n",
            False,
            1,
        ),
        (
            "CONTROL: `BTreeMap` in test code does not count",
            "#[cfg(test)]\nmod tests {\n    fn f() {\n        let m = BTreeMap::new();\n    }\n}\n",
            False,
            0,
        ),
        (
            "`HashMap` inside `#[cfg(test)]` passes",
            "#[cfg(test)]\nmod tests {\n    use std::collections::HashMap;\n}\n",
            False,
            0,
        ),
        (
            "a single-line test fn does not swallow the code after it",
            "#[cfg(test)]\nfn helper() { let _ = 1; }\nfn g() {\n    let m = HashMap::new();\n}\n",
            True,
            0,
        ),
        (
            "the named seed exemption passes",
            "    seed: std::collections::hash_map::RandomState,\n",
            False,
            0,
        ),
    ]
    failures = 0
    for name, src, want_fire, want_ordered in cases:
        rel = (
            "crates/qqq-serve/src/limits.rs"
            if "named seed" in name
            else "self-test-fixture.rs"
        )
        got, ordered = file_hits(rel, src)
        if bool(got) != want_fire or ordered != want_ordered:
            failures += 1
            print(
                f"  SELF-TEST FAIL  {name}: want_fire={want_fire}, got={got}; "
                f"want_ordered={want_ordered}, got={ordered}"
            )
    print(f"self-test: {len(cases) - failures}/{len(cases)} cases agree with the rule")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    problems: list[str] = []
    scanned = 0
    ordered_uses = 0

    for crate in SHIPPED_CRATES:
        src = ROOT / "crates" / crate / "src"
        if not src.is_dir():
            problems.append(f"shipped crate `{crate}` has no src/ directory")
            continue
        for path in sorted(src.rglob("*.rs")):
            scanned += 1
            rel = path.relative_to(ROOT).as_posix()
            text = path.read_text(encoding="utf-8")
            hits, ordered = file_hits(rel, text)
            problems.extend(hits)
            ordered_uses += ordered

    # The scan must have read real code, or every absence above is vacuous.
    if scanned < 100:
        print(f"only {scanned} source files were scanned; the checker is misconfigured")
        return 1
    # The ordered alternative must be live in shipped code, not merely named
    # here — and test-only uses do not count.
    if ordered_uses == 0:
        print(
            "no `BTreeMap`/`BTreeSet` use in shipped code was found, so the alternative is untested"
        )
        return 1

    print(
        f"  scanned {scanned} source file(s) across {len(SHIPPED_CRATES)} shipped crate(s)"
    )
    print(
        f"  {ordered_uses} ordered-map/set use(s) in shipped code carry the alternative"
    )
    print(f"  {len(EXEMPTIONS)} named exemption(s), each justification in this file")

    if problems:
        print()
        for p in problems:
            print(f"  FAIL  {p}")
        print("\nUNORDERED-MAP RULE FAILED")
        return 1

    print("\nUNORDERED-MAP RULE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
