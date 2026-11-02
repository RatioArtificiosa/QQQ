#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Every host entry point is panic-contained or panic-free (`HOST-011` gap H1).

Bindgen `impl Host for StoreData` trait methods return the WIT `result`
directly — the generated trait shape has no host-fault case — so they cannot
be wrapped in `guard::guard` (which returns `wasmtime::Result`) without lying
about the error. The property the tree relies on instead is: **these bodies
never panic**, and the unwinding that would escape through Wasmtime's frames
(`panic = "abort"` in ship profiles kills the whole process, `F-01`) cannot
start there.

Clippy's `unwrap_used` / `expect_used` / `indexing_slicing` (workspace `warn`,
denied in CI via `-D warnings`) is the first line of defence. This tool is
the second: it fails CI the moment a panicking primitive is introduced into a
host entry point by an edit no test exercises — including behind an
`#[allow(clippy::...)]` the lints would honor and this tool does not.

# What is checked

For every `impl <Trait> for [crate::linker::]StoreData` block and every
`func_wrap(` closure in `crates/qqq-host/src/host_*.rs`, the body must
satisfy at least one of:

1. it reaches `guard::guard(` (containment: a panic becomes a trap, `HOST-011`), or
2. it contains no panicking primitive: `.unwrap(`, `.expect(`, `panic!`,
   `unreachable!`, `todo!`, `unimplemented!`, `assert!`, `assert_eq!`,
   `assert_ne!`, `debug_assert!`.

`unwrap_or` / `unwrap_or_else` / `unwrap_or_default` are not flagged: the
match requires the open paren. Indexing (`a[i]`) is left to clippy's
`indexing_slicing`, which parses types; a bracket matcher cannot tell
indexing from array types.

# What is NOT covered, and why that is stated here

*Test code may panic.* `#[cfg(test)] mod ...` blocks, `#[test]` functions,
anything under `tests/`, and doc-comment lines are exempt. `host_test.rs`
(the `qqq:test/assertions` harness) is checked like every other host module:
its six closures refuse without state, and refusal must not panic either.
*WASI `add_to_linker_sync` internals* are wasmtime's code, not ours; the
grant-gated shims in `host_wasi.rs` (which shadow the stock `wasi:random`)
are ours and are checked.

Usage:
    python tools/check_no_panic_in_host_impls.py
    python tools/check_no_panic_in_host_impls.py --self-test
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# This tool's own stdout must be able to encode what it prints. On a Windows
# console the stream inherits `cp1252`, so text read as UTF-8 raises
# `UnicodeEncodeError` inside `print` and the tool dies while reporting its
# result.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass

# `impl Trait for StoreData` / `impl Trait for crate::linker::StoreData`.
# Generic params (`impl<T>`) are not used on these blocks today; the pattern
# allows them so a future generic impl is checked rather than skipped.
IMPL_RE = re.compile(
    r"^\s*impl\s*(?:<[^>]*>\s*)?\w[\w:]*\s+for\s+(?:crate::linker::)?StoreData\s*[{<]",
    re.MULTILINE,
)
FUNC_WRAP_RE = re.compile(r"\bfunc_wrap\s*\(\s*\"", re.MULTILINE)
GUARD_RE = re.compile(r"\bguard::guard\s*\(")
PANIC_RE = re.compile(
    r"\.(?:unwrap|expect)\s*\(|"
    r"\b(?:panic|unreachable|todo|unimplemented)\s*!|"
    r"\b(?:debug_assert|assert(?:_eq|_ne)?)\s*!"
)
CFG_TEST_MOD_RE = re.compile(r"^\s*#\[cfg\(test\)\]\s*\n\s*mod\s+\w+", re.MULTILINE)
TEST_FN_RE = re.compile(
    r"^\s*#\[test\]\s*\n(?:^\s*#\[[^\]]*\]\s*\n)*\s*fn\s+", re.MULTILINE
)
FN_RE = re.compile(r"\bfn\s+\w+", re.MULTILINE)
DOC_RE = re.compile(r"^\s*///|^//!")


def _strip_text(text: str) -> str:
    """Blank strings, chars, and comments, keeping newlines: brace matching
    below must not count braces inside literals."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            out.append("  ")
            i += 2
        elif c == '"':
            out.append(" ")
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    out.append("  ")
                    i += 2
                else:
                    out.append("\n" if text[i] == "\n" else " ")
                    i += 1
            out.append(" ")
            i += 1
        elif c == "'":
            rest = text[i:]
            lit = re.match(r"'(\\u\{[0-9a-fA-F]+\}|\\.|[^'\\])'", rest)
            if lit:
                out.append(" " * len(lit.group(0)))
                i += len(lit.group(0))
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _match_brace(stripped: str, open_pos: int) -> int:
    """Index just past the brace matching the `{` at `open_pos`."""
    depth = 0
    for i in range(open_pos, len(stripped)):
        if stripped[i] == "{":
            depth += 1
        elif stripped[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(stripped)


def test_regions(text: str) -> list[tuple[int, int]]:
    """`(start, end)` char ranges of test-only regions."""
    stripped = _strip_text(text)
    regions = []
    for m in CFG_TEST_MOD_RE.finditer(text):
        open_pos = stripped.find("{", m.end())
        if open_pos != -1:
            regions.append((m.start(), _match_brace(stripped, open_pos)))
    for m in TEST_FN_RE.finditer(text):
        open_pos = stripped.find("{", m.end())
        if open_pos != -1:
            regions.append((m.start(), _match_brace(stripped, open_pos)))
    return regions


def in_regions(pos: int, regions: list[tuple[int, int]]) -> bool:
    return any(s <= pos < e for s, e in regions)


def entry_spans(text: str) -> list[tuple[int, int, str]]:
    """`(start, end, kind)` for every host entry point: bindgen impl blocks
    and `func_wrap` closures, brace-matched on stripped text."""
    stripped = _strip_text(text)
    spans = []
    for m in IMPL_RE.finditer(text):
        open_pos = stripped.find("{", m.end() - 1)
        if open_pos != -1:
            spans.append((m.start(), _match_brace(stripped, open_pos), "impl"))
    for m in FUNC_WRAP_RE.finditer(text):
        # The closure body is the first `{` after the `func_wrap("name",`
        # that is not inside a string; stripped text makes it visible.
        open_pos = stripped.find("{", m.end())
        if open_pos != -1:
            spans.append((m.start(), _match_brace(stripped, open_pos), "func_wrap"))
    return spans


def host_files(root: Path) -> list[Path]:
    """The H1 surface: `crates/qqq-host/src/host_*.rs`."""
    return sorted((root / "crates" / "qqq-host" / "src").glob("host_*.rs"))


def check_tree(root: Path) -> list[str]:
    problems = []
    files = host_files(root)
    if not files:
        return ["no host_*.rs files found — the scan agreed with nothing"]
    for path in files:
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        stripped = _strip_text(text)
        regions = test_regions(text)
        lines = text.splitlines()
        for start, end, kind in entry_spans(text):
            if in_regions(start, regions):
                continue
            body = text[start:end]
            # Match against the comment/string-blanked body: a mention of a
            # primitive in prose (or a doctest-shaped example) is not a call.
            # Offsets are preserved (only newlines survive), so positions and
            # line numbers still refer to the original text.
            clean = stripped[start:end]
            if GUARD_RE.search(clean):
                continue
            for m in PANIC_RE.finditer(clean):
                pos = start + m.start()
                if in_regions(pos, regions):
                    continue
                lineno = text.count("\n", 0, pos) + 1
                if DOC_RE.match(lines[lineno - 1]):
                    continue
                problems.append(
                    f"{rel}:{lineno}: {kind} body reaches `{m.group(0).strip()}` "
                    f"without `guard::guard` containment"
                )
    return problems


def self_test() -> int:
    import shutil
    import tempfile

    cases: list[tuple[str, bool, str]] = []
    clean = check_tree(ROOT)
    cases.append(("the real tree is clean", not clean, f"{clean[:1]}"))

    def fires(name: str, watched: str, mutate, want: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "r"
            sandbox.mkdir()
            shutil.copytree(ROOT / "crates", sandbox / "crates")
            watch = sandbox / "crates" / "qqq-host" / "src" / watched
            before = watch.read_text(encoding="utf-8")
            mutate(sandbox)
            after = watch.read_text(encoding="utf-8")
            assert after != before, f"mutation for {name!r} did not apply"
            found = check_tree(sandbox)
        hit = [p for p in found if want in p]
        cases.append(
            (name, bool(hit), hit[0] if hit else f"NO {want} RAISED (got {found[:1]})")
        )

    def add_unwrap_to_impl(sandbox: Path) -> None:
        p = sandbox / "crates" / "qqq-host" / "src" / "host_env.rs"
        t = p.read_text(encoding="utf-8")
        anchor = "Ok((String::from_utf8(bytes).map_err(|_| WitEnvError::InvalidUtf8),))"
        assert anchor in t, "host_env.rs lost its anchor"
        t = t.replace(
            anchor,
            "Ok((String::from_utf8(bytes).map_err(|_| WitEnvError::InvalidUtf8).unwrap(),))",
            1,
        )
        # The injected unwrap sits in a guard-wrapped body, so strip the
        # guard to test the uncontained path the checker exists for.
        t = t.replace('crate::guard::guard("qqq:env/environment.get", || {', "|| {", 1)
        p.write_text(t, encoding="utf-8")

    fires(
        "an unwrap in an unguarded impl body is reported",
        "host_env.rs",
        add_unwrap_to_impl,
        "without `guard::guard` containment",
    )

    def add_unreachable_to_wrap(sandbox: Path) -> None:
        p = sandbox / "crates" / "qqq-host" / "src" / "host_wasi03.rs"
        t = p.read_text(encoding="utf-8")
        anchor = "Ok((store.data().ambient.tick_interval_nanos(),))"
        assert anchor in t, "host_wasi03.rs lost its anchor"
        t = t.replace(anchor, 'unreachable!("must not happen")', 1)
        t = t.replace(
            'crate::guard::guard("wasi:clocks@0.3.2/monotonic-clock.get-resolution", || {',
            "|| {",
            1,
        )
        p.write_text(t, encoding="utf-8")

    fires(
        "an unreachable in an unguarded func_wrap body is reported",
        "host_wasi03.rs",
        add_unreachable_to_wrap,
        "without `guard::guard` containment",
    )

    def guarded_body_is_exempt(sandbox: Path) -> None:
        # A panic primitive inside a guard-wrapped body stays silent: the
        # guard contains it, so the checker must not fire.
        p = sandbox / "crates" / "qqq-host" / "src" / "host_env.rs"
        t = p.read_text(encoding="utf-8")
        anchor = "Ok((String::from_utf8(bytes).map_err(|_| WitEnvError::InvalidUtf8),))"
        assert anchor in t, "host_env.rs lost its anchor"
        t = t.replace(
            anchor,
            "Ok((String::from_utf8(bytes).map_err(|_| WitEnvError::InvalidUtf8).unwrap(),))",
            1,
        )
        p.write_text(t, encoding="utf-8")
        found = check_tree(sandbox)
        assert not found, f"guarded body must stay silent, got {found[:1]}"

    with tempfile.TemporaryDirectory() as tmp:
        sandbox = Path(tmp) / "r"
        sandbox.mkdir()
        shutil.copytree(ROOT / "crates", sandbox / "crates")
        try:
            guarded_body_is_exempt(sandbox)
            cases.append(("a guarded body stays silent", True, ""))
        except AssertionError as e:
            cases.append(("a guarded body stays silent", False, str(e)))

    failed = [name for name, ok, _ in cases if not ok]
    for name, ok, detail in cases:
        print(f"{'ok' if ok else 'FAIL'}: {name}" + (f" — {detail}" if not ok else ""))
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    problems = check_tree(ROOT)
    for p in problems:
        print(p)
    if problems:
        print(f"{len(problems)} panic-containment violation(s) in host entry points")
        return 1
    print(
        f"checked {len(host_files(ROOT))} host modules: every entry point is guarded or panic-free"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
