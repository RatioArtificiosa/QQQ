#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Forbid poison-fragile locks and panicking `Drop`s (`F-21`).

A `std::sync::Mutex` poisoned by a panicking holder wedges every later
`.lock().expect(...)` — including inside `Drop`, where a panic during
unwinding aborts the process even with unwinding enabled (`F-01`). The
production rule is therefore twofold, and this tool checks both halves
where the decision is made, in the source:

1. No `.lock().expect(` / `.lock().unwrap(` in non-test code — across line
   breaks too, because the call chain is usually split over three lines.
   Locks whose state is panic-free between statements use `lock_recover()`
   (see `qqq-core::sync`); the audit chain head and multi-field invariants
   fail closed with a `QQQ-` code instead. Either way, never `expect`.
2. No `.expect(` / `.unwrap(` / `assert!` inside `impl Drop for` bodies in
   non-test code, generic implementations included. A `Drop` runs during
   unwinding; anything there that can panic is a double-panic abort waiting
   for its first unwind.

# What is NOT covered, and why that is stated here

*Test code may panic.* Test regions — `#[cfg(test)] mod ...` blocks (brace
matched, wherever they sit in the file), `#[test]` functions, anything under
`tests/`, and any `///` or `//!` doc-comment line (doctests are tests) — are
exempt. Forbidding panics in tests would push authors toward silent paths.
*Indexing* (`state[0]`) inside `Drop` is hand-audited per change, not
checked here: no `Drop` in the tree indexes today, and a bracket matcher
cannot tell indexing from array types without a real parser.

Usage:
    python tools/check_no_poison_expect.py
    python tools/check_no_poison_expect.py --self-test
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# This tool's own stdout must be able to encode what it prints. On a Windows
# console the stream inherits `cp1252`, so a variant name read as UTF-8 raises
# `UnicodeEncodeError` inside `print` and the tool dies while reporting its
# result. `§O-291`.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass

LOCK_RE = re.compile(r"\.lock\(\)\s*\.\s*(expect|unwrap)\s*\(")
BOUND_RE = re.compile(r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]*?\.lock\(\s*\))")
BOUND_USE_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(expect|unwrap)\s*\(")
DROP_RE = re.compile(r"^\s*impl\s*(<[^>]*>)?\s*Drop\s+for\s+(\S+)", re.MULTILINE)
DROP_BODY_RE = re.compile(r"\.(expect|unwrap)\(|assert!\(|assert_eq!\(|assert_ne!\(|panic!\(")
POISON_RE = re.compile(r"not poisoned")
CFG_TEST_MOD_RE = re.compile(r"^\s*#\[cfg\(test\)\]\s*\n\s*mod\s+\w+", re.MULTILINE)
TEST_FN_RE = re.compile(r"^\s*#\[test\]\s*\n(?:^\s*#\[[^\]]*\]\s*\n)*\s*fn\s+", re.MULTILINE)
DOC_RE = re.compile(r"^\s*///|^//!")


def _strip_text(text: str) -> str:
    """Blank strings, chars, and comments, keeping newlines: brace matching
    below must not count braces inside literals (`eprintln!("...{...}")`)."""
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
            # A lifetime (`&'a`, `MutexGuard<'_, T>`) is not a literal: only
            # `'x'`, `'\e'`, and `'\u{...}'` open char literals. Treating every
            # quote as a literal would swallow newlines up to some far-away
            # quote and shift every line number after it.
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
    # Raw strings (r#"..."#) are rare in this tree; a brace inside one would
    # miscount. The self-test pins one such case below.
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
    """`(start, end)` char ranges of test-only regions: `#[cfg(test)] mod`
    blocks (wherever they sit — production code after one is still checked)
    and `#[test]` functions."""
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


def production_text(path: Path) -> tuple[str, list[tuple[int, int]]]:
    """Full file text plus test-region ranges; doc lines are filtered by the
    caller (they are single lines, so a line test suffices for them)."""
    return path.read_text(encoding="utf-8"), test_regions(
        path.read_text(encoding="utf-8")
    )


def drop_spans(text: str) -> list[tuple[int, int, str]]:
    """`(start, end, name)` char ranges of `impl Drop for` bodies (generic
    implementations included), brace-matched on stripped text."""
    stripped = _strip_text(text)
    spans = []
    for m in DROP_RE.finditer(text):
        open_pos = stripped.find("{", m.end())
        if open_pos == -1:
            continue
        spans.append((m.start(), _match_brace(stripped, open_pos), m.group(2)))
    return spans


def source_files(root: Path) -> list[Path]:
    """Every production-candidate Rust file: under a `src/` dir, never under
    `tests/` (integration tests are test code) and never under `target/`."""
    return sorted(
        {
            p
            for p in (root / "crates").rglob("*.rs")
            if "/src/" in p.relative_to(root).as_posix()
            and "/tests/" not in p.relative_to(root).as_posix()
            and "/target/" not in p.relative_to(root).as_posix()
        }
    )


def check_tree(root: Path) -> list[str]:
    problems = []
    files = source_files(root)
    if not files:
        return ["no Rust source files found under crates/ — the scan agreed with nothing"]
    for path in files:
        rel = path.relative_to(root).as_posix()
        text, regions = production_text(path)
        lines = text.splitlines()
        # Multiline-aware lock scan over the whole text; report the `.lock()`
        # line so the location stays precise across the break.
        for m in LOCK_RE.finditer(text):
            if in_regions(m.start(), regions):
                continue
            lineno = text.count("\n", 0, m.start()) + 1
            if DOC_RE.match(lines[lineno - 1]):
                continue
            problems.append(f"{rel}:{lineno}: lock().expect/unwrap in non-test code")
        # A `LockResult` bound to a name and expected later panics exactly
        # like the chained form — the binding only moves the panic. Track
        # `let name = <expr>.lock()` (without an inline expect, which the
        # pass above already covers) and flag `.expect(`/`.unwrap(` on the
        # name. Propagations (`map_err(...)?`, `.ok()`) are not flagged:
        # only the panicking calls are.
        bound: dict[str, int] = {}
        for m in BOUND_RE.finditer(text):
            if in_regions(m.start(), regions):
                continue
            name, rhs = m.group(1), m.group(2)
            if name == "_" or ".expect(" in rhs or ".unwrap(" in rhs:
                continue
            bound.setdefault(name, text.count("\n", 0, m.start()) + 1)
        for m in BOUND_USE_RE.finditer(text):
            if in_regions(m.start(), regions):
                continue
            name = m.group(1)
            if name not in bound:
                continue
            lineno = text.count("\n", 0, m.start()) + 1
            if DOC_RE.match(lines[lineno - 1]):
                continue
            problems.append(
                f"{rel}:{lineno}: bound lock result expected/unwrapped "
                f"(bound at :{bound[name]}) in non-test code"
            )
        for m in POISON_RE.finditer(text):
            if in_regions(m.start(), regions):
                continue
            lineno = text.count("\n", 0, m.start()) + 1
            if DOC_RE.match(lines[lineno - 1]):
                continue
            # A lock().expect line already reported above carries its own
            # 'not poisoned' message; report the string only when it stands
            # alone, so each violation yields exactly one diagnostic.
            window = text[max(0, m.start() - 120):m.start()]
            if ".lock()" in window:
                continue
            problems.append(f"{rel}:{lineno}: 'not poisoned' in non-test code")
        for start, end, name in drop_spans(text):
            if in_regions(start, regions):
                continue
            for m in DROP_BODY_RE.finditer(text, start, end):
                lineno = text.count("\n", 0, m.start()) + 1
                if DOC_RE.match(lines[lineno - 1]):
                    continue
                problems.append(
                    f"{rel}:{lineno}: panicking call inside `impl Drop for {name}`"
                )
    return problems


def self_test() -> int:
    import shutil
    import tempfile

    cases: list[tuple[str, bool, str]] = []
    clean = check_tree(ROOT)
    cases.append(("the real tree is clean", not clean, f"{clean[:1]}"))

    def before_tests(sandbox: Path) -> tuple[Path, str, int]:
        """The pool.rs copy plus the `#[cfg(test)]` split point, guarded:
        a mutation anchored on a marker that is absent, or one that leaves
        the file unchanged, fails the self-test instead of testing nothing."""
        p = sandbox / "crates" / "qqq-host" / "src" / "pool.rs"
        t = p.read_text(encoding="utf-8")
        cut = t.find("#[cfg(test)]")
        assert cut != -1, "pool.rs lost its #[cfg(test)] marker"
        return p, t, cut

    def fires(name: str, mutate, want: str, watched: str = "pool.rs") -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "r"
            sandbox.mkdir()
            shutil.copytree(ROOT / "crates", sandbox / "crates")
            watch = sandbox / "crates" / "qqq-host" / "src" / watched
            before = watch.read_text(encoding="utf-8") if watch.exists() else None
            mutate(sandbox)
            after = watch.read_text(encoding="utf-8") if watch.exists() else None
            assert after != before, f"mutation for {name!r} did not apply"
            found = check_tree(sandbox)
        hit = [p for p in found if want in p]
        cases.append((name, bool(hit), hit[0] if hit else f"NO {want} RAISED (got {found[:1]})"))

    def add_lock_expect(sandbox: Path) -> None:
        p, t, cut = before_tests(sandbox)
        p.write_text(
            t[:cut] + 'fn injected() { let g = m.lock().expect("must not deadlock"); }\n' + t[cut:],
            encoding="utf-8",
        )

    fires(
        "a lock().expect in non-test code is reported, by its own diagnostic",
        add_lock_expect,
        "lock().expect/unwrap",
    )

    def add_multiline_lock(sandbox: Path) -> None:
        p, t, cut = before_tests(sandbox)
        injected = (
            "fn injected() {\n"
            "    let g = m\n"
            "        .lock()\n"
            '        .expect("must not deadlock");\n'
            "}\n"
        )
        p.write_text(t[:cut] + injected + t[cut:], encoding="utf-8")

    fires(
        "a lock().expect split across lines is reported",
        add_multiline_lock,
        "lock().expect/unwrap",
    )

    def add_bound_expect(sandbox: Path) -> None:
        p, t, cut = before_tests(sandbox)
        injected = (
            "fn injected() {\n"
            "    let guard = m.lock();\n"
            '    let guard = guard.expect("must not deadlock");\n'
            "}\n"
        )
        p.write_text(t[:cut] + injected + t[cut:], encoding="utf-8")

    fires(
        "a bound lock result expected later is reported",
        add_bound_expect,
        "bound lock result",
    )

    def add_propagated_lock(sandbox: Path) -> None:
        p, t, cut = before_tests(sandbox)
        injected = (
            "fn injected() -> Result<(), String> {\n"
            '    let guard = m.lock().map_err(|_| "gone")?;\n'
            "    Ok(())\n"
            "}\n"
        )
        p.write_text(t[:cut] + injected + t[cut:], encoding="utf-8")

    with tempfile.TemporaryDirectory() as tmp:
        sandbox = Path(tmp) / "r"
        sandbox.mkdir()
        shutil.copytree(ROOT / "crates", sandbox / "crates")
        watch = sandbox / "crates" / "qqq-host" / "src" / "pool.rs"
        before = watch.read_text(encoding="utf-8")
        add_propagated_lock(sandbox)
        assert watch.read_text(encoding="utf-8") != before, "propagated mutation did not apply"
        found = [p for p in check_tree(sandbox) if "pool.rs" in p]
        cases.append(
            ("a propagated lock result stays silent", not found, f"{found[:1]}")
        )

    def add_drop_expect(sandbox: Path) -> None:
        p, t, cut = before_tests(sandbox)
        p.write_text(
            t[:cut] + 'impl Drop for Injected { fn drop(&mut self) { self.x.expect("boom"); } }\n' + t[cut:],
            encoding="utf-8",
        )

    fires(
        "an expect inside a Drop body is reported",
        add_drop_expect,
        "impl Drop for Injected",
    )

    def add_generic_drop(sandbox: Path) -> None:
        p, t, cut = before_tests(sandbox)
        p.write_text(
            t[:cut]
            + 'impl<T> Drop for Generic<T> { fn drop(&mut self) { self.x.unwrap(); } }\n'
            + t[cut:],
            encoding="utf-8",
        )

    fires(
        "an unwrap inside a generic Drop body is reported",
        add_generic_drop,
        "impl Drop for Generic<T>",
    )

    def add_nested_lock(sandbox: Path) -> None:
        nested = sandbox / "crates" / "qqq-host" / "src" / "nested_proof"
        nested.mkdir()
        (nested / "mod.rs").write_text(
            'pub fn injected() { let g = STATICS.lock().expect("must not deadlock"); }\n',
            encoding="utf-8",
        )

    fires(
        "a lock().expect in a nested src module is reported",
        add_nested_lock,
        "nested_proof",
        "nested_proof/mod.rs",
    )

    def add_doc_and_test(sandbox: Path) -> None:
        p, t, cut = before_tests(sandbox)
        head = t[:cut] + '/// m.lock().expect("doc example stays exempt")\n'
        tail = t[cut:] + '\n#[test]\nfn injected_allows() { let g = m.lock().expect("test stays exempt"); }\n'
        p.write_text(head + tail, encoding="utf-8")

    with tempfile.TemporaryDirectory() as tmp:
        sandbox = Path(tmp) / "r"
        sandbox.mkdir()
        shutil.copytree(ROOT / "crates", sandbox / "crates")
        watch = sandbox / "crates" / "qqq-host" / "src" / "pool.rs"
        before = watch.read_text(encoding="utf-8")
        add_doc_and_test(sandbox)
        assert watch.read_text(encoding="utf-8") != before, "doc/test mutation did not apply"
        found = [p for p in check_tree(sandbox) if "pool.rs" in p]
        cases.append(("doc lines and test code stay exempt", not found, f"{found[:1]}"))

    failed = 0
    print("check_no_poison_expect self-test")
    for name, ok, detail in cases:
        print(f"  {'OK ' if ok else 'FAIL'}  {name}  ({detail})")
        failed += not ok
    if failed:
        print(f"SELF-TEST FAILED -- {failed} case(s) wrong")
        return 1
    print("SELF-TEST PASSED -- every predicate fires on mutation, silent on the real tree")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    problems = check_tree(ROOT)
    if problems:
        for p in problems:
            print(f"FAIL  {p}")
        print("POISON-EXPECT FAILED -- recover locks, never expect them; Drops never panic")
        return 1
    count = len(source_files(ROOT))
    print(f"POISON-EXPECT OK -- no lock().expect/unwrap and no panicking Drops outside tests ({count} files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
