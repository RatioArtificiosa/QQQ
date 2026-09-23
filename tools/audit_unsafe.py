# SPDX-License-Identifier: Apache-2.0

"""Exhaustive audit of `unsafe` in the QQQ workspace, for SEC-020.

# Why this is a script rather than one grep

`SEC-020` says "audit every `unsafe` block in the three exception crates and
record the findings". An audit whose method is one `Select-String` is an audit
whose completeness nobody can check -- and a *missed* `unsafe` block is the one
class of finding where "I looked and found nothing" is dangerously wrong.

So this enumerates every `.rs` file in the workspace and classifies every
occurrence of the token, including ones a naive grep would miss:

  * `unsafe { ... }` blocks
  * `unsafe fn`, `unsafe impl`, `unsafe trait`, `unsafe extern`
  * `#[allow(unsafe_code)]` attributes (the lint escape)
  * `cfg_attr(..., allow(unsafe_code))` (the conditional escape)
  * `unsafe` in doc comments and strings (NOT code -- reported separately so the
    code count is honest)

# The self-test, and why a scanner needs one

A scanner that reports "0 findings" is indistinguishable from a scanner that is
broken -- and this session has recorded that failure four times (`§O-079`): a
filter that ran zero tests, a fixture measuring the wrong ceiling, an injection
that did not compile. So `--self-test` injects each of the five `unsafe` forms
into a temporary file tree, asserts the scanner detects every one, and asserts it
does **not** fire on prose. A scanner that cannot pass its own self-test is not
evidence about the code.

Run `python tools/audit_unsafe.py --self-test` to check the checker.
"""
import os
import re
import sys
import tempfile

ROOT = os.environ.get("QQQ_UNSAFE_ROOT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "crates"))
# The page this scan is the evidence for. Checked by `--check-doc`; see `check_doc` for why
# a hand-copied count in a safety document is a defect rather than a stale detail.
DOC = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "docs", "unsafe-audit.md"
)

# Code-position unsafe forms. The `unsafe` KEYWORD followed by a code construct.
CODE_PATTERNS = {
    "block": re.compile(r"\bunsafe\s*\{"),
    "fn": re.compile(r"\bunsafe\s+fn\b"),
    "impl": re.compile(r"\bunsafe\s+impl\b"),
    "trait": re.compile(r"\bunsafe\s+trait\b"),
    "extern": re.compile(r"\bunsafe\s+extern\b"),
}
LINTS = {
    "allow_attr": re.compile(r"#\s*!?\s*\[\s*allow\s*\(\s*unsafe_code\s*\)"),
    "forbid_attr": re.compile(r"#\s*!?\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)"),
    "cfg_attr_allow": re.compile(r"cfg_attr\s*\([^)]*allow\s*\(\s*unsafe_code"),
}


def is_comment_or_string(line, idx):
    """Is the position at `idx` inside a `//` comment or a string literal?

    # Not a parser, and the self-test is what keeps that honest

    This is a character scan, not a Rust lexer. It answers one question: is the
    byte at `idx` part of a comment or a string rather than code? Getting it wrong
    in either direction has a cost, and they are not symmetric:

    * **A false negative** (code called prose) hides an `unsafe` block. That is the
      dangerous direction, and it is why the classifier errs toward reporting.
    * **A false positive** (prose called code) makes the audit fail on a
      doc comment. Annoying, and it is what got fixed here.

    # The bug the self-test found

    The first version only looked for `//` before the position, so a string
    literal containing `unsafe {` was classified as code — a **false positive**
    the self-test's prose control caught. That control (`let s = "unsafe { }";`)
    exists precisely because a scanner whose *only* tests are injections will
    happily over-report, and an audit that cries wolf is one people stop running.

    The scan below therefore walks the line tracking three states — code, inside a
    string, inside a comment — so a `//` inside a string does not start a comment
    and an `unsafe {` inside a string is not code.
    """
    in_string = False
    in_char = False
    escaped = False
    i = 0
    while i < idx:
        ch = line[i]

        if escaped:
            escaped = False
        elif ch == "\\" and (in_string or in_char):
            escaped = True
        elif in_string:
            if ch == '"':
                in_string = False
        elif in_char:
            if ch == "'":
                in_char = False
        elif ch == '"':
            in_string = True
        elif ch == "'":
            # A `'` may start a char literal or a lifetime. A lifetime is followed
            # by an identifier and has no closing `'`; a char literal closes within
            # a few characters. Treating a lifetime as a char literal would swallow
            # the rest of the line, so only open a char literal when a closing `'`
            # appears nearby — which is the heuristic Rust's own pretty-printers use
            # for the same reason.
            rest = line[i + 1 : i + 4]
            if "'" in rest:
                in_char = True
        elif ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
            return True
        i += 1

    return in_string or in_char


def scan(root):
    """Scan a directory tree, returning (code_hits, prose_hits, lint_hits)."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("target", ".git")]
        for fn in filenames:
            if fn.endswith(".rs"):
                files.append(os.path.join(dirpath, fn))

    code_hits = []
    prose_hits = []
    lint_hits = []

    for path in files:
        rel = os.path.relpath(path, root)
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        for lineno, line in enumerate(lines, 1):
            for name, pat in CODE_PATTERNS.items():
                for m in pat.finditer(line):
                    entry = (rel, lineno, name, line.strip()[:100])
                    if is_comment_or_string(line, m.start()):
                        prose_hits.append(entry)
                    else:
                        code_hits.append(entry)

            for name, pat in LINTS.items():
                for m in pat.finditer(line):
                    lint_hits.append((rel, lineno, name, line.strip()[:100]))

    return files, code_hits, prose_hits, lint_hits


def self_test():
    """Inject each `unsafe` form and confirm the scanner finds it.

    Returns 0 when every injection is detected, 1 otherwise. A failure here means
    the audit's *zero* is not evidence, so it must fail the build loudly rather
    than print a warning.
    """
    cases = [
        ("block", "#![forbid(unsafe_code)]\npub fn f() { let x = unsafe { std::mem::zeroed::<u32>() }; let _ = x; }\n"),
        ("fn", "#![forbid(unsafe_code)]\npub unsafe fn f() {}\n"),
        ("impl", "#![forbid(unsafe_code)]\nunsafe impl Send for Foo {}\n"),
        ("trait", "#![forbid(unsafe_code)]\nunsafe trait Marker {}\n"),
        ("extern", "#![forbid(unsafe_code)]\nunsafe extern \"C\" fn f() {}\n"),
        ("allow_attr", "#![forbid(unsafe_code)]\n#[allow(unsafe_code)]\nfn f() {}\n"),
        ("cfg_attr_allow", "#![forbid(unsafe_code)]\n#![cfg_attr(feature = \"x\", allow(unsafe_code))]\n"),
    ]

    prose_cases = [
        "// This is the unsafe direction to take.\n",
        '//! `#![allow(unsafe_code)]` with no argument written down.\n',
        'let s = "unsafe { }";\n',
    ]

    failures = 0
    print(f"self-test: {len(cases)} injection(s), {len(prose_cases)} prose control(s)")
    print()

    for name, source in cases:
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src")
            os.makedirs(src)
            with open(os.path.join(src, "lib.rs"), "w", encoding="utf-8") as f:
                f.write(source)

            _files, code, _prose, _lints = scan(tmp)
            # `allow_attr` and `cfg_attr_allow` are lint escapes, not code forms;
            # they are detected through `lint_hits`, so check both.
            _files2, _code2, _prose2, lints = scan(tmp)
            detected = bool(code) or any(k in ("allow_attr", "cfg_attr_allow") for _, _, k, _ in lints)

            if detected:
                print(f"  OK    {name}: detected")
            else:
                print(f"  DEAD  {name}: NOT detected -- the audit cannot be trusted")
                failures += 1

    for source in prose_cases:
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src")
            os.makedirs(src)
            with open(os.path.join(src, "lib.rs"), "w", encoding="utf-8") as f:
                f.write(source)

            _files, code, _prose, _lints = scan(tmp)
            if code:
                print(f"  FALSE POSITIVE on prose: {source.strip()}")
                for c in code:
                    print(f"      {c}")
                failures += 1
            else:
                print(f"  OK    prose control: no code hit ({source.strip()[:50]})")

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} problem(s)")
        return 1

    # --- The document check, proven live ---------------------------------
    #
    # `--check-doc` is a gate on a safety page, so it needs the same treatment as the
    # scanner: a checker that has never rejected anything has never been shown to work.
    # Three cases, and the middle one is the point -- a check that fired on *everything*
    # would pass the first and third while being useless.
    root = os.path.normpath(ROOT)
    files, _code, _prose, lint_hits = scan(root)
    with tempfile.TemporaryDirectory() as tmp:
        good = os.path.join(tmp, "good.md")
        with open(good, "w", encoding="utf-8") as f:
            f.write(
                f"| `.rs` files scanned under `crates/` | **{len(files)}** |\n"
                "| Crates carrying a bare `#![forbid(unsafe_code)]` | **11** (every crate) |\n"
            )
        if check_doc(files, lint_hits, good) == 0:
            print("  OK    doc check accepts a correct table")
        else:
            print("  DEAD  doc check rejects a correct table")
            failures += 1

        bad = os.path.join(tmp, "bad.md")
        with open(bad, "w", encoding="utf-8") as f:
            f.write(
                "| `.rs` files scanned under `crates/` | **85** |\n"
                "| Crates carrying a bare `#![forbid(unsafe_code)]` | **11** (every crate) |\n"
            )
        if check_doc(files, lint_hits, bad) != 0:
            print("  OK    doc check catches a stale file count")
        else:
            print("  DEAD  doc check accepted a stale file count")
            failures += 1

        missing = os.path.join(tmp, "missing.md")
        with open(missing, "w", encoding="utf-8") as f:
            f.write("# no table at all\n")
        if check_doc(files, lint_hits, missing) != 0:
            print("  OK    doc check catches a table that lost its row")
        else:
            print("  DEAD  doc check accepted a document with no table")
            failures += 1

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} problem(s)")
        return 1
    print("SELF-TEST PASSED -- every injection detected, no prose false positive")
    return 0


def check_doc(files, lint_hits, doc_path=None) -> int:
    """Fail when `docs/unsafe-audit.md`'s table disagrees with the live scan.

    # Why the report is checked rather than trusted

    The document said **85** `.rs` files scanned while the tree held 139. The count
    was true when it was written and nothing tied it to the tree afterwards, so it
    decayed the way every hand-copied number decays — silently, and in the direction
    of understating the work.

    It matters more here than the arithmetic suggests. This page is the *evidence* for
    the workspace's central safety claim (`SEC-020`), and its argument is "a zero that
    appears for the wrong reason is worse than a non-zero". A page whose own sample
    size is wrong is exactly the wrong reason, in miniature: the reader cannot tell
    whether 85 was the real count and the tree grew, or whether the scanner was
    looking somewhere else all along.

    So the number is derived from the scan that is already running, and this mode is a
    gate on the page rather than a second report.
    """
    forbids = [h for h in lint_hits if h[2] == "forbid_attr"]
    # `#![forbid(unsafe_code)]` on every crate, plus incidental mentions of the attribute in
    # doc comments and test fixtures. The claim is about crates, so it is counted from the
    # crate roots rather than from every hit.
    crate_roots = {
        rel.split(os.sep)[0] for rel, _ln, kind, _text in lint_hits if kind == "forbid_attr"
    }

    try:
        with open(doc_path or DOC, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as e:
        print(f"DRIFT: could not read {doc_path or DOC}: {e}")
        return 1

    problems = []

    m = re.search(r"\|\s*`\.rs` files scanned under `crates/`\s*\|\s*\*\*(\d+)\*\*\s*\|", text)
    if not m:
        problems.append("the `files scanned` row is missing or has lost its `**bold**` count")
    elif int(m.group(1)) != len(files):
        problems.append(
            f"`files scanned` says {m.group(1)}, the scan found {len(files)}"
        )

    m = re.search(r"\|\s*Crates carrying a bare `#!\[forbid\(unsafe_code\)\]`\s*\|\s*\*\*(\d+)\*\*", text)
    if not m:
        problems.append("the `Crates carrying a bare forbid` row is missing")
    elif int(m.group(1)) != len(crate_roots):
        problems.append(
            f"`crates carrying forbid` says {m.group(1)}, {len(crate_roots)} crate root(s) carry it"
        )

    if problems:
        for p in problems:
            print(f"  DRIFT: {p}")
        print(
            "  Update the table in `docs/unsafe-audit.md` to match this scan. The numbers "
            "are produced by `python tools/audit_unsafe.py`, so the page never needs to be "
            "guessed at."
        )
        return 1

    print(
        f"UNSAFE AUDIT DOC OK -- {len(files)} file(s), {len(crate_roots)} crate root(s) "
        f"carrying `forbid(unsafe_code)`"
    )
    return 0


def main():
    if "--self-test" in sys.argv:
        return self_test()

    root = os.path.normpath(ROOT)
    files, code_hits, prose_hits, lint_hits = scan(root)

    if "--check-doc" in sys.argv:
        return check_doc(files, lint_hits)

    print(f"scanned {len(files)} .rs files under {root}")
    print()

    print("=== CODE-POSITION `unsafe` ===")
    if code_hits:
        for rel, ln, kind, text in code_hits:
            print(f"  {rel}:{ln}  [{kind}]  {text}")
    else:
        print("  NONE")

    print()
    print("=== LINT ATTRIBUTES (`forbid` / `allow` / `cfg_attr`) ===")
    for rel, ln, kind, text in lint_hits:
        print(f"  {rel}:{ln}  [{kind}]  {text}")

    print()
    print("=== `unsafe` IN PROSE (comments/strings, not code) ===")
    print(f"  {len(prose_hits)} occurrence(s) -- documentation, not code")

    allows = [h for h in lint_hits if h[2] in ("allow_attr", "cfg_attr_allow")]
    forbids = [h for h in lint_hits if h[2] == "forbid_attr"]

    print()
    print("=== SUMMARY ===")
    print(f"  files scanned        : {len(files)}")
    print(f"  code-position unsafe : {len(code_hits)}")
    print(f"  allow(unsafe_code)   : {len(allows)}")
    print(f"  forbid(unsafe_code)  : {len(forbids)}")

    # Exit non-zero if any code-position unsafe exists, so this doubles as a gate.
    return 1 if code_hits else 0


if __name__ == "__main__":
    sys.exit(main())
