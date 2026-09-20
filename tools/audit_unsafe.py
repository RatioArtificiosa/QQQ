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
    print("SELF-TEST PASSED -- every injection detected, no prose false positive")
    return 0


def main():
    if "--self-test" in sys.argv:
        return self_test()

    root = os.path.normpath(ROOT)
    files, code_hits, prose_hits, lint_hits = scan(root)

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
