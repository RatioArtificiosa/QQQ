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
  * lint-attribute *mentions* (`#![forbid(unsafe_code)]` quoted in a comment,
    string or block comment -- prose, not a crate carrying the attribute)
  * raw-string content (`r#"..."#`, `br##"..."##` -- inner quotes toggle
    nothing; only a quote with the matching hash count closes)
  * item-level `#[forbid(unsafe_code)]` and inner attributes on non-entrypoint
    targets (reported under their own kind, never counted toward root
    coverage -- same guard, same reason)

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


# This tool's own stdout must be able to encode what it prints. On a Windows console the stream
# inherits `cp1252`, so a character read from a subprocess -- which this file now reads as UTF-8 --
# raises `UnicodeEncodeError` inside `print` and the tool dies while reporting its result. `§O-291`.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


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


def walk_line(line, idx, depth_in, string_in, raw_in):
    """Walk the chars before `idx`, tracking strings and both comment forms.

    Returns `(is_prose, depth_out, string_out, raw_out)`: whether the
    position at `idx` is inside a `//` comment, a `/* ... */` block, or a
    string/char/raw-string literal rather than code, and the block nesting
    depth plus string/raw states still open at `idx`.

    Block comments nest in Rust -- one opener needs one closer each, and
    the content stays comment until the depth reaches zero. A boolean
    clears at the first `*/` and certifies everything after it, which is
    the wrong answer for `/* /* */ code */`. Depth is what the language
    tracks, so depth is what the scan tracks; `scan()` threads it across
    lines with the string and raw states.

    Raw strings (`r"..."`, `br"..."`, with `r#*"..."*#` hashes) are real
    literals with two properties a plain `"` scan gets wrong: backslashes
    inside them are literal (no escapes), and they close only on a `"`
    followed by exactly the opening hash count. A `"` that opens a normal
    string inside raw content -- or closes one early -- desyncs the scan in
    either direction, so the opener is recognised (prefix plus hashes, with
    an identifier boundary before it, exactly as the Rust lexer demands)
    and its state threads across lines like block and string state. `cr`
    takes the same path; `rb` is rejected -- it is no language's prefix,
    and accepting it misread `\r` followed by `b` as a raw opener hiding
    the rest of the line. Char
    state stays per line -- a char literal cannot span lines, and carrying
    it over would let a stray `'` swallow the next line. The precedence at
    every character is block, then raw, then string, then char, then comment
    openers, so each construct wins exactly where it is lexically inside.

    # Not a parser, and the self-test is what keeps that honest

    This is a character scan, not a Rust lexer. It answers one question: is the
    byte at `idx` part of a comment or a string rather than code? Getting it wrong
    in either direction has a cost, and they are not symmetric:

    * **A false negative** (code called prose) hides an `unsafe` block. That is the
      dangerous direction, and it is why the classifier errs toward reporting.
    * **A false positive** (prose called code) makes the audit fail on a
      doc comment. Annoying, and it is what got fixed here.

    # The bugs the self-test found

    The first version only looked for `//` before the position, so a string
    literal containing `unsafe {` was classified as code — a **false positive**
    the self-test's prose control caught. That control (`let s = "unsafe { }";`)
    exists precisely because a scanner whose *only* tests are injections will
    happily over-report, and an audit that cries wolf is one people stop running.

    The second version still knew only `//`, so `/* #![forbid(unsafe_code)] */`
    classified as a crate carrying the attribute — a **false negative** in the
    dangerous direction, certifying a root on a comment. Block state therefore
    threads across lines: `scan()` feeds each line's exit state into the next,
    so a match on a continuation line classifies against the opener above it.

    The third version threaded blocks but reset strings per line, so a `/*`
    inside a multiline string opened a block that swallowed the code beneath
    it — same dangerous direction, one layer deeper. String state threads too,
    and a file ending with either state open is refused as `unterminated`.

    The fourth version still scanned raw strings as plain quotes, so a `"`
    inside `r#"..."#` toggled string mode and desynced the line in either
    direction. Raw openers (prefix plus hash count, identifier boundary
    included) and their exact-count closers are recognised, escapes are
    ignored inside them, and their state threads across lines with the rest.

    The fifth version tracked blocks as a boolean, which clears at the
    first `*/` -- but Rust block comments nest, so `/* /* */ code */` is
    still comment after the inner close and the boolean certified the
    rest. The state is a depth now: openers increment, closers decrement,
    and content stays comment until zero.

    The scan below therefore walks the line tracking four states — code, inside a
    string, inside a char, inside a block comment — so a `//` inside a string
    does not start a comment, an `unsafe {` inside a string is not code, and a
    `/*` inside a string does not open a block while a `"` inside a block does
    not open a string.
    """
    in_string = string_in
    in_char = False
    depth = depth_in
    raw = raw_in
    escaped = False
    i = 0
    while i < idx:
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""

        if depth > 0:
            if ch == "/" and nxt == "*":
                depth += 1
                i += 2
                continue
            if ch == "*" and nxt == "/":
                depth -= 1
                i += 2
                continue
            i += 1
            continue

        if raw is not None:
            # Inside a raw string: no escapes, and only a quote with the
            # matching hash count closes.
            if ch == '"':
                hashes = 0
                while line[i + 1 + hashes : i + 2 + hashes] == "#":
                    hashes += 1
                if hashes == raw:
                    raw = None
                    i += 1 + hashes
                    continue
            i += 1
            continue

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
            m = re.search(r"(?:^|[^A-Za-z0-9_])(?:br|cr|r)(#*)$", line[:i])
            if m is not None:
                raw = len(m.group(1))
            else:
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
        elif ch == "/" and nxt == "/":
            return True, depth, in_string, raw
        elif ch == "/" and nxt == "*":
            depth += 1
            i += 2
            continue
        i += 1

    return (in_string or in_char or depth > 0 or raw is not None), depth, in_string, raw


def is_comment_or_string(line, idx):
    """Single-line shorthand: `walk_line` with no state open above."""
    prose, _, _, _ = walk_line(line, idx, 0, False, None)
    return prose


def is_entrypoint(rel):
    """Is `rel` (relative to `crates/`) a crate entrypoint?

    `src/lib.rs`, `src/main.rs`, the crate-root `build.rs`, and Cargo's
    autobins: `src/bin/<name>.rs` and `src/bin/<name>/main.rs`. Only an
    inner `#![forbid(unsafe_code)]` at one of these is evidence the crate
    forbids `unsafe`: an outer `#[forbid]` on an item scopes to that item,
    and an inner attribute in `tests/` or an example scopes to that target.
    Counting any of those as crate coverage certifies a root on a target
    the attribute never governed -- and an uncovered bin compiles `unsafe`
    no library attribute forbids.
    """
    parts = rel.replace(os.sep, "/").split("/")
    if len(parts) < 2 or len(parts) > 5:
        return False
    if parts[1] == "build.rs" and len(parts) == 2:
        return True
    if len(parts) < 3 or parts[1] != "src":
        return False
    if len(parts) == 3 and parts[2] in ("lib.rs", "main.rs"):
        return True
    if len(parts) == 4 and parts[2] == "bin" and parts[3].endswith(".rs"):
        return True
    return len(parts) == 5 and parts[2] == "bin" and parts[4] == "main.rs"


def entrypoints(root):
    """The entrypoints `validate_scan` requires a forbid attribute at.

    Discovered, not declared: every immediate crate directory (one carrying
    `Cargo.toml`) contributes the entrypoint files it actually has --
    `src/lib.rs`, `src/main.rs`, the crate-root `build.rs`, and every
    autobin under `src/bin` (both the `<name>.rs` and the `<name>/main.rs`
    shapes). A list nobody reads is how a new bin target would silently
    skip the invariant.
    """
    found = []
    for name in sorted(os.listdir(root)):
        crate_dir = os.path.join(root, name)
        if not os.path.isdir(crate_dir):
            continue
        if not os.path.isfile(os.path.join(crate_dir, "Cargo.toml")):
            continue
        for ep in ("src/lib.rs", "src/main.rs", "build.rs"):
            if os.path.isfile(os.path.join(crate_dir, ep)):
                found.append(name + "/" + ep)
        bindir = os.path.join(crate_dir, "src", "bin")
        if not os.path.isdir(bindir):
            continue
        for entry in sorted(os.listdir(bindir)):
            full = os.path.join(bindir, entry)
            if entry.endswith(".rs") and os.path.isfile(full):
                found.append(name + "/src/bin/" + entry)
            elif os.path.isdir(full) and os.path.isfile(os.path.join(full, "main.rs")):
                found.append(name + "/src/bin/" + entry + "/main.rs")
    return found


def scan(root):
    """Scan a directory tree.

    Returns (files, code_hits, prose_hits, lint_hits, entrypoints,
    unterminated): `entrypoints` are the crate entry files `validate_scan`
    requires a forbid attribute at, and `unterminated` are `(rel, what)`
    pairs for files ending with a block comment or string still open --
    content after the opener classifies as prose, so the scan cannot see
    it and validation must refuse.
    """
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("target", ".git")]
        for fn in filenames:
            if fn.endswith(".rs"):
                files.append(os.path.join(dirpath, fn))

    code_hits = []
    prose_hits = []
    lint_hits = []
    unterminated = []

    for path in files:
        rel = os.path.relpath(path, root)
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        # Block, string AND raw state reset at every file: a `/*` (or an open
        # quote) left open in one file must not swallow the next file's code
        # into prose. An opener left open at EOF is reported (see
        # `unterminated`): the scan classified everything after it as
        # comment, so that file's zero is not evidence and validation
        # refuses it loudly rather than passing it silently.
        entry_depth = 0
        entry_string = False
        entry_raw = None
        for lineno, line in enumerate(lines, 1):
            # Collect every pattern's matches first: each classifies against
            # the states at the line's start (the walker is a pure function
            # of position and entry state, so order is irrelevant), then the
            # exit states thread into the next line.
            pending = []
            for name, pat in CODE_PATTERNS.items():
                for m in pat.finditer(line):
                    pending.append((m.start(), "code", name, m.group(0)))
            for name, pat in LINTS.items():
                for m in pat.finditer(line):
                    pending.append((m.start(), "lint", name, m.group(0)))
            for idx, bucket, name, text in pending:
                prose, _, _, _ = walk_line(line, idx, entry_depth, entry_string, entry_raw)
                entry = (rel, lineno, name, line.strip()[:100])
                if bucket == "code":
                    (prose_hits if prose else code_hits).append(entry)
                elif prose:
                    prose_hits.append(entry)
                else:
                    kind = name
                    if name == "forbid_attr":
                        # An outer `#[forbid]` (no `!`) scopes to its item, not
                        # its crate; only an inner attribute at an entrypoint
                        # counts toward root coverage.
                        inner = "!" in text.split("[")[0]
                        if not inner:
                            kind = "forbid_item"
                        elif not is_entrypoint(rel):
                            kind = "forbid_elsewhere"
                    lint_hits.append((rel, lineno, kind, entry[3]))
            _, entry_depth, entry_string, entry_raw = walk_line(
                line, len(line), entry_depth, entry_string, entry_raw
            )
        if entry_depth > 0:
            unterminated.append((rel, "block comment"))
        if entry_string:
            unterminated.append((rel, "string"))
        if entry_raw is not None:
            unterminated.append((rel, "raw string"))

    return files, code_hits, prose_hits, lint_hits, entrypoints(root), unterminated



def validate_scan(files, lint_hits, entrypoints, unterminated) -> list:
    """Refuse an empty scan: no files, no forbid-carrying roots, an
    entrypoint without a crate-level attribute, or a file ending inside a
    block comment or string.

    A scanner that reports zero over nothing certifies nothing, and an
    audit whose sample is empty is the fixture-that-cannot-fail in safety
    clothing. Every mode (report, record, check-doc) runs this first.

    Coverage means an inner `#![forbid(unsafe_code)]` at a discovered
    entrypoint (`scan()` files every other shape — comments, strings,
    item-level `#[forbid]`, other targets — as prose or as an uncounted
    kind, so it can never certify a root). The self-test proves each shape
    with a dedicated tree, which validation must refuse by name.
    """
    import os as _os

    problems = []
    if not files:
        problems.append("scan found no .rs files; an empty target set certifies nothing")
    covered = {
        rel.replace(_os.sep, "/") for rel, _ln, kind, _text in lint_hits if kind == "forbid_attr"
    }
    roots = {rel.split("/")[0] for rel in covered}
    if not roots:
        problems.append("scan found no crate roots carrying forbid_attr; nothing was checked")
    for ep in entrypoints:
        if ep not in covered:
            problems.append(
                f"entrypoint {ep} carries no crate-level forbid(unsafe_code); "
                "an item-level attribute or another target's attribute is not coverage"
            )
    for rel, what in unterminated:
        problems.append(
            f"{rel} ends inside a {what}; everything after the opener "
            "classified as prose, so that file's zero is not evidence"
        )
    return problems


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
        "// Every crate carries #![forbid(unsafe_code)] at its root.\n",
        'let s = "#![forbid(unsafe_code)]";\n',
        "/* a block comment with unsafe { } inside */\n",
        "/* a block comment naming #![forbid(unsafe_code)] */\n",
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

            _files, code, _prose, _lints, _eps, _un = scan(tmp)
            # `allow_attr` and `cfg_attr_allow` are lint escapes, not code forms;
            # they are detected through `lint_hits`, so check both.
            _files2, _code2, _prose2, lints, _eps2, _un2 = scan(tmp)
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

            _files, code, _prose, lints, _eps, _un = scan(tmp)
            if code or lints:
                print(f"  FALSE POSITIVE on prose: {source.strip()}")
                for c in [*code, *lints]:
                    print(f"      {c}")
                failures += 1
            else:
                print(f"  OK    prose control: no code or lint hit ({source.strip()[:50]})")

    # A crate whose only `forbid` is a mention carries no attribute: the scan
    # must file it as prose, and validation must refuse the tree. These two
    # ride the `shape_cases` table below (crate-shaped, entrypoint-aware)
    # rather than a bespoke loop, so a misfiling fails the same way every
    # other shape does.

    # The shapes that must never count as crate coverage, each in a
    # crate-shaped tree (with `m/Cargo.toml`, so `entrypoints()` discovers
    # it): comment and string mentions, block comments, a multiline block
    # comment, an item-level attribute, and an inner attribute on another
    # target. Each red proof below once validated clean. Crate-shaped
    # matters: an earlier version of the mention cases built `src/lib.rs`
    # with no manifest, so discovery returned nothing and the refusal came
    # from the empty root set -- the entrypoint path never engaged.
    def crate_tree(extra):
        tmp = tempfile.TemporaryDirectory()
        os.makedirs(os.path.join(tmp.name, "m"), exist_ok=True)
        with open(os.path.join(tmp.name, "m", "Cargo.toml"), "w", encoding="utf-8") as f:
            f.write('[package]\nname = "m"\n')
        for relpath, source in extra:
            target = os.path.join(tmp.name, relpath)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w", encoding="utf-8") as f:
                f.write(source)
        return tmp

    # (label, files, expect_recorded, must_name): the lib's own inner
    # attribute records in the "other target" and "uncovered bin" cases --
    # their refusal must come from the uncovered entrypoint, named, not from
    # an empty root set.
    shape_cases = [
        (
            "comment mention",
            [("m/src/lib.rs", "// #![forbid(unsafe_code)] lives here one day.\npublic fn f() {}\n")],
            False,
            None,
        ),
        (
            "string mention",
            [("m/src/lib.rs", 'let s = "#![forbid(unsafe_code)]";\n')],
            False,
            None,
        ),
        (
            "block comment",
            [("m/src/lib.rs", "/* #![forbid(unsafe_code)] one day. */\npub fn f() {}\n")],
            False,
            None,
        ),
        (
            "multiline block comment",
            [("m/src/lib.rs", "/*\n#![forbid(unsafe_code)]\n*/\npub fn f() {}\n")],
            False,
            None,
        ),
        (
            "item-level attribute",
            [("m/src/lib.rs", "#[forbid(unsafe_code)]\npub fn f() {}\n")],
            False,
            None,
        ),
        (
            "other target",
            [
                ("m/src/lib.rs", "#![forbid(unsafe_code)]\npub fn f() {}\n"),
                ("m/src/main.rs", "fn main() {}\n"),
                ("m/tests/t.rs", "#![forbid(unsafe_code)]\n#[test]\nfn t() {}\n"),
            ],
            True,
            "m/src/main.rs",
        ),
        (
            "uncovered bin",
            [
                ("m/src/lib.rs", "#![forbid(unsafe_code)]\npub fn f() {}\n"),
                (
                    "m/src/bin/tool.rs",
                    "pub fn main() { let x = unsafe { 1 }; let _ = x; }\n",
                ),
            ],
            True,
            "m/src/bin/tool.rs",
        ),
    ]
    for label, extra, expect_recorded, must_name in shape_cases:
        with crate_tree(extra) as tmp:
            mfiles, _mc, _mp, mlints, meps, mun = scan(tmp)
            recorded = any(k == "forbid_attr" for _, _, k, _ in mlints)
            problems = validate_scan(mfiles, mlints, meps, mun)
            refused = bool(problems)
            named = must_name is None or any(must_name in p for p in problems)
            # The "other target" case additionally pins the uncounted kind:
            # its `tests/` attribute must file as `forbid_elsewhere`.
            elsewhere = label != "other target" or any(
                k == "forbid_elsewhere" and r.endswith("m/tests/t.rs".replace("/", os.sep))
                for r, _l, k, _t in mlints
            )
            if recorded == expect_recorded and refused and named and elsewhere:
                print(f"  OK    a {label} forbid covers nothing, and the tree is refused")
            else:
                print(f"  DEAD  a {label} forbid counted as a crate root")
                failures += 1

    # Both autobin shapes discover (`src/bin/<name>.rs` and
    # `src/bin/<name>/main.rs`); anything else under `src/bin` is a module
    # or a data file, not an entrypoint.
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "m", "src", "bin", "nested"))
        with open(os.path.join(tmp, "m", "Cargo.toml"), "w", encoding="utf-8") as f:
            f.write('[package]\nname = "m"\n')
        for relpath in (
            "m/src/bin/tool.rs",
            "m/src/bin/nested/main.rs",
            "m/src/bin/notes.txt",
            "m/src/bin/nested/other.rs",
        ):
            with open(os.path.join(tmp, relpath), "w", encoding="utf-8") as f:
                f.write("// placeholder\n")
        eps = entrypoints(tmp)
        want = {"m/src/bin/tool.rs", "m/src/bin/nested/main.rs"}
        if want <= set(eps) and not any(
            e.endswith(("notes.txt", "other.rs")) for e in eps
        ):
            print("  OK    both autobin shapes discover; non-entries do not")
        else:
            print(f"  DEAD  autobin discovery wrong: {eps}")
            failures += 1

    # A `/*` inside a multiline string must not open a block: the `unsafe`
    # below the string is code and must survive. String state threads across
    # lines for exactly this reason -- resetting it per line lets a string
    # held `/*` open a block that swallows the code beneath it.
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "s.rs"), "w", encoding="utf-8") as f:
            f.write('let s = "abc\n/*\n";\npub fn f() { let x = unsafe { 1 }; let _ = x; }\n')
        _mf, mcode, _mp, _ml, _me, _mu = scan(tmp)
        if any(k == "block" for _, _, k, _ in mcode):
            print("  OK    a /* inside a multiline string opens nothing")
        else:
            print("  DEAD  a /* inside a multiline string hid the unsafe block")
            failures += 1

    # Raw strings: inner quotes open and close nothing (no escapes, and
    # only a quote with the matching hash count closes), so the `unsafe`
    # after the closer is code.
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "r.rs"), "w", encoding="utf-8") as f:
            f.write(
                'let s = r#"say "hi""#;\n'
                "pub fn f() { let x = unsafe { 1 }; let _ = x; }\n"
            )
        _mf, mcode, _mp, _ml, _me, _mu = scan(tmp)
        if any(k == "block" for _, _, k, _ in mcode):
            print("  OK    inner quotes in a raw string hide nothing")
        else:
            print("  DEAD  a raw string inner quote hid the unsafe block")
            failures += 1

    # The `br` prefix and a two-hash count take the same path.
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "r.rs"), "w", encoding="utf-8") as f:
            f.write(
                'let b = br##"x " y"##;\n'
                "pub fn h() { let z = unsafe { 3 }; let _ = z; }\n"
            )
        _mf, mcode, _mp, _ml, _me, _mu = scan(tmp)
        if any(k == "block" for _, _, k, _ in mcode):
            print("  OK    a hashed byte-raw string hides nothing")
        else:
            print("  DEAD  a hashed byte-raw string hid the unsafe block")
            failures += 1

    # The `cr` prefix takes the same path.
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "r.rs"), "w", encoding="utf-8") as f:
            f.write(
                'let c = cr#"a " b"#;\n'
                "pub fn f() { let x = unsafe { 1 }; let _ = x; }\n"
            )
        _mf, mcode, _mp, _ml, _me, _mu = scan(tmp)
        if any(k == "block" for _, _, k, _ in mcode):
            print("  OK    a cr-prefixed raw string hides nothing")
        else:
            print("  DEAD  a cr-prefixed raw string hid the unsafe block")
            failures += 1

    # And `rb` is not a prefix: the escape stays an escape, so the code
    # after the string is code. Accepting `rb` misread this closing quote
    # as a raw opener and hid the rest of the line.
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "r.rs"), "w", encoding="utf-8") as f:
            f.write('let s = "a\\rb"; let x = unsafe { 1 }; let _ = x;\n')
        _mf, mcode, _mp, _ml, _me, _mu = scan(tmp)
        if any(k == "block" for _, _, k, _ in mcode):
            print("  OK    an rb escape closes its string")
        else:
            print("  DEAD  an rb escape opened a phantom raw string")
            failures += 1

    # `unsafe`-shaped text inside a multiline raw string is prose; real
    # code after the closer is code. Before raw tracking this went DEAD:
    # the opener's quote started a plain string, the reset dropped it, and
    # the content classified as code.
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "r.rs"), "w", encoding="utf-8") as f:
            f.write(
                'let s = r#"\n'
                "unsafe { not_code }\n"
                '"#;\n'
                "pub fn g() { let y = unsafe { 2 }; let _ = y; }\n"
            )
        _mf, mcode, _mp, _ml, _me, _mu = scan(tmp)
        by_line = {}
        for _r, ln, k, _t in mcode:
            by_line.setdefault(ln, []).append(k)
        if by_line.get(4) == ["block"] and 2 not in by_line:
            print("  OK    raw content is prose; code after the closer is code")
        else:
            print("  DEAD  a multiline raw string desynced the scan")
            failures += 1

    # Block comments nest in Rust, so one opener needs two closers: the
    # attribute between the inner close and the outer close is still
    # comment. A boolean state clears at the first `*/` and certifies the
    # rest -- depth is what the language tracks, so depth is what the scan
    # tracks.
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "n.rs"), "w", encoding="utf-8") as f:
            f.write(
                "/* outer /* inner */ #![forbid(unsafe_code)] still comment */\n"
                "pub fn f() {}\n"
            )
        with open(os.path.join(tmp, "n2.rs"), "w", encoding="utf-8") as f:
            f.write("/* /* */ unsafe { x } */\npub fn g() {}\n")
        _mf, mcode, _mp, mlints, _me, _mu = scan(tmp)
        attr_leaked = any(k == "forbid_attr" for _, _, k, _ in mlints)
        code_leaked = bool(mcode)
        if not attr_leaked and not code_leaked:
            print("  OK    nested block comments hide attribute and code")
        else:
            print("  DEAD  a nested block comment leaked into code")
            failures += 1

    # Block state must not leak across files: the first file leaves a block
    # open (swallowing its own `unsafe`), the second holds real `unsafe`
    # code. The second file's hit must survive, and the first file's
    # unterminated block must be refused by name -- before the per-file
    # reset, the opener swallowed the second file too and nothing was
    # reported.
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "a_first.rs"), "w", encoding="utf-8") as f:
            f.write("/* left open\npub fn f() { let x = unsafe { 1 }; let _ = x; }\n")
        with open(os.path.join(tmp, "b_second.rs"), "w", encoding="utf-8") as f:
            f.write("pub fn g() { let y = unsafe { 2 }; let _ = y; }\n")
        mfiles, mcode, _mp, mlints, meps, mun = scan(tmp)
        kept = any(r.endswith("b_second.rs") and k == "block" for r, _l, k, _t in mcode)
        problems = validate_scan(mfiles, mlints, meps, mun)
        named = any("a_first.rs" in p and "block comment" in p for p in problems)
        if kept and named:
            print("  OK    block state resets per file; the open block is refused by name")
        else:
            print("  DEAD  block state leaked across files or the open block went unreported")
            failures += 1

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
    files, _code, _prose, lint_hits, live_entrypoints, live_unterminated = scan(root)
    # The live scan must validate before anything is checked against it: the
    # doc cases below build their "correct" table from these very numbers, so
    # an empty or rootless scan would certify a page about nothing. Pointing
    # `QQQ_UNSAFE_ROOT` at an empty directory once passed this whole
    # self-test; now it fails here.
    real = validate_scan(files, lint_hits, live_entrypoints, live_unterminated)
    if real:
        for problem in real:
            print(f"  DEAD  the live scan is refused: {problem}")
        failures += 1
    else:
        print(f"  OK    the live scan validates ({len(files)} file(s))")
    roots = len({rel.split(os.sep)[0] for rel, _ln, kind, _text in lint_hits if kind == "forbid_attr"})
    with tempfile.TemporaryDirectory() as tmp:
        good = os.path.join(tmp, "good.md")
        with open(good, "w", encoding="utf-8") as f:
            f.write(
                f"| `.rs` files scanned under `crates/` | **{len(files)}** |\n"
                f"| Crates carrying a bare `#![forbid(unsafe_code)]` | **{roots}** (every crate) |\n"
            )
        if check_doc(files, lint_hits, good) == 0:
            print("  OK    doc check accepts a correct table")
        else:
            print("  DEAD  doc check rejects a correct table")
            failures += 1

        bad = os.path.join(tmp, "bad.md")
        with open(bad, "w", encoding="utf-8") as f:
            f.write(
                f"| `.rs` files scanned under `crates/` | **{len(files) + 7}** |\n"
                f"| Crates carrying a bare `#![forbid(unsafe_code)]` | **{roots}** (every crate) |\n"
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

        # `--record` gets the same treatment as `--check-doc`, for the same reason: **a recorder that has
        # never been shown to write is a recorder that might be inert**, and the build would stay green
        # whether it repaired the page or wrote nothing at all.
        #
        # Case one: a stale count is repaired AND the repaired file passes the checker. **The second half
        # is what makes this a test of the recorder rather than of the writer** -- a recorder can write a
        # number its own gate then rejects.
        stale = os.path.join(tmp, "stale.md")
        table = (
            "| `.rs` files scanned under `crates/` | **{n}** |\n"
            f"| Crates carrying a bare `#![forbid(unsafe_code)]` | **{roots}** (every crate) |\n"
        )
        with open(stale, "w", encoding="utf-8") as f:
            f.write(table.format(n=len(files) + 7, roots=roots))
        if record_doc(files, lint_hits, stale) == 0 and check_doc(files, lint_hits, stale) == 0:
            print("  OK    record repairs a stale count and the repaired page passes")
        else:
            print("  DEAD  record did not repair a stale count, or wrote one its own check rejects")
            failures += 1

        # Case two: **a document that lost its row is refused.** A recorder that silently wrote nothing
        # would report success on a page it never touched, which is the defect `--record` exists to
        # remove -- so the refusal is the property, not an implementation detail.
        if record_doc(files, lint_hits, missing) != 0:
            print("  OK    record refuses a document whose row it cannot find")
        else:
            print("  DEAD  record reported success on a document with no row to write")
            failures += 1

        # Case three: **a correct document is left byte-identical.** A recorder that rewrote what was
        # already right would churn the page on every run, and this page's own diff is evidence.
        correct = os.path.join(tmp, "correct.md")
        with open(correct, "w", encoding="utf-8") as f:
            f.write(table.format(n=len(files), roots=roots))
        before = open(correct, "rb").read()
        record_doc(files, lint_hits, correct)
        if open(correct, "rb").read() == before:
            print("  OK    record leaves a correct page byte-identical")
        else:
            print("  DEAD  record rewrote a page that was already correct")
            failures += 1

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} problem(s)")
        return 1
    if validate_scan([], [], [], []):
        print("  OK    an empty scan is refused")
    else:
        print("  DEAD  an empty scan passed vacuously")
        failures += 1
    if validate_scan(["a.rs"], [], ["a/src/lib.rs"], []):
        print("  OK    a scan with no forbid roots is refused")
    else:
        print("  DEAD  a scan with no forbid roots passed vacuously")
        failures += 1
    rooted = [("a/src/lib.rs", 1, "forbid_attr", "#![forbid(unsafe_code)]")]
    if not validate_scan(["a.rs"], rooted, ["a/src/lib.rs"], []):
        print("  OK    a non-empty scan with roots passes")
    else:
        print("  DEAD  a non-empty scan with roots was refused")
        failures += 1
    item = [("a/src/lib.rs", 1, "forbid_item", "#[forbid(unsafe_code)]")]
    if validate_scan(["a.rs"], item, ["a/src/lib.rs"], []):
        print("  OK    an item-level attribute covers nothing")
    else:
        print("  DEAD  an item-level attribute counted as a crate root")
        failures += 1
    elsewhere = [("a/tests/t.rs", 1, "forbid_elsewhere", "#![forbid(unsafe_code)]")]
    if validate_scan(["a/tests/t.rs"], elsewhere, ["a/src/lib.rs"], []):
        print("  OK    another target's attribute covers nothing")
    else:
        print("  DEAD  another target's attribute counted as a crate root")
        failures += 1
    partial = [("a/src/lib.rs", 1, "forbid_attr", "#![forbid(unsafe_code)]")]
    missing = validate_scan(["a.rs"], partial, ["a/src/lib.rs", "a/src/main.rs"], [])
    if missing and any("a/src/main.rs" in p for p in missing):
        print("  OK    an uncovered entrypoint is refused by name")
    else:
        print("  DEAD  an uncovered entrypoint passed unnamed")
        failures += 1

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} problem(s)")
        return 1
    print("SELF-TEST PASSED -- every injection detected, no prose false positive")
    return 0


def record_doc(files, lint_hits, doc_path=None) -> int:
    """Rewrite the two derived counts in `docs/unsafe-audit.md` to match the live scan.

    # Why this exists beside `check_doc` rather than instead of it

    `check_doc` is the gate and stays one. This is the regenerator. **The two must agree**, so this
    function deliberately reuses `check_doc`'s own regexes rather than introducing a second pair -- a
    recorder whose patterns drift from its checker's is a recorder that writes numbers the checker will
    then reject.

    # Why a missing row is an error and not a no-op

    Because a recorder that quietly does nothing when its pattern stops matching certifies a page it never
    touched. **Measured cost of getting this wrong**: the same row has taken `files scanned` from 170 to
    172 to 173 across two rounds, each time because a human typed it. So this prints what it changed and
    returns 1 when it could not.

    # Why it edits rather than regenerates

    Because the page is an argument. **Two counts are derived; the prose around them is written**, and a
    generator that reformatted the prose would be editing the argument to protect the numbers -- which is
    the wrong way round for a page whose whole claim is about evidence.
    """
    path = doc_path or DOC
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as e:
        print(f"DRIFT: could not read {path}: {e}")
        return 1

    crate_roots = {
        rel.split(os.sep)[0] for rel, _ln, kind, _text in lint_hits if kind == "forbid_attr"
    }
    wanted = [
        (
            r"(\|\s*`\.rs` files scanned under `crates/`\s*\|\s*\*\*)(\d+)(\*\*\s*\|)",
            len(files),
            "files scanned",
        ),
        (
            r"(\|\s*Crates carrying a bare `#!\[forbid\(unsafe_code\)\]`\s*\|\s*\*\*)(\d+)(\*\*)",
            len(crate_roots),
            "crates carrying a bare forbid",
        ),
    ]

    changed = []
    for pattern, value, label in wanted:
        m = re.search(pattern, text)
        # **A missing row is an error.** See the docstring: a no-op that reports success is the defect
        # this function exists to remove.
        if not m:
            print(f"DRIFT: the `{label}` row is missing, so `--record` cannot write it")
            return 1
        if int(m.group(2)) == value:
            print(f"  {label}: {value} (unchanged)")
            continue
        print(f"  {label}: {m.group(2)} -> {value}")
        changed.append(label)
        text = text[: m.start(2)] + str(value) + text[m.end(2) :]

    # **`newline=""` so the file's own line endings survive.** A recorder that normalised them would be
    # rewriting every line to change two numbers, and `normalize_eol.py --check` would then disagree with
    # whichever end-of-line the platform happened to produce.
    if changed:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        print(f"recorded {len(changed)} count(s) in {path}")
    else:
        print(f"{path} already matches the scan")

    # **Verified by re-reading through `check_doc`.** A recorder that does not check its own output is a
    # recorder that can write a page its own gate rejects.
    return check_doc(files, lint_hits, doc_path)


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
    # `scan()` files every non-covering shape elsewhere: comment, string and
    # block-comment mentions go to prose; item-level `#[forbid]` and inner
    # attributes on other targets keep their own uncounted kinds. Every hit
    # here is an inner attribute at a discovered entrypoint, so the claim
    # about crates is counted from the crate roots rather than from every hit.
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
    files, code_hits, prose_hits, lint_hits, live_entrypoints, live_unterminated = scan(root)
    bad = validate_scan(files, lint_hits, live_entrypoints, live_unterminated)
    if bad:
        for problem in bad:
            print(f"SCAN REFUSED -- {problem}")
        return 1

    if "--record" in sys.argv:
        return record_doc(files, lint_hits)

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
