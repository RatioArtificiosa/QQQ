#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Refuse a `subprocess` call that decodes text with the *locale's* encoding.

    python tools/check_subprocess_encoding.py            # report every site
    python tools/check_subprocess_encoding.py --self-test
    python tools/check_subprocess_encoding.py --list     # one line per site

`subprocess.run(..., text=True)` without an explicit `encoding=` decodes the child's output using
`locale.getpreferredencoding(False)`. On a default Windows console that is **cp1252**, so any child
emitting UTF-8 — `git show` of a document containing `§` or an em-dash, `git ls-files --eol` on a
UTF-8 path — raises `UnicodeDecodeError` inside subprocess's reader thread. The thread dies,
`stdout` comes back **empty**, and the caller treats "no output" as a real result.

**The failure is invisible where it is tested.** CI runs on a UTF-8 locale, so it passes there and
fails only on a developer's Windows box.

# What it cost, and why the whole class is checked rather than the instance

`§O-268` is the instance that was caught: `tools/check_handoff.py` hashed the committed blob of
every normative document and, on Windows, got the SHA-256 of **no bytes at all**
(`e3b0c442…`) — reporting digest drift against a **correct** tree, from the one tool whose job is to
say whether a hand-off is safe. The instance was fixed and an AST scan found **43 sites in 27
tools**; the scan then lived in `.scratch/`, which is gitignored, so nothing enforced it.

Two more faces of the same class were found later and are **not** covered here, because they are not
`subprocess` calls: a script's own **stdout** cannot encode what it read (`§O-271`, `§O-273`), and
Python's text-mode `open` translates `\n` to `os.linesep` on write, which put CRLF into five
generators' tracked output (`§O-273`). This file covers the boundary it can prove statically.

# Why an AST and not a regex

`text=True` and `text=some_var` are different claims: the first is provably locale-decoded, the
second depends on a value a static scan cannot see. Reporting the second as clean would be the
"found nothing, therefore fine" defect this checker exists to catch, so they are reported
separately as **unverifiable** and the report says so.

Usage:  python tools/check_subprocess_encoding.py [--self-test|--list]
Exit:   0 = every executable site passes an explicit encoding, 1 = at least one does not
"""

from __future__ import annotations

import argparse
import ast
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
TOOLS = ROOT / "tools"

# The callables that decode a child's output when asked to produce text.
CALLS = {"run", "Popen", "check_output", "check_call", "call", "getoutput", "getstatusoutput"}

# The keywords that ask for text mode, and the one that makes it safe.
TEXT_KWARGS = ("text", "universal_newlines")
ENCODING_KWARG = "encoding"

# A module-level stream reconfigure is the standard fix for the *other* direction — a script's own
# stdout cannot encode what it read. Recorded here because fixing the read side **unmasked** it in
# two tools (`§O-291`); it is not enforced by this file, which checks the read side only.
STDOUT_FIX = ("reconfigure(", "PYTHONIOENCODING")


def scan(path: Path) -> tuple[list[int], list[int]]:
    """`(executable sites, unverifiable sites)` — line numbers, ascending.

    An *executable* site passes a literal `True` (or a bare `universal_newlines`); an
    *unverifiable* one passes an expression whose value cannot be read statically.

    # `ast.parse` is not a validity check, and this is not a detail

    The scan parses with `ast.parse`, which **accepts a repeated keyword argument** that the
    compiler rejects:

    ```python
    compile('f(a=1, a=2)', 'x', 'exec')   # SyntaxError: keyword argument repeated: a
    ast.parse('f(a=1, a=2)')              # fine
    ```

    That difference hid eleven broken files. A mechanical edit added `encoding=`/`errors=` to calls
    that already carried `errors=`, the edit script verified the result with `ast.parse`, reported
    success, and **eleven tools were un-runnable** — the gate went from 1 failure to 18. The
    verification was the weaker of the two available and nothing said so (`§O-291`).

    So the parse below is followed by a `compile`, and a file that fails either yields no findings
    rather than a confident empty answer.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(text, filename=str(path))
        compile(text, str(path), "exec")  # stricter: catches a repeated keyword
    except SyntaxError:
        return [], []

    executable: list[int] = []
    unverifiable: list[int] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # **Only an attribute call counts** — `subprocess.run`, `sp.run`, `self.run`.
        #
        # A bare `run(...)` is a local function, and the first version of this scanner accepted
        # any name in `CALLS`, so a test helper named `run` taking a `text=True` argument was
        # reported as a locale-decoded subprocess call. That is a false positive, and a checker
        # with false positives is one that gets worked around rather than kept (`§O-274`). The
        # self-test's `an unrelated call named run is not covered` case is what found it.
        if not isinstance(func, ast.Attribute):
            continue
        name = func.attr
        if name not in CALLS:
            continue

        text_kw = None
        has_encoding = False
        for kw in node.keywords:
            if kw.arg == ENCODING_KWARG:
                has_encoding = True
            elif kw.arg in TEXT_KWARGS:
                text_kw = kw
        if text_kw is None or has_encoding:
            continue

        value = text_kw.value
        if isinstance(value, ast.Constant) and value.value is True:
            executable.append(node.lineno)
        elif isinstance(value, ast.Name) and value.id == "True":  # pragma: no cover - 3.8 shape
            executable.append(node.lineno)
        else:
            unverifiable.append(node.lineno)

    return sorted(executable), sorted(unverifiable)


def collect() -> tuple[dict[str, list[int]], dict[str, list[int]]]:
    executable: dict[str, list[int]] = {}
    unverifiable: dict[str, list[int]] = {}
    for path in sorted(TOOLS.glob("*.py")):
        ex, un = scan(path)
        if ex:
            executable[path.name] = ex
        if un:
            unverifiable[path.name] = un
    return executable, unverifiable


def prints_subprocess_output(path: Path) -> bool:
    """Whether a tool passes a subprocess's captured output to `print`.

    A tool that only *uses* the output (parses it, hashes it) needs the read-side fix alone. A tool
    that **prints** it needs its own stdout to be able to encode it, and on cp1252 that fails for
    the same bytes the read-side fix just made visible.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    captures = "capture_output=True" in text or "stdout=subprocess.PIPE" in text
    if not captures:
        return False
    return "print(" in text and (".stdout" in text or "stdout + " in text or ".stderr" in text)


def stdout_safe(path: Path) -> bool:
    """Whether the tool has made its own stdout encoding-explicit."""
    text = path.read_text(encoding="utf-8", errors="replace")
    return any(marker in text for marker in STDOUT_FIX)


def validate(listing: bool) -> int:
    executable, unverifiable = collect()
    total_ex = sum(len(v) for v in executable.values())
    total_un = sum(len(v) for v in unverifiable.values())

    print(f"scanned                   : {len(list(TOOLS.glob('*.py')))} tool(s) under tools/")
    print(f"locale-decoded call sites : {total_ex} in {len(executable)} file(s)")
    print(f"unverifiable (text=<expr>): {total_un} in {len(unverifiable)} file(s)")

    if listing:
        for name, lines in executable.items():
            for line in lines:
                print(f"  {name}:{line}")

    if total_ex:
        print("")
        print(f"SUBPROCESS ENCODING FAILED -- {total_ex} site(s) decode with the locale's encoding:")
        for name, lines in list(executable.items())[:12]:
            print(f"  {name}  ({len(lines)} site(s)): lines {lines}")
        if len(executable) > 12:
            print(f"  … and {len(executable) - 12} more file(s)")
        print("")
        print("Pass `encoding=\"utf-8\", errors=\"replace\"` to every one. On Windows the default is")
        print("cp1252, so a child emitting UTF-8 kills subprocess's reader thread and `stdout`")
        print("comes back empty -- a silent wrong answer, invisible in CI (§O-268).")
        return 1

    print("")
    print("SUBPROCESS ENCODING OK -- every text-mode call states its encoding")
    if total_un:
        print(f"  note: {total_un} call(s) pass `text=<expression>`; a static scan cannot prove")
        print("        the value, so they are counted as unverifiable rather than clean")
    return 0


def self_test() -> int:
    import tempfile

    failures = 0

    def case(name: str, source: str, want_ex: int, want_un: int) -> None:
        nonlocal failures
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "probe.py"
            p.write_text(source, encoding="utf-8")
            ex, un = scan(p)
        ok = len(ex) == want_ex and len(un) == want_un
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}: executable={len(ex)} unverifiable={len(un)}")
        if not ok:
            failures += 1

    case("text=True with no encoding is an executable site",
         "import subprocess\nsubprocess.run(['git'], text=True)\n", 1, 0)
    case("text=True WITH encoding passes",
         "import subprocess\nsubprocess.run(['git'], text=True, encoding='utf-8')\n", 0, 0)
    case("no text mode is not a site",
         "import subprocess\nsubprocess.run(['git'], capture_output=True)\n", 0, 0)
    case("universal_newlines is the same claim",
         "import subprocess\nsubprocess.run(['git'], universal_newlines=True)\n", 1, 0)
    case("text=<variable> is unverifiable, not clean",
         "import subprocess\nx = True\nsubprocess.run(['git'], text=x)\n", 0, 1)
    case("check_output is covered",
         "import subprocess\nsubprocess.check_output(['git'], text=True)\n", 1, 0)
    case("an unrelated call named run is not covered",
         "def run(*a, **k): pass\nrun(['git'], text=True)\n", 0, 0)
    case("a syntax error yields no findings rather than crashing",
         "this is not python((", 0, 0)
    case("a method named run on an object is still covered",
         "class S:\n    def run(self, *a, **k): pass\nS().run(['git'], text=True)\n", 1, 0)

    # The real corpus must currently be clean -- this is the substantive case, and it is the one
    # that goes red when someone adds a call site.
    executable, _un = collect()
    real = sum(len(v) for v in executable.values())
    ok = real == 0
    print(f"  {'OK  ' if ok else 'DEAD'}  the real tools/ is clean ({real} site(s))")
    if not ok:
        failures += 1

    total = 10
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) behaved wrongly")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s); the scanner and its exemptions are live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--self-test", action="store_true", help="prove the scanner is live")
    ap.add_argument("--list", action="store_true", help="one line per site")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return validate(listing=args.list)


if __name__ == "__main__":
    raise SystemExit(main())
