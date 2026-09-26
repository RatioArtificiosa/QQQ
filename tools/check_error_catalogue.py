#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Verify `docs/errors.md` matches the `ErrorCode` enum (`DOC-019`).

A wrapper over `tools/gen_error_catalogue.py --check`, with a self-test.

# Why the self-test is the point

The generator's value is that the catalogue *cannot* be missing a code — the enum is
its only source. That guarantee is only as strong as the parse, and a parser that
silently matched nothing would emit an empty document that the check then agreed with.

So the self-test drives the parse directly on synthetic enum sources, including the
cases that matter:

  * a variant with no doc comment — must be reported, not emitted blank;
  * a variant with no `**Remediation:**` line — must be reported, because §12.2
    requires every code to tell the user what to do;
  * two variants sharing a code — must be reported, because a code that identifies two
    faults identifies neither;
  * a code outside every documented range — must be reported rather than filed under a
    wrong heading.

Each is a realistic mistake, not a synthetic one: a new variant is usually added by
copying a neighbour, and the doc comment is the part that gets dropped.

Usage:
    python tools/check_error_catalogue.py
    python tools/check_error_catalogue.py --self-test
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "tools" / "gen_error_catalogue.py"

# The root the generator is aimed at. `None` means the repository, which is what a
# plain `--check` run wants; the self-test points it at a copy before injecting.
ACTIVE_ROOT: Path | None = None

# Import the generator so the self-test can drive its parser directly, rather than
# only through the `--check` mode that needs a file on disk.
sys.path.insert(0, str(ROOT / "tools"))
import gen_error_catalogue as gen  # noqa: E402

import sys as _sys

# The byte-faithful writer is shared with the other corpus checkers rather than
# copied, because two copies of a newline rule is how the two copies drift.
_sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_xrefs import sandbox_copy, write_text_lf  # noqa: E402


# This tool's own stdout must be able to encode what it prints. On a Windows console the stream
# inherits `cp1252`, so a character read from a subprocess -- which this file now reads as UTF-8 --
# raises `UnicodeEncodeError` inside `print` and the tool dies while reporting its result. `§O-291`.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass



GOOD_ENUM = """\
pub enum ErrorCode {
    // -- 1xxx: build ---------------------------------------------------------
    /// A language toolchain failed to compile the project.
    /// **Remediation:** run the underlying compiler directly.
    CompilationFailed = 1001,
    /// The project's target was not installed.
    /// **Remediation:** `rustup target add wasm32-wasip2`.
    MissingTarget = 1003,
}
"""


def run_check() -> tuple[int, str]:
    args = [sys.executable, str(GEN), "--check"]
    if ACTIVE_ROOT is not None:
        args += ["--root", str(ACTIVE_ROOT)]
    p = subprocess.run(
        args,
        capture_output=True,
        text=True,
        cwd=ROOT, encoding="utf-8", errors="replace")
    return p.returncode, p.stdout + p.stderr


def self_test() -> int:
    failures = 0

    def case(name: str, source: str, expect_problem: str) -> None:
        nonlocal failures
        try:
            variants = gen.parse_variants(source)
            problems = gen.validate(variants)
        except ValueError as e:
            problems = [str(e)]
        joined = "\n".join(problems)
        ok = (expect_problem == "" and not problems) or (
            expect_problem != "" and expect_problem in joined
        )
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            print(f"        expected {expect_problem!r}, got: {joined[:220]}")

    case("a well-formed enum", GOOD_ENUM, "")
    case(
        "a variant with no cause",
        GOOD_ENUM.replace("    /// The project's target was not installed.\n", ""),
        "has no doc comment describing its cause",
    )
    case(
        "a variant with no remediation",
        GOOD_ENUM.replace(
            "    /// **Remediation:** `rustup target add wasm32-wasip2`.\n", ""
        ),
        "has no `**Remediation:**` line",
    )
    case(
        "two variants sharing a code",
        GOOD_ENUM.replace("MissingTarget = 1003", "MissingTarget = 1001"),
        "is assigned to both",
    )
    case(
        "a code outside every documented range",
        GOOD_ENUM.replace("MissingTarget = 1003", "MissingTarget = 9001"),
        "falls outside every documented range",
    )
    case(
        "an enum that is not there",
        "fn main() {}\n",
        "has no `pub enum ErrorCode`",
    )

    # The real repository and the real generated file must currently agree.
    code, out = run_check()
    ok = code == 0
    print(f"  {'OK  ' if ok else 'DEAD'}  the committed catalogue matches the enum")
    if not ok:
        failures += 1
        print(f"        exit {code}: {out.strip()[:220]}")

    # **This case injects, so it runs against a copy.** Mutating the repository's own
    # `docs/errors.md` means a sweep killed mid-injection leaves the file edited and the
    # next run blames the generator (`§O-260`). `--root` aims the generator, and the
    # path below aims the mutation, at the copy: same injection, same expected failure.
    global ACTIVE_ROOT
    _holder = tempfile.TemporaryDirectory(prefix="qqq-errors-")
    ACTIVE_ROOT = sandbox_copy(ROOT, Path(_holder.name) / "root")

    # A hand-edit inside the generated file must be caught.
    target = ACTIVE_ROOT / "docs" / "errors.md"
    original = target.read_text(encoding="utf-8") if target.exists() else None
    try:
        if original is not None:
            write_text_lf(target,original + "\n### `QQQ-9999` — invented\n", encoding="utf-8")
            code, out = run_check()
            ok = code != 0
            print(f"  {'OK  ' if ok else 'DEAD'}  a hand-edit to the generated catalogue")
            if not ok:
                failures += 1
                print(f"        exit {code}: {out.strip()[:220]}")
    finally:
        if original is not None:
            write_text_lf(target,original, encoding="utf-8")

    total = 8
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every check is live")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    code, out = run_check()
    print(out.strip())
    return code


if __name__ == "__main__":
    raise SystemExit(main())
