#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate every WIT interface with `wasm-tools`.

# Why this script exists

The Rust tests in `qqq-abi` assert that the registry and the `.wit` files agree
— every capability maps to exactly one interface, every interface has source,
names are versioned and unique. **They cannot tell whether a `.wit` file is
valid WIT.** The first draft of all thirteen files passed every Rust test while
being rejected outright by `wasm-tools`:

    error: expected '.', found ';'
     --> wit/qqq-clock.wit:7:22
      |

That is the gap this script closes. A structural test checks the shape of your
model; a parser checks the language.

# And why it now has a `--self-test`

`§O-354`: this checker was named as a conformance obligation by `conformance/suite.json`, and
`tools/check_conformance.py` requires every obligation's checker to demonstrate its own failure mode
**in the gates**. Measured across the six WIT-surface checkers: **three** are proven by a
`tools/fault_inject_*.py` harness (`wit_since`, `wit_errors`, `no_ambient`), **two** carry
`--self-test` (`wit_bindings`, `wit_style`), and **this one had neither**. A checker nobody has
watched fail is a checker nobody has seen work, so the missing half was added rather than the
obligation being dropped.

Usage:  python tools/check_wit.py [--self-test]
Exit:   0 = every interface parses, 1 = at least one does not

Requires `wasm-tools` on PATH:
    cargo install wasm-tools --locked
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
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


def validate(target: Path) -> tuple[bool, str]:
    """Run `wasm-tools` on one file or one world-package directory."""
    proc = subprocess.run(
        ["wasm-tools", "component", "wit", str(target)],
        capture_output=True,
        text=True, encoding="utf-8", errors="replace")
    return proc.returncode == 0, (proc.stderr or proc.stdout).strip()


def self_test() -> int:
    """Prove this checker rejects an unparseable interface **and accepts a valid one**.

    # Why both halves are asserted

    A checker that rejected *everything* would also "detect" the malformed input, so a self-test
    showing only the bad case failing proves nothing -- it is satisfied by `return 1`. **The valid
    half is what makes the invalid half mean something.**

    # Why the malformed input is the SUBTLE one

    The file below is missing one semicolon. Every structural assertion in `qqq-abi`'s tests accepts
    it; only a parser rejects it. That is the gap this checker exists to close, so it is the gap the
    self-test injects. A file that was obviously not WIT would exercise the parser and not the case
    that motivated the checker -- `§O-280`'s rule: confirm the injection measured what it claims to.
    """
    if shutil.which("wasm-tools") is None:
        print("SELF-TEST FAILED -- wasm-tools is not on PATH, so nothing was measured.")
        return 1

    valid = "package qqq:probe@1.0.0;\n\ninterface probe {\n  ping: func() -> string;\n}\n"
    # One missing semicolon, and nothing else: measured to exit 1 under `wasm-tools component wit`,
    # while `good.wit` exits 0.
    invalid = "package qqq:probe@1.0.0;\n\ninterface probe {\n  ping: func() -> string\n}\n"

    with tempfile.TemporaryDirectory() as tmp:
        good = Path(tmp) / "good.wit"
        bad = Path(tmp) / "bad.wit"
        # `newline="\n"` is required: on Windows the default would write CRLF and the parser would
        # be measuring the line endings rather than the syntax (`§O-268`, `§O-273`).
        good.write_text(valid, encoding="utf-8", newline="\n")
        bad.write_text(invalid, encoding="utf-8", newline="\n")
        good_ok, good_detail = validate(good)
        bad_ok, bad_detail = validate(bad)

    failures = 0
    if good_ok:
        print("  OK    a valid interface is accepted")
    else:
        print(f"  FAIL  a VALID interface was rejected, so this checker rejects everything: {good_detail}")
        failures += 1
    if not bad_ok:
        first = bad_detail.splitlines()[0] if bad_detail else "(no detail)"
        print(f"  OK    an interface missing one semicolon is rejected: {first}")
    else:
        print("  FAIL  NOT DETECTED: an interface missing one semicolon was accepted")
        failures += 1

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} half(s) wrong")
        return 1
    print("SELF-TEST PASSED -- valid WIT is accepted and a one-character defect is rejected")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()

    if shutil.which("wasm-tools") is None:
        print(
            "wasm-tools not found on PATH.\n"
            "Install it with:  cargo install wasm-tools --locked\n"
            "Skipping WIT validation would mean shipping unparsed interface\n"
            "definitions, so this is a failure rather than a warning."
        )
        return 1

    # Two kinds of WIT live here, and they validate differently.
    #
    # An **interface** file is a self-contained package, so a single file path is
    # the right unit: `wasm-tools` parses it with nothing else.
    #
    # A **world** may reference another package (`export qqq:http/incoming-handler`
    # needs `qqq:http` resolvable), and WIT resolves dependencies only from a
    # `deps/` directory beside the package. So a world is validated as its
    # **directory**, not as a bare file. A bare file fails with
    # `package 'qqq:http@1.0.0' not found` -- measured when the first world landed
    # in `wit/` as `qqq-app.wit` and this checker reported:
    #
    #     FAIL  qqq-app.wit
    #       error: package 'qqq:http@1.0.0' not found. known packages:
    #           qqq:app@1.0.0
    #
    # The layout that satisfies WIT: interfaces in `wit/*.wit`, each world in its
    # own `wit/<name>/` package directory with its dependencies in
    # `wit/<name>/deps/`.
    files = sorted(WIT_DIR.glob("*.wit"))
    worlds = sorted(d for d in WIT_DIR.iterdir() if d.is_dir() and any(d.glob("*.wit")))
    if not files and not worlds:
        print(f"no .wit files found under {WIT_DIR}")
        return 1

    failed: list[tuple[str, str]] = []
    units: list[tuple[str, Path]] = [(f.name, f) for f in files]
    units += [(f"{d.name}/ (world package)", d) for d in worlds]

    for label, target in units:
        ok, detail = validate(target)
        if ok:
            print(f"  OK    {label}")
        else:
            print(f"  FAIL  {label}")
            for line in detail.splitlines()[:6]:
                print(f"        {line}")
            failed.append((label, detail))

    print(f"\n{len(units) - len(failed)}/{len(units)} interface(s)/world(s) valid")
    if failed:
        print("\nWIT VALIDATION FAILED")
        return 1
    print("WIT VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
