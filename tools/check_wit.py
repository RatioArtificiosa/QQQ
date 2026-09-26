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

Usage:  python tools/check_wit.py
Exit:   0 = every interface parses, 1 = at least one does not

Requires `wasm-tools` on PATH:
    cargo install wasm-tools --locked
"""

from __future__ import annotations

import shutil
import subprocess
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


def main() -> int:
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
        proc = subprocess.run(
            ["wasm-tools", "component", "wit", str(target)],
            capture_output=True,
            text=True, encoding="utf-8", errors="replace")
        if proc.returncode == 0:
            print(f"  OK    {label}")
        else:
            print(f"  FAIL  {label}")
            detail = (proc.stderr or proc.stdout).strip()
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
