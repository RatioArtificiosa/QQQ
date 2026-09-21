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

    files = sorted(WIT_DIR.glob("*.wit"))
    if not files:
        print(f"no .wit files found under {WIT_DIR}")
        return 1

    failed: list[tuple[str, str]] = []
    for f in files:
        proc = subprocess.run(
            ["wasm-tools", "component", "wit", str(f)],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            print(f"  OK    {f.name}")
        else:
            print(f"  FAIL  {f.name}")
            detail = (proc.stderr or proc.stdout).strip()
            for line in detail.splitlines()[:6]:
                print(f"        {line}")
            failed.append((f.name, detail))

    print(f"\n{len(files) - len(failed)}/{len(files)} interface(s) valid")
    if failed:
        print("\nWIT VALIDATION FAILED")
        return 1
    print("WIT VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
