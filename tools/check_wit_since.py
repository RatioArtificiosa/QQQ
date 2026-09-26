#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Enforce the WIT interface-versioning policy — Checklist `CON-007` and `CON-008`.

# The policy

Proposal §2.5 (NN-5, explicit contracts over implicit behaviour) states:

> | Interfaces are versioned | Every WIT package is versioned; `@since` /
>   `@unstable` annotations are **mandatory**. |

`CON-007` defines the policy; `CON-008` is this check.

# Why a separate check is needed

`tools/check_wit.py` proves each file **parses**. It cannot prove the annotation
policy is followed, and that was verified rather than assumed: a WIT file with no
`@since` at all is accepted by `wasm-tools` without complaint —

    $ wasm-tools component wit test2.wit
    package test:anno2@1.0.0;
    interface foo { now: func() -> u64; }
    $ echo $?
    0

So a parser proves the language, and this proves the *contract*. They are
different questions and both are required; the same distinction `check_wit.py`
itself documents about structural tests versus parsers.

# What is checked, and why each rule exists

| Rule | Why |
|---|---|
| The file has a `package ... @x.y.z;` line | An unversioned package cannot be depended on precisely; `CON-007` requires SemVer per package |
| Every **exported function** carries `@since(version = ...)` | This is the machine-checkable half of "contracts are explicit". A caller reading the interface learns which version introduced a function without reading a changelog |
| Every `@since` version is `<=` the package version | A function introduced in 2.0.0 inside a package claiming 1.0.0 is a contradiction, and it is the kind of copy-paste error that survives review |
| `@since` appears **before** the item it annotates | WIT gate syntax attaches to the next item. A misplaced annotation silently annotates the wrong thing, which is worse than a missing one because the file still parses |

# What is deliberately NOT required

* **Types and variants.** `CON-007` says "every published WIT function". Types
  inherit their introducer's version within a package, and annotating all of them
  would triple the file size for no information a caller needs.
* **`@unstable`.** The policy admits it as an alternative, but nothing in V1 is
  marked unstable — everything shipped here is claimed stable, so requiring the
  choice would be inventing work. If an unstable interface is added, this tool
  should be extended to accept `@unstable` as satisfying the rule.

Usage:  python tools/check_wit_since.py
Exit:   0 = policy satisfied, 1 = at least one violation
"""

from __future__ import annotations

import re
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

# `package qqq:clock@1.0.0;`
PACKAGE_RE = re.compile(r"^\s*package\s+([a-z0-9-]+):([a-z0-9-]+)@(\d+)\.(\d+)\.(\d+)\s*;")

# `now: func(...) -> ...;` at any indentation, first token the function name.
FUNC_RE = re.compile(r"^\s*([a-z][a-z0-9-]*)\s*:\s*(?:async\s+)?func\b")

# `@since(version = 1.0.0)`
SINCE_RE = re.compile(r"^\s*@since\s*\(\s*version\s*=\s*(\d+)\.(\d+)\.(\d+)\s*\)")

# `world app {`
WORLD_RE = re.compile(r"^\s*world\s+([a-z][a-z0-9-]*)\s*\{")

# `export qqq:http/incoming-handler@1.0.0;`
WORLD_EXPORT_RE = re.compile(r"^\s*export\s+\S+\s*;")


def parse_version(text: str) -> tuple[int, int, int]:
    parts = text.split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def check_file(path: Path) -> list[str]:
    """Return a list of human-readable violations for one `.wit` file."""
    lines = path.read_text(encoding="utf-8").splitlines()
    problems: list[str] = []

    package_version: tuple[int, int, int] | None = None
    for i, line in enumerate(lines, start=1):
        m = PACKAGE_RE.match(line)
        if m:
            package_version = (int(m.group(3)), int(m.group(4)), int(m.group(5)))
            break

    if package_version is None:
        problems.append(
            "no `package <ns>:<name>@x.y.z;` line found; CON-007 requires every "
            "WIT package to be versioned"
        )
        # Without a package version the per-function check cannot run, because
        # "since <= package" is unanswerable.
        return problems

    # The most recent `@since` seen, if it is still "pending" for the next item.
    pending_since: tuple[tuple[int, int, int], int] | None = None
    seen_functions = 0

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # A blank line does not detach an annotation; WIT permits it. A comment
        # does not either — doc comments sit between `@since` and the item.
        if not stripped or stripped.startswith("//") or stripped.startswith("///"):
            continue

        m = SINCE_RE.match(line)
        if m:
            pending_since = (parse_version(f"{m.group(1)}.{m.group(2)}.{m.group(3)}"), i)
            continue

        # Any other gate annotation (`@unstable`, `@deprecated`) also attaches to
        # the next item, so it must not clear a pending `@since`.
        if stripped.startswith("@"):
            continue

        m = FUNC_RE.match(line)
        if m:
            seen_functions += 1
            name = m.group(1)
            if pending_since is None:
                problems.append(
                    f"line {i}: function `{name}` has no `@since(version = ...)`; "
                    "CON-007 makes the annotation mandatory"
                )
            else:
                since, since_line = pending_since
                if since > package_version:
                    problems.append(
                        f"line {since_line}: `@since` {'.'.join(map(str, since))} is "
                        f"greater than the package version "
                        f"{'.'.join(map(str, package_version))}; a function cannot "
                        "predate its package"
                    )
                if since < (1, 0, 0):
                    problems.append(
                        f"line {since_line}: `@since` {'.'.join(map(str, since))} is "
                        "below 1.0.0; nothing shipped before the first release"
                    )
            pending_since = None
            continue

        # Any other structural line ends the "pending" window, so an annotation
        # separated from its target by a `use` or an `interface` declaration is
        # reported rather than silently applied to something later. This is the
        # rule that catches a misplaced annotation, which parses fine.
        if stripped.startswith(("interface ", "world ", "use ", "type ", "record ",
                                "variant ", "enum ", "resource ", "flags ", "}",
                                "package ")):
            pending_since = None

    # A **world** is not an interface. `@since` annotates types and functions, and
    # a world declares neither -- so the versioning policy has nothing to say about
    # one. What it *can* say is that a world must export something: a world that
    # exports nothing is a component contract with no contract in it, and a guest
    # built against it could not be called.
    #
    # This branch exists because the first world in this repository
    # (`wit/qqq-app.wit`, added with `SRV-018`) made the interface rule fire:
    #
    #     FAIL  qqq-app.wit
    #       no exported functions found; if that is true this interface should not
    #       be checked, and if it is not, this checker is broken
    #
    # That guard was doing its job -- it caught a file it did not understand rather
    # than passing it silently, which is the right instinct. The fix is to teach it
    # what a world is, not to exempt the file.
    if any(WORLD_RE.match(line) for line in lines):
        if not any(WORLD_EXPORT_RE.match(line) for line in lines):
            problems.append(
                "world declares no `export`; a world with no export is a contract "
                "with nothing to implement, so no guest could be called through it"
            )
        if any(FUNC_RE.match(line) for line in lines):
            problems.append(
                "world declares a bare `func` outside an interface; WIT places "
                "functions in interfaces, and a stray one here would be invisible "
                "to every other checker"
            )
        # Package versioning still applies -- `CON-007` requires it of every
        # package, world or interface.
        return problems

    if seen_functions == 0:
        problems.append(
            "no exported functions found; if that is true this interface should "
            "not be checked, and if it is not, this checker is broken"
        )

    return problems


def main() -> int:
    # Interfaces in `wit/*.wit`, and each **world package** in its own
    # `wit/<name>/` directory. A world has to live in a package directory because
    # it references `qqq:http`, which WIT resolves only from a sibling `deps/`
    # (see `tools/check_wit.py`).
    #
    # This glob was `wit/*.wit` alone, which silently stopped covering the world
    # the moment it moved into `wit/app/` -- and the world rule below became dead
    # code that could never fire. The fault-injection harness caught it:
    #
    #     MISSED  world with no export: expected `world declares no `export``
    #
    # A checker that no longer reaches its own subject is the failure this whole
    # file exists to prevent, so the harness earns its place again.
    files = sorted(WIT_DIR.glob("*.wit"))
    files += sorted(
        p
        for d in sorted(WIT_DIR.iterdir())
        if d.is_dir() and not d.name == "deps"
        for p in sorted(d.glob("*.wit"))
    )
    if not files:
        print(f"no .wit files found under {WIT_DIR}")
        return 1

    total_functions = 0
    world_count = 0
    all_problems: list[tuple[str, list[str]]] = []

    for f in files:
        problems = check_file(f)
        # Count functions regardless, for an honest summary.
        text = f.read_text(encoding="utf-8")
        for line in text.splitlines():
            if FUNC_RE.match(line):
                total_functions += 1
        if any(WORLD_RE.match(line) for line in text.splitlines()):
            world_count += 1
        if problems:
            print(f"  FAIL  {f.name}")
            for p in problems:
                print(f"        {p}")
            all_problems.append((f.name, problems))
        else:
            print(f"  OK    {f.name}")

    print(
        f"\n{len(files) - len(all_problems)}/{len(files)} file(s) satisfy the "
        f"versioning policy ({total_functions} exported function(s) checked; "
        f"{world_count} world(s))"
    )

    if all_problems:
        print("\nWIT VERSIONING POLICY FAILED")
        return 1
    print("WIT VERSIONING POLICY PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
