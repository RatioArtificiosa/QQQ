#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check that every vendored WIT dependency is byte-identical to its source in `wit/`.

A guest is built against a **world** (`wit/app/app.wit`, and the same layout again under
`examples/orders-api/wit/`) which vendors the interfaces it uses into `deps/`. Vendoring
means *a copy*, and a copy is correct exactly once: after that it drifts silently.

# The drift this was written after finding

`wit/qqq-http.wit` was corrected to admit that `send` has no transport — that it refuses
unconditionally, that the **resolved** address is not checked, and that there is no
redirect policy. The correction was made *in the source* and the two vendored copies were
left behind, still asserting the retracted guarantee:

    /// allowlist. The host checks the **resolved** authority, so a redirect
    /// cannot be used to escape the allowlist.

That is a **false security property, in the file a guest author's toolchain actually
consumes.** The source file told the truth and the artefact told a lie, and no check looked
at the relationship between them.

`tools/check_wit_bindings.py` enforces the relationship between `wit/` and the `qqq-abi`
registry. It does not look at `deps/`, so every vendored copy was outside every control.
That is `§O-085`'s shape again: a control that covers what it was pointed at and not what
it was supposed to guarantee.

# What is enforced

  1. Every `**/deps/**/*.wit` whose basename has a counterpart in `wit/` is **byte-identical**
     to that counterpart. A one-byte change to either side fails.
  2. A vendored file whose basename has **no** counterpart in `wit/` is reported, not failed:
     a third-party package (`wasi:http`, say) is not ours to compare. It is printed so that
     an unowned vendored file is visible rather than silently skipped.
  3. **Vacuity is a failure.** If no comparable pair exists, the check fails rather than
     passing — a checker that finds nothing to check has proved nothing, and would go on
     passing after a layout change moved the files out of its reach.

Byte-identity rather than a parsed comparison is deliberate: the vendored copy is a copy,
the remedy is a copy, and a structural comparison would accept a file that had drifted in
its documentation — which is precisely the drift that occurred.

Usage:  python tools/check_wit_vendoring.py [--self-test]
Exit:   0 = every vendored copy matches its source, 1 = one does not (or nothing was found)
"""

from __future__ import annotations

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

# Directories that hold build output or history rather than source.
SKIP = {".git", "target", "__pycache__", ".graf", ".scratch", "node_modules"}


def canonical_sources(wit_dir: Path) -> dict[str, bytes]:
    """`basename -> bytes` for every `.wit` directly under `wit/`."""
    return {p.name: p.read_bytes() for p in sorted(wit_dir.glob("*.wit"))}


def vendored_files(root: Path) -> list[Path]:
    """Every `.wit` under a `deps/` directory, excluding build output and history."""
    found = []
    for path in sorted(root.rglob("*.wit")):
        if any(part in SKIP for part in path.parts):
            continue
        if "deps" in path.parts:
            found.append(path)
    return found


def first_difference(a: bytes, b: bytes) -> str:
    """A one-line description of where two byte strings diverge, for the message."""
    if a == b:
        return ""
    la = a.splitlines()
    lb = b.splitlines()
    for i in range(max(len(la), len(lb))):
        x = la[i] if i < len(la) else b"<absent>"
        y = lb[i] if i < len(lb) else b"<absent>"
        if x != y:
            return (
                f"line {i + 1}: vendored {x[:70]!r} != source {y[:70]!r}"
            )
    return f"{len(a)} bytes vs {len(b)} bytes"


def check(pairs: list[tuple[str, bytes, bytes | None]]) -> list[str]:
    """Problems with a list of `(vendored relpath, vendored bytes, canonical bytes|None)`.

    Pure: it takes the bytes rather than reading them, so `--self-test` can inject a
    drifted copy without touching the repository.
    """
    problems: list[str] = []
    comparable = 0
    unowned: list[str] = []

    for relpath, vendored, canonical in pairs:
        if canonical is None:
            unowned.append(relpath)
            continue
        comparable += 1
        if vendored != canonical:
            problems.append(
                f"{relpath} has drifted from its source in `wit/` -- "
                f"{first_difference(vendored, canonical)}"
            )

    if comparable == 0:
        problems.append(
            "no vendored WIT file has a counterpart in `wit/`, so nothing was compared -- "
            "a check that compares nothing is not a passing check"
        )

    for relpath in unowned:
        print(f"  --    {relpath} has no counterpart in `wit/` (third-party; not compared)")

    return problems


def collect() -> list[tuple[str, bytes, bytes | None]]:
    sources = canonical_sources(WIT_DIR)
    pairs: list[tuple[str, bytes, bytes | None]] = []
    for path in vendored_files(ROOT):
        rel = path.relative_to(ROOT).as_posix()
        pairs.append((rel, path.read_bytes(), sources.get(path.name)))
    return pairs


def validate() -> int:
    pairs = collect()
    print(f"vendored WIT files found : {len(pairs)}")
    print(f"canonical sources in wit/: {len(canonical_sources(WIT_DIR))}")
    problems = check(pairs)
    print("")
    if problems:
        print(f"FAIL -- {len(problems)} problem(s):")
        for p in problems:
            print(f"  - {p}")
        return 1
    comparable = sum(1 for _, _, c in pairs if c is not None)
    print(f"OK -- {comparable} vendored copy/copies are byte-identical to `wit/`")
    return 0


def self_test() -> int:
    failures = 0
    SRC = b"package qqq:http@1.0.0;\n\ninterface http {\n  send: func();\n}\n"

    def case(name: str, pairs: list[tuple[str, bytes, bytes | None]], expect: str | None) -> None:
        nonlocal failures
        problems = check(pairs)
        if expect is None:
            ok = not problems
        else:
            ok = any(expect in p for p in problems)
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            for p in problems[:2]:
                print(f"        got: {p}")

    case(
        "an identical copy passes",
        [("wit/app/deps/qqq-http/qqq-http.wit", SRC, SRC)],
        None,
    )
    case(
        "a retracted sentence left in the copy is caught",
        [("wit/app/deps/qqq-http/qqq-http.wit",
          SRC + b"/// The host checks the resolved authority.\n", SRC)],
        "has drifted from its source",
    )
    case(
        "a single changed byte is caught",
        [("a/deps/x/x.wit", SRC.replace(b"send", b"Send"), SRC)],
        "has drifted from its source",
    )
    case(
        "a copy that is behind the source is caught",
        [("a/deps/x/x.wit", SRC, SRC + b"/// new in the source\n")],
        "has drifted from its source",
    )
    case(
        "a third-party copy with no source is reported, not failed",
        [("a/deps/wasi-http/wasi-http.wit", b"package wasi:http@0.2.0;\n", None),
         ("a/deps/x/x.wit", SRC, SRC)],
        None,
    )
    case(
        "no comparable pair fails rather than passing vacuously",
        [("a/deps/wasi-http/wasi-http.wit", b"package wasi:http@0.2.0;\n", None)],
        "nothing was compared",
    )
    case("an empty list fails rather than passing vacuously", [], "nothing was compared")

    # The real repository must currently agree — this is the substantive case.
    real = check(collect())
    ok = not real
    print(f"  {'OK  ' if ok else 'DEAD'}  the real vendored copies match `wit/`")
    if not ok:
        failures += 1
        for p in real[:3]:
            print(f"        {p}")

    total = 8
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every rule is live")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    return validate()


if __name__ == "__main__":
    raise SystemExit(main())
