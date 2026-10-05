#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Verify `ErrorCode::all()` lists every enum variant (`F-02` follow-up).

`from_number`, `parse`, and the schema output all read through `all()`, so a
variant missing from that list is a code the runtime cannot name — while the
catalogue, the cookbook, and the llms index all claim it exists. That is the
§11 shape exactly: a registry that looks complete from the documents and is
incomplete from the code. `GuestResponseRefused` shipped that way; this
checker is the guard that stops the next code doing the same.

# Why the self-test is the point

The check is a set comparison between two parses of one file. Either parse
silently matching nothing would agree with anything — an empty `all()` would
pass against an empty variant list, which is vacuity, not verification. So
the self-test drives both parses on synthetic sources, including the cases
that matter:

  * a variant missing from `all()` — must be reported (the 3009 defect);
  * an `all()` entry naming no variant — must be reported (a stale name
    after a rename keeps `from_number` honest about nothing);
  * an empty `all()` — must be reported, not agreed with;
  * an enum the parser cannot find — must raise rather than return empty.

Usage:
    python tools/check_error_all.py
    python tools/check_error_all.py --self-test
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ERROR_RS = ROOT / "crates" / "qqq-core" / "src" / "error.rs"

# Reuse the catalogue generator's variant parse rather than copying it: two
# copies of the enum grammar is how the two copies drift, and the drift would
# land exactly here, as a variant one parser sees and the other does not.
sys.path.insert(0, str(ROOT / "tools"))
import gen_error_catalogue as gen  # noqa: E402

# This tool's own stdout must be able to encode what it prints. On a Windows
# console the stream inherits `cp1252`, so a variant name read as UTF-8 raises
# `UnicodeEncodeError` inside `print` and the tool dies while reporting its
# result. `§O-291`.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


def parse_all_entries(text: str) -> list[str]:
    """Every `Self::Variant` named in `ErrorCode::all()`.

    Raises when the function itself cannot be found, because an empty result
    would agree with an empty `all()` and the check would then certify
    nothing.
    """
    marker = "pub const fn all()"
    start = text.find(marker)
    if start == -1:
        raise ValueError("crates/qqq-core/src/error.rs has no `ErrorCode::all`")
    body = text[start:]
    end = body.find("\n    }")
    if end == -1:
        raise ValueError("`ErrorCode::all` body never closes")
    return re.findall(r"Self::([A-Z][A-Za-z0-9]*)", body[:end])


def classify(source: str) -> list[str]:
    """Problems with the `all()` list for one source text, empty when clean."""
    variants = {v["variant"] for v in gen.parse_variants(source)}
    listed = parse_all_entries(source)
    problems = []
    for name in sorted(variants - set(listed)):
        problems.append(f"{name}: declared by the enum and absent from `all()`")
    for name in sorted(set(listed) - variants):
        problems.append(f"{name}: listed in `all()` and absent from the enum")
    if not listed:
        problems.append("`all()` lists nothing")
    return problems


def self_test() -> int:
    cases: list[tuple[str, bool, str]] = []

    def fires(name: str, mutate) -> None:
        text = ERROR_RS.read_text(encoding="utf-8")
        clean = classify(text)
        cases.append((f"the real tree is clean ({name} control)", not clean, f"{clean[:1]}"))
        broken = classify(mutate(text))
        cases.append((name, bool(broken), broken[0] if broken else "NO PROBLEM RAISED"))

    def drop_from_all(text: str) -> str:
        code = next(c for c in parse_all_entries(text) if c != "CompilationFailed")
        return text.replace(f"Self::{code},", "", 1)

    fires("a variant missing from `all()` is reported", drop_from_all)

    def phantom_entry(text: str) -> str:
        return text.replace("Self::CompilationFailed,", "Self::CompilationFailed,\n            Self::NoSuchCode,", 1)

    fires("an `all()` entry naming no variant is reported", phantom_entry)

    def empty_all(text: str) -> str:
        start = text.find("pub const fn all()")
        end = text.find("\n    }", start)
        return text[:start] + "pub const fn all()\n    }\n" + text[end + len("\n    }"):]

    fires("an empty `all()` is reported", empty_all)

    def no_enum(text: str) -> str:
        return text.replace("pub enum ErrorCode {", "pub enum ErrorCodeRenamed {", 1)

    try:
        classify(no_enum(ERROR_RS.read_text(encoding="utf-8")))
        cases.append(("an enum the parser cannot find is reported", False, "NO PROBLEM RAISED"))
    except ValueError as e:
        cases.append(("an enum the parser cannot find is reported", True, f"{e}"))

    try:
        parse_all_entries("no function here")
        cases.append(("an `all()` the parser cannot find is reported", False, "NO PROBLEM RAISED"))
    except ValueError as e:
        cases.append(("an `all()` the parser cannot find is reported", True, f"{e}"))

    failed = 0
    print("check_error_all self-test")
    for name, ok, detail in cases:
        print(f"  {'OK ' if ok else 'FAIL'}  {name}  ({detail})")
        failed += not ok
    if failed:
        print(f"SELF-TEST FAILED -- {failed} case(s) wrong")
        return 1
    print("SELF-TEST PASSED -- every predicate fires on a mutated copy, and is silent on the real one")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    try:
        problems = classify(ERROR_RS.read_text(encoding="utf-8"))
    except ValueError as e:
        print(f"FATAL: {e}")
        return 1
    if problems:
        for p in problems:
            print(f"FAIL  {p}")
        print("ERROR ALL FAILED -- every enum variant must appear in `ErrorCode::all()`")
        return 1
    count = len(parse_all_entries(ERROR_RS.read_text(encoding="utf-8")))
    print(f"ERROR ALL OK -- {count} code(s) in `all()`, every enum variant listed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
