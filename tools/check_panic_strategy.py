#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Forbid `panic = "abort"` in release-class profiles (`F-01`).

`catch_unwind` only works when the panic strategy is `unwind`. With
`panic = "abort"` the process terminates at the panic site: the HOST-011
panic guard, the handler `JoinError` recovery, and every poison-tolerant
`Drop` become dead code in the shipped binary — while the test suite stays
green, because Cargo always builds test harnesses with unwinding regardless
of the profile. A test cannot observe the shipped strategy; only the
release-profile probe (`panic_probe`, `SURVIVED` on all three OSes) sees
the build as it ships. This checker is the second line of defence: it fails
CI the moment the abort line is reintroduced, including by a `Cargo.toml`
edit no test exercises.

# What is checked, and what is NOT

* `[profile.release]` (and any profile inheriting it without overriding
  `panic`, like `[profile.bench]`) must not set `panic = "abort"`.
  `panic = "unwind"` written explicitly is allowed — it states the
  requirement rather than relying on the default.
* `[profile.dev]`, `[profile.test]`, and test-only profiles are exempt:
  abort in dev/test is a fast-fail choice, not a shipping guarantee.
* Only the workspace root manifest is read: profiles cannot be set by
  dependencies, so there is nowhere else for the line to hide.

Usage:
    python tools/check_panic_strategy.py
    python tools/check_panic_strategy.py --self-test
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_TOML = ROOT / "Cargo.toml"

# This tool's own stdout must be able to encode what it prints. On a Windows
# console the stream inherits `cp1252`, so text read as UTF-8 raises
# `UnicodeEncodeError` inside `print` and the tool dies while reporting its
# result. `§O-291`.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass

# Profiles that ship: release itself plus anything inheriting it. Dev/test
# profiles fail fast locally, which is a workflow choice, not a guarantee.
SHIP_PROFILES = ("release", "bench")
EXEMPT_PROFILES = ("dev", "test")


def check_text(text: str) -> list[str]:
    """Profiles in one manifest text that abort, empty when clean.

    Parsed per-section first, evaluated second: key order inside a table
    must not matter (`panic` before `inherits` aborts exactly like the
    reverse), and a section ends only at the next header, so keys from a
    following table are never attributed to the previous profile.
    """
    sections: list[tuple[str, dict[str, tuple[str, int]]]] = []
    current: str | None = None
    pairs: dict[str, tuple[str, int]] = {}
    for n, line in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*\[profile\.([A-Za-z0-9_-]+)\]\s*(?:#.*)?$", line)
        if m:
            if current is not None:
                sections.append((current, pairs))
            current = m.group(1)
            pairs = {}
            continue
        if current is None:
            continue
        stripped = line.split("#", 1)[0].strip()
        if not stripped or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        pairs[key.strip()] = (value.strip().strip('"'), n)
    if current is not None:
        sections.append((current, pairs))
    problems = []
    for name, kv in sections:
        panic, lineno = kv.get("panic", ("", 0))
        if panic != "abort":
            continue
        if name in SHIP_PROFILES:
            problems.append(f"line {lineno}: [profile.{name}] sets panic = \"abort\"")
        elif kv.get("inherits", ("", 0))[0] == "release" and name not in EXEMPT_PROFILES:
            problems.append(
                f"line {lineno}: [profile.{name}] inherits release and sets panic = \"abort\""
            )
    return problems


def self_test() -> int:
    cases: list[tuple[str, bool, str]] = []

    real = check_text(WORKSPACE_TOML.read_text(encoding="utf-8"))
    cases.append(("the real manifest is clean", not real, f"{real[:1]}"))

    def fires(name: str, doc: str) -> None:
        found = check_text(doc)
        cases.append((name, bool(found), found[0] if found else "NO PROBLEM RAISED"))

    fires(
        "an abort line in [profile.release] is reported",
        '[profile.release]\nopt-level = 3\npanic = "abort"\n',
    )
    fires(
        "an abort line in an inheriting profile is reported",
        '[profile.release]\nopt-level = 3\n[profile.custom]\ninherits = "release"\npanic = "abort"\n',
    )
    fires(
        "panic before inherits in one profile is still reported",
        '[profile.release]\nopt-level = 3\n[profile.custom]\npanic = "abort"\ninherits = "release"\n',
    )
    # An abort in an unrelated custom profile is that profile's own
    # fail-fast choice (like dev/test), not a shipping guarantee — and it
    # must be attributed to its own table, never to release.
    quiet_custom = check_text(
        '[profile.release]\nopt-level = 3\n[profile.custom]\ninherits = "release"\n[profile.other]\npanic = "abort"\n'
    )
    cases.append(
        ("an abort in an unrelated profile stays silent", not quiet_custom, f"{quiet_custom[:1]}")
    )

    quiet = check_text(
        '[profile.release]\nopt-level = 3\npanic = "unwind"\n'
        '[profile.dev]\npanic = "abort"\n'
        '[profile.bench]\ninherits = "release"\nlto = "fat"\n'
    )
    cases.append(("explicit unwind, dev abort, and plain inherit stay silent", not quiet, f"{quiet[:1]}"))

    failed = 0
    print("check_panic_strategy self-test")
    for name, ok, detail in cases:
        print(f"  {'OK ' if ok else 'FAIL'}  {name}  ({detail})")
        failed += not ok
    if failed:
        print(f"SELF-TEST FAILED -- {failed} case(s) wrong")
        return 1
    print("SELF-TEST PASSED -- abort lines fire, explicit unwind stays silent")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    problems = check_text(WORKSPACE_TOML.read_text(encoding="utf-8"))
    if problems:
        for p in problems:
            print(f"FAIL  {p}")
        print("PANIC-STRATEGY FAILED -- release builds must unwind so catch_unwind is live")
        return 1
    print("PANIC-STRATEGY OK -- no release-class profile aborts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
