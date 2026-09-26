#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check that every WIT file is embedded in `qqq-abi`, and vice versa (`ABI-015`).

`qqq-abi` is how the runtime publishes its interfaces: the crate embeds each `.wit` with
`include_str!` and exposes it through `ALL_WIT`. If a file in `wit/` is not embedded, it
exists on disk and **nowhere else** — no host can serve it, no binding can be generated
from it, and nothing reports a problem.

# The drift this was written after finding

The audit that produced this check found the repository already drifted: `wit/` held 15
files and the crate embedded 13. `qqq-test.wit` and `qqq-agent.wit` had been authored,
validated, and rendered into the reference documentation — and were invisible to the
runtime.

Nothing was broken, which is what made it dangerous: every existing check looked at
`wit/` and found it fine, and nothing looked at the *relationship* between the directory
and the crate. That is the shape of `§O-085` and `§O-088` again — a control that covers
what it was pointed at and not what it was supposed to guarantee.

# What is enforced

  1. Every `wit/*.wit` file appears in an `include_str!` in `crates/qqq-abi/src/wit.rs`.
  2. Every `include_str!` names a file that exists.
  3. Every file's `package <name>@<version>;` line matches the name registered in
     `ALL_WIT`, so the registry cannot advertise a package the WIT does not declare.
  4. `ALL_WIT` is sorted by interface name, because an unsorted registry makes a missing
     entry invisible in a diff — the eye cannot see which name is absent.

Usage:  python tools/check_wit_bindings.py [--self-test]
Exit:   0 = the directory and the crate agree, 1 = they do not
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
BINDINGS = ROOT / "crates" / "qqq-abi" / "src" / "wit.rs"


def embedded_files(text: str) -> set[str]:
    """The `.wit` filenames named by `include_str!` in the bindings crate."""
    return {
        Path(m.group(1)).name
        for m in re.finditer(r'include_str!\("([^"]+\.wit)"\)', text)
    }


def registered_names(text: str) -> list[str]:
    """The interface names in the `ALL_WIT` registry, in declaration order."""
    start = text.find("pub const ALL_WIT")
    if start == -1:
        return []
    end = text.find("];", start)
    body = text[start:end] if end != -1 else text[start:]
    return re.findall(r'\("([^"]+)"\s*,', body)


def declared_package(path: Path) -> str | None:
    """The `package <name>@<version>;` line of a WIT file."""
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("package "):
            return stripped.rstrip(";").replace("package ", "").strip()
    return None


def check(wit_dir: Path, bindings_text: str) -> list[str]:
    """Return the drift problems. Empty means the two agree."""
    problems: list[str] = []

    files = sorted(p.name for p in wit_dir.glob("*.wit"))
    embedded = embedded_files(bindings_text)
    registered = registered_names(bindings_text)

    if not files:
        return [f"no `.wit` files in {wit_dir}"]
    if not embedded:
        return [
            "no `include_str!` for any `.wit` found in the bindings crate. Either the "
            "crate stopped embedding them or the syntax changed, and an empty result "
            "would make every comparison below trivially pass."
        ]

    # 1. Every file on disk must be embedded.
    for name in files:
        if name not in embedded:
            problems.append(
                f"{name} exists in wit/ but is not embedded in qqq-abi, so no host can "
                f"serve it and no binding can be generated from it. It is on disk and "
                f"nowhere else — and nothing else reports that."
            )

    # 2. Every embedded file must exist.
    on_disk = set(files)
    for name in sorted(embedded - on_disk):
        problems.append(
            f"qqq-abi embeds {name}, which does not exist in wit/. The crate would fail "
            f"to compile, so this usually means the file was renamed and only one of the "
            f"two references was updated."
        )

    # 3. The registry must name the package each file declares.
    declared = {p.name: declared_package(p) for p in sorted(wit_dir.glob("*.wit"))}
    registered_set = set(registered)

    for name, package in declared.items():
        if package is None:
            problems.append(f"{name} has no `package <name>@<version>;` line")
            continue
        if name in embedded and package not in registered_set:
            problems.append(
                f"{name} declares package `{package}`, which is not in `ALL_WIT`. A "
                f"registry that advertises a different name than the WIT declares means "
                f"a caller resolving by name finds nothing."
            )

    for reg in registered:
        if reg not in set(v for v in declared.values() if v):
            problems.append(
                f"ALL_WIT registers `{reg}`, which no `.wit` file declares"
            )

    # 4. The registry must be sorted, so a missing entry is visible in a diff.
    if registered != sorted(registered):
        first_bad = next(
            (i for i in range(1, len(registered)) if registered[i] < registered[i - 1]),
            None,
        )
        detail = (
            f"`{registered[first_bad]}` follows `{registered[first_bad - 1]}`"
            if first_bad
            else "order differs from sorted"
        )
        problems.append(
            f"ALL_WIT is not sorted by interface name: {detail}. An unsorted registry "
            f"makes an absent entry invisible in a diff — the eye cannot see which name "
            f"is missing from an arbitrary order."
        )

    return problems


def validate() -> int:
    if not BINDINGS.exists():
        print(f"FATAL: {BINDINGS} does not exist")
        return 1
    if not WIT_DIR.is_dir():
        print(f"FATAL: {WIT_DIR} does not exist")
        return 1

    text = BINDINGS.read_text(encoding="utf-8")
    problems = check(WIT_DIR, text)
    if problems:
        print("WIT BINDINGS FAILED")
        print("")
        for p in problems:
            print(f"  FAIL  {p}")
        return 1

    files = sorted(p.name for p in WIT_DIR.glob("*.wit"))
    print(
        f"WIT BINDINGS OK -- {len(files)} file(s) in wit/, all embedded and registered, "
        f"registry sorted"
    )
    return 0


# A fixture that satisfies every rule, so the negative cases have a baseline.
GOOD_BINDINGS = """\
pub const AI_WIT: &str = include_str!("../../../wit/qqq-ai.wit");
pub const CLOCK_WIT: &str = include_str!("../../../wit/qqq-clock.wit");

pub const ALL_WIT: &[(&str, &str)] = &[
    ("qqq:ai@1.0.0", AI_WIT),
    ("qqq:clock@1.0.0", CLOCK_WIT),
];
"""

GOOD_WIT = {
    "qqq-ai.wit": "package qqq:ai@1.0.0;\ninterface inference {}\n",
    "qqq-clock.wit": "package qqq:clock@1.0.0;\ninterface wall-clock {}\n",
}


def self_test() -> int:
    """Prove every rule fires, using a temporary WIT directory."""
    import shutil
    import tempfile

    failures = 0

    def case(name: str, wit: dict[str, str], bindings: str, expect: str) -> None:
        nonlocal failures
        tmp = Path(tempfile.mkdtemp(prefix="qqq-witbind-selftest-"))
        try:
            for fname, content in wit.items():
                (tmp / fname).write_text(content, encoding="utf-8")
            problems = check(tmp, bindings)
            joined = "\n".join(problems)
            ok = (expect == "" and not problems) or (expect != "" and expect in joined)
            print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
            if not ok:
                failures += 1
                print(f"        expected {expect!r}, got: {joined[:220]}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    case("a consistent pair", GOOD_WIT, GOOD_BINDINGS, "")

    case(
        "a file on disk that is not embedded",
        {**GOOD_WIT, "qqq-new.wit": "package qqq:new@1.0.0;\ninterface n {}\n"},
        GOOD_BINDINGS,
        "is not embedded in qqq-abi",
    )

    case(
        "an embedded file that does not exist",
        GOOD_WIT,
        GOOD_BINDINGS.replace(
            'pub const CLOCK_WIT: &str = include_str!("../../../wit/qqq-clock.wit");',
            'pub const GHOST_WIT: &str = include_str!("../../../wit/qqq-ghost.wit");',
        ).replace('("qqq:clock@1.0.0", CLOCK_WIT),', '("qqq:ghost@1.0.0", GHOST_WIT),'),
        "which does not exist",
    )

    case(
        "a registry entry no file declares",
        GOOD_WIT,
        GOOD_BINDINGS.replace(
            '("qqq:clock@1.0.0", CLOCK_WIT),',
            '("qqq:clock@1.0.0", CLOCK_WIT),\n    ("qqq:zzz@1.0.0", CLOCK_WIT),',
        ),
        "which no `.wit` file declares",
    )

    case(
        "an unsorted registry",
        GOOD_WIT,
        GOOD_BINDINGS.replace(
            '    ("qqq:ai@1.0.0", AI_WIT),\n    ("qqq:clock@1.0.0", CLOCK_WIT),',
            '    ("qqq:clock@1.0.0", CLOCK_WIT),\n    ("qqq:ai@1.0.0", AI_WIT),',
        ),
        "is not sorted by interface name",
    )

    case(
        "a WIT file with no package line",
        {"qqq-ai.wit": "interface inference {}\n", "qqq-clock.wit": GOOD_WIT["qqq-clock.wit"]},
        GOOD_BINDINGS,
        "has no `package",
    )

    # The real repository must currently agree — this is the substantive case.
    real = check(WIT_DIR, BINDINGS.read_text(encoding="utf-8"))
    ok = not real
    print(f"  {'OK  ' if ok else 'DEAD'}  the real wit/ and qqq-abi agree")
    if not ok:
        failures += 1
        for p in real[:3]:
            print(f"        {p}")

    total = 7
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
