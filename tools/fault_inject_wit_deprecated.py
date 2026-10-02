#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Prove `tools/check_wit_deprecated.py` detects the violations it claims to.

`CON-015` requires the CI check; a check that has never been seen to fail is worth
nothing (`§M-006`). Six injections, one per rule in the tool's header, plus a
positive control proving the check does not false-positive:

  1. **Deprecated below `@since`** — `@deprecated(version = 0.9.0)` on a
     function introduced at 1.0.0. Parses (verified); the contradiction is
     the checker's to catch.
  2. **Deprecated above the package version** — `@deprecated(version = 9.9.9)`
     in a 1.0.0 package. Also parses (verified), so unlike the `@since`
     analogue this rule is checker-exclusive rather than defence in depth.
  3. **Deprecated without a ledger row** — a valid annotation the ledger does
     not know about.
  4. **Ledger row without an annotation** — an orphan row in
     `docs/deprecations.md` promising something no interface declares.
  5. **Removal inside the NN-8 window** — ledger removal one minor after
     deprecation, where two are required.
  6. **Positive control** — a valid annotation with a conforming ledger row:
     the checker must PASS. A harness that only breaks things cannot tell a
     strict checker from a broken one that fails everything.

Every injection must leave the file **parseable WIT**. One that breaks the
parser proves nothing about this checker, because the checker would report a
violation for the wrong reason. `wasm-tools` verifies parseability of each
injected file before its detection is counted — the discipline `§O-048c` and
`§O-058e` established.
"""
import io
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _fault_inject_io import restore  # noqa: E402


# This tool's own stdout must be able to encode what it prints. On a Windows console the stream
# inherits `cp1252`, so a character read from a subprocess -- which this file now reads as UTF-8 --
# raises `UnicodeEncodeError` inside `print` and the tool dies while reporting its result. `§O-291`.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


ROOT = Path(__file__).resolve().parent.parent
WIT_TARGET = "wit/qqq-clock.wit"
LEDGER_TARGET = "docs/deprecations.md"

# The anchor both annotation injections build on: `timezone` carries a doc
# comment and `@since(version = 1.0.0)` in package `qqq:clock@1.0.0`.
TIMEZONE_BLOCK = (
    "  @since(version = 1.0.0)\n"
    "  timezone: func() -> string;"
)

# A ledger row the positive control and the window case share.
VALID_ROW = (
    "| `qqq:clock.wall-clock.timezone` | `1.0.0` | `1.2.0` | "
    "`monotonic-clock.now` |\n"
)

# (label, file, find, replace, expected fragment, must_pass, extra edits)
#
# The `find` strings are copied from the real files rather than composed from
# memory. `must_pass` inverts the verdict: the positive control fails the
# harness when the checker reports anything. `extra` maps another tracked
# file to a function building its injected text from the original: the window
# case needs the annotation in the tree AND the bad row in the ledger,
# because a bad row alone is an orphan-row violation that never reaches the
# window rule. The positive control needs its conforming row the same way.
def _window_ledger(original: str) -> str:
    return original.replace(
        "| *(none — no interface item is currently deprecated)* | | | |",
        VALID_ROW.replace("`1.2.0`", "`1.1.0`").rstrip("\n"),
        1,
    )


def _positive_ledger(original: str) -> str:
    return original.replace(
        "| *(none — no interface item is currently deprecated)* | | | |",
        VALID_ROW.rstrip("\n"),
        1,
    )


VALID_ANNOTATION = (
    "  @since(version = 1.0.0)\n"
    "  @deprecated(version = 1.0.0)\n"
    "  timezone: func() -> string;"
)

# A named type declaration with its doc block, for the type-level case. The
# `@since` is required: the toolchain itself rejects `@deprecated` without
# `@since` or `@unstable` ("cannot specify both @deprecated without @since
# or @unstable"), so an injection without it could never parse — and an
# injection that does not parse proves nothing about this checker. The
# checker's own without-`@since` rule stays as defence in depth and says so.
VARIANT_BLOCK = (
    "  /// Why a clock operation failed.\n"
    "  variant clock-error {"
)
VARIANT_INJECTED = (
    "  /// Why a clock operation failed.\n"
    "  @since(version = 1.0.0)\n"
    "  @deprecated(version = 1.0.0)\n"
    "  variant clock-error {"
)
INJECTIONS = [
    (
        "deprecated below @since",
        WIT_TARGET,
        TIMEZONE_BLOCK,
        "  @since(version = 1.0.0)\n"
        "  @deprecated(version = 0.9.0)\n"
        "  timezone: func() -> string;",
        "before its `@since`",
        False,
        {},
    ),
    (
        "deprecated above the package version",
        WIT_TARGET,
        TIMEZONE_BLOCK,
        "  @since(version = 1.0.0)\n"
        "  @deprecated(version = 9.9.9)\n"
        "  timezone: func() -> string;",
        "after the package",
        False,
        {},
    ),
    (
        "deprecated without a ledger row",
        WIT_TARGET,
        TIMEZONE_BLOCK,
        "  @since(version = 1.0.0)\n"
        "  @deprecated(version = 1.0.0)\n"
        "  timezone: func() -> string;",
        "with no ledger row",
        False,
        {},
    ),
    (
        "deprecated type without a ledger row",
        WIT_TARGET,
        VARIANT_BLOCK,
        VARIANT_INJECTED,
        "with no ledger row",
        False,
        {},
    ),
    (
        "ledger row without an annotation",
        LEDGER_TARGET,
        "| *(none — no interface item is currently deprecated)* | | | |",
        VALID_ROW.rstrip("\n").replace(
            "`qqq:clock.wall-clock.timezone`", "`qqq:clock.wall-clock.now`"
        ),
        "names no live",
        False,
        {},
    ),
    (
        "removal inside the two-minor window",
        WIT_TARGET,
        TIMEZONE_BLOCK,
        VALID_ANNOTATION,
        "inside NN-8",
        False,
        {LEDGER_TARGET: _window_ledger},
    ),
    (
        "positive control: valid annotation with a conforming row",
        WIT_TARGET,
        TIMEZONE_BLOCK,
        VALID_ANNOTATION,
        "1 deprecated item(s)",
        True,
        {LEDGER_TARGET: _positive_ledger},
    ),
]

# Every `extra` builder above replaces the placeholder; an `extra` whose
# find text moved is a harness defect, reported rather than silently skipped.


def run_checker() -> subprocess.CompletedProcess[str]:
    """The checker result with its exit status preserved.

    Text matching alone would count a checker that prints FAILED yet exits 0
    as a detection — a harness that cannot tell a failing check from a
    noisy pass certifies nothing. Every verdict below requires the status
    AND the text to agree.
    """
    return subprocess.run(
        [sys.executable, "tools/check_wit_deprecated.py"],
        capture_output=True, text=True, cwd=ROOT, encoding="utf-8", errors="replace")


def parses(path: Path) -> bool:
    out = subprocess.run(
        ["wasm-tools", "component", "wit", str(path)],
        capture_output=True, text=True, cwd=ROOT, encoding="utf-8", errors="replace")
    return out.returncode == 0


def main() -> int:
    # `wasm-tools` is not optional here: every detection below is meaningful
    # only on parseable input, and a harness that reports DETECTED without
    # verifying parseability certifies nothing. CI and the bridge image both
    # install it; a checkout without it fails loudly rather than passing
    # quietly.
    if shutil.which("wasm-tools") is None:
        print("wasm-tools is absent: parseability cannot be verified, aborting")
        return 2
    # Sanity: the checker passes on the pristine tree, or the injections below
    # would be measuring a pre-existing failure.
    baseline = run_checker()
    if baseline.returncode != 0 or "POLICY OK" not in (baseline.stdout + baseline.stderr):
        print("the checker already fails on the pristine tree; fix that first")
        print((baseline.stdout + baseline.stderr)[-800:])
        return 2

    originals: dict[str, str] = {}
    for _label, rel, _find, _replace, _expect, _must_pass, _extra in INJECTIONS:
        path = ROOT / rel
        if rel not in originals:
            if not path.is_file():
                print(f"  SKIP      target {rel} does not exist")
                return 2
            originals[rel] = io.open(path, encoding="utf-8").read()

    failures = []

    for label, rel, find, replace, expect, must_pass, extras in INJECTIONS:
        full = ROOT / rel
        original = originals[rel]

        if find not in original:
            print(f"  SKIP      {label}: injection point moved")
            failures.append(label)
            continue

        injected = original.replace(find, replace, 1)
        extra: dict[str, str] = {}
        broken_extra = False
        for extra_rel, build in extras.items():
            extra_original = originals.get(extra_rel)
            if extra_original is None:
                path = ROOT / extra_rel
                if not path.is_file():
                    print(f"  SKIP      {label}: extra target {extra_rel} missing")
                    failures.append(label)
                    broken_extra = True
                    break
                extra_original = originals[extra_rel] = io.open(path, encoding="utf-8").read()
            extra[extra_rel] = build(extra_original)
        if broken_extra:
            # Skip the whole label: injecting without the companion edit
            # would fail for the wrong reason and report a second MISSED for
            # one missing file.
            continue

        with tempfile.TemporaryDirectory() as tmp:
            backups = {r: Path(tmp) / Path(r).name for r in {rel, *extra}}
            for r, backup in backups.items():
                shutil.copy(ROOT / r, backup)
            try:
                io.open(full, "w", encoding="utf-8", newline="\n").write(injected)
                for r, text in extra.items():
                    io.open(ROOT / r, "w", encoding="utf-8", newline="\n").write(text)

                if rel.endswith(".wit") and not parses(full):
                    print(f"  BROKEN    {label}: the injected WIT does not parse, so "
                          f"the checker never ran")
                    failures.append(label)
                    continue

                combined = run_checker()
                text = combined.stdout + combined.stderr
                if must_pass:
                    if (
                        combined.returncode == 0
                        and "POLICY OK" in text
                        and "1 deprecated item(s)" in text
                    ):
                        print(f"  DETECTED  {label} (pass, as required)")
                    else:
                        print(f"  MISSED    {label}: expected a clean pass")
                        failures.append(label)
                elif (
                    combined.returncode != 0
                    and expect in text
                    and "POLICY FAILED" in text
                ):
                    print(f"  DETECTED  {label}")
                else:
                    print(f"  MISSED    {label}: expected `{expect}`")
                    failures.append(label)
            finally:
                for r, backup in backups.items():
                    restore(backup, ROOT / r)

            for r in {rel, *extra}:
                if io.open(ROOT / r, encoding="utf-8").read() != originals[r]:
                    print(f"  RESTORE FAILED for {label} ({r})")
                    return 3

    # And every touched file must be back to its original bytes.
    for rel, original in originals.items():
        if io.open(ROOT / rel, encoding="utf-8").read() != original:
            print(f"  RESTORE FAILED for {rel}")
            return 3

    # And the tree must be back to passing.
    final = run_checker()
    if final.returncode != 0 or "POLICY OK" not in (final.stdout + final.stderr):
        print("the checker fails after restore -- the tree is not clean")
        return 3

    print()
    if failures:
        print(f"WIT DEPRECATION FAULT INJECTION FAILED -- not detected: {failures}")
        return 1
    print(f"ALL {len(INJECTIONS)} WIT DEPRECATION FAULT INJECTIONS DETECTED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
