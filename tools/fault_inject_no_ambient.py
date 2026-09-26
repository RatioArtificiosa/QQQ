#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Prove `tools/check_no_ambient.py` detects the violations it claims to.

`CON-010` / `CON-018` forbid hidden global state. Four injections, chosen so that
one of them tests the *exemption* rather than the rule:

  1. `std::env::var` in a host crate — the rule the item is named for.
  2. `current_dir` in a host crate — the CWD dependency the Proposal names
     second, and the one that makes an identical artifact behave differently
     depending on where it was launched.
  3. `std::env::temp_dir` in non-test code.
  4. **A bare `std::env::var` INSIDE the exempted file, next to the exempted
     construct.** This is the important one: the exemption is scoped to
     `(file, construct)` rather than to the whole file, so the exempted `var_os`
     in `RealEnv` must not blanket-cover a different construct in the same file.
     A harness that never tested this would not notice if the exemption were
     widened to a file-level skip.

Plus one **negative control**: a construct inside a `#[cfg(test)]` module must NOT
be reported, and the harness asserts that — because a checker that flags test code
would be worked around rather than obeyed.

Every injection must leave the file **compilable**, or the check proves nothing
about a file the compiler would reject anyway. The harness runs `cargo check` on
the injected crate before counting a detection.
"""
import io
import shutil

from _fault_inject_io import restore
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


def run_checker() -> str:
    out = subprocess.run(
        [sys.executable, 'tools/check_no_ambient.py'],
        capture_output=True, text=True, cwd=ROOT, encoding="utf-8", errors="replace")
    return out.stdout + out.stderr


def compiles(crate: str) -> bool:
    out = subprocess.run(
        ['cargo', 'check', '-p', crate, '--quiet'],
        capture_output=True, text=True, cwd=ROOT, encoding="utf-8", errors="replace")
    return out.returncode == 0


# (label, path, needle, replacement, expected fragment)
#
# Every `needle` was READ from the file, not composed from memory. The first
# version of this harness guessed four anchors and three of them did not exist,
# so the run reported SKIP three times and a harness failure was printed as a
# checker failure. Reading the anchors first is faster than guessing.
INJECTIONS = [
    (
        'ambient env read in a host crate',
        Path('crates/qqq-host/src/ambient.rs'),
        'use std::sync::atomic::{AtomicU64, Ordering};',
        '/// INJECTED: an ambient configuration read.\n'
        '#[must_use]\n'
        'pub fn injected_ambient() -> bool {\n'
        '    std::env::var("QQQ_INJECTED").is_ok()\n'
        '}\n\n'
        'use std::sync::atomic::{AtomicU64, Ordering};',
        'std::env::var',
    ),
    (
        'CWD dependency in a host crate',
        Path('crates/qqq-cap/src/normalize.rs'),
        'impl HostEnv for RealEnv {',
        '/// INJECTED: a CWD dependency.\n'
        '#[must_use]\n'
        'pub fn injected_cwd() -> bool {\n'
        '    std::env::current_dir().is_ok()\n'
        '}\n\n'
        'impl HostEnv for RealEnv {',
        'current_dir',
    ),
    (
        'ambient temp_dir outside tests',
        Path('crates/qqq-serve/src/response.rs'),
        'use qqq_core::{Error, ErrorCode};',
        'use qqq_core::{Error, ErrorCode};\n\n'
        '/// INJECTED: an ambient scratch location.\n'
        '#[must_use]\n'
        'pub fn injected_scratch() -> std::path::PathBuf {\n'
        '    std::env::temp_dir()\n'
        '}\n',
        'temp_dir',
    ),
    (
        # The exemption is (file, construct), NOT (file). This injects a
        # DIFFERENT construct into the same file that holds the exempted
        # `var_os`, and it must still fail.
        'a second construct in the exempted file',
        Path('crates/qqq-cap/src/normalize.rs'),
        'impl Normalized {',
        '/// INJECTED: a bare var read, not the exempted var_os.\n'
        '#[must_use]\n'
        'pub fn injected_var() -> Option<String> {\n'
        '    std::env::var("QQQ_INJECTED").ok()\n'
        '}\n\n'
        'impl Normalized {',
        'std::env::var',
    ),
]

NEGATIVE_CONTROL = (
    'a construct inside #[cfg(test)] must NOT be reported',
    Path('crates/qqq-host/src/config.rs'),
    'fn target_triple_is_stable_and_recognised() {',
    'fn target_triple_is_stable_and_recognised() {\n'
    '        let _ = std::env::temp_dir();\n',
    'temp_dir',
)


def main() -> int:
    baseline = run_checker()
    if 'RULE PASSED' not in baseline:
        print('the checker already fails on the pristine tree; fix that first')
        print(baseline[-900:])
        return 2

    failures = []

    for label, path, needle, replacement, expect in INJECTIONS:
        full = ROOT / path
        original = io.open(full, encoding='utf-8').read()
        if needle not in original:
            print(f'  SKIP      {label}: injection point moved in {path}')
            failures.append(label)
            continue

        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / full.name
            shutil.copy(full, backup)
            try:
                io.open(full, 'w', encoding='utf-8', newline='\n').write(
                    original.replace(needle, replacement, 1)
                )
                if not compiles(path.parts[1]):
                    print(f'  BROKEN    {label}: the injected source did not compile')
                    failures.append(label)
                    continue
                combined = run_checker()
                if expect in combined and 'RULE FAILED' in combined:
                    print(f'  DETECTED  {label}')
                else:
                    print(f'  MISSED    {label}: expected `{expect}`')
                    failures.append(label)
            finally:
                restore(backup, full)

            if io.open(full, encoding='utf-8').read() != original:
                print(f'  RESTORE FAILED for {label}')
                return 3

    # -- the negative control --------------------------------------------------
    label, path, needle, replacement, construct = NEGATIVE_CONTROL
    full = ROOT / path
    original = io.open(full, encoding='utf-8').read()
    if needle not in original:
        print(f'  SKIP      {label}: injection point moved in {path}')
        failures.append(label)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / full.name
            shutil.copy(full, backup)
            try:
                io.open(full, 'w', encoding='utf-8', newline='\n').write(
                    original.replace(needle, replacement, 1)
                )
                combined = run_checker()
                if f'{construct}' in combined and 'RULE FAILED' in combined:
                    print(f'  MISSED    {label}: test code was reported')
                    failures.append(label)
                else:
                    print(f'  CONTROL   {label}')
            finally:
                restore(backup, full)

    if run_checker().find('RULE PASSED') < 0:
        print('the checker fails after restore -- the tree is not clean')
        return 3

    print()
    if failures:
        print(f'AMBIENT-STATE FAULT INJECTION FAILED -- {failures}')
        return 1
    print(
        f'ALL {len(INJECTIONS)} AMBIENT-STATE INJECTIONS DETECTED, '
        f'AND THE TEST-CODE CONTROL HELD'
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
