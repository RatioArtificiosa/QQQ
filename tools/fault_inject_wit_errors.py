#!/usr/bin/env python3
"""Prove `tools/check_wit_errors.py` detects the violations it claims to.

`CON-009` defines the typed-error rule; the checker enforces it. A rule enforced
by a check that has never been seen to fail is worth nothing (`§M-006`), and this
one has three distinct rules, so each needs its own injection:

  1. **A fallible-looking function with no `result` and no allowlist entry** —
     the primary rule. Injected as a new function in an interface.
  2. **A primitive error type** — `result<list<u8>, string>`, which parses fine
     and defeats §2.5's *"not a status code buried in a payload"*.
  3. **A stale allowlist entry** — a name in INFALLIBLE that no longer exists, so
     the list silently exempts nothing and grows without bound.

Every injection must leave the file **parseable WIT**: an injection that breaks
the parser proves nothing about the checker, because the checker's result would
be about a file no compiler would accept anyway. The harness runs `wasm-tools`
on each injected file and refuses to count a detection whose input did not parse.
"""
import io
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / 'tools'
TARGET = Path('wit/qqq-clock.wit')


def run_checker() -> str:
    out = subprocess.run(
        [sys.executable, 'tools/check_wit_errors.py'],
        capture_output=True, text=True, errors='replace', cwd=ROOT,
    )
    return out.stdout + out.stderr


def parses(path: Path) -> bool:
    if shutil.which('wasm-tools') is None:
        return True
    out = subprocess.run(
        ['wasm-tools', 'component', 'wit', str(path)],
        capture_output=True, text=True, cwd=ROOT,
    )
    return out.returncode == 0


def main() -> int:
    baseline = run_checker()
    if 'RULE PASSED' not in baseline:
        print('the checker already fails on the pristine tree; fix that first')
        print(baseline[-900:])
        return 2

    if shutil.which('wasm-tools') is None:
        print('  NOTE  wasm-tools absent, so parseability is not verified')

    full = ROOT / TARGET
    original = io.open(full, encoding='utf-8').read()
    tools_check = TOOLS / 'check_wit_errors.py'
    tools_original = io.open(tools_check, encoding='utf-8').read()

    failures = []

    # -- 1 and 2: edit the WIT file -------------------------------------------
    wit_injections = [
        (
            'fallible function with no result',
            '  @since(version = 1.0.0)\n  timezone: func() -> string;',
            '  @since(version = 1.0.0)\n  timezone: func() -> string;\n\n'
            '  /// INJECTED: a new function with no error type.\n'
            '  @since(version = 1.0.0)\n'
            '  bogus: func() -> string;',
            '`wall-clock.bogus` returns no `result<T, E>`',
        ),
        (
            'primitive error type',
            '  @since(version = 1.0.0)\n  timezone: func() -> string;',
            '  @since(version = 1.0.0)\n  timezone: func() -> string;\n\n'
            '  /// INJECTED: a result whose error side is a primitive.\n'
            '  @since(version = 1.0.0)\n'
            '  bogus: func() -> result<string, string>;',
            'must be a NAMED variant',
        ),
    ]

    for label, find, replace, expect in wit_injections:
        if find not in original:
            print(f'  SKIP      {label}: injection point moved')
            failures.append(label)
            continue
        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / full.name
            shutil.copy(full, backup)
            try:
                io.open(full, 'w', encoding='utf-8', newline='\n').write(
                    original.replace(find, replace, 1)
                )
                if not parses(full):
                    print(f'  BROKEN    {label}: the injected WIT does not parse')
                    failures.append(label)
                    continue
                combined = run_checker()
                if expect in combined and 'RULE FAILED' in combined:
                    print(f'  DETECTED  {label}')
                else:
                    print(f'  MISSED    {label}: expected `{expect}`')
                    failures.append(label)
            finally:
                shutil.copy(backup, full)

    # -- 3: edit the allowlist -------------------------------------------------
    label = 'stale allowlist entry'
    needle = '    "qqq-clock.wit:wall-clock.timezone": "constant: always UTC",'
    if needle not in tools_original:
        print(f'  SKIP      {label}: allowlist entry moved')
        failures.append(label)
    else:
        injected_tool = tools_original.replace(
            needle,
            '    "qqq-clock.wit:wall-clock.ghost": "INJECTED: names nothing",\n'
            '    "qqq-clock.wit:wall-clock.timezone": "constant: always UTC",',
            1,
        )
        try:
            io.open(tools_check, 'w', encoding='utf-8', newline='\n').write(injected_tool)
            combined = run_checker()
            if 'does not exist in this file' in combined and 'RULE FAILED' in combined:
                print(f'  DETECTED  {label}')
            else:
                print(f'  MISSED    {label}')
                failures.append(label)
        finally:
            io.open(tools_check, 'w', encoding='utf-8', newline='\n').write(tools_original)

    # -- verify the restore ----------------------------------------------------
    if io.open(full, encoding='utf-8').read() != original:
        print('RESTORE FAILED -- the WIT file is left modified')
        return 3
    if io.open(tools_check, encoding='utf-8').read() != tools_original:
        print('RESTORE FAILED -- the checker is left modified')
        return 3

    final = run_checker()
    if 'RULE PASSED' not in final:
        print('the checker fails after restore -- the tree is not clean')
        return 3

    print()
    if failures:
        print(f'TYPED-ERROR FAULT INJECTION FAILED -- not detected: {failures}')
        return 1
    print(f'ALL {len(wit_injections) + 1} TYPED-ERROR FAULT INJECTIONS DETECTED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
