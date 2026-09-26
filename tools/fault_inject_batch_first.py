#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Prove `tools/check_batch_first.py` detects the pair defects it claims to.

`CON-012`'s batch-first rule is only partly decidable, and the checker
deliberately covers the decidable half: **declared batch pairs must be real,
batched, and consistent.** Three injections, one per rule:

  1. **The sibling is missing** — a `-many` deleted or renamed, leaving the
     singular form with no bulk path.
  2. **The sibling is not batched** — `digest-many` rewritten to take a single
     buffer, so it is a batch form in name only.
  3. **The error types disagree** — the most valuable check, because it is
     invisible in review: the two signatures sit in different parts of the file
     and both look correct in isolation.

Plus one **negative control**: adding a brand-new *unpaired* singular function
must NOT fail. The checker deliberately does not demand a batch form for every
singular operation — that is a design judgement for review — and a harness that
never tested this would not notice if the checker drifted into demanding one,
which is the paperwork-generating failure its own docstring describes.

Every injection must leave the file **parseable WIT**, verified with `wasm-tools`
before a detection is counted.
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
        [sys.executable, 'tools/check_batch_first.py'],
        capture_output=True, text=True, cwd=ROOT, encoding="utf-8", errors="replace")
    return out.stdout + out.stderr


def parses(path: Path) -> bool:
    if shutil.which('wasm-tools') is None:
        return True
    out = subprocess.run(
        ['wasm-tools', 'component', 'wit', str(path)],
        capture_output=True, text=True, cwd=ROOT, encoding="utf-8", errors="replace")
    return out.returncode == 0


# (label, file, needle, replacement, expected fragment)
INJECTIONS = [
    (
        'batch sibling renamed away',
        Path('wit/qqq-kv.wit'),
        'get-many: func(store: string, keys: list<string>)',
        'get-all-at-once: func(store: string, keys: list<string>)',
        '`get-many`',
    ),
    (
        # The batch form is rewritten to take ONE buffer, which is what its
        # singular sibling already takes. It is then a batch form in name only --
        # and this is the case that made the checker's first `takes_a_list`
        # implementation wrong: "does the signature contain `list<`" passes
        # `input: list<u8>`, so the crude test certified the defect.
        'batch form takes no collection',
        Path('wit/qqq-crypto.wit'),
        'digest-many: func(algorithm: algorithm, inputs: list<list<u8>>)',
        'digest-many: func(algorithm: algorithm, input: list<u8>)',
        'batch form in name only',
    ),
    (
        # A second error variant is ADDED to the `hashing` interface and the
        # batch sibling is pointed at it, so the file still parses and the pair
        # disagrees.
        #
        # This is the defect review reliably misses: the two signatures sit in
        # different parts of the file and both look correct in isolation, while
        # together they force a caller to handle two failure vocabularies for one
        # operation.
        #
        # Two earlier attempts failed and both taught something about WIT that
        # the injection must respect:
        #
        #   * Naming a nonexistent type does not parse -- obviously.
        #   * Naming a type from a DIFFERENT interface does not parse either:
        #     `error: name 'hmac-error' does not exist`. **WIT types are
        #     interface-scoped**, so an in-file mismatch requires the second
        #     variant to be declared in the same interface. Verified with a
        #     two-variant probe before writing this.
        'error types disagree',
        Path('wit/qqq-crypto.wit'),
        'digest-many: func(algorithm: algorithm, inputs: list<list<u8>>) -> result<list<list<u8>>, hash-error>;',
        'variant injected-other-error {\n    injected-failure,\n  }\n\n'
        '  @since(version = 1.0.0)\n'
        '  digest-many: func(algorithm: algorithm, inputs: list<list<u8>>) -> result<list<list<u8>>, injected-other-error>;',
        'two failure vocabularies',
    ),
]

NEGATIVE_CONTROL = (
    'a new unpaired singular function must NOT fail',
    Path('wit/qqq-clock.wit'),
    '  @since(version = 1.0.0)\n  timezone: func() -> string;',
    '  @since(version = 1.0.0)\n  timezone: func() -> string;\n\n'
    '  /// INJECTED: a new singular function with no batch sibling.\n'
    '  @since(version = 1.0.0)\n'
    '  unpaired-thing: func() -> string;',
)


def main() -> int:
    baseline = run_checker()
    if 'PAIR RULE PASSED' not in baseline:
        print('the checker already fails on the pristine tree; fix that first')
        print(baseline[-800:])
        return 2
    if shutil.which('wasm-tools') is None:
        print('  NOTE  wasm-tools absent, so parseability is not verified')

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
                restore(backup, full)

            if io.open(full, encoding='utf-8').read() != original:
                print(f'  RESTORE FAILED for {label}')
                return 3

    # -- negative control ------------------------------------------------------
    label, path, needle, replacement = NEGATIVE_CONTROL
    full = ROOT / path
    original = io.open(full, encoding='utf-8').read()
    if needle not in original:
        print(f'  SKIP      {label}: injection point moved')
        failures.append(label)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / full.name
            shutil.copy(full, backup)
            try:
                io.open(full, 'w', encoding='utf-8', newline='\n').write(
                    original.replace(needle, replacement, 1)
                )
                if not parses(full):
                    print(f'  BROKEN    {label}: the injected WIT does not parse')
                    failures.append(label)
                else:
                    combined = run_checker()
                    if 'unpaired-thing' in combined and 'RULE FAILED' in combined:
                        print(f'  MISSED    {label}: an unpaired function failed '
                              f'the check, which demands a batch form for every '
                              f'singular operation')
                        failures.append(label)
                    else:
                        print(f'  CONTROL   {label}')
            finally:
                restore(backup, full)

    if 'PAIR RULE PASSED' not in run_checker():
        print('the checker fails after restore -- the tree is not clean')
        return 3

    print()
    if failures:
        print(f'BATCH-FIRST FAULT INJECTION FAILED -- {failures}')
        return 1
    print(
        f'ALL {len(INJECTIONS)} BATCH-FIRST INJECTIONS DETECTED, '
        f'AND THE UNPAIRED-SINGULAR CONTROL HELD'
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
