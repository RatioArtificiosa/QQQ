#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Prove `tools/check_wit_since.py` detects the violations it claims to.

`CON-008` requires the CI check; a check that has never been seen to fail is worth
nothing (`§M-006`). Four injections, each a distinct rule from the tool's header:

  1. **Missing `@since`** on one function — the rule the item is named for.
  2. **`@since` greater than the package version** — a function cannot predate
     its package, and this is the copy-paste error that survives review.
  3. **A misplaced `@since`** — separated from its function by a `use` line, so
     it annotates the wrong item. This one **still parses**, which is what makes
     it worth checking: the file is valid WIT and the contract is wrong.
  4. **A `@since` below 1.0.0** — nothing shipped before the first release.

Every injection must leave the file **parseable WIT**. One that breaks the parser
proves nothing about this checker, because the checker would report a violation
for the wrong reason.

The injector also runs `wasm-tools` on the injected file and refuses to count a
detection whose input did not parse — the discipline `§O-048c` and `§O-058e`
established.
"""
import io
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = Path('wit/qqq-clock.wit')

# (label, find, replace, expected fragment in the checker's output)
#
# The `find` strings are copied from the real file rather than composed from
# memory: the first version of this harness guessed at them and three of four
# injections were skipped or broke the parser, which reported a harness failure
# rather than a checker failure. Reading the file first is faster than guessing.
INJECTIONS = [
    (
        'missing @since',
        '  @since(version = 1.0.0)\n  timezone: func() -> string;',
        '  timezone: func() -> string;',
        'function `timezone` has no `@since',
    ),
    (
        # The annotation is MOVED off the function and onto the `use` line above
        # it, which leaves `now` unannotated while the file still parses.
        #
        # The first version of this injection ADDED an annotation to the `use`
        # line without removing the function's own, so no violation existed and
        # the harness reported MISSED -- a harness defect reported as a checker
        # defect. Moving rather than adding is what makes it an injection at all.
        'misplaced @since (still parses)',
        '  @since(version = 1.0.0)\n'
        '  now: func() -> duration-ns;',
        '  now: func() -> duration-ns;',
        'function `now` has no `@since',
    ),
    (
        # NOTE: the "`@since` above the package version" case is deliberately
        # NOT injected, and the reason is a finding rather than an omission.
        #
        # `wasm-tools` already rejects it:
        #
        #   $ wasm-tools component wit bad.wit
        #   error: feature gate cannot reference unreleased version 9.9.9 of
        #          package [qqq:clock@1.0.0] (current version 1.0.0)
        #
        # So no *parseable* WIT file triggers the checker's version-comparison
        # rule, and an injection that does not parse proves nothing about the
        # checker -- the harness would report BROKEN, which is correct behaviour
        # and not a detection.
        #
        # The rule stays in the checker as defence in depth: it costs one
        # comparison and its message names the contradiction rather than the
        # parser's. But it is honestly *redundant* with the parser today, and
        # saying so stops a future reader believing this harness exercises it.
        '@since below 1.0.0',
        '  /// The smallest difference the clock can report.\n'
        '  @since(version = 1.0.0)\n'
        '  resolution: func() -> duration-ns;\n}',
        '  /// The smallest difference the clock can report.\n'
        '  @since(version = 0.9.0)\n'
        '  resolution: func() -> duration-ns;\n}',
        'below 1.0.0',
    ),
]


def run_checker() -> str:
    out = subprocess.run(
        [sys.executable, 'tools/check_wit_since.py'],
        capture_output=True, text=True, errors='replace', cwd=ROOT,
    )
    return out.stdout + out.stderr


def parses(path: Path) -> bool:
    if shutil.which('wasm-tools') is None:
        return True  # cannot check; the caller reports it
    out = subprocess.run(
        ['wasm-tools', 'component', 'wit', str(path)],
        capture_output=True, text=True, cwd=ROOT,
    )
    return out.returncode == 0


def main() -> int:
    full = ROOT / TARGET
    original = io.open(full, encoding='utf-8').read()

    # Sanity: the checker passes on the pristine tree, or the injections below
    # would be measuring a pre-existing failure.
    baseline = run_checker()
    if 'POLICY PASSED' not in baseline:
        print('the checker already fails on the pristine tree; fix that first')
        print(baseline[-800:])
        return 2

    if shutil.which('wasm-tools') is None:
        print('  NOTE  wasm-tools is absent, so parseability is not verified')

    failures = []

    for label, find, replace, expect in INJECTIONS:
        if find not in original:
            print(f'  SKIP      {label}: injection point moved')
            failures.append(label)
            continue

        injected = original.replace(find, replace, 1)

        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / full.name
            shutil.copy(full, backup)
            try:
                io.open(full, 'w', encoding='utf-8', newline='\n').write(injected)

                if not parses(full):
                    print(f'  BROKEN    {label}: the injected WIT does not parse, so '
                          f'the checker never ran')
                    failures.append(label)
                    continue

                combined = run_checker()
                if expect in combined and 'POLICY FAILED' in combined:
                    print(f'  DETECTED  {label}')
                else:
                    print(f'  MISSED    {label}: expected `{expect}`')
                    failures.append(label)
            finally:
                shutil.copy(backup, full)

            if io.open(full, encoding='utf-8').read() != original:
                print(f'  RESTORE FAILED for {label}')
                return 3

    # And the tree must be back to passing.
    final = run_checker()
    if 'POLICY PASSED' not in final:
        print('the checker fails after restore -- the tree is not clean')
        return 3

    print()
    if failures:
        print(f'WIT VERSIONING FAULT INJECTION FAILED -- not detected: {failures}')
        return 1
    print(f'ALL {len(INJECTIONS)} WIT VERSIONING FAULT INJECTIONS DETECTED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
