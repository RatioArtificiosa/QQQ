"""Prove the architecture tests detect real violations.

Three injections, each of which must make exactly the intended test go red:

  1. A topology violation: `qqq-cap` (position 1) gains a dependency on
     `qqq-serve` (position 5) — an edge pointing UP the §4.3 order.
  2. An unsafe-code violation: `qqq-io` loses its `forbid` and takes a bare
     `allow`.
  3. A widening constructor: `qqq-cap` gains a `fn union(` on `GrantSet`.

Every injection must produce **valid Rust or valid TOML** — an injection that
fails to parse proves nothing about the check, because the check never runs
(Observations §O-048c, §O-058e). Where an injection would break the build, this
harness reports that separately rather than counting it as a detection.

The working tree is restored from a `tempfile` copy, not from `.scratch/`, which
is gitignored and absent on a fresh checkout (§O-058f).
"""
import io
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

INJECTIONS = [
    (
        # `qqq-cap` is position 1; `qqq-debug` is position 9. The edge points UP,
        # which is the violation. It is also ACYCLIC, and that matters: the first
        # version of this injection used `qqq-serve`, which created a dependency
        # cycle — `qqq-serve` already depends on `qqq-cap` — so Cargo refused the
        # manifest and the test never ran. That reported "BROKEN", not
        # "DETECTED", and a cycle is a *different* protection from the one under
        # test (§O-059c).
        'topology (upward dependency)',
        Path('crates/qqq-cap/Cargo.toml'),
        '[dependencies]',
        '[dependencies]\nqqq-debug = { path = "../qqq-debug", version = "0.0.0" }',
        'no_crate_depends_on_a_crate_above_it',
        'depends on `qqq-debug`',
    ),
    (
        'unsafe policy (bare allow)',
        Path('crates/qqq-io/src/lib.rs'),
        '#![forbid(unsafe_code)]',
        '#![allow(unsafe_code)]',
        'every_non_exception_crate_forbids_unsafe_code',
        'does not forbid `unsafe_code`',
    ),
    (
        'grant widening (union on GrantSet)',
        Path('crates/qqq-cap/src/resolve.rs'),
        'impl GrantSet {',
        'impl GrantSet {\n    /// INJECTED widening primitive, for the architecture test.\n    pub fn union(&self, _other: &Self) -> Self {\n        self.clone()\n    }\n',
        'no_widening_constructor_on_grants_exists_anywhere',
        'widening primitive',
    ),
]


def run_test(name: str) -> str:
    out = subprocess.run(
        ['cargo', 'test', '-p', 'qqq-core', '--test', 'architecture', name],
        capture_output=True, text=True, errors='replace', cwd=ROOT,
    )
    return out.stdout + out.stderr


def main() -> int:
    failures = []

    for label, path, needle, replacement, test_name, expect in INJECTIONS:
        full = ROOT / path
        original = io.open(full, encoding='utf-8').read()
        if needle not in original:
            print(f'  SKIP  {label}: injection point moved in {path}')
            failures.append(label)
            continue

        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / full.name
            shutil.copy(full, backup)
            try:
                io.open(full, 'w', encoding='utf-8', newline='').write(
                    original.replace(needle, replacement, 1)
                )
                combined = run_test(test_name)

                if expect in combined and 'test result: FAILED' in combined:
                    print(f'  DETECTED  {label}')
                elif 'error[' in combined or 'error: ' in combined:
                    print(f'  BROKEN    {label}: injected source did not compile')
                    for line in combined.splitlines():
                        if line.startswith('error'):
                            print('              ' + line[:120])
                    failures.append(label)
                else:
                    print(f'  MISSED    {label}: the test passed on violating code')
                    failures.append(label)
            finally:
                shutil.copy(backup, full)

            if io.open(full, encoding='utf-8').read() != original:
                print(f'  RESTORE FAILED for {label} -- fix the tree')
                return 3

    print()
    if failures:
        print(f'ARCHITECTURE FAULT INJECTION FAILED -- {len(failures)} of '
              f'{len(INJECTIONS)} injections were not detected: {failures}')
        return 1
    print(f'ALL {len(INJECTIONS)} ARCHITECTURE FAULT INJECTIONS DETECTED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
