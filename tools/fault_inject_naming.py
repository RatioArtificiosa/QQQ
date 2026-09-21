# SPDX-License-Identifier: Apache-2.0

"""Prove the naming tests detect the defect the objective names.

The objective states: *"a build producing a `qqq` binary is a defect."*
`crates/qqq-core/tests/naming.rs` is what enforces it, and a check that has never
been seen to fail is worth nothing (`§M-006`).

Three injections, each a realistic way the rule gets broken:

  1. `qqq-run`'s `[[bin]] name` changed to `qqq` -- someone "fixing" the binary
     name to match the brand.
  2. A document teaching `qqq new` instead of `qqqai new`.
  3. A package renamed to `qqq` -- the crates.io name that is taken.

Each injection must produce valid TOML or valid Markdown; one that breaks the
build proves nothing about the check.
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
        'binary named qqq',
        Path('crates/qqq-run/Cargo.toml'),
        'name = "qqqai"',
        'name = "qqq"',
        'the_cli_binary_is_named_qqqai_and_never_qqq',
        'binary named `qqq`',
    ),
    (
        'document teaches `qqq new`',
        Path('README.md'),
        'qqqai new',
        'qqq new',
        'the_documents_never_teach_a_bare_qqq_command',
        '`qqq new`',
    ),
    (
        'package named qqq',
        Path('crates/qqq-debug/Cargo.toml'),
        'name = "qqq-debug"',
        'name = "qqq"',
        'no_package_is_named_qqq',
        'named `qqq`',
    ),
]


def run_test(name: str) -> str:
    out = subprocess.run(
        ['cargo', 'test', '-p', 'qqq-core', '--test', 'naming', name],
        capture_output=True, text=True, errors='replace', cwd=ROOT,
    )
    return out.stdout + out.stderr


def main() -> int:
    failures = []

    # `Cargo.lock` is rewritten by Cargo whenever a manifest changes -- including
    # an injected package rename -- and the injector restores only the manifest.
    # Without this, running the harness leaves the lock file modified, which then
    # shows up as an unexplained diff in the next commit. Backed up and verified
    # with the same care as the sources.
    lock = ROOT / 'Cargo.lock'
    lock_original = io.open(lock, encoding='utf-8').read() if lock.is_file() else None

    for label, path, needle, replacement, test_name, expect in INJECTIONS:
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
                # `qqqai new` appears many times in README; replacing only the
                # first is enough and keeps the diff legible.
                io.open(full, 'w', encoding='utf-8', newline='').write(
                    original.replace(needle, replacement, 1)
                )
                combined = run_test(test_name)

                if expect in combined and 'test result: FAILED' in combined:
                    print(f'  DETECTED  {label}')
                elif 'error[' in combined or '\nerror: ' in combined:
                    print(f'  BROKEN    {label}: injected source did not compile')
                    failures.append(label)
                else:
                    print(f'  MISSED    {label}: the check passed on violating input')
                    failures.append(label)
            finally:
                shutil.copy(backup, full)

            if io.open(full, encoding='utf-8').read() != original:
                print(f'  RESTORE FAILED for {label}')
                return 3

    # Restore the lock file too, and say so if it had been rewritten.
    if lock_original is not None:
        io.open(lock, 'w', encoding='utf-8', newline='').write(lock_original)
        if io.open(lock, encoding='utf-8').read() != lock_original:
            print('RESTORE FAILED -- Cargo.lock is left modified')
            return 3

    print()
    if failures:
        print(f'NAMING FAULT INJECTION FAILED -- not detected: {failures}')
        return 1
    print(f'ALL {len(INJECTIONS)} NAMING FAULT INJECTIONS DETECTED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
