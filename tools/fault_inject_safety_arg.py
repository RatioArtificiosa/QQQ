# SPDX-License-Identifier: Apache-2.0

"""Prove the ARCH-009 exception-process test catches the one state that matters.

`the_unsafe_exception_was_granted_through_its_process` permits three of the four
combinations of (SAFETY.md present, `unsafe` forbidden) and forbids exactly one:
**`unsafe` permitted with no written argument**.

That is the state to inject, and it takes two edits at once — remove `SAFETY.md`
and allow `unsafe` — because either alone is a legitimate point in the process:

  * `SAFETY.md` present, `unsafe` forbidden: the argument is written ahead of
    the code, which is the order that makes it a design decision.
  * `SAFETY.md` absent, `unsafe` forbidden: the stub state.

Both are therefore NOT injected. A harness that injected them would report a
false failure and teach the next person to weaken the test.
"""
import io
import shutil
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
LIB = Path('crates/qqq-sys/src/lib.rs')
SAFETY = Path('crates/qqq-sys/SAFETY.md')


def run_test(name: str) -> str:
    out = subprocess.run(
        ['cargo', 'test', '-p', 'qqq-core', '--test', 'architecture', name],
        capture_output=True, text=True, cwd=ROOT, encoding="utf-8", errors="replace")
    return out.stdout + out.stderr


def main() -> int:
    lib_original = io.open(ROOT / LIB, encoding='utf-8').read()
    needle = '#![forbid(unsafe_code)]'
    if needle not in lib_original:
        print('the injection point moved in qqq-sys; update this script')
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        lib_backup = Path(tmp) / 'lib.rs'
        shutil.copy(ROOT / LIB, lib_backup)
        safety_existed = (ROOT / SAFETY).is_file()
        if safety_existed:
            shutil.copy(ROOT / SAFETY, Path(tmp) / 'SAFETY.md')

        try:
            # Both edits together: this is the violation.
            io.open(ROOT / LIB, 'w', encoding='utf-8', newline='').write(
                lib_original.replace(needle, '#![allow(unsafe_code)]', 1)
            )
            if safety_existed:
                (ROOT / SAFETY).unlink()

            combined = run_test('the_unsafe_exception_was_granted_through_its_process')

            if 'has no' in combined and 'SAFETY.md' in combined and 'FAILED' in combined:
                print('INJECTION DETECTED -- unsafe permitted with no written argument')
                print('  ' + next(l for l in combined.splitlines()
                                  if 'SAFETY.md`' in l).strip()[:150])
                code = 0
            elif 'error[' in combined or '\nerror: ' in combined:
                print('the injected source did not compile, so the check could not run')
                code = 2
            else:
                print('INJECTION NOT DETECTED -- the check passed on a violation')
                print(combined[-1000:])
                code = 1
        finally:
            shutil.copy(lib_backup, ROOT / LIB)
            if safety_existed:
                shutil.copy(Path(tmp) / 'SAFETY.md', ROOT / SAFETY)

    # Verify the restore.
    if io.open(ROOT / LIB, encoding='utf-8').read() != lib_original:
        print('RESTORE FAILED -- qqq-sys/src/lib.rs is left modified')
        return 3
    if safety_existed and not (ROOT / SAFETY).is_file():
        print('RESTORE FAILED -- qqq-sys/SAFETY.md was not put back')
        return 3

    return code


if __name__ == '__main__':
    sys.exit(main())
