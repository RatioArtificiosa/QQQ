# SPDX-License-Identifier: Apache-2.0

"""Fault-inject the HOST-011 guard check: remove one guard, expect the test to fail.

Two properties this script exists to guarantee, both learned the hard way:

1. **The injection must produce valid Rust that is merely unguarded.** Replacing
   a guard call with a syntactic fragment (the first version did) leaves the
   crate uncompilable, and then the check under test never runs -- so a "pass"
   here would say nothing at all (Observations §O-058e, §O-048c).

2. **The backup must not live under `.scratch/`.** That directory is gitignored
   and therefore absent on a fresh CI checkout, so the first version failed in CI
   with `FileNotFoundError` while passing locally -- an environment-dependent
   defect in a check, which is the worst place to have one. `tempfile` always
   exists and cleans up after itself.

3. **The file must be restored even if the process dies.** A `try/finally` covers
   an exception; a `KeyboardInterrupt` or a hard kill does not. The restore is
   therefore also verified at the end, and the script exits non-zero if the
   working tree is left modified -- a fault-injection harness that corrupts the
   tree on failure is worse than no harness.
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


SRC = Path('crates/qqq-host/src/host_clock.rs')

# The `timezone` body: swap the guarded form for a bare expression with the same
# return type. Valid Rust, same behaviour, no guard.
BEFORE = '''            crate::guard::guard("qqq:clock@1.0.0/wall-clock.timezone", || {
                // Always UTC. A host that applied its local timezone would make
                // guest output depend on deployment configuration, which the WIT
                // documentation explicitly forbids.
                Ok(("UTC".to_owned(),))
            })'''
AFTER = '''            // INJECTED: unguarded, for the HOST-011 check's benefit.
            Ok(("UTC".to_owned(),))'''

original = io.open(SRC, encoding='utf-8').read()
if BEFORE not in original:
    print('the injection point moved; update tools/fault_inject_guard.py')
    sys.exit(2)

injected = original.replace(BEFORE, AFTER, 1)
assert injected != original, 'the injection must change the file'

# A temp directory that always exists, unlike `.scratch/`.
with tempfile.TemporaryDirectory() as tmp:
    backup = Path(tmp) / 'host_clock.rs'
    shutil.copy(SRC, backup)
    try:
        io.open(SRC, 'w', encoding='utf-8', newline='').write(injected)

        out = subprocess.run(
            ['cargo', 'test', '-p', 'qqq-host', '--lib', 'every_host_function'],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        combined = out.stdout + out.stderr

        if 'registers 5 host functions but only 4' in combined:
            print('INJECTION DETECTED -- the check fails for the right reason')
            print(
                '  '
                + next(l for l in combined.splitlines() if 'registers 5' in l).strip()[:160]
            )
            code = 0
        elif 'error[E' in combined or '\nerror: ' in combined:
            # The check could not run at all. Reporting success here would be the
            # §O-048c mistake: a broken instrument read as a working one.
            print('the injected source did not compile, so the check could not run:')
            for line in combined.splitlines():
                if line.startswith('error'):
                    print('  ' + line)
            code = 2
        else:
            print('INJECTION NOT DETECTED -- the check passed on unguarded code')
            print(combined[-1200:])
            code = 1
    finally:
        shutil.copy(backup, SRC)

# Verify the restore, because a harness that leaves the tree modified on failure
# is worse than no harness.
restored = io.open(SRC, encoding='utf-8').read()
if restored != original:
    print('RESTORE FAILED -- the working tree is left modified; fix it before committing')
    sys.exit(3)

sys.exit(code)
