"""Fault-inject the HOST-011 guard check: remove one guard, expect the test to fail.

The injection must produce *valid Rust* that is merely unguarded — otherwise the
crate fails to compile and the check cannot run, which proves nothing. This is
the trap §O-048c records: an injection that does not compile, or that writes a
file identical to its backup, reports a failure that is not about the system
under test.
"""
import io
import shutil
import subprocess
import sys

SRC = 'crates/qqq-host/src/host_clock.rs'
BAK = '.scratch/host_clock_inject.bak'

shutil.copy(SRC, BAK)

text = io.open(SRC, encoding='utf-8').read()

# The `timezone` body: swap the guarded form for a bare closure with the same
# return type. Valid Rust, same behaviour, no guard.
before = '''            crate::guard::guard("qqq:clock@1.0.0/wall-clock.timezone", || {
                // Always UTC. A host that applied its local timezone would make
                // guest output depend on deployment configuration, which the WIT
                // documentation explicitly forbids.
                Ok(("UTC".to_owned(),))
            })'''
after = '''            // INJECTED: unguarded, for the HOST-011 check's benefit.
            Ok(("UTC".to_owned(),))'''

assert before in text, 'the injection point moved; update this script'
injected = text.replace(before, after, 1)
assert injected != text
io.open(SRC, 'w', encoding='utf-8', newline='').write(injected)

try:
    out = subprocess.run(
        ['cargo', 'test', '-p', 'qqq-host', '--lib', 'every_host_function'],
        capture_output=True, text=True, errors='replace',
    )
    combined = out.stdout + out.stderr
    if 'registers 5 host functions but only 4' in combined:
        print('INJECTION DETECTED -- the check fails for the right reason')
        print('  ' + next(l for l in combined.splitlines()
                          if 'registers 5' in l).strip()[:160])
        sys.exit(0)
    if 'error[E' in combined or 'error: ' in combined:
        print('the injected source did not compile, so the check could not run:')
        for line in combined.splitlines():
            if line.startswith('error'):
                print('  ' + line)
        sys.exit(2)
    print('INJECTION NOT DETECTED -- the check passed on unguarded code')
    print(combined[-1200:])
    sys.exit(1)
finally:
    shutil.copy(BAK, SRC)
