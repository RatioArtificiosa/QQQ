# SPDX-License-Identifier: Apache-2.0

"""A restore that survives a transient Windows error — `§O-338`.

    from _fault_inject_io import restore
    ...
    finally:
        restore(backup, full)

# Why this module exists

Every `fault_inject_*.py` **modifies a source file on purpose**, then copies a backup back over it. That
restore was a bare `shutil.copy`, and inside the gate it raised:

    File "tools/fault_inject_architecture.py", line 230, in main
        shutil.copy(backup, full)
    OSError: [Errno 22] Invalid argument: 'E:\\QQQ\\crates\\qqq-cap\\Cargo.toml'

**The exception escaped `main`, the restore never happened, and the injected dependency stayed in the
tree.** Three consequences followed, and they are all one defect:

  * `fault_inject_wit_since`, `fault_inject_wit_errors` and `fault_inject_batch_first` then **failed** —
    they run `cargo`, and a broken `Cargo.toml` is a broken workspace;
  * a failing fault injector **leaves its own injection in place**, so the `@since` annotation went too;
  * **`git add -A` committed all of it** — twice, in `02903b7` and `29dbbcd`.

# Why a retry, and why not a better copy

Because the error is **transient by nature**: `Errno 22` writing a path that exists and is writable means
something else held it for a moment — a concurrent `cargo`, an indexer, a scanner. **Retrying is the
answer to a transient failure, and the alternative — a different copy call — would fail the same way.**

# Why the last error is re-raised rather than swallowed

Because a restore that **cannot** happen is a fact the caller must act on: `fault_inject_wit_since`
verifies its restore and returns `3`, and swallowing the error here would turn a **reported** failure
into a **silent** one — which is the shape this whole entry is about.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path

# Enough attempts to outlast a `cargo` build's hold on a file, and few enough that a genuinely
# un-restorable path fails promptly rather than hanging the gate.
ATTEMPTS = 20

# Linear backoff. The holds are short and the total is under four seconds, which is far cheaper than a
# gate that leaves the tree dirty.
DELAY = 0.02


def restore(backup: Path, target: Path, attempts: int = ATTEMPTS) -> None:
    """Copy `backup` over `target`, retrying a transient `OSError`.

    # Errors
    #
    # The last `OSError`, if every attempt fails. **A restore that cannot happen must be loud**, because
    # the caller's `finally` is the only thing standing between an injection and a commit.
    """
    last: OSError | None = None
    for attempt in range(attempts):
        try:
            shutil.copy(backup, target)
            return
        except OSError as e:
            last = e
            time.sleep(DELAY * (attempt + 1))
    raise OSError(
        f"could not restore {target} after {attempts} attempts; the injected state is STILL IN THE TREE "
        f"and `git add -A` would commit it: {last}"
    )


def restore_bytes(backup: Path, target: Path, attempts: int = ATTEMPTS) -> None:
    """Write `backup`'s **bytes** over `target`, retrying a transient `OSError`.

    # Why this exists beside `restore`

    Because `shutil.copy` also copies **metadata**, and on Windows that is a second place to fail. The
    callers that captured the original bytes rather than a file use this, so the retry covers the write
    itself and nothing else.
    """
    data = backup.read_bytes()
    last: OSError | None = None
    for attempt in range(attempts):
        try:
            with open(target, "wb") as f:
                f.write(data)
            return
        except OSError as e:
            last = e
            time.sleep(DELAY * (attempt + 1))
    raise OSError(
        f"could not restore {target} after {attempts} attempts; the injected state is STILL IN THE TREE "
        f"and `git add -A` would commit it: {last}"
    )


def write_bytes(target: Path, data: bytes, attempts: int = ATTEMPTS) -> None:
    """Write `data` over `target`, retrying a transient `OSError`.

    # Why this exists beside `restore_bytes`

    Because a checker that captured the original **in memory** -- rather than copying it to a file --
    has nothing to hand `restore_bytes`. Three of them do exactly that, and they were the ones my
    snapshot/verify bracket **missed**, because they are not named `fault_inject_*`.

    # Errors

    The last `OSError` if every attempt fails. **A restore that cannot happen must be loud**: the
    caller's `finally` is the only thing between an injection and a commit.
    """
    last: OSError | None = None
    for attempt in range(attempts):
        try:
            target.write_bytes(data)
            return
        except OSError as e:
            last = e
            time.sleep(DELAY * (attempt + 1))
    raise OSError(
        f"could not restore {target} after {attempts} attempts; the injected state is STILL IN THE TREE "
        f"and `git add -A` would commit it: {last}"
    )
