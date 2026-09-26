#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prove the corpus guard's repair path works, without touching the repository.

# Why this exists

`tools/self_test_xrefs.py`'s `assert_clean_corpus` is the **recovery** path: it
detects left-over fault injections from a killed run, reverses them, and verifies
the reversal. It is the one function in the harness that writes to the corpus, and
until this file nothing tested it -- every path it touches was one of the three real
documents, so testing it meant mutating the repository.

The cost of that gap is `§O-191`. The verification loop read `for path in targets:`
and `targets` was never assigned anywhere in the file, so the guard repaired the
corpus, printed `repaired: QQQ-Proposal-V1.md`, and then raised
`NameError: name 'targets' is not defined` on a corpus it had just made clean. The
harness exited 1 and the Linux bridge's `checks` command failed for a reason that
had nothing to do with the corpus. No test noticed, because no test ran the
function.

# How it tests the real thing

It imports the harness module (safe: the module has a `__main__` guard), copies the
real corpus into a temporary directory, re-points the module's three path constants
and its marker table at the copy, and calls the **real** `assert_clean_corpus`. The
function under test is the shipped one; only its file paths are substituted.

# What it proves

1. A left-over injection is detected and reported.
2. The repair restores the file to its exact original bytes.
3. The verification step runs and the function returns `True` -- the assertion that
   the `NameError` would have failed.
4. A clean corpus returns `True` without writing anything.
5. `autofix=False` detects and refuses, which is the commit gate's behavior.

Usage:  python tools/check_corpus_repair.py [--self-test]
Exit:   0 = every case behaved, 1 = a case failed
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "tools" / "self_test_xrefs.py"

# The byte-faithful writer is shared, not copied, so the newline rule has one
# definition across the corpus tooling.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_xrefs import write_text_lf  # noqa: E402


# This tool's own stdout must be able to encode what it prints. On a Windows console the stream
# inherits `cp1252`, so a character read from a subprocess -- which this file now reads as UTF-8 --
# raises `UnicodeEncodeError` inside `print` and the tool dies while reporting its result. `§O-291`.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


# The three documents the harness mutates, and the marker it leaves behind for
# check [10b] -- chosen because its injection is a single-token substitution and
# therefore the easiest to assert on byte-for-byte.
CORPUS_FILES = (
    "QQQ-Proposal-V1.md",
    "QQQ-Checklist-V1.md",
    "QQQ-Observations-and-Memories.md",
)
MARKER = "\u00a7REMOVED"
# The mutated text, copied verbatim from the harness's own marker table.
INJECTED = MARKER
ORIGINAL = "\u00a7D-005"


def _load_harness():
    """Import `self_test_xrefs.py` as a module.

    The module has an `if __name__ == "__main__"` guard, so importing it does not
    start the harness. It does install signal handlers only inside `main()`, which
    is not called here.
    """
    spec = importlib.util.spec_from_file_location("qqq_self_test_xrefs", HARNESS)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {HARNESS}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stage(tmp: Path) -> None:
    """Copy the real corpus into `tmp` so the harness can be pointed at it."""
    for name in CORPUS_FILES:
        src = ROOT / name
        if not src.exists():
            raise RuntimeError(f"missing corpus file: {src}")
        shutil.copy2(src, tmp / name)


def _point_at(module, tmp: Path) -> None:
    """Re-point the harness's corpus constants and marker table at `tmp`.

    The three constants are module globals read at call time by
    `assert_clean_corpus`, and `INJECTION_MARKERS` is a list of tuples holding the
    `Path` objects. Both must be replaced or the function would search the real
    documents.
    """
    module.PROPOSAL = tmp / "QQQ-Proposal-V1.md"
    module.CHECKLIST = tmp / "QQQ-Checklist-V1.md"
    module.OBS = tmp / "QQQ-Observations-and-Memories.md"

    swapped = []
    for marker, path, source, multi in module.INJECTION_MARKERS:
        if path.name == "QQQ-Proposal-V1.md":
            path = module.PROPOSAL
        elif path.name == "QQQ-Checklist-V1.md":
            path = module.CHECKLIST
        elif path.name == "QQQ-Observations-and-Memories.md":
            path = module.OBS
        swapped.append((marker, path, source, multi))
    module.INJECTION_MARKERS = swapped


def _run_cases() -> int:
    failures = 0
    total = 0

    # The real documents' bytes, captured before anything runs.
    #
    # # Why this is captured and asserted
    #
    # `assert_clean_corpus` prints its warnings to `sys.stderr` with the file's
    # **basename**, which is identical in the temporary copy and in the repository.
    # So the transcript alone cannot prove the write went to the copy, and a checker
    # whose own output is ambiguous should prove the property rather than assert it.
    # This is the proof: every real document must be byte-identical afterwards.
    real_before = {n: (ROOT / n).read_bytes() for n in CORPUS_FILES}

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures, total
        total += 1
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            if detail:
                print(f"         {detail}")

    try:
        module = _load_harness()
    except Exception as e:  # noqa: BLE001
        print(f"  DEAD  the harness imports\n         {e}")
        return 1

    # --- case 1: a clean corpus is reported clean and nothing is written -------
    with tempfile.TemporaryDirectory(prefix="qqq-repair-clean-") as td:
        tmp = Path(td)
        _stage(tmp)
        _point_at(module, tmp)
        before = {n: (tmp / n).read_bytes() for n in CORPUS_FILES}
        try:
            result = module.assert_clean_corpus()
            ok = result is True
            detail = f"returned {result!r}, expected True"
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"raised {type(e).__name__}: {e}"
        after = {n: (tmp / n).read_bytes() for n in CORPUS_FILES}
        check("a clean corpus returns True", ok, detail)
        check(
            "a clean corpus is not written to",
            before == after,
            "a clean run modified a file, so the guard is not read-only when idle",
        )

    # --- case 2: a left-over injection is repaired and verified ----------------
    with tempfile.TemporaryDirectory(prefix="qqq-repair-dirty-") as td:
        tmp = Path(td)
        _stage(tmp)
        target = tmp / "QQQ-Proposal-V1.md"
        pristine = target.read_bytes()

        # Apply the injection exactly as the harness does: replace one token.
        #
        # Written as **bytes**, not text. `Path.write_text` translates newlines on
        # Windows, so the file would come back CRLF and the byte-for-byte assertion
        # below would measure the newline translation rather than the repair -- which
        # is what the first version of this case did, reporting a 3956-byte
        # difference that was entirely `\r`.
        text = pristine.decode("utf-8")
        if ORIGINAL not in text:
            print(f"  DEAD  the injection anchor {ORIGINAL!r} is not in the Proposal")
            return 1
        injected_bytes = text.replace(ORIGINAL, INJECTED, 1).encode("utf-8")
        target.write_bytes(injected_bytes)
        if INJECTED.encode("utf-8") not in target.read_bytes():
            print("  DEAD  the injection did not land, so the case would prove nothing")
            return 1

        _point_at(module, tmp)
        try:
            result = module.assert_clean_corpus()
            ok = result is True
            detail = (
                f"returned {result!r}, expected True -- this is the exact failure of "
                f"\u00a7O-191, where the repair succeeded and the verification raised"
            )
        except Exception as e:  # noqa: BLE001
            ok = False
            detail = (
                f"raised {type(e).__name__}: {e} -- the repair path must not raise "
                f"(\u00a7O-191)"
            )
        check("a left-over injection is repaired and the function returns True", ok, detail)

        # The repair must be surgical: the file back to its exact bytes.
        restored = target.read_bytes()
        check(
            "the repair restores the file byte-for-byte",
            restored == pristine,
            f"the file is {len(restored)} bytes; the original was {len(pristine)}",
        )
        check(
            "the marker is gone after the repair",
            INJECTED not in target.read_text(encoding="utf-8"),
            "the marker survived the repair",
        )

    # --- case 3: autofix=False detects and does not write ---------------------
    with tempfile.TemporaryDirectory(prefix="qqq-repair-detect-") as td:
        tmp = Path(td)
        _stage(tmp)
        target = tmp / "QQQ-Proposal-V1.md"
        text = target.read_text(encoding="utf-8")
        write_text_lf(target,text.replace(ORIGINAL, INJECTED, 1), encoding="utf-8")
        dirty_bytes = target.read_bytes()

        _point_at(module, tmp)
        try:
            result = module.assert_clean_corpus(autofix=False)
            ok = result is False
            detail = f"returned {result!r}, expected False for the detect-only mode"
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"raised {type(e).__name__}: {e}"
        check("autofix=False detects the leftover", ok, detail)
        check(
            "autofix=False leaves the file untouched",
            target.read_bytes() == dirty_bytes,
            "the commit gate must not edit the corpus",
        )

    # --- the exclusive lock, which is what stops two mutators overlapping ------
    #
    # §O-193: a second harness run started while a repair was in progress, restored the
    # first run's injection mid-flight, and left `§C-006` renamed to `REMOVED` in the
    # Observations document -- which read as document drift and cost an audit cycle to
    # trace. A lock is the fix, and a lock that is never exercised is the kind of
    # control this project has been burned by before.
    #
    # The lock is taken at a **temporary path**, never `module.LOCK`, so running this
    # checker cannot disturb a real harness run.
    with tempfile.TemporaryDirectory(prefix="qqq-repair-lock-") as td:
        lock_path = Path(td) / "harness.lock"

        first = module._Lock(lock_path)
        try:
            got_first = first.acquire()
            check("the harness lock can be taken", got_first is True)
            check("the lock file exists while held", lock_path.exists())
            check(
                "the lock file names the owning pid",
                f"pid={os.getpid()}" in lock_path.read_text(encoding="utf-8"),
                f"the file reads {lock_path.read_text(encoding='utf-8')!r}",
            )

            # Capture stderr: `acquire` explains the refusal there, by design.
            import contextlib
            import io

            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                got_second = module._Lock(lock_path).acquire()
            check(
                "a second acquisition is refused while the lock is held",
                got_second is False,
                "two mutators could run at once, which is the §O-193 defect",
            )
            check(
                "the refusal explains why, and names a way forward",
                "cannot overlap" in err.getvalue() and "--break-lock" in err.getvalue(),
                f"the message was {err.getvalue()!r}",
            )
        finally:
            first.release()
        check("the lock file is gone after release", not lock_path.exists())

        # A pid that cannot be running: both platforms cap far below this.
        write_text_lf(lock_path,"pid=999999999 started=1970-01-01T00:00:00", encoding="utf-8")
        third = module._Lock(lock_path)
        try:
            check(
                "a lock whose process is gone is reclaimed",
                third.acquire() is True,
                "a stale lock must not make the harness permanently unusable",
            )
        finally:
            third.release()

        write_text_lf(lock_path,"pid=1 started=1970-01-01T00:00:00", encoding="utf-8")
        module._Lock(lock_path).break_lock()
        check("--break-lock removes the lock", not lock_path.exists())

    # --- the real documents must be byte-identical to before -------------------
    #
    # The assertion that makes every case above trustworthy: the function under test
    # writes files, and the transcript names them by basename alone.
    real_after = {n: (ROOT / n).read_bytes() for n in CORPUS_FILES}
    drifted = [n for n in CORPUS_FILES if real_before[n] != real_after[n]]
    check(
        "no real document was touched",
        not drifted,
        f"the checker modified {drifted} in the repository; the substitution failed",
    )

    if failures:
        print(f"\nFAILED -- {failures}/{total} case(s) bad")
        return 1
    print(f"\nPASSED -- {total}/{total} case(s); the repair path detects, repairs, verifies")
    return 0


def self_test() -> int:
    """Prove this checker fails when the thing it checks is broken.

    # The fault this injects

    `assert_clean_corpus`'s verification loop is rewritten to raise, which is the
    `\u00a7O-191` defect reproduced: the repair succeeds and the verification dies.
    A checker that cannot fail manufactures confidence, so the injected run must
    report FAILED.
    """
    import re

    # Bytes, not text: `Path.write_text` translates newlines on Windows, so the
    # restore below would leave the file CRLF -- the very defect this checker was
    # written for (`§O-191`). Caught by measuring the harness's CRLF count after a
    # self-test run: 704.
    original = HARNESS.read_bytes()
    original_text = original.decode("utf-8")
    anchor = "    for path, _marker, _source in dirty:"
    if anchor not in original_text:
        print("  REFUSING: the verification loop anchor is gone")
        return 1

    fault = "    raise NameError('injected: the verification loop was reached')\n" + anchor
    HARNESS.write_bytes(original_text.replace(anchor, fault, 1).encode("utf-8"))
    if b"injected: the verification loop was reached" not in HARNESS.read_bytes():
        HARNESS.write_bytes(original)
        print("  REFUSING: the fault did not land")
        return 1

    try:
        code = _run_cases_quiet()
    finally:
        HARNESS.write_bytes(original)
        restored = HARNESS.read_bytes()
        if restored != original:
            print("  FATAL: the restore is not byte-for-byte")
            return 1

    if code != 0:
        print("SELF-TEST PASSED -- the fault was detected (the checker exited non-zero)")
        return 0
    print("SELF-TEST FAILED -- the checker passed with the repair path broken")
    return 1


def _run_cases_quiet() -> int:
    """Run the cases with output suppressed, for the self-test."""
    import io
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        return _run_cases()


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    if not HARNESS.exists():
        print(f"FATAL: missing {HARNESS}")
        return 1
    print("The corpus guard's repair path, against a throwaway copy")
    print("=" * 60)
    return _run_cases()


if __name__ == "__main__":
    raise SystemExit(main())
