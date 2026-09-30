#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prove the live-component tests detect disconnected controls; always restore bytes.

Run only with other builds/checkers stopped:
    python tools/fault_inject_live_components.py
"""

from pathlib import Path
import subprocess
import argparse
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
CASES = [
    (
        "stale update",
        "crates/qqq-run/src/generations.rs",
        ".is_none_or(|e| e.requested != update.revision)",
        ".is_none_or(|_| false)",
        ["--lib", "generations::tests::stale_and_foreign_updates_cannot_publish"],
    ),
    (
        "publication",
        "crates/qqq-run/src/live.rs",
        "self.registry\n            .publish(update, next.digest().to_owned(), next)",
        "drop(next); self.registry.cancel(update)?; Ok(0)",
        ["--test", "live_components", "replaced_code_answers_while_old_session_keeps_its_version"],
    ),
    (
        "aggregate capacity",
        "crates/qqq-run/src/guest_handler.rs",
        "next.pool = Arc::clone(&self.pool);",
        "// injected: retain the independent candidate pool",
        ["--test", "live_components", "overlapping_generations_share_one_capacity_limit"],
    ),
    (
        "native cache wiring",
        "crates/qqq-run/src/aot.rs",
        "config.cache(Some(cache.clone()));",
        "config.cache(None);",
        ["--test", "live_components", "native_output_is_real_and_cache_survives_engine_recreation"],
    ),
]


def exercise(path, old, new, invoke):
    """Mutate only a unique anchor, require an executed assertion, restore on every exit."""
    original = path.read_bytes()
    needle = old.encode()
    if original.count(needle) != 1:
        raise RuntimeError("mutation anchor changed; inspect the implementation")
    try:
        path.write_bytes(original.replace(needle, new.encode(), 1))
        result = invoke()
        output = result.stdout + result.stderr
        if result.returncode == 0 or "test result: FAILED" not in output or "panicked at" not in output:
            raise RuntimeError("expected an executed failing assertion, not a build/tool failure")
    finally:
        path.write_bytes(original)
        assert path.read_bytes() == original, "mutation was not restored"


def run():
    for name, relative, old, new, selection in CASES:
        command = ["cargo", "test", "-p", "qqq-run", "--all-features", "--locked", *selection, "--", "--exact", "--nocapture"]
        exercise(ROOT / relative, old, new, lambda: subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=600))
        print(f"PASS: {name} mutation was detected by an executed assertion")
    return 0


def self_test():
    with tempfile.TemporaryDirectory(prefix="qqq-mutation-self-") as temporary:
        path = Path(temporary) / "fixture.rs"
        original = b"unique anchor\r\n"
        path.write_bytes(original)
        calls = []
        def invoke(code, output):
            assert path.read_bytes() == b"changed\r\n"
            calls.append(True)
            return SimpleNamespace(returncode=code, stdout=output, stderr="")
        try:
            exercise(path, "absent", "changed", lambda: invoke(1, ""))
        except RuntimeError as error:
            assert "anchor changed" in str(error)
        else:
            raise AssertionError("missing mutation anchor accepted")
        assert not calls and path.read_bytes() == original
        for code, output in [(0, "test result: ok"), (101, "error: could not compile")]:
            try:
                exercise(path, "unique anchor", "changed", lambda: invoke(code, output))
            except RuntimeError as error:
                assert "executed failing assertion" in str(error)
            else:
                raise AssertionError("passing test or compiler failure accepted")
            assert path.read_bytes() == original
        exercise(path, "unique anchor", "changed", lambda: invoke(101, "panicked at assertion\ntest result: FAILED"))
        assert path.read_bytes() == original
        def failing_invoke():
            raise AssertionError("fixture assertion")
        try:
            exercise(path, "unique anchor", "changed", failing_invoke)
        except AssertionError as error:
            assert str(error) == "fixture assertion"
        else:
            raise AssertionError("fixture exception swallowed")
        assert path.read_bytes() == original
    print("SELF-TEST PASSED: unique anchor, actual failure, compiler refusal and exact-byte restoration")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        return self_test() if args.self_test else run()
    except (AssertionError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
