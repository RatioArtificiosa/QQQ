#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prove the live-component tests detect disconnected controls; always restore bytes.

Run only with other builds/checkers stopped:
    python tools/fault_inject_live_components.py
"""

from pathlib import Path
import subprocess

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


def main() -> int:
    for name, relative, old, new, selection in CASES:
        path = ROOT / relative
        original = path.read_bytes()
        needle = old.encode()
        if original.count(needle) != 1:
            raise RuntimeError(f"{name}: mutation anchor changed; inspect the implementation")
        try:
            path.write_bytes(original.replace(needle, new.encode(), 1))
            command = ["cargo", "test", "-p", "qqq-run", "--all-features", "--locked", *selection, "--", "--exact", "--nocapture"]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=600)
            output = result.stdout + result.stderr
            if result.returncode == 0 or "test result: FAILED" not in output or "panicked at" not in output:
                print(output)
                raise RuntimeError(f"{name}: expected an executed failing assertion, not a build/tool failure")
            print(f"PASS: {name} mutation was detected by an executed assertion")
        finally:
            path.write_bytes(original)
            assert path.read_bytes() == original
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
