#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Fault-inject the Q-Block level checks: break one level, expect the test to fail.

Checklist `REG-005`. The five injections mirror the six tests in
`crates/qqq-core/tests/qblock.rs`: four break one level each, and the fifth
breaks the module agreement the sixth test pins.

1. `declared-count` -- a 23rd interface in WIT. The declared count must move.
2. `bindable-name` -- a capability name outside every manifest stanza. The two
   bindable definitions must disagree.
3. `bound-flag` -- `qqq:fs` flipped to implemented without host code. The bound
   pin must refuse the claim.
4. `level-prose` -- the Observed row broken in Proposal §4.8.5. The prose
   guard must fail rather than let the section silently lose a level.
5. `module-count` -- a phantom 15th module in `HOST_MODULES`. The agreement
   test must refuse a module the linker never registers.

Two properties, learned from `tools/fault_inject_guard.py`:

1. **Every injection must leave the tree in a state the check can run on.**
   The qblock tests read text, so a renamed string literal is still valid Rust
   and a deleted table row is still valid Markdown -- the test runs and fails
   for the right reason, rather than the build breaking before it starts
   (Observations §O-048c).

2. **The backup must not live under the repo, and the restore must be
   verified.** `tempfile` always exists; the script exits non-zero if the
   working tree is left modified.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from _fault_inject_io import restore

# This tool's own stdout must be able to encode what it prints. On a Windows console the stream
# inherits `cp1252`, so a character read from a subprocess -- which this file now reads as UTF-8 --
# raises `UnicodeEncodeError` inside `print` and the tool dies while reporting its result. `§O-291`.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


ROOT = Path(__file__).resolve().parent.parent

INJECTIONS = [
    dict(
        name="declared-count",
        file="wit/qqq-test.wit",
        test="wit_declares_fifteen_packages_and_22_interfaces",
        before="    errored(string),\n  }\n}",
        after="    errored(string),\n  }\n}\n\ninterface phantom-probe {\n}",
        expect="declared interfaces changed",
    ),
    dict(
        name="bindable-name",
        file="crates/qqq-cap/src/capability.rs",
        test="bindable_namespaces_are_thirteen_in_both_definitions",
        before='Self::SecretUse => "secret.use",',
        after='Self::SecretUse => "secret2.use",',
        expect="capability names and manifest stanzas disagree",
    ),
    dict(
        name="bound-flag",
        file="crates/qqq-abi/src/registry.rs",
        test="bound_interfaces_are_ten_pinned_by_name",
        before='"qqq:fs@1.0.0",\n            &[FsRead, FsWrite, FsWatch],\n            false,',
        after='"qqq:fs@1.0.0",\n            &[FsRead, FsWrite, FsWatch],\n            true,',
        expect="bound set changed",
    ),
    dict(
        name="level-prose",
        file="QQQ-Proposal-V1.md",
        test="proposal_section_485_names_all_five_levels",
        # The level name is broken, not the row deleted: the table keeps its
        # shape while the word the guard looks for is gone.
        before="| **Observed** | What did it actually call? | the capability audit stream |",
        after="| **Ob served** | What did it actually call? | the capability audit stream |",
        expect="no longer carries the | **Observed** | table row",
    ),
    dict(
        name="module-count",
        file="crates/qqq-host/src/arch003.rs",
        test="host_module_linker_and_registry_sets_agree",
        before='    "host_http.rs",\n    "host_test.rs",',
        after='    "host_http.rs",\n    "host_test.rs",\n    "host_phantom.rs",',
        expect="HOST_MODULES changed",
    ),
]


def run_one(inj) -> int:
    src = ROOT / inj["file"]
    with open(src, encoding="utf-8") as f:
        original = f.read()
    if inj["before"] not in original:
        print(
            f"[{inj['name']}] the injection point moved; update tools/fault_inject_qblock.py"
        )
        return 2
    injected = original.replace(inj["before"], inj["after"], 1)
    assert injected != original, "the injection must change the file"

    with tempfile.TemporaryDirectory() as tmp:
        backup = Path(tmp) / "orig"
        shutil.copy(src, backup)
        try:
            with open(src, "w", encoding="utf-8", newline="") as f:
                f.write(injected)
            out = subprocess.run(
                ["cargo", "test", "-p", "qqq-core", "--test", "qblock", inj["test"]],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=600,
            )
            combined = out.stdout + out.stderr
            # The DETECTED check comes first: a failing test makes cargo print
            # `error: test failed` as its summary line, so a compile-error
            # heuristic that runs first would misread every detection as a
            # broken instrument.
            if (
                inj["test"] in combined
                and inj["expect"] in combined
                and "FAILED" in combined
            ):
                print(
                    f"[{inj['name']}] DETECTED -- {inj['test']} fails for the right reason"
                )
                return 0
            if "error[E" in combined or "could not compile" in combined:
                print(f"[{inj['name']}] the injected source did not compile:")
                for line in combined.splitlines():
                    if line.startswith("error"):
                        print("  " + line)
                return 2
            print(
                f"[{inj['name']}] NOT DETECTED -- the check passed on injected content"
            )
            print(combined[-1200:])
            return 1
        finally:
            restore(backup, src)


def main() -> int:
    # Byte-exact originals, read before any injection: the restore check
    # compares full bytes, not the absence of the injected text — a restore
    # that differs anywhere else is corruption, not a restore.
    originals = {}
    for inj in INJECTIONS:
        with open(ROOT / inj["file"], encoding="utf-8") as f:
            originals[inj["file"]] = f.read()
    results = []
    for inj in INJECTIONS:
        code = run_one(inj)
        results.append(code)
        with open(ROOT / inj["file"], encoding="utf-8") as f:
            current = f.read()
        if current != originals[inj["file"]]:
            print(f"[{inj['name']}] RESTORE FAILED -- tree left modified")
            return 3
    failed = [INJECTIONS[i]["name"] for i, c in enumerate(results) if c != 0]
    if failed:
        print(f"QBLOCK FAULT INJECTION FAILED -- {failed}")
        return 1
    print("QBLOCK FAULT INJECTION OK -- 5/5 DETECTED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
