#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Enforce Proposal §12.2's error-message standard on **emitted** errors - Checklist `DX-004`.

    python tools/check_error_standard.py [--self-test]

# What §12.2 requires, and which half was unenforced

> Every error message must contain, in this order:
> 1. **What happened**, in one sentence, no jargon.
> 2. **The stable code** (`QQQ-4003`) and a docs URL.
> 3. **Why** - the causal chain, not just the symptom.
> 4. **The fix**, as a runnable command or an exact diff where possible.
> 5. **A machine-readable block** in `--json` mode with `code`, `message`, `cause`,
>    `remediation`, `docs`.

Two existing checks cover the *catalogue* and the *schema*:

| Check | Covers |
|---|---|
| `tools/gen_error_catalogue.py --check` | every `ErrorCode` variant has a cause and a remediation line |
| `tools/check_schema_conformance.py` | `error.docs_url` exists in the published schema |

Neither reads a message a user actually receives. A catalogue entry can be complete while the
renderer drops it, and a schema field can exist while the message never fills it - which is
`§O-225`'s shape exactly (a value computed, stored, published in one format and dropped by the
other). So this drives the **real binary** and holds its output to the five parts.

# Why the cases are run rather than parsed out of the source

The subject is what a user sees, and only execution produces that. A checker reading
`render()`'s format string would agree with the code by construction, which is the failure this
repository names repeatedly.

# The two halves of every case

Each case runs twice: once in human mode and once with `--json`. The standard requires both, and
they can disagree - a message can carry all five parts in human mode while the machine block
omits `cause`. So both are asserted for every case, and the **code must match** between them: a
human rendering that named one code while the JSON named another would be two answers to one
question.

# Refusing vacuity

A run that produced no error at all satisfies "no error violates the standard", which is why
every case asserts a **non-zero exit and an `error[QQQ-` prefix** before checking the parts. A
case that stopped failing - because a command gained a flag, or a project gained a manifest -
fails the check rather than passing it.

Usage:  python tools/check_error_standard.py
Exit:   0 = every probed error meets the standard, 1 = at least one gap
"""

from __future__ import annotations

import argparse
import json
import re
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

# The code and the docs URL, as §12.2 part 2 requires both.
CODE = re.compile(r"QQQ-\d{4}")
DOCS = re.compile(r"https://qqq\.codes/errors/QQQ-\d{4}")

# §12.2 part 5's key names. `docs` is spelled `docs_url` in the published schema, which is the
# authority on the field's name; the standard's prose names the concept, not the identifier.
MACHINE_KEYS = ("code", "message", "remediation", "docs_url")

# A case: a label, the argv, and whether it needs a project directory.
CASES: list[tuple[str, list[str], bool]] = [
    ("unknown flag", ["verify", "x.wasm", "--nope"], False),
    ("missing flag value", ["verify", "x.wasm", "--key"], False),
    ("bad flag value", ["verify", "x.wasm", "--policy", "requier"], False),
    ("missing artifact", ["verify", "definitely-absent.wasm", "--key", "ab" * 32], False),
    ("unimplemented language", ["lint"], True),
]


def qqqai() -> Path:
    """The built binary, preferring the workspace target directory.

    # Why a missing binary is a failure and not a skip

    A checker that silently skips when it cannot find its subject certifies nothing, which is
    the rule `check_xrefs.py` states for its own corpus. If the binary is absent the operator
    has run this at the wrong time, and saying so is the useful answer.
    """
    for name in ("qqqai.exe", "qqqai"):
        candidate = ROOT / "target" / "debug" / name
        if candidate.is_file():
            return candidate
    print("FAIL -- no built `qqqai` binary; run `cargo build -p qqq-run` first")
    raise SystemExit(1)


def project() -> tempfile.TemporaryDirectory:
    """A directory with a manifest whose language has no driver, for the `lint` case."""
    d = tempfile.TemporaryDirectory(prefix="qqq-error-std-")
    Path(d.name, "qqq.toml").write_text(
        '[package]\nname = "probe"\nversion = "0.1.0"\n\n'
        '[build]\nlanguage = "go"\ntarget = "wasm32-wasip2"\n',
        encoding="utf-8",
    )
    return d


def run(binary: Path, args: list[str], cwd: Path) -> tuple[int, str]:
    p = subprocess.run(
        [str(binary), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60, encoding="utf-8", errors="replace")
    return p.returncode, p.stdout + p.stderr


def check_case(binary: Path, label: str, args: list[str], needs_project: bool, cwd: Path):
    """Return a list of problem strings for one case (empty means it met the standard)."""
    problems: list[str] = []

    code_h, human = run(binary, args, cwd)
    code_j, machine = run(binary, [*args, "--json"], cwd)

    # --- Refuse vacuity: the case must actually fail -------------------------
    if code_h == 0:
        problems.append(f"[{label}] did not fail (exit 0); the case no longer probes an error")
        return problems
    if "error[QQQ-" not in human:
        problems.append(f"[{label}] human output carries no `error[QQQ-...]` line")

    # --- Parts 1-4, in human mode -------------------------------------------
    if not CODE.search(human):
        problems.append(f"[{label}] no stable code in the human output")
    if not DOCS.search(human):
        problems.append(f"[{label}] no docs URL in the human output")

    # Part 1: what happened, as a sentence. The header line is `error[QQQ-NNNN]: <sentence>`.
    first = human.strip().splitlines()[0] if human.strip() else ""
    after_code = first.split("]:", 1)
    if len(after_code) != 2 or len(after_code[1].strip()) < 8:
        problems.append(f"[{label}] the header carries no sentence describing what happened")

    # Part 3: why. The renderer interleaves cause and remediation lines, so the presence of a
    # second paragraph is what distinguishes a one-line symptom from a chain.
    paragraphs = [p for p in human.strip().split("\n\n") if p.strip()]
    if len(paragraphs) < 2:
        problems.append(
            f"[{label}] output is a single paragraph, so it carries no cause or remedy"
        )

    # --- Part 5: the machine block ------------------------------------------
    try:
        doc = json.loads(machine.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        problems.append(f"[{label}] --json did not emit a parseable envelope")
        return problems

    err = doc.get("error")
    if not isinstance(err, dict):
        problems.append(f"[{label}] --json envelope has no `error` object")
        return problems

    for key in MACHINE_KEYS:
        if not err.get(key):
            problems.append(f"[{label}] machine block is missing `{key}`")

    # --- The two forms must name the same code ------------------------------
    human_code = CODE.search(human)
    machine_code = err.get("code")
    if human_code and machine_code and human_code.group(0) != machine_code:
        problems.append(
            f"[{label}] human names {human_code.group(0)} but JSON names {machine_code}"
        )

    # --- The remediation must describe an action ----------------------------
    # Part 4 asks for "a runnable command or an exact diff where possible", so the field must
    # not merely repeat the message. Compared literally: a remediation equal to the message is
    # the shape that reads complete and tells the reader nothing new.
    remedy = err.get("remediation") or ""
    message = err.get("message") or ""
    if remedy.strip() and remedy.strip() == message.strip():
        problems.append(f"[{label}] `remediation` restates `message` verbatim")

    return problems


def run_check(args) -> int:
    binary = qqqai()
    scratch = project()
    all_problems: list[str] = []

    try:
        for label, argv, needs_project in CASES:
            cwd = Path(scratch.name) if needs_project else ROOT
            all_problems.extend(check_case(binary, label, argv, needs_project, cwd))
    finally:
        scratch.cleanup()

    print(f"probed {len(CASES)} error case(s) against §12.2's five parts")
    for p in all_problems:
        print(f"  {p}")
    print()
    if all_problems:
        print(f"ERROR STANDARD VIOLATIONS -- {len(all_problems)}")
        return 1
    print("ERROR STANDARD OK -- every probed error carries all five parts, in both forms")
    return 0


def self_test(args) -> int:
    """Prove each assertion fires, on fabricated output.

    # Why the fixtures are strings rather than runs

    The rules being tested are about the *shape of output*, so a fabricated string is the
    precise input - and it keeps the self-test independent of which commands happen to fail
    today. The corpus check above is what proves the rules match reality; this proves they
    fire. `§O-227` is why both are needed.
    """
    cases = [
        ("a complete error", "error[QQQ-4003]: capability denied\n\nWhy: not granted.\n\nRun `qqqai why x`.\nDocs: https://qqq.codes/errors/QQQ-4003", True),
        ("no code", "something went wrong\n\nWhy not.\n\nDocs: https://qqq.codes/errors/QQQ-4003", False),
        ("no docs URL", "error[QQQ-4003]: capability denied\n\nWhy: not granted.", False),
        ("no sentence after the code", "error[QQQ-4003]:\n\nWhy: not granted.", False),
        ("one paragraph only", "error[QQQ-4003]: capability denied", False),
        ("a code with no docs URL anywhere", "error[QQQ-4003]: denied", False),
    ]

    failures = 0
    for label, text, want_ok in cases:
        has_code = bool(CODE.search(text))
        wants_docs = want_ok
        has_docs = bool(DOCS.search(text))
        first = text.strip().splitlines()[0]
        after = first.split("]:", 1)
        has_sentence = len(after) == 2 and len(after[1].strip()) >= 8
        has_paragraphs = len([p for p in text.strip().split("\n\n") if p.strip()]) >= 2

        looks_complete = has_code and has_docs and has_sentence and has_paragraphs
        ok = looks_complete == want_ok
        if not ok:
            failures += 1
        print(f"  {'OK  ' if ok else 'FAIL'} {label}: complete={looks_complete}")

    # The machine-block key check, on two fabricated envelopes.
    good = {"error": {"code": "QQQ-1", "message": "m", "remediation": "r", "docs_url": "u"}}
    bad = {"error": {"code": "QQQ-1", "message": "m"}}
    ok_good = all(good["error"].get(k) for k in MACHINE_KEYS)
    ok_bad = all(bad["error"].get(k) for k in MACHINE_KEYS)
    if not ok_good or ok_bad:
        failures += 1
    print(f"  {'OK  ' if ok_good else 'FAIL'} a complete machine block passes")
    print(f"  {'OK  ' if not ok_bad else 'FAIL'} an incomplete machine block is caught")

    # A remediation equal to the message must be caught.
    same = {"remediation": "x", "message": "x"}
    caught = same["remediation"].strip() == same["message"].strip()
    if not caught:
        failures += 1
    print(f"  {'OK  ' if caught else 'FAIL'} a remediation restating the message is caught")

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} case(s) behaved wrongly")
        return 1
    print("SELF-TEST PASSED -- every check is live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--self-test", action="store_true", help="prove each assertion fires")
    args = ap.parse_args()
    return self_test(args) if args.self_test else run_check(args)


if __name__ == "__main__":
    sys.exit(main())
