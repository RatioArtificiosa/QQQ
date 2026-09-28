#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the conformance suite against a guest you name -- `TEST-016`.

`TEST-016` asks for *"the conformance-suite runner as an independently usable tool"*. Until now the
execution half lived in `crates/qqq-run/tests/conformance_exec.rs`, which is the right place for
regression coverage and the wrong place for a tool: you cannot point a `cargo test` at **somebody
else's** guest, and `DOD-001` requires five toolchains to pass *"the identical conformance suite"*.

    python tools/run_conformance.py --guest target/qqq/orders-api.component.wasm --language rust
    python tools/run_conformance.py --list

# The assertions come from the fixture, not from here

Each execution case declares its assertion in `conformance/suite.json`:

    "assert": { "kind": "runtime-classification-is", "value": "component" }

**That is the point of the declarative form.** This tool and the Rust test both read the same
statement, so they cannot drift -- and a tool that re-derived the assertions in Python would be the
second derivation of one fact that `§O-277` records as the defect to avoid. The vocabulary is two
words wide, and an unknown one is an **error** in both consumers rather than a silent pass.

# A declared gap is not a pass

Four of the five languages are `gap` with an owner and a date. Running this against one of them says
so and exits non-zero: the suite did not pass, and a tool that reported success for a language with no
toolchain would be the exact failure the parity matrix exists to make visible.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass

ROOT = pathlib.Path(__file__).resolve().parent.parent
SUITE = ROOT / "conformance" / "suite.json"
EXECUTION = "execution"

# The vocabulary. Kept in step with `run_case` in `crates/qqq-run/tests/conformance_exec.rs` by the
# fixture being the single declaration: both read `assert.kind` and neither invents a third name.
ASSERTIONS = {"runtime-classification-is", "no-unmapped-qqq-interfaces"}


def load() -> dict:
    return json.loads(SUITE.read_text(encoding="utf-8"))


def find_binary() -> pathlib.Path | None:
    # **The platform's own binary first.** `qqqai.exe` is a WINDOWS artifact, and the bridge's bind
    # mount makes it visible inside a Linux container (Linux `target/` lives in a named volume; the
    # host tree does not), so a search that prefers `.exe` returns a file the container can only run
    # through WSL interop -- which fails against `docker-init` (`§O-398`).
    names = ("qqqai.exe", "qqqai") if os.name == "nt" else ("qqqai", "qqqai.exe")
    for profile in ("debug", "release"):
        for name in names:
            p = ROOT / "target" / profile / name
            if p.is_file():
                return p
    return None


def evaluate(assertion: dict, report: dict) -> tuple[bool, str]:
    """Apply one declarative assertion to a `qqqai inspect --json` report."""
    data = report.get("data")
    if not isinstance(data, dict):
        return False, "the report carries no `data`"

    kind = assertion.get("kind")
    if kind == "runtime-classification-is":
        want = assertion.get("value")
        got = data.get("kind")
        if got == want:
            return True, f"classified `{got}`"
        return False, f"classified `{got}`, not `{want}`"

    if kind == "no-unmapped-qqq-interfaces":
        unmapped = [i for i in (data.get("unmapped_interfaces") or []) if str(i).startswith("qqq:")]
        if not unmapped:
            return True, "every `qqq:` import is mapped to a capability"
        return False, f"{len(unmapped)} `qqq:` import(s) no capability describes: {', '.join(unmapped)}"

    return False, (
        f"unknown assertion `{kind}`; the vocabulary is declared in `conformance/suite.json`"
    )


def static_checks(doc: dict) -> list[str]:
    problems: list[str] = []
    langs = doc.get("languages", [])
    if not langs:
        problems.append("the fixture declares no languages")
    for c in doc.get("cases", []):
        if c.get("kind") != EXECUTION:
            continue
        a = c.get("assert")
        if not isinstance(a, dict) or not a.get("kind"):
            problems.append(f"execution case `{c.get('id')}` declares no assertion")
        elif a["kind"] not in ASSERTIONS:
            problems.append(f"execution case `{c.get('id')}` uses an unknown assertion `{a['kind']}`")
    if not [c for c in doc.get("cases", []) if c.get("kind") == EXECUTION]:
        problems.append("the fixture declares no execution case, so this tool would run nothing")
    return problems


def run(guest: pathlib.Path | None, language: str, listing: bool, explicit: bool) -> int:
    doc = load()
    problems = static_checks(doc)
    langs = {l["id"]: l for l in doc.get("languages", [])}
    cases = [c for c in doc.get("cases", []) if c.get("kind") == EXECUTION]

    if listing:
        for c in cases:
            print(f"  {c['id']:32s} {c['assert']['kind']:34s} {c.get('summary', '')[:60]}")
        return 0 if not problems else 1

    print(f"conformance suite: {len(cases)} execution case(s), language `{language}`")
    if problems:
        for p in problems:
            print(f"  FAIL  {p}")
        return 1

    # --- the language's declared state ------------------------------------------------------
    lang = langs.get(language)
    if lang is None:
        print(f"  FAIL  `{language}` is not a language the fixture declares: {sorted(langs)}")
        return 1
    if lang.get("status") != "supported":
        print(f"  FAIL  `{language}` is a declared GAP -- owner {lang.get('owner')!r}, "
              f"target {lang.get('target')!r}. The suite did not pass, and a tool that reported "
              "success here would hide exactly what the parity matrix exists to show.")
        return 1

    # --- the guest ---------------------------------------------------------------------------
    if guest is None:
        print("  FAIL  no `--guest` was given, and the execution half needs an artifact")
        return 1
    if not guest.is_file():
        if explicit:
            # The caller named an artifact. A missing one is their problem, not this shell's.
            print(f"  FAIL  no artifact at `{guest}`")
            return 1
        # The DEFAULT is missing. In the bridge there is no build output at all, so this is the same
        # declared skip as the missing binary -- and it is what lets both gates run one command.
        print(f"SKIPPED -- no artifact at the default `{guest}` (build the reference application, or "
              "pass --guest); the fixture's assertions were checked above")
        return 0
    binary = find_binary()
    if binary is None:
        print("SKIPPED -- this needs a built qqqai (cargo build -p qqq-run)")
        return 0

    r = subprocess.run([str(binary), "inspect", str(guest), "--json"], capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=180)
    if r.returncode != 0:
        print(f"  FAIL  `qqqai inspect` failed: {r.stderr.strip()[:200]}")
        return 1
    report = json.loads(r.stdout)

    failures = 0
    for c in cases:
        ok, detail = evaluate(c["assert"], report)
        print(f"  {'PASS' if ok else 'FAIL'}  {c['id']:32s} {detail}")
        failures += 0 if ok else 1

    print()
    if failures:
        print(f"CONFORMANCE FAILED -- {failures} of {len(cases)} case(s) against `{guest.name}`")
        return 1
    print(f"CONFORMANCE OK -- all {len(cases)} execution case(s) against `{guest.name}`, "
          f"language `{language}`")
    return 0


def self_test() -> int:
    cases: list[tuple[str, bool, str]] = []
    doc = load()
    cases.append(("the fixture declares languages", bool(doc.get("languages")), ""))
    cases.append(("every execution case declares a known assertion", not static_checks(doc), ""))

    # The evaluator must fire in both directions -- a checker that cannot fail is not a checker.
    good = {"data": {"kind": "component", "unmapped_interfaces": []}}
    bad = {"data": {"kind": "module", "unmapped_interfaces": ["qqq:kv/store@1.0.0"]}}
    ok1, _ = evaluate({"kind": "runtime-classification-is", "value": "component"}, good)
    ok2, _ = evaluate({"kind": "runtime-classification-is", "value": "component"}, bad)
    ok3, _ = evaluate({"kind": "no-unmapped-qqq-interfaces"}, good)
    ok4, _ = evaluate({"kind": "no-unmapped-qqq-interfaces"}, bad)
    cases.append(("a component passes the classification assertion", ok1, ""))
    cases.append(("a core module FAILS it", not ok2, ""))
    cases.append(("a fully mapped guest passes the mapping assertion", ok3, ""))
    cases.append(("an unmapped `qqq:` import FAILS it", not ok4, ""))
    ok5, detail5 = evaluate({"kind": "no-such-assertion"}, good)
    cases.append(("an unknown assertion is an ERROR, not a pass", not ok5, detail5))

    failed = 0
    print("run_conformance self-test")
    for name, ok, detail in cases:
        print(f"  {'OK  ' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
        failed += 0 if ok else 1
    if failed:
        print(f"\nSELF-TEST FAILED -- {failed} case(s) wrong")
        return 1
    print("\nSELF-TEST PASSED -- the vocabulary, and both directions of both assertions, are live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--guest", type=pathlib.Path,
                    help="the component to run the suite against; defaults to the reference "
                         "application's build output, so both gates run one command")
    ap.add_argument("--language", default="rust", help="the language id to check the fixture for")
    ap.add_argument("--list", action="store_true", help="list the execution cases and exit")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    guest = args.guest or (ROOT / "examples" / "orders-api" / "target" / "qqq"
                         / "orders-api.component.wasm")
    return run(guest, args.language, args.list, explicit=args.guest is not None)


if __name__ == "__main__":
    sys.exit(main())
