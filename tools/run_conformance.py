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
second derivation of one fact that `§O-277` records as the defect to avoid. The vocabulary is
declared in `conformance/suite.json`, and an unknown one is an **error** in both consumers
rather than a silent pass.

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
# fixture being the single declaration: both read `assert.kind` and neither invents a name outside it.
ASSERTIONS = {
    "runtime-classification-is",
    "no-unmapped-qqq-interfaces",
    "wasi03-clock-required",
    "wasi03-unserved-reported",
}


def load() -> dict:
    return json.loads(SUITE.read_text(encoding="utf-8"))


def find_binary() -> pathlib.Path | None:
    # **The running platform's binary ONLY.** `qqqai.exe` is a WINDOWS artifact, and the bridge's bind
    # mount makes it visible inside a Linux container (Linux `target/` lives in a named volume; the
    # host tree does not), so a search that can reach it returns a file the container can only run
    # through WSL interop -- which fails against `docker-init` (`§O-398`).
    #
    # **Excluding, not preferring.** An earlier version tried the native name first and fell back to
    # the other; on Linux the native name is absent (named volume) so the fallback still won. A
    # preference is not a filter (`§O-399`).
    name = "qqqai.exe" if os.name == "nt" else "qqqai"
    # **`CARGO_TARGET_DIR` is where cargo actually wrote it.** The bridge sets it to `/linux-target`,
    # because Linux build output lives in a named volume rather than the bind-mounted tree
    # (`docker/compose.yaml`). Searching only `ROOT / "target"` finds nothing there, and the schema
    # self-test's runtime case -- which exists precisely so the comparison cannot be silently skipped --
    # reported "no binary after `cargo build`" for that reason.
    roots = []
    if os.environ.get("CARGO_TARGET_DIR"):
        roots.append(pathlib.Path(os.environ["CARGO_TARGET_DIR"]))
    roots.append(ROOT / "target")
    for root in roots:
        for profile in ("debug", "release"):
            p = root / profile / name
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
        unmapped = [
            i
            for i in (data.get("unmapped_interfaces") or [])
            if str(i).startswith("qqq:")
        ]
        if not unmapped:
            return True, "every `qqq:` import is mapped to a capability"
        return (
            False,
            f"{len(unmapped)} `qqq:` import(s) no capability describes: {', '.join(unmapped)}",
        )

    if kind == "wasi03-clock-required":
        # A 0.3 clock import resolves to clock.monotonic (CON-019): the report
        # must require it, never reinterpret it onto 0.2 and never drop it.
        # Matched on the `0.3.` revision prefix so a patch release cannot slip
        # out of the report — the same rule AbiVersion::detect routes by.
        for r in data.get("required") or []:
            if not isinstance(r, dict):
                continue
            if r.get("name") != "clock.monotonic":
                continue
            if str(r.get("interface", "")).startswith(
                "wasi:clocks/monotonic-clock@0.3."
            ):
                return (
                    True,
                    "required clock.monotonic from a wasi:clocks/monotonic-clock@0.3.x import",
                )
        return (
            False,
            "no required clock.monotonic from a wasi:clocks/monotonic-clock@0.3.x import",
        )

    if kind == "wasi03-unserved-reported":
        # Unserved 0.3 imports are reported as unmapped, never claimed and
        # never dropped (CON-019): the fixture declares the expected names in
        # `value`, and an entry missing from the report is the defect. An
        # empty `value` is an error, not a pass — a case asserting nothing
        # over an empty loop proves nothing.
        want = assertion.get("value")
        if not isinstance(want, list) or not want:
            return False, "the case declares no `value`, so there is nothing to check"
        unmapped = data.get("unmapped_interfaces") or []
        missing = [w for w in want if w not in unmapped]
        if not missing:
            return True, f"all {len(want)} unserved 0.3 import(s) reported as unmapped"
        return (
            False,
            f"0.3 imports neither required nor reported as unmapped: {', '.join(missing)}",
        )

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
            problems.append(
                f"execution case `{c.get('id')}` uses an unknown assertion `{a['kind']}`"
            )
    if not [c for c in doc.get("cases", []) if c.get("kind") == EXECUTION]:
        problems.append(
            "the fixture declares no execution case, so this tool would run nothing"
        )
    return problems


def run(
    guest: pathlib.Path | None, language: str, listing: bool, explicit: bool
) -> int:
    doc = load()
    problems = static_checks(doc)
    langs = {l["id"]: l for l in doc.get("languages", [])}
    cases = [c for c in doc.get("cases", []) if c.get("kind") == EXECUTION]

    if listing:
        for c in cases:
            print(
                f"  {c['id']:32s} {c['assert']['kind']:34s} {c.get('guest') or '<default guest>'!s:44s} {c.get('summary', '')[:60]}"
            )
        return 0 if not problems else 1

    print(f"conformance suite: {len(cases)} execution case(s), language `{language}`")
    if problems:
        for p in problems:
            print(f"  FAIL  {p}")
        return 1

    # --- the language's declared state ------------------------------------------------------
    lang = langs.get(language)
    if lang is None:
        print(
            f"  FAIL  `{language}` is not a language the fixture declares: {sorted(langs)}"
        )
        return 1
    if lang.get("status") != "supported":
        print(
            f"  FAIL  `{language}` is a declared GAP -- owner {lang.get('owner')!r}, "
            f"target {lang.get('target')!r}. The suite did not pass, and a tool that reported "
            "success here would hide exactly what the parity matrix exists to show."
        )
        return 1

    # --- per-case guests; the default guest below is shared by the rest ------
    #
    # A case names its own committed fixture guest when the default reference
    # application cannot supply it (CON-019: no toolchain emits 0.3, so the 0.3
    # guest is committed rather than built). A named guest that does not exist
    # is a FAIL, not a skip — it is committed, so absence is a defect, not a
    # missing build. Cases without one share the CLI/default guest below, with
    # its pre-existing skip semantics intact.
    default_guest = guest
    default_report: dict | None = None
    if not default_guest.is_file():
        if explicit:
            # The caller named an artifact. A missing one is their problem, not this shell's.
            print(f"  FAIL  no artifact at `{default_guest}`")
            return 1
        # The DEFAULT is missing. In the bridge there is no build output at all, so this is the same
        # declared skip as the missing binary -- and it is what lets both gates run one command.
        # Cases naming a committed guest still run below; only default-guest cases skip.
        print(
            f"SKIPPED -- no artifact at the default `{default_guest}` (build the reference application, or "
            "pass --guest); the cases naming a committed guest still run below"
        )
    binary = find_binary()
    if binary is None:
        print("SKIPPED -- this needs a built qqqai (cargo build -p qqq-run)")
        return 0

    reports: dict[str, dict] = {}

    def report_for(path: pathlib.Path) -> dict | None:
        """Inspect one artifact; None only for the skipped default guest."""
        key = str(path)
        if key in reports:
            return reports[key]
        r = subprocess.run(
            [str(binary), "inspect", str(path), "--json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
        if r.returncode != 0:
            print(
                f"  FAIL  `qqqai inspect` failed on `{path.name}`: {r.stderr.strip()[:200]}"
            )
            reports[key] = {}
            return reports[key]
        reports[key] = json.loads(r.stdout)
        return reports[key]

    if default_guest.is_file():
        maybe = report_for(default_guest)
        default_report = maybe if maybe else {}

    failures = 0
    skipped = 0
    for c in cases:
        if isinstance(c.get("guest"), str):
            artifact = ROOT / c["guest"]
            if not artifact.is_file():
                print(
                    f"  FAIL  {c['id']:32s} fixture guest `{c['guest']}` does not exist"
                )
                failures += 1
                continue
            report = report_for(artifact)
        else:
            if default_report is None:
                print(f"  SKIPPED  {c['id']:32s} no default artifact to run against")
                skipped += 1
                continue
            report = default_report
        if not report:
            failures += 1
            continue
        ok, detail = evaluate(c["assert"], report)
        print(f"  {'PASS' if ok else 'FAIL'}  {c['id']:32s} {detail}")
        failures += 0 if ok else 1

    print()
    if failures:
        print(f"CONFORMANCE FAILED -- {failures} case(s) failed")
        return 1
    if skipped:
        print(
            "CONFORMANCE OK -- all runnable cases passed "
            f"({skipped} skipped: no default artifact)"
        )
        return 0
    print(
        f"CONFORMANCE OK -- all {len(cases)} execution case(s), language `{language}`"
    )
    return 0


def self_test() -> int:
    cases: list[tuple[str, bool, str]] = []
    doc = load()
    cases.append(("the fixture declares languages", bool(doc.get("languages")), ""))
    cases.append(
        ("every execution case declares a known assertion", not static_checks(doc), "")
    )

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

    # CON-019: the 0.3 assertions must fire in both directions too, and an
    # empty `value` must be an error rather than a vacuous pass.
    good03 = {
        "data": {
            "required": [
                {
                    "name": "clock.monotonic",
                    "interface": "wasi:clocks/monotonic-clock@0.3.2",
                }
            ],
            "unmapped_interfaces": ["wasi:http/incoming-handler@0.3.2"],
        }
    }
    bad03 = {"data": {"required": [], "unmapped_interfaces": []}}
    ok6, _ = evaluate({"kind": "wasi03-clock-required"}, good03)
    ok7, _ = evaluate({"kind": "wasi03-clock-required"}, bad03)
    cases.append(("a required 0.3 clock passes the 0.3 mapping assertion", ok6, ""))
    cases.append(("a guest without one FAILS it", not ok7, ""))
    ok8, _ = evaluate(
        {
            "kind": "wasi03-unserved-reported",
            "value": ["wasi:http/incoming-handler@0.3.2"],
        },
        good03,
    )
    ok9, _ = evaluate(
        {
            "kind": "wasi03-unserved-reported",
            "value": ["wasi:http/incoming-handler@0.3.2"],
        },
        bad03,
    )
    cases.append(
        ("a reported unserved 0.3 import passes the report assertion", ok8, "")
    )
    cases.append(("a dropped one FAILS it", not ok9, ""))
    ok10, detail10 = evaluate({"kind": "wasi03-unserved-reported", "value": []}, good03)
    cases.append(("an empty `value` is an ERROR, not a pass", not ok10, detail10))

    failed = 0
    print("run_conformance self-test")
    for name, ok, detail in cases:
        print(
            f"  {'OK  ' if ok else 'FAIL'}  {name}"
            + (f"  ({detail})" if detail else "")
        )
        failed += 0 if ok else 1
    if failed:
        print(f"\nSELF-TEST FAILED -- {failed} case(s) wrong")
        return 1
    print(
        "\nSELF-TEST PASSED -- the vocabulary, and both directions of every assertion, are live"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--guest",
        type=pathlib.Path,
        help="the component to run the suite against; defaults to the reference "
        "application's build output, so both gates run one command",
    )
    ap.add_argument(
        "--language", default="rust", help="the language id to check the fixture for"
    )
    ap.add_argument(
        "--list", action="store_true", help="list the execution cases and exit"
    )
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    guest = args.guest or (
        ROOT
        / "examples"
        / "orders-api"
        / "target"
        / "qqq"
        / "orders-api.component.wasm"
    )
    return run(guest, args.language, args.list, explicit=args.guest is not None)


if __name__ == "__main__":
    sys.exit(main())
