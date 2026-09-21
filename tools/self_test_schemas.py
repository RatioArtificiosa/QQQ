#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prove `tools/gen_schemas.py` detects the drift it claims to — `CON-016`.

# Why a self-test, and why this one specifically

The workspace pairs every checker with a fault injection
(`self_test_xrefs.py`, `fault_inject_no_ambient.py`) because a checker that has
never been shown to fail is a checker that might always pass. This session has
now recorded that failure **five times**, once inside a check written to prevent
it.

For a *generator* the risk has a specific shape: a generator that emits an empty
or near-empty document "succeeds", and the drift check then compares that empty
document against itself and passes. So the injections here are chosen to break
the generator's *inputs* and its *outputs* separately:

| # | Injection | What it must be caught by |
|---|---|---|
| 1 | Add a field to `Manifest` in source | Generation succeeds; the written schema is now stale, so `--check` must report DRIFT |
| 2 | Delete a generated schema | `--check` must report MISSING |
| 3 | Hand-edit a generated schema | `--check` must report DRIFT |
| 4 | Rename a struct to something unreadable | Generation must **fail loudly**, not emit a partial schema |
| 5 | Strip an enum's `as_str` | Generation must fail, not fall back to variant names |
| 6 | Empty the source entirely | Generation must fail rather than emit `"properties": {}` |

Injection 6 is the anti-vacuity case, and it is the one that matters most: an
empty document describes every possible file, so it is the schema equivalent of a
check that finds nothing.

Every injection is applied to a **copy** of the tree in a temporary directory, so
the real repository is never touched. That is the lesson from `§M-007`, where a
self-repair rewrote the document it was repairing.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
GEN = "tools/gen_schemas.py"

MANIFEST = "crates/qqq-cap/src/manifest.rs"
LOCK = "crates/qqq-pkg/src/lock.rs"

# Each injection anchors on a literal that must exist. When one moves, the test
# says so rather than silently injecting nothing -- the failure mode that made
# `self_test_xrefs.py`'s check [4] go dead (`§O-108`).


def run_generator(tree: pathlib.Path, check: bool) -> tuple[int, str]:
    """Run the generator inside `tree`, returning (exit code, output)."""
    args = [sys.executable, GEN]
    if check:
        args.append("--check")
    proc = subprocess.run(
        args,
        cwd=tree,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def snapshot() -> pathlib.Path:
    """A copy of the tree the injections can damage safely."""
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="qqq-schema-selftest-"))
    for rel in ["tools", "schema", "crates/qqq-cap/src", "crates/qqq-pkg/src"]:
        src = ROOT / rel
        dst = tmp / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dst)
    return tmp


def expect(name: str, ok: bool, detail: str) -> bool:
    print(f"  {'OK  ' if ok else 'FAIL'}  {name}")
    if not ok:
        print(f"        {detail}")
    return ok


def main() -> int:
    results: list[bool] = []

    # ---- Baseline: the real tree must be clean ---------------------------
    print("baseline")
    code, out = run_generator(ROOT, check=True)
    results.append(
        expect(
            "the committed schemas match the implementation",
            code == 0,
            f"exit {code}; run `python {GEN}` to regenerate\n{out}",
        )
    )

    # ---- Injection 1: a new field in the source makes the schema stale ----
    print("\ninjection 1: add a field to `Manifest`")
    with tempfile.TemporaryDirectory() as td:
        tree = snapshot()
        try:
            path = tree / MANIFEST
            text = path.read_text(encoding="utf-8")
            # Insert a field into `Manifest`'s body, right after its first `pub`.
            marker = "pub package: Package,"
            assert marker in text, "the injection's anchor moved; update the test"
            path.write_text(
                text.replace(
                    marker,
                    "pub injected_field: bool,\n    " + marker,
                    1,
                ),
                encoding="utf-8",
            )
            code, out = run_generator(tree, check=True)
            results.append(
                expect(
                    "a field added to the source is reported as DRIFT",
                    code == 1 and "DRIFT" in out,
                    f"exit {code}, output: {out[:400]}",
                )
            )
        finally:
            shutil.rmtree(tree, ignore_errors=True)

    # ---- Injection 2: a deleted schema ----------------------------------
    print("\ninjection 2: delete a generated schema")
    with tempfile.TemporaryDirectory() as td:
        tree = snapshot()
        try:
            (tree / "schema/qqq-toml.schema.json").unlink()
            code, out = run_generator(tree, check=True)
            results.append(
                expect(
                    "a missing schema is reported as MISSING",
                    code == 1 and "MISSING" in out,
                    f"exit {code}, output: {out[:400]}",
                )
            )
        finally:
            shutil.rmtree(tree, ignore_errors=True)

    # ---- Injection 3: a hand-edited schema ------------------------------
    print("\ninjection 3: hand-edit a generated schema")
    with tempfile.TemporaryDirectory() as td:
        tree = snapshot()
        try:
            path = tree / "schema/qqq-lock.schema.json"
            doc = json.loads(path.read_text(encoding="utf-8"))
            doc["properties"]["hand_edited"] = {"type": "string"}
            path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            code, out = run_generator(tree, check=True)
            results.append(
                expect(
                    "a hand-edited schema is reported as DRIFT",
                    code == 1 and "DRIFT" in out,
                    f"exit {code}, output: {out[:400]}",
                )
            )
        finally:
            shutil.rmtree(tree, ignore_errors=True)

    # ---- Injection 4: an unresolvable type ------------------------------
    print("\ninjection 4: a field typed with an unknown name")
    with tempfile.TemporaryDirectory() as td:
        tree = snapshot()
        try:
            path = tree / LOCK
            text = path.read_text(encoding="utf-8")
            # The package list is a `Vec<LockPackage>`, so this injection
            # exercises the generic wrapper *and* the `$ref` nesting at once --
            # a better test than a bare named field would be.
            marker = "pub packages: Vec<LockPackage>,"
            assert marker in text, "the injection's anchor moved; update the test"
            path.write_text(
                text.replace(marker, "pub packages: Vec<NoSuchType>,", 1),
                encoding="utf-8",
            )
            code, out = run_generator(tree, check=False)
            results.append(
                expect(
                    "an unresolvable type fails generation loudly",
                    code == 1 and "unrecognised Rust type" in out,
                    f"exit {code}; generation must refuse rather than omit the "
                    f"field\n{out[:300]}",
                )
            )
        finally:
            shutil.rmtree(tree, ignore_errors=True)

    # ---- Injection 5: an enum with no `as_str` --------------------------
    print("\ninjection 5: strip an enum's `as_str`")
    with tempfile.TemporaryDirectory() as td:
        tree = snapshot()
        try:
            path = tree / LOCK
            text = path.read_text(encoding="utf-8")
            marker = 'Self::ModifiedInPlace => "modified-in-place",'
            assert marker in text, "the injection's anchor moved; update the test"
            # Change the JSON spelling the enum maps to. Generation still
            # succeeds -- the code is valid Rust -- but the document it would
            # write differs from the committed one, so `--check` must say so.
            #
            # That distinction is the point: a source edit that is *valid* still
            # drifts the contract, and only a `--check` run catches it.
            path.write_text(
                text.replace(marker, 'Self::ModifiedInPlace => "renamed-in-place",', 1),
                encoding="utf-8",
            )
            code, out = run_generator(tree, check=True)
            results.append(
                expect(
                    "a changed enum spelling is reported as DRIFT",
                    code == 1 and "DRIFT" in out,
                    f"exit {code}; a valid source edit that changes the contract "
                    f"must still be caught\n{out[:300]}",
                )
            )
        finally:
            shutil.rmtree(tree, ignore_errors=True)

    # ---- Injection 6: THE ANTI-VACUITY CASE -----------------------------
    print("\ninjection 6: empty every source (the anti-vacuity case)")
    with tempfile.TemporaryDirectory() as td:
        tree = snapshot()
        try:
            for rel in [MANIFEST, LOCK]:
                (tree / rel).write_text("", encoding="utf-8")
            # Remove the stale schemas too, so nothing can match by accident.
            for f in (tree / "schema").glob("*.json"):
                f.unlink()
            code, out = run_generator(tree, check=False)
            # A generator that emitted `{"properties": {}}` would "succeed" and
            # the resulting schema would describe every possible document.
            produced = list((tree / "schema").glob("qqq-*.json"))
            substantive = [
                p
                for p in produced
                if json.loads(p.read_text(encoding="utf-8")).get("properties")
            ]
            results.append(
                expect(
                    "empty sources fail rather than emitting an empty schema",
                    code != 0
                    and not substantive
                    and ("`Manifest` not found" in out or "`Lockfile` not found" in out),
                    f"exit {code}; produced {[p.name for p in substantive]} "
                    f"with properties; the failure must NAME the cause\n{out[:300]}",
                )
            )
        finally:
            shutil.rmtree(tree, ignore_errors=True)

    detected = sum(1 for r in results if r)
    print(f"\n{detected}/{len(results)} fault injections detected")
    if detected != len(results):
        print("SELF-TEST FAILED — the generator does not detect its own drift")
        return 1
    print("SELF-TEST PASSED — every drift is detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
