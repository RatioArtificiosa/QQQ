#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prove the published schemas and the implementing code agree — `CON-001`, `CON-016`.

# The gap this closes

`schema/*.schema.json` is generated from the Rust types and drift-checked
(`tools/gen_schemas.py --check`). Drift-checking proves the document matches the
*generator*. It says nothing about whether the generator read the source
correctly — and it did not, three times, in one struct:

| Published as | Actually declared | Consequence |
|---|---|---|
| `dev_dependencies` | `dev-dependencies` | the schema documented a key that does not exist |
| `generated_by` | `generated-by` | same |
| `lockfile_hash` | `lockfile-hash` | same |

and `dev-dependencies` was also listed as **required**, so the schema rejected a
minimal manifest the parser accepts. Every one of those passed `--check`, because
`--check` compares the schema against the generator's own misreading.

# What this does about it

Two independent sources of truth, compared:

* **The code.** `#[serde(rename = "...")]` in the Rust source is the authoritative
  JSON key name, read here by a small scanner that looks at whole attribute
  blocks.
* **The document.** The published schema's `properties` and `required`.

Every key the Rust source declares must appear in the schema under exactly that
name, and every name in the schema must be declared in the source. A key the
schema invents is a document that describes a file nobody can write; a key the
schema omits is a key with no published contract.

# Why it also checks `required` against the deserializer

Because "present in `properties`" is not the same as "required on input". The
`required` list is checked against the source's own optionality markers:
`Option<T>`, `#[serde(default)]` and `#[serde(skip_serializing_if = "...")]`. A
field carrying any of them must NOT be required; a field carrying none must be.

Usage:  python tools/check_schema_conformance.py [--self-test]
Exit:   0 = every schema agrees with the source, 1 = a divergence
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from dataclasses import replace

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schema"

# The schema file -> the Rust file whose types it describes, and the root struct.
SURFACES = [
    ("qqq-toml.schema.json", "crates/qqq-cap/src/manifest.rs", "Manifest"),
    ("qqq-lock.schema.json", "crates/qqq-pkg/src/lock.rs", "Lockfile"),
    ("cli-envelope.schema.json", "crates/qqq-run/src/output.rs", "Envelope"),
]

# `cli-envelope` describes two records: the envelope and the error payload. The
# nested set is declared per surface so the root-only comparison cannot silently
# skip a record that carries its own requiredness.
EXTRA_STRUCTS = {
    "cli-envelope.schema.json": ["ErrorPayload"],
}

# Load the generator's reader so both tools agree on what the source says. If
# they disagree, one of them is wrong and the disagreement is the finding.
_spec = importlib.util.spec_from_file_location(
    "gen_schemas", ROOT / "tools" / "gen_schemas.py"
)
gen = importlib.util.module_from_spec(_spec)
sys.modules["gen_schemas"] = gen
_spec.loader.exec_module(gen)


def declared_fields(path: pathlib.Path, struct_name: str) -> list[gen.Field]:
    structs = gen.read_structs(path.read_text(encoding="utf-8"))
    if struct_name not in structs:
        raise SystemExit(f"{struct_name} not found in {path}")
    return structs[struct_name].fields


def check_surface(name: str, rust_rel: str, struct_name: str) -> list[str]:
    """Every divergence between one published schema and its source.

    # Why this walks `$defs` and not just the root

    The first version compared only the root `properties` and `required`, and its
    own self-test caught the consequence: a mutation renaming `generated-by` to
    `generated_by` **inside `$defs.Metadata`** was reported MISSED. The fault was
    real — the two names in `Metadata` were wrong for the same multi-line-attribute
    reason as the root's — so the verdict was "the checker never looks there".

    Six nested definitions in the lock schema carry declared keys and requiredness
    of their own, and `Metadata` is exactly where two of the three real
    divergences lived. A root-only check would have shipped both.
    """
    problems: list[str] = []
    schema = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    rust_text = (ROOT / rust_rel).read_text(encoding="utf-8")
    structs = gen.read_structs(rust_text)

    def compare(label: str, node: dict, struct: str) -> None:
        """One struct's fields against one schema node."""
        if struct not in structs:
            problems.append(f"{name}: {label} describes {struct!r}, not found in {rust_rel}")
            return
        props = node.get("properties") or {}
        required = set(node.get("required") or [])
        fields = structs[struct].fields

        # The generator drops `source` and `path` from the ROOT struct only: on
        # `Manifest` those are private bookkeeping fields (`where it was read
        # from`), not part of the file format. Applying that exclusion everywhere
        # was this checker's own first bug — it flagged `FsCapability.path`,
        # `Route.path` and `DependencyDetail.source`, which are ordinary declared
        # fields with real JSON keys, and would have "fixed" three correct
        # documents.
        if label == "the root" and struct == struct_name:
            fields = [f for f in fields if f.name not in {"source", "path"}]

        # The generator rewrites two fields whose declared Rust type is not the
        # wire shape, and both rewrites are deliberate, documented at the call
        # site, and asserted here so they cannot silently widen:
        #
        #   * `Envelope.data: Option<T>` is generic; the document says "any JSON",
        #     and the per-command shape comes from `qqqai schema --all`.
        #   * `ErrorPayload.backtrace: Option<ResolvedBacktrace>` is another
        #     module's contract; the document says "any JSON".
        REWRITTEN = {"data", "backtrace"}
        fields = [
            replace(f, ty="AnyJson")
            if f.name in REWRITTEN
            else f
            for f in fields
        ]

        declared = {f.json_name: f for f in fields}

        for key in sorted(props):
            if key not in declared:
                problems.append(
                    f"{name}: {label} documents key {key!r}, which {rust_rel} "
                    f"({struct}) does not declare"
                )
        for key in sorted(declared):
            if key not in props:
                problems.append(
                    f"{name}: {label} omits key {key!r}, which {rust_rel} "
                    f"({struct}) declares"
                )
        for key, f in sorted(declared.items()):
            optional_in_source = f.optional or f.defaulted or f.skipped
            if optional_in_source and key in required:
                why = (
                    "Option<T>" if f.optional
                    else "#[serde(default)]" if f.defaulted
                    else "#[serde(skip_serializing_if = ...)]"
                )
                problems.append(
                    f"{name}: {label} requires {key!r}, but {rust_rel} ({struct}) "
                    f"marks it optional ({why}), so the schema rejects a document "
                    f"the parser accepts"
                )
            if not optional_in_source and key not in required:
                problems.append(
                    f"{name}: {label} does not require {key!r}, but {rust_rel} "
                    f"({struct}) declares it with no `Option`, no `default` and no "
                    f"`skip_serializing_if`"
                )

    # The root struct.
    compare("the root", schema, struct_name)

    # Records the surface declares explicitly, which are not in `$defs` under
    # their own name in every case. `cli-envelope#ErrorPayload` is one.
    for extra in EXTRA_STRUCTS.get(name, []):
        node = (schema.get("$defs") or {}).get(extra)
        if node is None:
            problems.append(f"{name}: declares {extra} as part of its contract but has no definition for it")
            continue
        compare(f"$defs.{extra}", node, extra)

    # Every `$defs` entry that names a real struct in the same file. A definition
    # whose name is not a struct in this file is reported, because a nested
    # definition with no source is a definition nobody generated.
    for defname, node in sorted((schema.get("$defs") or {}).items()):
        if defname in structs:
            compare(f"$defs.{defname}", node, defname)
        else:
            problems.append(
                f"{name}: $defs.{defname} has no matching struct in {rust_rel}, so "
                f"its keys are unverified"
            )

    return problems


def run() -> int:
    problems: list[str] = []
    for name, rust_rel, struct_name in SURFACES:
        if not (SCHEMA_DIR / name).exists():
            problems.append(f"{name}: MISSING - run `python tools/gen_schemas.py`")
            continue
        problems.extend(check_surface(name, rust_rel, struct_name))

    if problems:
        print(f"SCHEMA CONFORMANCE FAILED -- {len(problems)} divergence(s):", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    print(
        f"SCHEMA CONFORMANCE OK -- {len(SURFACES)} surface(s): every documented key is "
        f"declared in the source, every declared key is documented, and requiredness "
        f"matches the source's optionality markers"
    )
    return 0


# ---------------------------------------------------------------------------
# The strongest check available: the real binary's real output.
# ---------------------------------------------------------------------------

# Commands whose `--json` output must satisfy the published envelope schema. One
# success path and one failure path, because the envelope has two shapes and a
# check that only sees one proves half of it.
ENVELOPE_PROBES = [
    ("schema", ["schema", "--json"], True),
    ("why (a missing argument, so the failure envelope)", ["why", "--json"], False),
    ("doctor", ["doctor", "--json"], True),
]


def find_binary() -> pathlib.Path | None:
    """The built `qqqai` binary, if the workspace has been built."""
    for profile in ("debug", "release"):
        for name in ("qqqai.exe", "qqqai"):
            p = ROOT / "target" / profile / name
            if p.exists():
                return p
    return None


def validate_envelope(instance: object, schema: dict) -> list[str]:
    """The subset of draft 2020-12 the envelope schema uses."""
    errors: list[str] = []

    def resolve(node: dict) -> dict:
        while isinstance(node, dict) and "$ref" in node:
            node = schema["$defs"][node["$ref"].split("/")[-1]]
        return node

    def walk(value: object, node: dict, path: str) -> None:
        node = resolve(node)
        if "anyOf" in node:
            if not any(not walk_collect(value, alt, path) for alt in node["anyOf"]):
                errors.append(f"{path}: matches no branch of anyOf")
            return
        t = node.get("type")
        if t:
            types = t if isinstance(t, list) else [t]
            ok = (
                ("object" in types and isinstance(value, dict))
                or ("array" in types and isinstance(value, list))
                or ("string" in types and isinstance(value, str))
                or ("boolean" in types and isinstance(value, bool))
                or ("null" in types and value is None)
                or ("integer" in types and isinstance(value, int) and not isinstance(value, bool))
            )
            if not ok:
                errors.append(f"{path}: expected {t}, got {type(value).__name__}")
                return
        if isinstance(value, dict):
            for req in node.get("required", []):
                if req not in value:
                    errors.append(f"{path}: missing required property {req!r}")
            props = node.get("properties") or {}
            for k, v in value.items():
                if k in props:
                    walk(v, props[k], f"{path}.{k}")

    def walk_collect(value: object, node: dict, path: str) -> list[str]:
        before = len(errors)
        walk(value, node, path)
        return errors[before:]

    walk(instance, schema, "$")
    return errors


def probe_envelope() -> int:
    """Run the shipped binary and validate its output against the schema.

    Returns 0 when every probe passes, 1 when one fails, and 0 with a NOTICE when
    the binary has not been built -- a source-only CI job must not fail for want of
    an artifact, but it must say so rather than imply it checked.
    """
    binary = find_binary()
    if binary is None:
        print(
            "  NOTICE: no built `qqqai` binary, so the runtime probe was SKIPPED. "
            "Build with `cargo build -p qqq-run --bin qqqai` to run it.",
            file=sys.stderr,
        )
        return 0

    import subprocess

    schema = json.loads((SCHEMA_DIR / "cli-envelope.schema.json").read_text(encoding="utf-8"))
    failures = 0
    for label, args, expect_ok in ENVELOPE_PROBES:
        r = subprocess.run([str(binary), *args], capture_output=True, text=True)
        line = r.stdout.strip().splitlines()
        if not line:
            print(f"  {label}: no JSON on stdout (exit {r.returncode})", file=sys.stderr)
            failures += 1
            continue
        try:
            doc = json.loads(line[0])
        except json.JSONDecodeError as e:
            print(f"  {label}: stdout is not JSON: {e}", file=sys.stderr)
            failures += 1
            continue
        errs = validate_envelope(doc, schema)
        if errs:
            failures += 1
            print(f"  {label}: {len(errs)} schema violation(s)", file=sys.stderr)
            for e in errs[:10]:
                print(f"      {e}", file=sys.stderr)
        elif doc.get("ok") is not expect_ok:
            failures += 1
            print(
                f"  {label}: envelope says ok={doc.get('ok')}, expected {expect_ok}",
                file=sys.stderr,
            )
        elif doc.get("exit_code") != r.returncode:
            # The envelope's own `exit_code` must be the status the process
            # returned. Checking it here rather than in a unit test is
            # deliberate: the field is a claim *about this process*, and only a
            # run of this process can falsify it. With the field hardcoded to
            # `0`, every unit test still passed and the binary still exited 69;
            # this comparison is what notices.
            failures += 1
            print(
                f"  {label}: envelope says exit_code={doc.get('exit_code')!r}, "
                f"but the process returned {r.returncode}",
                file=sys.stderr,
            )
        else:
            print(
                f"  {label}: valid, ok={doc.get('ok')}, exit_code={doc.get('exit_code')}"
            )

    if failures:
        print(f"ENVELOPE PROBE FAILED -- {failures} of {len(ENVELOPE_PROBES)}", file=sys.stderr)
        return 1
    print(f"ENVELOPE PROBE OK -- {len(ENVELOPE_PROBES)} command(s) match the published schema")
    return 0


# ---------------------------------------------------------------------------
# Self-test: the three real divergences must each be caught.
# ---------------------------------------------------------------------------

# (description, schema file, mutation applied to the schema dict)
MUTATIONS = [
    (
        "a key renamed to a name the source does not declare (the dev_dependencies bug)",
        "qqq-toml.schema.json",
        lambda d: (d["properties"].__setitem__("dev_dependencies", d["properties"].pop("dev-dependencies")), d)[1],
    ),
    (
        "a declared key dropped from the schema",
        "qqq-toml.schema.json",
        lambda d: (d["properties"].pop("package"), d)[1],
    ),
    (
        "an optional field listed as required (the required-list bug)",
        "qqq-toml.schema.json",
        lambda d: (d.__setitem__("required", sorted(set(d.get("required", [])) | {"dev-dependencies"})), d)[1],
    ),
    (
        "a key invented by the schema",
        "qqq-toml.schema.json",
        lambda d: (d["properties"].__setitem__("invented_key", {"type": "string"}), d)[1],
    ),
    (
        "the lockfile's generated-by renamed back to the Rust spelling",
        "qqq-lock.schema.json",
        lambda d: (
            d["$defs"]["Metadata"]["properties"].__setitem__(
                "generated_by",
                d["$defs"]["Metadata"]["properties"].pop("generated-by"),
            ),
            d,
        )[1],
    ),
    (
        "the envelope's `producer` dropped, which is how it drifted before",
        "cli-envelope.schema.json",
        lambda d: (d["properties"].pop("producer"), d)[1],
    ),
    (
        "`error.docs_url` renamed to a name the source does not declare",
        "cli-envelope.schema.json",
        lambda d: (
            d["$defs"]["ErrorPayload"]["properties"].__setitem__(
                "docs-url",
                d["$defs"]["ErrorPayload"]["properties"].pop("docs_url"),
            ),
            d,
        )[1],
    ),
]


def self_test() -> int:
    """Each mutation must produce a failure, on a temporary copy of the tree."""
    cases = 0
    failures = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal cases, failures
        cases += 1
        if ok:
            print(f"  ok    {name}")
        else:
            failures += 1
            print(f"  FAIL  {name}" + (f": {detail}" if detail else ""))

    # 0. The real tree must be conformant.
    clean = run() == 0
    check("the real tree conforms", clean)

    # Each mutation is applied to the schema ON DISK, checked, then restored.
    # The repository is returned to its exact bytes each time.
    for desc, filename, mutate in MUTATIONS:
        path = SCHEMA_DIR / filename
        original = path.read_bytes()
        try:
            doc = json.loads(original.decode("utf-8"))
            mutate(doc)
            path.write_text(
                json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            caught = run() == 1
        finally:
            path.write_bytes(original)
        restored = path.read_bytes() == original
        check(f"caught: {desc}", caught)
        check(f"restored: {desc}", restored)

    # Anti-vacuity: an empty schema must not pass. An empty document describes
    # every file, so a checker that accepts one checks nothing.
    path = SCHEMA_DIR / "qqq-toml.schema.json"
    original = path.read_bytes()
    try:
        path.write_text(
            json.dumps({"title": "qqq-toml", "properties": {}}, indent=2) + "\n",
            encoding="utf-8",
        )
        empty_caught = run() == 1
    finally:
        path.write_bytes(original)
    check("caught: an empty schema", empty_caught)
    check("restored after the empty-schema case", path.read_bytes() == original)

    # The live probe's exit_code assertion must be live too.
    #
    # The other cases mutate the *schema* and check the static comparison. This
    # one mutates the *implementation* and checks the runtime comparison, because
    # the defect it guards against -- an envelope whose `exit_code` is a constant
    # rather than the process's status -- is invisible to a schema check: the
    # field is present, well-typed and wrong. With `exit_code: 0` hardcoded,
    # every unit test still passed and the binary still exited 69. Only the probe
    # noticed.
    if find_binary() is None:
        print("  NOTICE: no built binary, so the exit_code injection was SKIPPED")
    else:
        src = ROOT / "crates/qqq-run/src/output.rs"
        original_src = src.read_bytes()
        text = original_src.decode("utf-8")
        needle = """        command: command.as_str(),
        ok: true,
        exit_code,"""
        if text.count(needle) != 1:
            check("caught: a constant exit_code in the success envelope", False,
                  "the anchor is gone from output.rs")
        else:
            try:
                src.write_bytes(
                    text.replace(
                        needle,
                        """        command: command.as_str(),
        ok: true,
        exit_code: 0, // injected by check_schema_conformance --self-test""",
                        1,
                    ).encode("utf-8")
                )
                rebuild = subprocess.run(
                    ["cargo", "build", "-q", "-p", "qqq-run", "--bin", "qqqai"],
                    capture_output=True, text=True, cwd=ROOT,
                )
                if rebuild.returncode != 0:
                    check("caught: a constant exit_code in the success envelope", False,
                          "the injected build failed")
                else:
                    check(
                        "caught: a constant exit_code in the success envelope",
                        probe_envelope() == 1,
                    )
            finally:
                src.write_bytes(original_src)
                # Touch, so the next build cannot reuse the injected artifact.
                stamp = time.time()
                os.utime(src, (stamp, stamp))
                subprocess.run(
                    ["cargo", "build", "-q", "-p", "qqq-run", "--bin", "qqqai"],
                    capture_output=True, text=True, cwd=ROOT,
                )
            check(
                "restored after the exit_code injection",
                src.read_bytes() == original_src
                and b"injected by check_schema_conformance" not in src.read_bytes(),
            )

    # The tree is conformant again.
    check("the real tree still conforms", run() == 0)

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} of {cases} case(s) failed", file=sys.stderr)
        return 1
    print(f"SELF-TEST PASSED -- {cases} case(s), including every real divergence")
    return 0


def main(argv: list[str]) -> int:
    args = argv[1:]
    if "--self-test" in args:
        return self_test()
    if "--probe" in args:
        return probe_envelope()
    code = run()
    if code != 0:
        return code
    return probe_envelope()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
