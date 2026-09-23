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
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schema"

# The schema file -> the Rust file whose types it describes, and the root struct.
SURFACES = [
    ("qqq-toml.schema.json", "crates/qqq-cap/src/manifest.rs", "Manifest"),
    ("qqq-lock.schema.json", "crates/qqq-pkg/src/lock.rs", "Lockfile"),
]

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

    # The tree is conformant again.
    check("the real tree still conforms", run() == 0)

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} of {cases} case(s) failed", file=sys.stderr)
        return 1
    print(f"SELF-TEST PASSED -- {cases} case(s), including every real divergence")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv[1:]:
        return self_test()
    return run()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
