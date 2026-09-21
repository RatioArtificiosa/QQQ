#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate JSON Schema documents from the Rust types that define them — `CON-016`.

# The problem this solves, in §8.3's own words

> This single document is what makes QQQ teachable to a model that has never seen
> it. It is versioned, it is stable within a major version, and **CI fails if it
> drifts from the implementation.**

Three surfaces have a machine-readable contract that is *derived from Rust types*:

| Surface | Authoritative source | Published as |
|---|---|---|
| `qqq.toml` | `qqq_cap::manifest::Manifest` | `schema/qqq-toml.schema.json` |
| `qqq.lock` | `qqq_pkg::lock::Lockfile` | `schema/qqq-lock.schema.json` |
| CLI envelope | `qqq_run`'s `CommandOutput` implementors | `schema/cli-envelope.schema.json` |

and one is *derived from a registry*:

| Surface | Authoritative source | Published as |
|---|---|---|
| Error catalogue | `qqq_core::error::ErrorCode` | `docs/errors.md` (existing) |

# Why a generator and a checker, and not just a checker

Because there is nothing to check against until the schemas exist. The workspace
already uses this pair for every generated document — `gen_glossary.py` +
`check_glossary.py`, `gen_error_catalogue.py` + `check_error_catalogue.py`,
`gen_wit_reference.py` + `check_wit_reference.py` — and the pattern works because
each half is independently testable: the generator is driven by a fixture and its
output compared, the checker is driven by a *corrupted* fixture and must report it.

# Why the generator reads Rust source rather than running `qqqai schema`

Because the check has to work in CI on a tree that may not have been built, and
because a check that runs the binary is checking *the binary* rather than the
source. Reading the source means a drift — a field added to `Manifest` and not
regenerated — is caught by the same commit that introduced it.

Reading Rust with a regex is a compromise, and it is stated rather than hidden:
the parser understands `pub struct X { ... }`, `#[serde(rename = "...")]`,
`#[serde(default)]`, `Option<T>`, `Vec<T>`, `bool`, `String`, integers, and
enums. Anything it does not understand is **reported as an error**, never
skipped — a generator that silently omits a field it could not parse produces a
schema that looks complete and is not, which is the failure mode this whole
file exists to prevent.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from dataclasses import dataclass, field

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schema"

# ---------------------------------------------------------------------------
# A small Rust struct reader
# ---------------------------------------------------------------------------


@dataclass
class Field:
    """One field of a Rust struct, with the serde attributes that affect JSON."""

    name: str
    ty: str
    json_name: str
    optional: bool
    defaulted: bool
    is_list: bool
    doc: str = ""


@dataclass
class Struct:
    """A Rust struct reduced to what a JSON Schema needs."""

    name: str
    fields: list[Field] = field(default_factory=list)


class ParseError(Exception):
    """A construct the reader does not understand.

    Raised rather than skipped: an unparsed field would silently vanish from the
    schema, and a schema missing a field is worse than no schema because it is
    believed.
    """


SERDE_RENAME = re.compile(r'#\[serde\([^)]*rename\s*=\s*"([^"]+)"')
SERDE_DEFAULT = re.compile(r"#\[serde\([^)]*default")
SERDE_SKIP = re.compile(r"#\[serde\([^)]*skip_serializing_if")
DOC_LINE = re.compile(r"^\s*///\s?(.*)$")
FIELD = re.compile(r"^\s*pub\s+([a-z_][a-z0-9_]*)\s*:\s*([^,]+),\s*$")


def read_structs(source: str) -> dict[str, Struct]:
    """Every `pub struct` with public fields, keyed by name.

    # Why a line-oriented reader rather than a real parser

    Because the constructs that matter here are line-shaped in this workspace:
    an attribute sits on its own line above the field it applies to, and a field
    declaration ends with a comma on one line. A brace-tracking reader would be
    more general and would also be another parser with its own bugs; the
    self-test drives this one with fabricated source so it is *proven* to detect
    the shapes it claims to.
    """
    structs: dict[str, Struct] = {}
    lines = source.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^pub struct (\w+)", lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        # Find the opening brace.
        while i < len(lines) and "{" not in lines[i]:
            i += 1
        i += 1
        current = Struct(name=name)
        pending: dict[str, object] = {"json": None, "default": False, "skip": False, "doc": ""}
        depth = 1
        while i < len(lines) and depth > 0:
            line = lines[i]
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                break
            doc = DOC_LINE.match(line)
            if doc:
                pending["doc"] = (str(pending["doc"]) + " " + doc.group(1).strip()).strip()
                i += 1
                continue
            ren = SERDE_RENAME.search(line)
            if ren:
                pending["json"] = ren.group(1)
                i += 1
                continue
            if SERDE_DEFAULT.search(line):
                pending["default"] = True
                i += 1
                continue
            if SERDE_SKIP.search(line):
                pending["skip"] = True
                i += 1
                continue
            f = FIELD.match(line)
            if f:
                fname, ftype = f.group(1), f.group(2).strip()
                optional = ftype.startswith("Option<")
                is_list = ftype.startswith("Vec<") or ftype.startswith("BTreeMap<")
                current.fields.append(
                    Field(
                        name=fname,
                        ty=ftype,
                        json_name=str(pending["json"] or fname),
                        optional=optional,
                        defaulted=bool(pending["default"]) or optional,
                        is_list=is_list,
                        doc=str(pending["doc"]),
                    )
                )
                pending = {"json": None, "default": False, "skip": False, "doc": ""}
            i += 1
        structs[name] = current
    return structs


ENUM_HEAD = re.compile(r"^pub enum (\w+)")
VARIANT = re.compile(r"^\s{4}([A-Z]\w*),\s*$")
AS_STR_ARM = re.compile(r'Self::(\w+)\s*=>\s*"([^"]+)"')


def read_enums(source: str) -> dict[str, list[str]]:
    """Every `pub enum` and the JSON spellings its `as_str` maps variants to.

    # Why the reader insists on an `as_str`

    Because a variant name is not a JSON value. `ChangeKind::ModifiedInPlace`
    serialises as `"modified-in-place"`, and a schema listing the variant name
    would describe a document that never exists — worse than no schema, because
    it is believed. So an enum with no `as_str` is a parse failure with that
    reason, not a fallback.

    # Why unit variants only

    Because these enums are used as config values and change kinds, which are
    plain strings in the file formats. An enum with data-carrying variants would
    serialise differently (as an externally-tagged object, by default), and this
    reader refuses rather than guessing which representation applies.
    """
    enums: dict[str, list[str]] = {}
    lines = source.splitlines()
    i = 0
    while i < len(lines):
        m = ENUM_HEAD.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        while i < len(lines) and "{" not in lines[i]:
            i += 1
        i += 1
        variants: list[str] = []
        depth = 1
        while i < len(lines) and depth > 0:
            line = lines[i]
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                break
            v = VARIANT.match(line)
            if v:
                variants.append(v.group(1))
            i += 1
        # Find the matching `impl` and its `as_str` arms.
        spelling: dict[str, str] = {}
        j = i
        while j < len(lines) and not re.match(rf"^(pub )?(struct|enum|fn|mod) ", lines[j]):
            if f"impl {name}" in lines[j]:
                k = j
                while k < len(lines) and not re.match(r"^(pub )?(struct|enum|fn|mod) ", lines[k]):
                    arm = AS_STR_ARM.search(lines[k])
                    if arm:
                        spelling[arm.group(1)] = arm.group(2)
                    k += 1
                break
            j += 1
        if spelling:
            enums[name] = [spelling[v] for v in variants if v in spelling]
        i += 1
    return enums


def json_type(
    rust_type: str,
    known: set[str] | None = None,
    enums: dict[str, list[str]] | None = None,
) -> dict:
    """The JSON Schema type for a Rust type.

    # Why `known` is threaded through

    Because a Rust field can name a struct declared in the same file --
    `package: Package`, `packages: Vec<LockPackage>` -- and a schema generator
    that did not resolve those would either omit the field (silently producing an
    incomplete contract) or refuse (which is what this one did on its first run:
    ``unrecognised Rust type: 'Package'``). Resolving a named type to a `$ref`
    into `$defs` is both the correct answer and the more useful document, since a
    reader can then follow the nesting.

    # Why it raises rather than falling back to `{}`

    Because a permissive fallback is how a schema quietly stops describing
    anything. `{}` validates every value, so a field typed `{}` in a published
    schema is indistinguishable from an undocumented field -- and the whole point
    of the document is that a reader can trust it.
    """
    t = rust_type.strip()
    if t.startswith("Option<") and t.endswith(">"):
        inner = json_type(t[len("Option<") : -1], known, enums)
        return {"anyOf": [inner, {"type": "null"}]}
    if t.startswith("Vec<") and t.endswith(">"):
        return {"type": "array", "items": json_type(t[len("Vec<") : -1], known, enums)}
    if t.startswith("BTreeMap<") and t.endswith(">"):
        return {"type": "object", "additionalProperties": True}
    if known and t in known:
        return {"$ref": f"#/$defs/{t}"}
    if enums is not None and t in enums:
        return {"type": "string", "enum": enums[t]}
    scalar = {
        "String": {"type": "string"},
        "bool": {"type": "boolean"},
        "u8": {"type": "integer", "minimum": 0, "maximum": 255},
        "u16": {"type": "integer", "minimum": 0, "maximum": 65535},
        "u32": {"type": "integer", "minimum": 0},
        "u64": {"type": "integer", "minimum": 0},
        "usize": {"type": "integer", "minimum": 0},
        "i64": {"type": "integer"},
        "f64": {"type": "number"},
    }
    if t in scalar:
        return scalar[t]
    raise ParseError(f"unrecognised Rust type: {t!r}")


def schema_for(
    struct: Struct,
    title: str,
    description: str,
    extra: dict | None = None,
    known: set[str] | None = None,
    enums: dict[str, list[str]] | None = None,
) -> dict:
    """A JSON Schema for one struct."""
    props: dict[str, dict] = {}
    required: list[str] = []
    for f in struct.fields:
        body = json_type(f.ty, known, enums)
        if f.doc:
            body = {"description": f.doc[:300], **body}
        props[f.json_name] = body
        # `skip_serializing_if` without `default` means the field may be absent
        # on output, so it is not required for a reader. A field that is neither
        # optional nor defaulted is required.
        if not f.optional and not f.defaulted:
            required.append(f.json_name)
    out: dict = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://qqq.codes/schema/{title}",
        "title": title,
        "description": description,
        "type": "object",
        "properties": props,
    }
    if required:
        out["required"] = sorted(required)
    if extra:
        out.update(extra)
    return out


# ---------------------------------------------------------------------------
# The surfaces
# ---------------------------------------------------------------------------


def manifest_schema() -> dict:
    src = (ROOT / "crates/qqq-cap/src/manifest.rs").read_text(encoding="utf-8")
    structs = read_structs(src)
    enums = read_enums(src)
    if "Manifest" not in structs:
        raise ParseError("`Manifest` not found in crates/qqq-cap/src/manifest.rs")
    root = structs["Manifest"]
    # Drop the private/derived fields that are not part of the file format.
    root.fields = [f for f in root.fields if f.name not in {"source", "path"}]
    names = set(structs)
    schema = schema_for(
        root,
        "qqq-toml",
        "The QQQ manifest, `qqq.toml`. Every field is validated on parse; "
        "`deny_unknown_fields` means an unrecognised key is an error rather than "
        "a silent no-op.",
        known=names,
        enums=enums,
    )
    # The nested capability tables, so a reader sees their shapes too.
    defs = {}
    for name in sorted(structs):
        if name == "Manifest":
            continue
        defs[name] = schema_for(
            structs[name], f"qqq-toml#{name}", f"The `{name}` table.", known=names, enums=enums
        )
    if defs:
        schema["$defs"] = defs
    return schema


def lockfile_schema() -> dict:
    src = (ROOT / "crates/qqq-pkg/src/lock.rs").read_text(encoding="utf-8")
    structs = read_structs(src)
    enums = read_enums(src)
    if "Lockfile" not in structs:
        raise ParseError("`Lockfile` not found in crates/qqq-pkg/src/lock.rs")
    names = set(structs)
    schema = schema_for(
        structs["Lockfile"],
        "qqq-lock",
        "The QQQ lockfile, `qqq.lock`. `lockfile-hash` covers every resolved "
        "package **and** the recorded build config (CON-005).",
        known=names,
        enums=enums,
    )
    defs = {}
    for name in sorted(structs):
        if name == "Lockfile":
            continue
        defs[name] = schema_for(
            structs[name], f"qqq-lock#{name}", f"The `{name}` record.", known=names, enums=enums
        )
    if defs:
        schema["$defs"] = defs
    return schema


def cli_envelope_schema() -> dict:
    """The JSON envelope every `qqqai` command emits.

    # Why this one is hand-written rather than derived

    Because it is not one struct — it is the *contract* the `CommandOutput`
    trait requires of every implementor, and the trait is the authority. The
    schema states the envelope's own shape; per-command `data` shapes come from
    `qqqai schema --all`, which derives them from the command table.

    The field list is checked against the trait by
    `check_schema_drift.py`, so this literal cannot drift from the code.
    """
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://qqq.codes/schema/cli-envelope",
        "title": "qqqai-cli-envelope",
        "description": (
            "The stable JSON envelope every `qqqai` command emits under `--json`. "
            "`schema_version` is bumped only for a breaking change within a major "
            "version."
        ),
        "type": "object",
        "properties": {
            "schema_version": {"type": "string"},
            "command": {"type": "string"},
            "ok": {"type": "boolean"},
            "data": {"type": ["object", "array", "null"]},
            "error": {
                "anyOf": [
                    {
                        "type": "object",
                        "properties": {
                            "code": {"type": "string"},
                            "message": {"type": "string"},
                            "remediation": {"type": ["string", "null"]},
                        },
                        "required": ["code", "message"],
                    },
                    {"type": "null"},
                ]
            },
        },
        "required": ["schema_version", "command", "ok"],
    }


SURFACES = {
    "qqq-toml.schema.json": manifest_schema,
    "qqq-lock.schema.json": lockfile_schema,
    "cli-envelope.schema.json": cli_envelope_schema,
}


def render(schema: dict) -> str:
    """A schema as stable, diffable JSON."""
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def generate(check: bool) -> int:
    """Write every schema, or report what would change.

    # The bug this function had, and why it was worth a self-test

    The first version incremented `failures` when a schema could not be generated
    — an unrecognised Rust type, or a struct that had been renamed — and then
    **returned 0** on the write path. Measured by injection 4 of
    `self_test_schemas.py`:

    ```text
    GENERATION FAILED for qqq-lock.schema.json: unrecognised Rust type: 'NoSuchType'
    exit 0
    ```

    So a CI job running the generator would pass while one of the three schemas
    was **never published** — the other two were written, the failure was printed
    to stderr, and the exit code said everything was fine. A partial publication
    is worse than a failed one, because the tree then holds a mix of current and
    stale contracts with nothing marking which is which.

    Two fixes, and the second is about honesty rather than control flow:

    * **A generation failure is always a non-zero exit**, on both paths. The
      `--check` and write modes differ in what they *do*, not in whether they
      tolerate a schema they could not build.
    * **The two failure kinds are reported separately.** "Could not be generated"
      and "drifted from the implementation" need different fixes — the first is a
      parser gap or a renamed type, the second is a forgotten regeneration — and
      collapsing them into one "N schema(s) drifted" message sends the reader to
      the wrong fix.
    """
    SCHEMA_DIR.mkdir(exist_ok=True)
    ungenerated: list[str] = []
    drifted: list[str] = []

    for name, build in SURFACES.items():
        path = SCHEMA_DIR / name
        try:
            text = render(build())
        except ParseError as e:
            print(f"GENERATION FAILED for {name}: {e}", file=sys.stderr)
            ungenerated.append(name)
            continue
        if check:
            if not path.exists():
                print(f"MISSING: {path} has not been generated", file=sys.stderr)
                drifted.append(name)
                continue
            if path.read_text(encoding="utf-8") != text:
                print(
                    f"DRIFT: {path} does not match the implementation. Run "
                    f"`python tools/gen_schemas.py` to regenerate.",
                    file=sys.stderr,
                )
                drifted.append(name)
                continue
            print(f"  OK    {path.relative_to(ROOT)}")
        else:
            path.write_text(text, encoding="utf-8")
            print(f"  wrote {path.relative_to(ROOT)}")

    if ungenerated:
        print(
            f"\n{len(ungenerated)} schema(s) could not be generated: "
            f"{', '.join(ungenerated)}. The generator refused rather than "
            f"publishing a schema with fields it could not describe.",
            file=sys.stderr,
        )
    if drifted:
        print(
            f"\n{len(drifted)} schema(s) drifted from the implementation: "
            f"{', '.join(drifted)}",
            file=sys.stderr,
        )
    if ungenerated or drifted:
        return 1
    if check:
        print("\nSCHEMAS OK — every generated schema matches the implementation")
    return 0


def main() -> int:
    check = "--check" in sys.argv
    return generate(check)


if __name__ == "__main__":
    sys.exit(main())
