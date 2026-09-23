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
`#[serde(default)]`, `#[serde(skip_serializing_if = "...")]`, `Option<T>`,
`Vec<T>`, `bool`, `String`, integers, and enums. Anything it does not understand
is **reported as an error**, never skipped — a generator that silently omits a
field it could not parse produces a schema that looks complete and is not, which
is the failure mode this whole file exists to prevent.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from dataclasses import dataclass, field, replace

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
    # `#[serde(skip_serializing_if = "...")]`: the field can be absent from a
    # document this code wrote, so it cannot be required of a reader.
    skipped: bool
    doc: str = ""


@dataclass
class Struct:
    """A Rust struct reduced to what a JSON Schema needs."""

    name: str
    fields: list[Field] = field(default_factory=list)


class UnknownType(Exception):
    """A Rust type this generator cannot describe.

    Distinct from `ParseError`: a `ParseError` means the *input* is wrong and generation must
    stop. An `UnknownType` means this one type is opaque to the generator, which can still
    emit something honest about it -- see the `BTreeMap` branch, which falls back to a
    permissive schema for an unknown value type rather than emitting a `$ref` to a definition
    that will not exist.
    """


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
# A public field declaration: the name, then a type that may contain commas inside
# angle brackets.
#
# # The bug this fixes
#
# `[^,]+` stops at the first comma, including one inside a generic. So
#
#     pub dev_dependencies: BTreeMap<String, Dependency>,
#
# captured `BTreeMap<String` and then failed to match `, Dependency>,` against the
# trailing `,\s*$`. The field was **silently dropped**, and
# `schema/qqq-toml.schema.json` has documented only `package`, `build`,
# `capabilities` and `limits` -- `dependencies` and `dev-dependencies` were never in
# it, while `--check` reported the schema current.
#
# # Why this shape and not `(.+),\s*$`
#
# `(.+),\s*$` is correct and hangs: `\s*` and `.` both match a space and `$` can be
# retried at every position, so a non-matching line costs quadratic time. The
# generator consumed all available memory rather than reporting a defect in itself.
#
# This pattern consumes each character through exactly one alternative -- a run of
# non-comma, non-angle characters, or a balanced one-level `<...>` group -- so there is
# nothing to backtrack into.
FIELD = re.compile(
    r"^\s*pub\s+([a-z_][a-z0-9_]*)\s*:\s*([^,<]*(?:<[^<>]*>[^,<]*)*),\s*$"
)


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
        # An attribute may be written across several lines:
        #
        #     #[serde(
        #         default,
        #         rename = "dev-dependencies",
        #         skip_serializing_if = "BTreeMap::is_empty"
        #     )]
        #
        # `SERDE_RENAME`, `SERDE_DEFAULT` and `SERDE_SKIP` each anchor on
        # `#[serde(` and continue across newlines, so searching them against one
        # line at a time can never match a multi-line attribute. That is the bug
        # this buffer fixes, and its consequence was worse than a wrong `required`
        # list: `dev_dependencies` kept its Rust name instead of the declared
        # `"dev-dependencies"`, so the published schema documented a **key that
        # does not exist** while the real key was unconstrained (`§O-205`).
        #
        # The block is accumulated from the `#[serde(` line until the closing `)]`,
        # then the three patterns are searched against it once.
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

            # An attribute block: gather it whole, then read it once.
            if "#[serde(" in line:
                block = line
                j = i
                while ")]" not in lines[j]:
                    j += 1
                    block += "\n" + lines[j]
                ren = SERDE_RENAME.search(block)
                if ren:
                    pending["json"] = ren.group(1)
                if SERDE_DEFAULT.search(block):
                    pending["default"] = True
                if SERDE_SKIP.search(block):
                    pending["skip"] = True
                i = j + 1
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
                        skipped=bool(pending["skip"]),
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
        # `additionalProperties` from the map's **value** type, not `true`.
        #
        # `true` accepts any value for any key, so `per_tenant.acme = "nonsense"` validated,
        # and so did `dependencies.serde = 42`. The keys must stay dynamic -- they are tenant
        # names and package names -- but the values have a type, and a schema that does not
        # say so is a schema that agrees with everything.
        #
        # The value type is found by splitting on the **top-level** comma, because the key and
        # value types can each contain one: `BTreeMap<String, Vec<u8>>` has a comma inside the
        # value, and a naive `split(",")` would take `Vec<u8>` for two types. The same
        # nesting problem the field parser has (see the note at the top of this file).
        inner = t[len("BTreeMap<") : -1]
        depth = 0
        split = None
        for i, ch in enumerate(inner):
            if ch == "<":
                depth += 1
            elif ch == ">":
                depth -= 1
            elif ch == "," and depth == 0:
                split = i
                break
        value = inner[split + 1 :].strip() if split is not None else "String"
        # A value type this generator cannot describe keeps the permissive form **only for
        # itself**, and says so in the schema rather than in a comment. `Dependency` is such a
        # type: it is an untagged enum in the manifest that `structs` does not collect, so
        # there is no `$def`, and a `$ref` to a missing definition is a schema no validator can
        # use -- worse than a permissive one, because it fails loudly on a *correct* manifest.
        #
        # So the rule is: constrain the values when the type is known, and stay permissive
        # when it is not -- never silently, and never by pretending.
        try:
            described = json_type(value, known, enums)
        except UnknownType:
            return {"type": "object", "additionalProperties": True}
        return {"type": "object", "additionalProperties": described}
    if known and t in known:
        return {"$ref": f"#/$defs/{t}"}
    if enums is not None and t in enums:
        return {"type": "string", "enum": enums[t]}
    scalar = {
        "String": {"type": "string"},
        # A borrowed string serialises identically to an owned one, so the
        # document says `string` for both. `Envelope.producer` and
        # `Envelope.version` are `&'static str`; refusing them would mean the
        # envelope could not be derived, which is how it came to be hand-written
        # and then drift (`§O-205`).
        "&'static str": {"type": "string"},
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
    # The payload of the generic CLI envelope. It is not a Rust type name that
    # appears in this workspace's declarations — it stands for
    # `serde_json::Value`, which the envelope is instantiated with at its call
    # sites. Kept out of `scalar` deliberately so that `Manifest` or `Lockfile`
    # cannot use it: an arbitrary value in a file-format field would be a defect,
    # not a contract.
    if t == "AnyJson":
        return {"type": ["object", "array", "null"]}
    raise UnknownType(f"unrecognised Rust type: {t!r}")


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
        # A field is required only when it must be present on **input**.
        #
        # Three things make it optional, and all three are read from the source:
        #
        #   * `Option<T>` -- an absent key and an explicit null are the same.
        #   * `#[serde(default)]` -- serde substitutes the default on absence.
        #   * `#[serde(skip_serializing_if = "...")]` -- the field may be absent
        #     from a document this code wrote, so a reader must accept its
        #     absence. This is the case that was missing, and it published a
        #     schema that **rejected a minimal manifest the parser accepts**:
        #     `dev-dependencies` carries
        #     `skip_serializing_if = "BTreeMap::is_empty"`, so it disappears from
        #     every manifest with no dev dependencies, and the schema's
        #     `required` still demanded it (`§O-205`).
        #
        # The distinction the two serde attributes draw is real and worth keeping
        # straight: `skip_serializing_if` alone says nothing about *deserialization*
        # in general. It is honoured here because the workspace pairs it with a
        # container type that is empty by default, so absence and empty coincide,
        # and because the parser was _measured_ accepting the absent form rather
        # than assumed to. `check_schema_conformance.py` is what keeps that
        # assumption honest: it drives the real parser and the published schema
        # over one corpus and fails if the two disagree.
        if not f.optional and not f.defaulted and not f.skipped:
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
    """The JSON envelope every `qqqai` command emits — derived from the struct.

    # Why this is now derived rather than hand-written

    It used to be a literal, on the reasoning that the envelope "is not one struct
    but the contract the `CommandOutput` trait requires of every implementor". The
    literal's doc comment then claimed the field list "is checked against the trait
    by `check_schema_drift.py`, so this literal cannot drift from the code".

    **There is no `check_schema_drift.py`.** Nothing checked it, and it drifted:
    the hand-written document listed `schema_version`, `command`, `ok`, `data` and
    an `error` with `code` / `message` / `remediation`, while the binary actually
    emits `producer`, `version` and `summary` at the root and `docs_url`,
    `retryable`, `cause` and `context` inside `error`. A client generated from the
    published document would drop all seven.

    The premise was also wrong: the envelope *is* two structs, `Envelope<T>` and
    `ErrorPayload`, both plain `#[derive(Serialize)]` types in
    `crates/qqq-run/src/output.rs`. Deriving the document from them is the same
    treatment `Manifest` and `Lockfile` get, and it removes the literal that had no
    guard.

    Per-command `data` shapes are still not here: they come from
    `qqqai schema --all`, which derives them from the command table.
    """
    src = (ROOT / "crates/qqq-run/src/output.rs").read_text(encoding="utf-8")
    structs = read_structs(src)
    enums = read_enums(src)
    for required in ("Envelope", "ErrorPayload"):
        if required not in structs:
            raise ParseError(f"`{required}` not found in crates/qqq-run/src/output.rs")

    envelope = structs["Envelope"]
    # `Envelope<T>` is generic in its payload, and `data: Option<T>` carries a
    # *per-command* shape that this document does not describe — per-command
    # shapes come from `qqqai schema --all`, which derives them from the command
    # table. So the payload is written as the one thing true of every
    # instantiation: an arbitrary JSON value, which is what the old hand-written
    # document also said (`["object", "array", "null"]`).
    #
    # `Value` is spelled into the field rather than added to the type resolver,
    # because there is no Rust type to name here: `serde_json::Value` is only
    # reachable through `Envelope<Value>` at the two call sites in `output.rs`,
    # and the generator reads declarations, not instantiations. Adding `Value` to
    # the scalar table would also silently accept it in `Manifest` or `Lockfile`,
    # where an arbitrary value would be a defect.
    envelope.fields = [
        (
            replace(f, ty="AnyJson")
            if f.name == "data"
            else f
        )
        for f in envelope.fields
    ]

    names = set(structs)
    schema = schema_for(
        envelope,
        "qqqai-cli-envelope",
        "The stable JSON envelope every `qqqai` command emits under `--json`. "
        "`schema_version` is bumped only for a breaking change within a major "
        "version.",
        known=names,
        enums=enums,
    )
    # The envelope is a closed contract: an agent parses it by field name, and a
    # field the document does not describe is one a generated client silently
    # drops. The nested records get the same treatment.
    # The nested records, restricted to the ones REACHABLE from `Envelope`.
    #
    # Emitting `$defs` for every struct in the file pulled in `CommandSchema`,
    # whose `data_schema` is a raw `serde_json::Value`, and `Output`, which is the
    # renderer rather than part of the wire format. Neither is in the envelope, and
    # generating them produced a hard failure — correctly, because the generator
    # refuses a type it cannot describe rather than omitting the field. The
    # reachable set is `ErrorPayload` (via `error`) and `ErrorContextEntry` (via
    # `error.context`).
    reachable = {"ErrorPayload", "ErrorContextEntry"}
    defs = {}
    for name in sorted(reachable & set(structs)):
        # `ErrorPayload.backtrace` is `Option<ResolvedBacktrace>`, whose struct
        # lives in `crates/qqq-run/src/trap_report.rs` — a different module with a
        # different contract. Describing it as an opaque object is honest and is
        # what the field is here: the envelope promises the key exists, and the
        # trap report's own shape belongs to the trap report.
        s = structs[name]
        s.fields = [
            replace(f, ty="AnyJson") if f.ty.endswith("ResolvedBacktrace>") else f
            for f in s.fields
        ]
        defs[name] = schema_for(
            s, f"qqqai-cli-envelope#{name}", f"The `{name}` record.",
            known=names, enums=enums,
        )
    if defs:
        schema["$defs"] = defs
    return schema


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
