#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Enforce the WIT deprecation policy — Checklist `CON-015`.

# The policy

Proposal §2.5 (NN-5) makes `@since` / `@unstable` mandatory; `CON-015` adds the
third gate annotation, `@deprecated(version = X.Y.Z)`, with the mechanics
`docs/deprecations.md` defines:

* `X.Y.Z` is the first version where the item is deprecated.
* It is never earlier than the item's `@since` (an item cannot be deprecated
  before it is introduced) and never later than the package version (an item
  cannot be deprecated in a release that does not exist yet).
* The deprecated item keeps its doc comment, which names the replacement —
  the migration pointer a silent removal would deny the reader.
* Every `@deprecated` has exactly one row in `docs/deprecations.md` naming
  the replacement and a removal version at least two minor versions later
  within the same major (NN-8's window; a new major version satisfies it).

# What this checks, and why each rule exists

| Rule | Why |
|---|---|
| Every `@deprecated` version parses as `X.Y.Z` | An unparseable version is not a policy, and the toolchain accepts only the numeric form |
| `@since` <= deprecated <= package version | A deprecation outside the item's lifetime is a contradiction, usually a copy-paste of another item's block |
| A deprecated function keeps its doc comment | The annotation carries no message field (verified: `wasm-tools` rejects `@deprecated(version, message)`), so the doc comment is the only place the replacement can live |
| Every `@deprecated` has a ledger row, and every ledger row names a live `@deprecated` | A ledger that drifts is worse than no ledger: it tells a reader an item is safe to remove when the interface says otherwise, or vice versa |
| Ledger removal version honours the two-minor window | NN-8's "minimum two-minor-version window" as arithmetic, not prose |

# What is deliberately NOT required

* **Removal detection.** Deleting a deprecated item before its removal version
  is a violation no tree snapshot can see — the item is simply absent. The
  ledger records the promise; history records the breach.
* **`@unstable` interaction.** Nothing in V1 is marked unstable, so there is
  no deprecated-unstable combination to rule on. If one appears, this tool
  should be extended rather than guessed at now.

# A rule the toolchain already enforces

`@deprecated` without `@since` is rejected by `wasm-tools` itself ("cannot
specify @deprecated without @since or @unstable" — verified, not assumed).
The checker's without-`@since` rule stays as defence in depth: it costs one
comparison and names the contradiction in policy terms rather than parser
terms. But it is honestly redundant today, and the harness proves the other
rules instead of pretending to exercise this one — a harness injection
without `@since` could never parse, so every type-level injection carries
both annotations.

Usage:  python tools/check_wit_deprecated.py
Exit:   0 = policy satisfied, 1 = at least one violation
"""

from __future__ import annotations

import re
import sys
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
WIT_DIR = ROOT / "wit"
LEDGER = ROOT / "docs" / "deprecations.md"

# `package qqq:clock@1.0.0;`
PACKAGE_RE = re.compile(r"^\s*package\s+([a-z0-9-]+):([a-z0-9-]+)@(\d+)\.(\d+)\.(\d+)\s*;")

# `now: func(...) -> ...;` at any indentation, first token the function name.
FUNC_RE = re.compile(r"^\s*([a-z][a-z0-9-]*)\s*:\s*(?:async\s+)?func\b")

# Named type declarations an annotation can precede: `record`, `variant`,
# `enum`, `flags`, and `type` aliases.
TYPE_RE = re.compile(r"^\s*(?:record|variant|enum|flags|type)\s+([a-z][a-z0-9-]*)")

# `resource handle {` — methods inside are qualified by it.
RESOURCE_RE = re.compile(r"^\s*resource\s+([a-z][a-z0-9-]*)\s*\{")

# `interface wall-clock {` — the block a function belongs to, for qualified names.
INTERFACE_RE = re.compile(r"^\s*interface\s+([a-z][a-z0-9-]*)\s*\{")

# `@since(version = 1.0.0)` and `@deprecated(version = 1.0.0)`, bare or quoted.
SINCE_RE = re.compile(r"@since\s*\(\s*version\s*=\s*\"?(\d+)\.(\d+)\.(\d+)\"?\s*\)")
DEPRECATED_RE = re.compile(r"@deprecated\s*\(\s*version\s*=\s*\"?(\d+)\.(\d+)\.(\d+)\"?\s*\)")

# Any `@deprecated(` opening, even a malformed one, so a broken annotation is
# reported as a violation rather than silently ignored.
DEPRECATED_ANY_RE = re.compile(r"@deprecated\s*\(")

# A line that is a doc comment.
DOC_RE = re.compile(r"^\s*///")

# Ledger rows: `| item | X.Y.Z | X.Y.Z | replacement |` (header and the
# `(none ...)` placeholder excluded by requiring three version-like cells...
# no — by requiring the row to parse; the placeholder row has empty version
# cells and is skipped explicitly.
LEDGER_ROW_RE = re.compile(
    r"^\|\s*(?P<item>[^|]+?)\s*\|\s*(?P<deprecated>[^|]+?)\s*\|\s*"
    r"(?P<remove>[^|]+?)\s*\|\s*(?P<replacement>[^|]+?)\s*\|$"
)


def parse_version(text: str) -> tuple[int, int, int] | None:
    """A strict `X.Y.Z` triple, or `None` — never a guess."""
    m = re.fullmatch(r"\s*\"?(\d+)\.(\d+)\.(\d+)\"?\s*", text)
    if m is None:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def window_ok(deprecated: tuple[int, int, int], remove: tuple[int, int, int]) -> bool:
    """NN-8's two-minor-version window as arithmetic.

    Removal must be strictly after deprecation: an earlier version is never a
    window, whatever the major. A later major version satisfies any window.
    Within one major, the minor difference must be at least two — patch
    versions do not count, so removing in the same minor (or the next) fails
    no matter how high the patch climbs.
    """
    if remove <= deprecated:
        return False
    if remove[0] != deprecated[0]:
        return remove[0] > deprecated[0]
    return (remove[1] - deprecated[1]) >= 2


def check_file(path: Path) -> tuple[list[str], list[tuple[str, tuple[int, int, int]]]]:
    """Violations plus `(qualified name, deprecated version)` pairs found."""
    lines = path.read_text(encoding="utf-8").splitlines()
    problems: list[str] = []
    found: list[tuple[str, tuple[int, int, int]]] = []

    package: tuple[str, str, tuple[int, int, int]] | None = None
    for line in lines:
        m = PACKAGE_RE.match(line)
        if m:
            package = (m.group(1), m.group(2), (int(m.group(3)), int(m.group(4)), int(m.group(5))))
            break
    if package is None:
        problems.append(f"{path.name}: no `package <ns>:<name>@x.y.z;` line found")
        return problems, found
    namespace, name, package_version = package

    # Pending annotations for the next item: doc lines do not detach them,
    # blank lines do not detach them, and other gate annotations do not
    # clear each other — WIT gate syntax attaches to the next item.
    pending_since: tuple[int, int, int] | None = None
    pending_deprecated: tuple[int, int, int] | None = None
    pending_doc = False
    interface = "(outside any interface)"
    # Resource nesting, as (name, brace depth): a method `old-op` in resource
    # `handle` qualifies as `iface.handle.old-op`, so two resources with the
    # same method name map to distinct ledger keys. Braces are counted on
    # comment-stripped lines — a `}` inside a `//` comment is not structure.
    resource_stack: list[tuple[str, int]] = []
    depth = 0

    def qualified(item: str) -> str:
        if resource_stack:
            return f"{namespace}:{name}.{interface}.{resource_stack[-1][0]}.{item}"
        return f"{namespace}:{name}.{interface}.{item}"

    def flush(item: str, line_number: int) -> None:
        flush_key(qualified(item), item, line_number)

    def flush_key(key: str, item: str, line_number: int) -> None:
        if pending_deprecated is None:
            return
        qualified_name = key
        if pending_since is None:
            problems.append(
                f"{path.name}:{line_number}: `{item}` is `@deprecated` without "
                f"`@since` — a deprecation of an undated item is undatable"
            )
        elif pending_deprecated < pending_since:
            problems.append(
                f"{path.name}:{line_number}: `{item}` deprecated at "
                f"{version_string(pending_deprecated)} before its `@since` "
                f"{version_string(pending_since)}"
            )
        if pending_deprecated > package_version:
            problems.append(
                f"{path.name}:{line_number}: `{item}` deprecated at "
                f"{version_string(pending_deprecated)} after the package "
                f"version {version_string(package_version)}"
            )
        if not pending_doc:
            problems.append(
                f"{path.name}:{line_number}: deprecated `{item}` has no doc "
                f"comment naming the replacement — the annotation carries no "
                f"message field, so the comment is the migration pointer"
            )
        found.append((qualified_name, pending_deprecated))

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if DOC_RE.match(line):
            pending_doc = True
            continue
        if stripped.startswith("//"):
            continue
        match_since = SINCE_RE.search(line)
        if match_since:
            pending_since = (
                int(match_since.group(1)),
                int(match_since.group(2)),
                int(match_since.group(3)),
            )
            continue
        if DEPRECATED_ANY_RE.search(line):
            match_deprecated = DEPRECATED_RE.search(line)
            if match_deprecated is None:
                problems.append(
                    f"{path.name}:{i}: `@deprecated` annotation does not parse "
                    f"as `@deprecated(version = X.Y.Z)`"
                )
                pending_deprecated = None
            else:
                pending_deprecated = (
                    int(match_deprecated.group(1)),
                    int(match_deprecated.group(2)),
                    int(match_deprecated.group(3)),
                )
            continue
        if stripped.startswith("@"):
            continue
        interface_match = INTERFACE_RE.match(line)
        if interface_match:
            # A deprecated interface is itself the item: flush it under the
            # package/interface key before the new block resets the context.
            interface = interface_match.group(1)
            flush_key(f"{namespace}:{name}.{interface}", interface, i)
            resource_stack.clear()
            pending_since = None
            pending_deprecated = None
            pending_doc = False
            depth += line.count("{") - line.count("}")
            continue
        resource_match = RESOURCE_RE.match(line)
        if resource_match:
            # A deprecated resource is itself the item: flush it under the
            # interface/resource key before pushing its block, so its own
            # annotations do not leak into its first method.
            resource_name = resource_match.group(1)
            flush_key(f"{namespace}:{name}.{interface}.{resource_name}", resource_name, i)
            depth += line.count("{") - line.count("}")
            resource_stack.append((resource_name, depth))
            pending_since = None
            pending_deprecated = None
            pending_doc = False
            continue
        match_func = FUNC_RE.match(line)
        if match_func:
            flush(match_func.group(1), i)
            # Unconditional: a doc comment above a plain function must not
            # leak into a later deprecated one, and a gate annotation
            # separated from its item by real code annotates the wrong thing
            # (the misplaced-annotation defect the `@since` harness
            # documents). Carrying anything forward would repeat it.
            pending_since = None
            pending_deprecated = None
            pending_doc = False
            depth += line.count("{") - line.count("}")
            continue
        match_type = TYPE_RE.match(line)
        if match_type:
            flush(match_type.group(1), i)
            pending_since = None
            pending_deprecated = None
            pending_doc = False
            depth += line.count("{") - line.count("}")
            continue
        # A closing brace can end a resource block: pop every resource whose
        # block closed, so a later same-named method does not inherit it.
        depth += line.count("{") - line.count("}")
        while resource_stack and resource_stack[-1][1] > depth:
            resource_stack.pop()
        # Any other item line clears everything pending, for the same reason
        # as above: stale annotations must not drift onto later items.
        pending_since = None
        pending_deprecated = None
        pending_doc = False

    return problems, found


def version_string(version: tuple[int, int, int]) -> str:
    return f"{version[0]}.{version[1]}.{version[2]}"


def check_ledger(
    found: list[tuple[str, tuple[int, int, int]]],
    ledger_path: Path = LEDGER,
) -> list[str]:
    """Both directions between the interfaces and the deprecation ledger."""
    problems: list[str] = []
    if not ledger_path.is_file():
        return ["docs/deprecations.md is missing — the ledger is required even when empty"]
    rows: dict[str, tuple[str, str, str]] = {}
    # Only the `## Entries` section holds entries: the `## Format` section
    # above documents the shape with an example row that must never parse as
    # a promise.
    in_entries = False
    for line in ledger_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            in_entries = line.strip() == "## Entries"
            continue
        if not in_entries:
            continue
        match = LEDGER_ROW_RE.match(line)
        if match is None:
            continue
        item = match.group("item").strip().strip("`").strip()
        bare = item
        # Skip the header, the `---` separator, and the documented empty-table
        # placeholder: none of them is a ledger entry, and matching them as
        # entries would fail every run until the first real deprecation.
        if not bare or bare.startswith("*") or set(bare) <= {"-"} or bare == "Item":
            continue
        rows[item] = (
            match.group("deprecated").strip(),
            match.group("remove").strip(),
            match.group("replacement").strip(),
        )
    by_item = {item: version for item, version in found}
    for item, version in found:
        if item not in rows:
            problems.append(
                f"`{item}` is `@deprecated` at {version_string(version)} with no "
                f"ledger row in docs/deprecations.md"
            )
            continue
        deprecated_text, remove_text, replacement = rows[item]
        if deprecated_text.strip("` ") != version_string(version):
            problems.append(
                f"ledger row for `{item}` says deprecated in {deprecated_text}, "
                f"the interface says {version_string(version)}"
            )
        remove = parse_version(remove_text.strip("` "))
        if remove is None:
            problems.append(
                f"ledger row for `{item}` has an unparseable removal version "
                f"{remove_text!r}"
            )
        elif remove <= version:
            problems.append(
                f"ledger row for `{item}` removes at {version_string(remove)}, "
                f"not after its deprecation at {version_string(version)}"
            )
        elif not window_ok(version, remove):
            problems.append(
                f"ledger row for `{item}` removes at {version_string(remove)}, "
                f"inside NN-8's two-minor-version window after "
                f"{version_string(version)}"
            )
        if not replacement or replacement.strip("` ") == "none":
            problems.append(
                f"ledger row for `{item}` names no replacement — `none` is "
                f"allowed only with a reason"
            )
    for item in rows:
        if item not in by_item:
            problems.append(
                f"ledger row for `{item}` names no live `@deprecated` item — "
                f"a row without an annotation is a promise about nothing"
            )
    return problems


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    problems, found = check_tree(WIT_DIR, LEDGER)
    if problems:
        print("DEPRECATION POLICY FAILED --")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print(
        f"DEPRECATION POLICY OK -- {len(found)} deprecated item(s), "
        f"ledger agrees in both directions"
    )
    return 0


def check_tree(
    wit_dir: Path, ledger_path: Path
) -> tuple[list[str], list[tuple[str, tuple[int, int, int]]]]:
    """Run the policy over one directory plus one ledger (testable half).

    Fails on zero `.wit` files: an empty directory agreeing with an empty
    ledger would pass while examining nothing — the vacuity this project
    refuses in checkers (`§O-130`, `§M-006`).
    """
    files = sorted(wit_dir.rglob("*.wit"))
    if not files:
        return (
            [f"no `.wit` files in {wit_dir} — an empty corpus cannot satisfy a policy"],
            [],
        )
    problems: list[str] = []
    found: list[tuple[str, tuple[int, int, int]]] = []
    for path in files:
        file_problems, file_found = check_file(path)
        problems.extend(file_problems)
        found.extend(file_found)
    problems.extend(check_ledger(found, ledger_path))
    return problems, found


def self_test() -> int:
    """Prove each rule can fail, against temporary fixtures.

    The fault-inject harness (`tools/fault_inject_wit_deprecated.py`) proves
    the same rules against the real tree with parseability verified; this
    self-test proves the pure logic fast, without touching the tree — the
    pairing the WIT checker family uses, so neither proof depends on the
    other.
    """
    import tempfile

    failures = 0
    total = 0

    def case(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures, total
        total += 1
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            if detail:
                print(f"        {detail[:220]}")

    package = "package test:probe@1.0.0;\n"
    ledger_head = (
        "# Ledger\n\n## Entries\n\n"
        "| Item | Deprecated in | Remove in | Replacement |\n"
        "|---|---|---|---|\n"
    )

    def run(wit_text: str | None, ledger_text: str | None) -> list[str]:
        return run_with(wit_text, ledger_text, with_doc=True, with_since=True)

    def run_no_doc(wit_text: str | None, ledger_text: str | None) -> list[str]:
        return run_with(wit_text, ledger_text, with_doc=False, with_since=True)

    def run_no_since(wit_text: str | None, ledger_text: str | None) -> list[str]:
        return run_with(wit_text, ledger_text, with_doc=True, with_since=False)

    def run_with(
        wit_text: str | None, ledger_text: str | None, with_doc: bool, with_since: bool
    ) -> list[str]:
        doc = "  /// Does the thing; use `new-call` instead.\n" if with_doc else ""
        since = "  @since(version = 1.0.0)\n" if with_since else ""
        with tempfile.TemporaryDirectory(prefix="wit-dep-") as tmp:
            root = Path(tmp)
            if wit_text is not None:
                (root / "probe.wit").write_text(
                    package
                    + "interface probe {\n"
                    + doc
                    + since
                    + wit_text
                    + "  old-call: func() -> string;\n"
                    + "}\n",
                    encoding="utf-8",
                )
            if ledger_text is not None:
                (root / "ledger.md").write_text(ledger_head + ledger_text, encoding="utf-8")
            problems, _found = check_tree(root, root / "ledger.md")
            return problems

    def run_type(wit_text: str | None, ledger_text: str | None) -> list[str]:
        with tempfile.TemporaryDirectory(prefix="wit-dep-") as tmp:
            root = Path(tmp)
            if wit_text is not None:
                (root / "probe.wit").write_text(
                    package
                    + "interface probe {\n"
                    + "  /// Old shape; use `new-shape` instead.\n"
                    + "  @since(version = 1.0.0)\n"
                    + wit_text
                    + "  record old-shape {\n"
                    + "    field: string,\n"
                    + "  }\n"
                    + "}\n",
                    encoding="utf-8",
                )
            if ledger_text is not None:
                (root / "ledger.md").write_text(ledger_head + ledger_text, encoding="utf-8")
            problems, _found = check_tree(root, root / "ledger.md")
            return problems

    def run_resource(ledger_text: str | None) -> list[str]:
        template = (
            "  /// A handle.\n"
            "  @since(version = 1.0.0)\n"
            "  resource %s {\n"
            "    /// Old op; use `new-op` instead.\n"
            "    @since(version = 1.0.0)\n"
            "    @deprecated(version = 1.0.0)\n"
            "    old-op: func();\n"
            "  }\n"
        )
        with tempfile.TemporaryDirectory(prefix="wit-dep-") as tmp:
            root = Path(tmp)
            (root / "probe.wit").write_text(
                package + "interface probe {\n" + template % "first" + template % "second" + "}\n",
                encoding="utf-8",
            )
            if ledger_text is not None:
                (root / "ledger.md").write_text(ledger_head + ledger_text, encoding="utf-8")
            problems, _found = check_tree(root, root / "ledger.md")
            return problems

    def run_iface(deprecated_line: str | None, ledger_text: str | None) -> list[str]:
        with tempfile.TemporaryDirectory(prefix="wit-dep-") as tmp:
            root = Path(tmp)
            annotation = deprecated_line if deprecated_line is not None else ""
            (root / "probe.wit").write_text(
                package
                + "  /// Old interface; use `new-iface` instead.\n"
                + "  @since(version = 1.0.0)\n"
                + annotation
                + "interface old-iface {\n"
                + "  /// A call.\n"
                + "  @since(version = 1.0.0)\n"
                + "  old-call: func() -> string;\n"
                + "}\n",
                encoding="utf-8",
            )
            if ledger_text is not None:
                (root / "ledger.md").write_text(ledger_head + ledger_text, encoding="utf-8")
            problems, _found = check_tree(root, root / "ledger.md")
            return problems

    def run_resource_decl(deprecated_line: str | None, ledger_text: str | None) -> list[str]:
        with tempfile.TemporaryDirectory(prefix="wit-dep-") as tmp:
            root = Path(tmp)
            annotation = deprecated_line if deprecated_line is not None else ""
            (root / "probe.wit").write_text(
                package
                + "interface probe {\n"
                + "  /// Old handle; use `new-handle` instead.\n"
                + "  @since(version = 1.0.0)\n"
                + annotation
                + "  resource old-handle {\n"
                + "    /// A call.\n"
                + "    @since(version = 1.0.0)\n"
                + "    op: func();\n"
                + "  }\n"
                + "}\n",
                encoding="utf-8",
            )
            if ledger_text is not None:
                (root / "ledger.md").write_text(ledger_head + ledger_text, encoding="utf-8")
            problems, _found = check_tree(root, root / "ledger.md")
            return problems

    row = "| `test:probe.probe.old-call` | `1.0.0` | `%s` | `new-call` |\n"
    row_none = "| `test:probe.probe.old-call` | `1.0.0` | `1.2.0` | `none` |\n"
    case(
        "a conforming annotation with a conforming row passes",
        run("  @deprecated(version = 1.0.0)\n", row % "1.2.0") == [],
    )
    case(
        "a deprecated version below @since fails",
        any("before its `@since`" in p for p in run("  @deprecated(version = 0.9.0)\n", row % "1.2.0")),
    )
    case(
        "a deprecated version above the package fails",
        any("after the package" in p for p in run("  @deprecated(version = 9.9.9)\n", row % "9.9.9")),
    )
    case(
        "a missing ledger row fails",
        any("no ledger row" in p for p in run("  @deprecated(version = 1.0.0)\n", "")),
    )
    case(
        "an orphan ledger row fails",
        any("no live" in p for p in run("", row % "1.2.0")),
    )
    case(
        "a removal inside the window fails",
        any("inside NN-8" in p for p in run("  @deprecated(version = 1.0.0)\n", row % "1.1.0")),
    )
    case(
        "a removal in a later major passes the window",
        run("  @deprecated(version = 1.0.0)\n", row % "2.0.0") == [],
    )
    case(
        "a removal before deprecation fails",
        any("not after its deprecation" in p for p in run("  @deprecated(version = 1.1.0)\n", row % "1.0.0")),
    )
    case(
        "a deprecated item without a doc comment fails",
        any("no doc comment" in p for p in run_no_doc("  @deprecated(version = 1.0.0)\n", row % "1.2.0")),
    )
    case(
        "an unparseable @deprecated value fails",
        any("does not parse" in p for p in run("  @deprecated(version = someday)\n", "")),
    )
    case(
        "@deprecated without @since fails",
        any("without `@since`" in p for p in run_no_since("  @deprecated(version = 1.0.0)\n", row % "1.2.0")),
    )
    case(
        "a ledger row with a bare `none` replacement fails",
        any("names no replacement" in p for p in run("  @deprecated(version = 1.0.0)\n", row_none)),
    )
    case(
        "an empty directory fails instead of passing vacuously",
        any("no `.wit` files" in p for p in run(None, "")),
    )
    iface_row = "| `test:probe.old-iface` | `1.0.0` | `1.2.0` | `new-iface` |\n"
    case(
        "a deprecated interface without a ledger row fails",
        any("no ledger row" in p for p in run_iface("  @deprecated(version = 1.0.0)\n", "")),
    )
    case(
        "a deprecated interface with a conforming row passes",
        run_iface("  @deprecated(version = 1.0.0)\n", iface_row) == [],
    )
    resource_row = "| `test:probe.probe.old-handle` | `1.0.0` | `1.2.0` | `new-handle` |\n"
    case(
        "a deprecated resource without a ledger row fails",
        any("no ledger row" in p for p in run_resource_decl("  @deprecated(version = 1.0.0)\n", "")),
    )
    case(
        "a deprecated resource with a conforming row passes",
        run_resource_decl("  @deprecated(version = 1.0.0)\n", resource_row) == [],
    )
    shape_row = "| `test:probe.probe.old-shape` | `1.0.0` | `1.2.0` | `new-shape` |\n"
    case(
        "a deprecated record passes with a conforming row",
        run_type("  @deprecated(version = 1.0.0)\n", shape_row) == [],
    )
    case(
        "a deprecated record without a ledger row fails",
        any("no ledger row" in p for p in run_type("  @deprecated(version = 1.0.0)\n", "")),
    )
    handle_row = "| `test:probe.probe.first.old-op` | `1.0.0` | `1.2.0` | `new-op` |\n"
    other_row = "| `test:probe.probe.second.old-op` | `1.0.0` | `1.2.0` | `new-op` |\n"
    third_row = "| `test:probe.probe.third.old-op` | `1.0.0` | `1.2.0` | `new-op` |\n"
    case(
        "same-named methods in different resources map to distinct keys",
        run_resource(handle_row + other_row) == [],
    )
    case(
        "a ledger row for a resource that does not exist fails as orphan",
        any("no live" in p for p in run_resource(handle_row + other_row + third_row)),
    )

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} of {total} case(s) not detected")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every rule is live")
    return 0


if __name__ == "__main__":
    sys.exit(main())
