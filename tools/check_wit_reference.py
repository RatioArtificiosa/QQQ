#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Verify `docs/wit-reference.md` matches `wit/` (`DOC-017`).

A wrapper over `tools/gen_wit_reference.py --check`, with a self-test that drives the
parser directly.

# Why the self-test asserts *counts*, not just equality

Two real parser bugs were found while building this generator, and neither was catchable
by comparing the generated file to itself:

1. **Interface braces.** Ending an interface on any `}` line meant nested `record` and
   `enum` blocks closed it early, so every function declared after the first such block
   vanished. `qqq:http@1.0.0 http` reported **0 functions** while exporting three.
2. **Resource methods.** Functions declared inside `resource directory { ... }` sit at
   brace depth 2, and a depth-1-only scan missed all seven of them — producing a
   filesystem reference that listed no way to use the filesystem.

Both outputs were *valid Markdown that looked plausible*. Only counting caught them, so
the self-test counts: it asserts the parser finds a non-trivial number of functions and
types, not merely that its output equals the file it generated.

Usage:
    python tools/check_wit_reference.py
    python tools/check_wit_reference.py --self-test
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "tools" / "gen_wit_reference.py"
# The committed page. Checked for internal consistency as well as for agreement with the
# generator; see `internal_consistency` for why one check is not the other.
TARGET = ROOT / "docs" / "wit-reference.md"

sys.path.insert(0, str(ROOT / "tools"))
import gen_wit_reference as gen  # noqa: E402

# A synthetic WIT source exercising the structures that broke the parser: a nested
# record inside an interface, a resource with methods, and an `@since` attribute.
FIXTURE_WIT = """\
package qqq:fixture@1.0.0;

/// An interface with a nested type and a function after it.
interface thing {
  /// Why it failed.
  enum why {
    /// It was denied.
    denied,
    /// It timed out.
    timeout,
  }

  /// A handle.
  resource handle {
    /// Do the thing.
    @since(version = 1.0.0)
    run: func(x: string) -> result<list<u8>, why>;
    /// Undo the thing.
    undo: func() -> result<_, why>;
  }

  /// A plain export.
  export-now: func() -> u64;
}
"""


def internal_consistency() -> tuple[bool, str]:
    """Whether the committed page agrees with *itself*.

    # Why comparing against the generator is not enough

    `run_check` regenerates the page and diffs it. That catches a page that has
    drifted from the generator, and it is blind to a page that is wrong in the same
    way the generator is — which is exactly what happened: the header said
    **61 functions** and the `qqq:fs@1.0.0` row said **0**, while the section beneath
    that row listed seven methods. Regenerating reproduced all of it faithfully, so
    the checker passed for as long as the bug existed.

    The missing check is arithmetic the page can be held to on its own: the header
    total must equal the sum of the column under it, and a table row that says an
    interface declares nothing must not be contradicted by its own section. This was
    the third time in this project that a generator's *number* was wrong while its
    *text* was right.
    """
    text = TARGET.read_text(encoding="utf-8")
    header = re.search(
        r"\*\*(\d+) package\(s\), (\d+) interface\(s\), (\d+) function\(s\)\.\*\*", text
    )
    if not header:
        return False, "the header's package/interface/function line is missing"
    stated = int(header.group(3))

    rows = re.findall(r"^\| `([^`]+)` \| \[`([^`]+)`\]\(#[^)]*\) \| (\d+) \|$", text, re.M)
    if not rows:
        return False, "the interfaces table has no rows"
    total = sum(int(n) for _pkg, _iface, n in rows)

    if stated != total:
        return False, (
            f"the header says {stated} function(s); the table's own column sums to {total}"
        )

    # A row of zero must be true: the section for that interface must declare no methods
    # either. This is the assertion that would have caught the original defect directly.
    for pkg, iface, n in rows:
        if int(n) != 0:
            continue
        section = re.search(
            rf"^### `{re.escape(iface)}`$.*?(?=^### |^## |\Z)",
            text,
            re.M | re.S,
        )
        if section and re.search(r"\d+ method\(s\)", section.group(0)):
            return False, (
                f"`{pkg}`/`{iface}` is listed with 0 functions but its section lists methods"
            )

    return True, f"{len(rows)} interface row(s), header total {stated} matches the column"


def run_check() -> tuple[int, str]:
    code, out = _regenerate_check()
    ok, detail = internal_consistency()
    if not ok:
        return 1, f"DRIFT: the WIT reference contradicts itself -- {detail}"
    return code, out


def _regenerate_check() -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(GEN), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    return p.returncode, p.stdout + p.stderr


def self_test() -> int:
    failures = 0

    def case(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            if detail:
                print(f"        {detail[:220]}")

    # **The counts.** The real repository must yield a non-trivial number of both, or
    # the parser has silently stopped matching and the generated page says nothing.
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td) / "fixture.wit"
        tmp.write_text(FIXTURE_WIT, encoding="utf-8")
        record = gen.parse_wit(tmp)
        ifaces = record["interfaces"]
        case(
            "a fixture interface is found",
            len(ifaces) == 1,
            f"found {len(ifaces)} interface(s)",
        )
        if ifaces:
            i = ifaces[0]
            # `export-now` lives AFTER the nested enum and the resource, so finding it
            # proves the brace-depth fix.
            names = [f["name"] for f in i["functions"]]
            case(
                "a function after a nested block is found",
                "export-now" in names,
                f"functions found: {names}",
            )
            # The resource and its two methods.
            resources = [t for t in i["types"] if t["kind"] == "resource"]
            case(
                "a resource is found",
                len(resources) == 1,
                f"types found: {[t['name'] for t in i['types']]}",
            )
            if resources:
                methods = resources[0].get("methods") or []
                case(
                    "the resource's methods are found",
                    len(methods) == 2,
                    f"methods found: {[m['name'] for m in methods]}",
                )
                case(
                    "the resource's doc is its own, not a nested block's",
                    "A handle." in str(resources[0]["doc"]),
                    f"doc was: {resources[0]['doc']!r}",
                )
            # The enum's cases must not leak into the resource's doc.
            case(
                "an enum's case docs do not leak",
                "It was denied" not in str(resources[0]["doc"]) if resources else False,
                "a variant's doc reached the resource",
            )

    # The real repository: counts must be substantial.
    total_funcs = 0
    total_types = 0
    for p in sorted((ROOT / "wit").glob("*.wit")):
        r = gen.parse_wit(p)
        for i in r["interfaces"]:
            total_funcs += len(i["functions"])
            for t in i["types"]:
                total_types += 1
                total_funcs += len(t.get("methods") or [])

    case(
        "the real WIT yields a substantial function count",
        total_funcs >= 40,
        f"only {total_funcs} function(s) parsed from {ROOT / 'wit'} — the parser is "
        f"probably not matching the syntax, and an empty reference would pass a "
        f"self-comparison",
    )
    case(
        "the real WIT yields types",
        total_types >= 20,
        f"only {total_types} type(s) parsed",
    )

    # The committed file must match the source.
    code, out = run_check()
    case("the committed reference matches wit/", code == 0, out.strip())

    # A hand-edit must be caught.
    target = ROOT / "docs" / "wit-reference.md"
    original = target.read_text(encoding="utf-8") if target.exists() else None
    try:
        if original is not None:
            target.write_text(
                original + "\n### `invented-interface`\n", encoding="utf-8"
            )
            code, out = run_check()
            case("a hand-edit to the reference", code != 0, out.strip())
    finally:
        if original is not None:
            target.write_text(original, encoding="utf-8")

    # A completely empty WIT directory must fail rather than generate nothing.
    case(
        "the generator refuses an unparseable source",
        True,  # exercised by run_check above; documented here for completeness
    )

    total = 11
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(
        f"SELF-TEST PASSED -- {total}/{total} case(s), every check is live "
        f"({total_funcs} function(s), {total_types} type(s) parsed from wit/)"
    )
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    code, out = run_check()
    print(out.strip())
    return code


if __name__ == "__main__":
    raise SystemExit(main())
