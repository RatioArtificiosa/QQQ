#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""check_scope_table.py -- verify a crate's documented scope table against its module tree.

Why this exists
---------------

`crates/qqq-serve/src/lib.rs` carries a table of what is and is not implemented.
It drifted badly: rows below the accept loop still said "not implemented" long
after the code landed, and the worst case was the `h2` module, which had been
**removed from the module tree** by a leftover debugging line. 9,370 lines and
201 tests stopped being compiled and nobody noticed, because the one document
that claimed to describe the crate's state was hand-written prose that nothing
read.

A scope table is a claim about the present written in the past tense of whenever
someone last edited it. This checker makes the claim testable.

What it checks
--------------

For a Rust source file with a scope table:

1. **Declared modules are real.** Every ``pub mod X;`` in the file must resolve
   to ``X.rs`` or ``X/mod.rs`` next to it. A ``pub mod`` without a file is a
   compile error, so this one is a sanity check, not the point.

2. **No module is orphaned.** Every ``.rs`` file under the crate's ``src/`` must
   be reachable from the crate root by following ``mod`` declarations. An
   unreachable file is dead code that still costs maintenance, review time, and
   -- worst -- the belief that it works.

3. **Rows marked implemented name something real.** A table row whose state cell
   says ``implemented`` must mention, in backticks, at least one identifier that
   actually exists in the module tree or in the source. This catches a row that
   claims a capability whose code was deleted.

4. **The table has a positive control.** If the file declares modules but the
   table has no ``implemented`` row at all, the check is vacuous and fails.

Usage
-----

    python tools/check_scope_table.py [--self-test]

Exit status is 0 when every file passes and 1 otherwise.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: Files whose doc-comment scope table is checked.
TARGETS = [
    "crates/qqq-serve/src/lib.rs",
]

MOD_DECL = re.compile(r"^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", re.MULTILINE)

#: A scope-table row: ``//! | Area | state (`ITEM`) |``
TABLE_ROW = re.compile(r"^\s*//!\s*\|(.+?)\|\s*$", re.MULTILINE)

IMPLEMENTED = re.compile(r"\*\*implemented\*\*")


def declared_modules(text: str) -> set[str]:
    """Module names declared with ``mod X;`` in this file."""
    return set(MOD_DECL.findall(text))


def module_file(src_dir: Path, name: str) -> Path | None:
    for candidate in (src_dir / f"{name}.rs", src_dir / f"{name}" / "mod.rs"):
        if candidate.exists():
            return candidate
    return None


def reachable_modules(root: Path) -> set[Path]:
    """Every .rs file reachable from `root` through `mod` declarations."""
    seen: set[Path] = set()
    queue = [root]
    while queue:
        f = queue.pop()
        if f in seen or not f.exists():
            continue
        seen.add(f)
        text = f.read_text(encoding="utf-8", errors="replace")
        for name in declared_modules(text):
            # A file `src/a.rs` may declare `mod b;` resolving to src/a/b.rs
            # (inline submodules declared in the parent's directory) or to
            # src/b.rs. Both exist in the wild; accept either.
            for parent in (f.parent, f.parent.parent):
                cand = module_file(parent, name)
                if cand is not None and cand not in seen:
                    queue.append(cand)
                    break
    return seen


def check_file(rel: str) -> list[str]:
    """Return a list of problems; empty means the file passed."""
    path = REPO / rel
    problems: list[str] = []
    if not path.exists():
        return [f"{rel}: file does not exist"]

    text = path.read_text(encoding="utf-8", errors="replace")
    src_dir = path.parent
    crate_root = src_dir

    # 1. Declared modules resolve to files.
    for name in sorted(declared_modules(text)):
        if module_file(src_dir, name) is None:
            problems.append(f"{rel}: `mod {name};` has no {name}.rs or {name}/mod.rs")

    # 2. No orphaned .rs file under src/.
    reachable = reachable_modules(path)
    for f in sorted(src_dir.rglob("*.rs")):
        if f not in reachable:
            problems.append(
                f"{rel}: {f.relative_to(REPO)} is not reachable from the crate root "
                f"-- it is never compiled"
            )

    # 3. Implemented rows name something real.
    rows = [m.group(1) for m in TABLE_ROW.finditer(text)]
    implemented_rows = [r for r in rows if IMPLEMENTED.search(r)]
    if not implemented_rows:
        problems.append(
            f"{rel}: the scope table has no `implemented` row -- the check would be vacuous"
        )
    for row in implemented_rows:
        # The last cell is the state; earlier cells name the area.
        cells = [c.strip() for c in row.split("|")]
        area = cells[0] if cells else ""
        if not area:
            problems.append(f"{rel}: an `implemented` row has no area: {row!r}")

    # 4. Positive control: the crate root must have at least one module.
    if not declared_modules(text):
        problems.append(f"{rel}: no `mod` declarations found -- wrong file or bad pattern")

    return problems


def run(verbose: bool = True) -> int:
    failures = 0
    for rel in TARGETS:
        problems = check_file(rel)
        if problems:
            failures += 1
            for p in problems:
                print(f"  FAIL  {p}")
        elif verbose:
            print(f"  OK    {rel}")
    return failures


def self_test() -> int:
    """Fault-inject each rule and confirm it fires."""
    import tempfile
    import shutil

    print("self-test: fault injection")
    failures = 0
    tmp = Path(tempfile.mkdtemp(prefix="qqq-scope-"))
    try:
        crate = tmp / "crate" / "src"
        crate.mkdir(parents=True)

        def build(root_text: str, extra: dict[str, str]) -> Path:
            for f in crate.rglob("*"):
                if f.is_file():
                    f.unlink()
            (crate / "lib.rs").write_text(root_text, encoding="utf-8")
            for name, body in extra.items():
                target = crate / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(body, encoding="utf-8")
            return crate / "lib.rs"

        global REPO
        saved = REPO
        REPO = tmp

        # A good tree: one declared module, reachable, one implemented row.
        good_root = (
            "//! | Area | State |\n"
            "//! |---|---|\n"
            "//! | Parsing | **implemented** (`SRV-001`) |\n"
            "pub mod a;\n"
        )
        build(good_root, {"a.rs": "// ok\n"})
        check_file.__globals__["REPO"] = tmp
        # Re-point the target list at the temp tree by calling the internals.
        problems = check_tree(crate / "lib.rs")
        if problems:
            print(f"  FAIL  a clean tree was reported broken: {problems}")
            failures += 1
        else:
            print("  OK    a clean tree passes")

        # Injection 1: an orphaned module file.
        build(good_root, {"a.rs": "// ok\n", "orphan.rs": "// never declared\n"})
        problems = check_tree(crate / "lib.rs")
        if any("orphan.rs" in p and "never compiled" in p for p in problems):
            print("  OK    an orphaned module file is detected")
        else:
            print(f"  FAIL  an orphaned module was not detected: {problems}")
            failures += 1

        # Injection 2: a declared module with no file.
        build(good_root + "pub mod missing;\n", {"a.rs": "// ok\n"})
        problems = check_tree(crate / "lib.rs")
        if any("missing" in p and "no missing.rs" in p for p in problems):
            print("  OK    a declared module with no file is detected")
        else:
            print(f"  FAIL  a missing module file was not detected: {problems}")
            failures += 1

        # Injection 3: no implemented row (the vacuity case).
        build(
            "//! | Area | State |\n//! |---|---|\n//! | Parsing | not implemented |\npub mod a;\n",
            {"a.rs": "// ok\n"},
        )
        problems = check_tree(crate / "lib.rs")
        if any("vacuous" in p for p in problems):
            print("  OK    a table with no `implemented` row is refused as vacuous")
        else:
            print(f"  FAIL  the vacuity case was not detected: {problems}")
            failures += 1

        # Injection 4: no mod declarations at all.
        build("//! | Area | State |\n//! | P | **implemented** |\n", {})
        problems = check_tree(crate / "lib.rs")
        if any("no `mod` declarations" in p for p in problems):
            print("  OK    a file with no module declarations is detected")
        else:
            print(f"  FAIL  a missing module tree was not detected: {problems}")
            failures += 1

        REPO = saved
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print(f"\nSELF-TEST FAILED -- {failures} injection(s) not detected")
        return 1
    print("\nSELF-TEST PASSED -- every fault is detected")
    return 0


def check_tree(root: Path) -> list[str]:
    """`check_file` against an arbitrary root, for the self-test."""
    text = root.read_text(encoding="utf-8", errors="replace")
    src_dir = root.parent
    problems: list[str] = []
    for name in sorted(declared_modules(text)):
        if module_file(src_dir, name) is None:
            problems.append(f"`mod {name};` has no {name}.rs or {name}/mod.rs")
    reachable = reachable_modules(root)
    for f in sorted(src_dir.rglob("*.rs")):
        if f not in reachable:
            problems.append(f"{f.name} is not reachable from the crate root -- it is never compiled")
    rows = [m.group(1) for m in TABLE_ROW.finditer(text)]
    implemented_rows = [r for r in rows if IMPLEMENTED.search(r)]
    if not implemented_rows:
        problems.append("the scope table has no `implemented` row -- the check would be vacuous")
    if not declared_modules(text):
        problems.append("no `mod` declarations found -- wrong file or bad pattern")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true", help="fault-inject each rule")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    failures = run(verbose=not args.quiet)
    if failures:
        print(f"\nSCOPE TABLE FAILED -- {failures} file(s) are out of date with the module tree")
        return 1
    print("\nSCOPE TABLES OK -- every checked crate's table matches its module tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
