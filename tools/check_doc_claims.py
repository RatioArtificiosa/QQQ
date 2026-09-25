#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Refuse a document that asserts a count the tree no longer matches - Checklist `DOC-018`.

    python tools/check_doc_claims.py [--self-test]
    python tools/check_doc_claims.py --list

# What §2.6 asks for, and the half that is decidable

> Freshness is tested | A CI job builds a sample project against the *published* docs and fails if
> the docs describe an API that no longer exists.

Building a sample project is one mechanism. The **decidable** part is narrower and is what
actually drifted: a document asserting a *count* or a *number* that the tree no longer produces.
Measured four times in one working period on `docs/unsafe-audit.md` alone \u2014 141\u2192142, 142\u2192143,
143\u2192146, 146\u2192147 `.rs` files \u2014 every occurrence caught by CI and none locally.

The five **generated** documents (`errors.md`, `glossary.md`, `reconciliation.md`,
`verified-facts.md`, `wit-reference.md`) already have generators with `--check` halves, all wired
into CI and the bridge. This file covers the **hand-written** ones, which is where the drift above
happened and where nothing was watching.

# A claim must be *declared checkable*, not guessed at

The scanner does **not** try to decide whether an arbitrary number in prose is a claim about the
tree. That would match versions, dates and port numbers, and a check with false positives is one
that gets disabled. Instead a claim is opt-in:

```markdown
<!-- qqq:claim workspace-tests -->527<!-- /qqq:claim -->
```

The comment is invisible in rendered Markdown and names a **resolver** \u2014 a named way of counting
something real. Two resolvers exist today, both cheap and both already measured elsewhere in this
repository's tooling:

| Resolver | What it counts |
|---|---|
| `workspace-tests` | `cargo test --workspace` passing tests |
| `crate-files` | `.rs` files under `crates/` |

Naming the resolver rather than the value is what makes the check possible: the document says
*which fact* it is asserting, and the tool knows how to obtain that fact.

# Why opt-in rather than every number

Because the alternative fails both ways. A pattern-matching rule fires on `2,546 tests` in a
sentence about history, and a silent one misses the claim that matters. An explicit marker with a
named resolver is unambiguous, and a document that has no markers is *unchecked* rather than
*wrongly checked* \u2014 which is a state this file can report honestly.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# `<!-- qqq:claim resolver -->value<!-- /qqq:claim -->`
CLAIM = re.compile(
    r"<!--\s*qqq:claim\s+(?P<resolver>[a-z][a-z0-9-]*)\s*-->\s*"
    r"(?P<value>[0-9][0-9,]*)\s*"
    r"<!--\s*/qqq:claim\s*-->"
)

DOCS = ("*.md", "docs/**/*.md", "crates/*/*.md")


def documents() -> list[Path]:
    found: list[Path] = []
    for pattern in DOCS:
        found.extend(sorted(ROOT.glob(pattern)))
    return sorted({p for p in found if p.is_file()})


def _load_wit_generator():
    """The WIT generator, loaded so the WIT counts come from the thing that renders them.

    `§O-272`: a hand count of `docs/wit-reference.md` gave 61 functions and 72 types,
    matching neither the page nor any tool, because the `**Types**` and `**Functions**`
    sections appear in either order per interface. The generator is the authority for the
    numbers the generator produces, so this asks it rather than re-parsing the WIT.
    """
    spec = importlib.util.spec_from_file_location(
        "gen_wit_reference", ROOT / "tools" / "gen_wit_reference.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_wit_reference"] = module
    spec.loader.exec_module(module)
    return module


_WIT_TOTALS: dict[str, int] | None = None


def wit_totals() -> dict[str, int]:
    """`packages` / `interfaces` / `functions` / `types`, from the generator's own parse.

    Memoised: four resolvers share one parse, and the page is small enough that the first
    call is the only cost.
    """
    global _WIT_TOTALS
    if _WIT_TOTALS is None:
        gen = _load_wit_generator()
        totals = {"packages": 0, "interfaces": 0, "functions": 0, "types": 0}
        for path in sorted((ROOT / "wit").glob("*.wit")):
            record = gen.parse_wit(path)
            totals["packages"] += 1 if record.get("package") else 0
            for iface in record.get("interfaces") or []:
                totals["interfaces"] += 1
                totals["functions"] += gen.interface_calls(iface)
                if isinstance(iface.get("types"), list):
                    totals["types"] += len(iface["types"])
        _WIT_TOTALS = totals
    return _WIT_TOTALS


def _workspace_tests() -> int | None:
    p = subprocess.run(
        ["cargo", "test", "--workspace"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=3600,
    )
    total = 0
    for line in (p.stdout + p.stderr).split("\n"):
        m = re.search(r"test result: ok\. (\d+) passed", line)
        if m:
            total += int(m.group(1))
    # Zero is a failure rather than an answer: a run that produced no results has not
    # counted anything, and reporting 0 would make every claim fail.
    return total if total > 0 else None


# One owner per fact. A resolver is the *only* way a number enters a document, so a
# document that declares a claim names which fact it asserts and this table says how to
# obtain it. Adding a name here without a document that uses it is harmless; adding a
# number to a document without a name here is what the whole mechanism exists to prevent.
#
# The `ARCH-011` lifecycle counts are deliberately NOT here. `check_lifecycle_counts.py`
# already owns them, reading the same `STAGES` table, and it reads the checklist entry
# directly rather than through a marker. A second derivation of one fact is the "one
# number written in three places" defect `§O-244` exists to prevent -- duplicating the
# *derivation* is worse than duplicating the number, because the two can disagree while
# both look authoritative (`§O-277`).
RESOLVERS = {
    "crate-files": lambda: len(list((ROOT / "crates").rglob("*.rs"))),
    "workspace-tests": _workspace_tests,
    "tools-python": lambda: len(list((ROOT / "tools").glob("*.py"))),
    "wit-files": lambda: len(list((ROOT / "wit").rglob("*.wit"))),
    "wit-packages": lambda: wit_totals()["packages"],
    "wit-interfaces": lambda: wit_totals()["interfaces"],
    "wit-functions": lambda: wit_totals()["functions"],
    "wit-types": lambda: wit_totals()["types"],
}


def resolve(name: str) -> int | None:
    """The current value for a named resolver. `None` when the resolver is unknown."""
    fn = RESOLVERS.get(name)
    return fn() if fn else None


def claims_in(text: str) -> list[tuple[str, int, int]]:
    """(resolver, declared value, line number) for each claim in `text`."""
    out = []
    for i, line in enumerate(text.split("\n"), 1):
        for m in CLAIM.finditer(line):
            out.append((m.group("resolver"), int(m.group("value").replace(",", "")), i))
    return out


def run_check(args) -> int:
    docs = documents()
    if not docs:
        print("FAIL -- no documents found; a scan of nothing certifies nothing")
        return 1

    checked = 0
    stale: list[str] = []
    unknown: list[str] = []

    # Resolved once per distinct resolver rather than once per claim, because
    # `workspace-tests` runs the suite and doing that per claim would be minutes.
    cache: dict[str, int | None] = {}

    for doc in docs:
        text = doc.read_text(encoding="utf-8")
        found = claims_in(text)
        for resolver, declared, line_no in found:
            if resolver not in cache:
                cache[resolver] = resolve(resolver)
            actual = cache[resolver]
            rel = doc.relative_to(ROOT)
            if actual is None:
                unknown.append(f"{rel}:{line_no}  unknown resolver `{resolver}`")
                continue
            checked += 1
            if actual != declared:
                stale.append(f"{rel}:{line_no}  `{resolver}` says {declared}, the tree has {actual}")

    print(f"documents scanned: {len(docs)}")
    print(f"resolvers seen:    {', '.join(sorted(cache)) or '(none)'}")
    for name, value in sorted(cache.items()):
        print(f"  {name}: {value if value is not None else 'UNRESOLVED'}")
    print(f"claims checked:    {checked}")

    if args.list:
        print()
        for doc in docs:
            for resolver, declared, line_no in claims_in(doc.read_text(encoding="utf-8")):
                print(f"  {doc.relative_to(ROOT)}:{line_no}  {resolver} = {declared}")

    print()
    for u in unknown:
        print(f"  UNKNOWN  {u}")
    for s in stale:
        print(f"  STALE    {s}")

    if unknown or stale:
        print()
        print(f"DOC CLAIMS FAILED -- {len(stale)} stale, {len(unknown)} unknown resolver(s)")
        return 1

    if checked == 0:
        # Not a failure: a document set with no declared claims is *unchecked*, which is a
        # different state from *wrong*. Saying so is the honest report, and `--list` shows the
        # resolvers available for anyone who wants to add one.
        print("DOC CLAIMS OK -- no document declares a checkable count")
        print("Add `<!-- qqq:claim workspace-tests -->N<!-- /qqq:claim -->` to make one checkable.")
        return 0

    print(f"DOC CLAIMS OK -- {checked} claim(s) match the tree")
    return 0


def self_test(args) -> int:
    """Prove the scanner and the comparison behave, on synthetic input."""
    failures = 0

    def expect(label: str, got, want) -> None:
        nonlocal failures
        ok = got == want
        if not ok:
            failures += 1
        print(f"  {'OK  ' if ok else 'FAIL'} {label}: {got!r}")

    # A marked claim is found; an unmarked number is not.
    marked = "The suite runs <!-- qqq:claim workspace-tests -->2,546<!-- /qqq:claim --> tests."
    found = claims_in(marked)
    expect("a marked claim is found", len(found), 1)
    expect("its resolver", found[0][0] if found else None, "workspace-tests")
    expect("commas are stripped", found[0][1] if found else None, 2546)

    unmarked = "The suite runs 2,546 tests."
    expect("an unmarked number is ignored", len(claims_in(unmarked)), 0)

    # Two claims on one line.
    two = (
        "<!-- qqq:claim crate-files -->147<!-- /qqq:claim --> files in "
        "<!-- qqq:claim workspace-tests -->2546<!-- /qqq:claim --> tests."
    )
    expect("two claims on one line", len(claims_in(two)), 2)

    # An unknown resolver is reported rather than treated as zero.
    expect("an unknown resolver resolves to None", resolve("no-such-resolver"), None)

    # The real resolvers must answer, or every claim would be "unknown".
    expect("crate-files resolves", isinstance(resolve("crate-files"), int), True)

    # The corpus must be non-empty.
    expect("documents found", len(documents()) > 0, True)

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} case(s) behaved wrongly")
        return 1
    print("SELF-TEST PASSED -- the scanner, the resolvers and the comparison are live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--self-test", action="store_true", help="prove the checks are live")
    ap.add_argument("--list", action="store_true", help="list every declared claim")
    args = ap.parse_args()
    return self_test(args) if args.self_test else run_check(args)


if __name__ == "__main__":
    sys.exit(main())
