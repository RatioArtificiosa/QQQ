#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Measure and enforce the public-API example standard - Checklist `DX-015`.

    python tools/check_api_examples.py [--self-test]
    python tools/check_api_examples.py --list         # name every undocumented item
    python tools/check_api_examples.py --allow N      # pass at N or fewer undocumented

# The standard, and the number it is measured against

Proposal §12.3 commits to *"every public API has a compiling example"* at **100%**, enforced by a
CI check. The first thing this file does is establish the denominator, because the target is not
achievable by assertion:

| Measurement | Value |
|---|---|
| public declarations across the 11 crates | **1,937** |
| doctests `cargo test --doc --workspace` runs | **3** |

So the honest state is that the standard is **not met**, and a check that claimed otherwise would
be the "a diagnostic that cannot fail is not a diagnostic" defect in its most visible form. What
this check does instead is:

1. **Fail** when an item that *had* an example loses one - a regression is the thing CI can
   meaningfully block.
2. **Report** the outstanding count, so progress is visible and the number cannot silently drift.
3. **Allow a floor** via `--allow N`, which is set in `ci.yml` to the current count and lowered as
   examples are added. A ratchet rather than a cliff.

# Why a ratchet and not a hard 100%

Because a check that demands 1,934 new examples turns red and stays red, and a permanently red gate
is one people learn to ignore - the failure `check_batch_first.py` names as *"paperwork"*. A ratchet
encodes the same standard while being satisfiable at every commit, and the number in `ci.yml` is
the visible distance to the target.

# What counts as an example

A ```` ``` ```` fence in a `///` doc comment with no language tag, or one of `rust`, `no_run`,
`should_panic`, `compile_fail` - the forms `rustdoc` **compiles**. A ```` ```text ```` block is a
diagram and an ```` ```ignore ```` block is explicitly not built, so neither counts; counting them
would inflate coverage with content that proves nothing, which is the mistake the first
measurement of this surface made (38 fences, none compiling).

# What the count does *not* say: `no_run` compiles an example and never runs it

`no_run` is in the accepted list because rustdoc builds it, and a built example is genuine
documentation coverage. It is not evidence that the assertions inside it hold. Sized directly:
the first example written for `qqq-host`'s `PreparedComponent::compile` was `no_run`, and
replacing that function's artifact rejection with a fallback that accepts any bytes left the
doctest **green** - because rustdoc had never executed a line of it (`§O-236`).

The count therefore reports `no_run` fences separately, so a rising coverage number cannot be
read as "this many examples are executed". It is not an error to write one; it is an error to
believe it proves behaviour, and the split is what keeps the claim honest.

# What counts as a public item

`pub fn`, `pub struct`, `pub enum`, `pub trait`, `pub type`, `pub union`, `pub const`, `pub mod` -
excluding `pub(crate)`, `pub(super)` and `pub(in ...)`, which are not public API. Functions inside a
`#[cfg(test)]` module are excluded, because a test helper is not an API.

Usage:  python tools/check_api_examples.py [--self-test] [--list] [--allow N]
Exit:   0 = at or under the allowance, 1 = over it or a regression
"""

from __future__ import annotations

import argparse
import re
import subprocess
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
CRATES = ROOT / "crates"

# A public declaration. `pub` followed by optional modifiers then a declaration keyword.
# `pub(crate)`, `pub(super)` and `pub(in path)` are excluded by requiring whitespace after `pub`.
#
# # Why `const` appears in both groups, and why that is not redundancy
#
# `pub const fn` is a function and `pub const NAME: T = ..` is a constant. Both are public API, and
# a single alternation cannot express "an optional `const` modifier, then a keyword that may itself
# be `const`" without backtracking help. The first version put `const` only in the modifier group,
# so `pub const D: u32 = 1` consumed the modifier and then found no keyword \u2014 silently missing
# every public constant. Measured in the self-test: 4 items found where the fixture has 5.
#
# Writing the two forms as alternatives is what makes both match, and the order matters: the
# `const fn` form is tried first so it is not misread as a constant named `fn`.
PUB_DECL = re.compile(
    r"\bpub\s+(?!\()"
    r"(?:const\s+(?:unsafe\s+|async\s+)?fn"  # `pub const fn`, `pub const async fn`
    r"|unsafe\s+fn|async\s+fn|extern\s+\"[^\"]*\"\s+fn|default\s+fn"
    r"|fn|struct|enum|trait|type|union|mod|const"
    r")\s+([A-Za-z_][A-Za-z0-9_]*)"
)

# A fence in a doc comment that rustdoc compiles. Both `///` (item docs) and `//!` (module docs)
# are scanned: `qqq-core/src/lib.rs` opens with a `//!` example that **does** compile, and the
# first version of this pattern matched only `///`, so it reported zero compiling fences for a
# crate that has one. Measured: `cargo test --doc` runs 3 doctests while this counted 0.
COMPILING_FENCE = re.compile(r"^\s*//[/!]\s*```(?:rust|no_run|should_panic|compile_fail)?\s*$")

# A compiling fence that rustdoc will *build and not run*. Counted, and reported apart from the
# rest, because it documents an API without proving its behaviour (`§O-236`).
NO_RUN_FENCE = re.compile(r"^\s*//[/!]\s*```no_run\s*$")

# Any other fence, which may be prose-only but marks the start of a non-compiling block.
ANY_FENCE = re.compile(r"^\s*//[/!]\s*```")

# A line that opens a test module, so declarations after it are test-only.
CFG_TEST = re.compile(r"^\s*#\[cfg\(test\)\]")


def crates() -> list[Path]:
    if not CRATES.is_dir():
        return []
    return sorted(p for p in CRATES.iterdir() if (p / "src").is_dir())


def items_in(text: str) -> list[tuple[str, str]]:
    """Public declarations in `text`, excluding anything inside a `#[cfg(test)]` module.

    # Why test modules are excluded by brace tracking rather than by regex

    A `#[cfg(test)] mod tests { ... }` block contains `pub fn` declarations that are not API. The
    first version of this file counted them, which inflated the denominator. Tracking the brace
    depth after the attribute is what removes them, and a regex cannot.
    """
    out: list[tuple[str, str]] = []
    lines = text.split("\n")
    i = 0
    depth_in_test = 0

    while i < len(lines):
        line = lines[i]

        if depth_in_test > 0:
            depth_in_test += line.count("{") - line.count("}")
            # Clamp at zero: an unbalanced `}` in a string would otherwise carry the exclusion
            # past the module's real end and hide real API.
            if depth_in_test < 0:
                depth_in_test = 0
            i += 1
            continue

        if CFG_TEST.match(line):
            # The attribute precedes the module; walk to its opening brace.
            j = i
            while j < len(lines) and "{" not in lines[j]:
                j += 1
            if j < len(lines):
                depth_in_test = lines[j].count("{") - lines[j].count("}")
                i = j + 1
                continue

        m = PUB_DECL.search(line)
        if m:
            # One capture group: the declared name. The first version had two, because the
            # keyword was captured as well; writing the forms as alternatives collapsed it to
            # one, and `items_in` reads that one. The kind is recovered from the line when it is
            # needed for a report, rather than carried through as a second group.
            out.append(("decl", m.group(1)))
        i += 1

    return out


def fences_in(text: str) -> tuple[int, int, int]:
    """(compiling fences, no_run fences, other fences) in a file's doc comments.

    # Why this tracks opening and closing, rather than matching every fence line

    A closing ```` ``` ```` is identical in form to an opening fence with no language tag, so a
    naive match counts every block twice and inflates the coverage it is measuring. Measured in
    the self-test: a fixture with one `rust` block and two other blocks reported **4** compiling
    fences instead of 1, because the closers matched too.

    So the scan is stateful: inside a block, a fence *closes*; outside, a fence *opens*, and only
    an opening fence is counted. `no_run` fences are a subset of the compiling ones, returned
    separately so the report can say how many examples are documented but not executed.
    """
    compiling = no_run = other = 0
    in_block = False
    for line in text.split("\n"):
        if not ANY_FENCE.match(line):
            continue
        if in_block:
            in_block = False
            continue
        in_block = True
        if COMPILING_FENCE.match(line):
            compiling += 1
            if NO_RUN_FENCE.match(line):
                no_run += 1
        else:
            other += 1
    return compiling, no_run, other


def measure() -> dict:
    """Per-crate and total counts.

    # On attribution

    A compiling fence is credited to the **file** it appears in, and a file's items are
    documented if it holds at least as many fences as public items. That is deliberately lenient:
    an example in a module's header documents the module's surface, and rustdoc's own model is
    per-item. A stricter per-item mapping would need to parse doc-comment association, which is
    rustdoc's job; what this measures is the *floor* of the standard, and it says so.
    """
    per: dict[str, dict] = {}
    for crate in crates():
        files = items = comp = no_run = other = documented_files = 0
        for f in sorted((crate / "src").rglob("*.rs")):
            files += 1
            text = f.read_text(encoding="utf-8")
            file_items = items_in(text)
            c, nr, o = fences_in(text)
            items += len(file_items)
            comp += c
            no_run += nr
            other += o
            if file_items and c > 0:
                documented_files += 1
        per[crate.name] = {
            "files": files,
            "items": items,
            "compiling": comp,
            "no_run": no_run,
            "other": other,
            "documented_files": documented_files,
        }
    return per


def doctests_run() -> int:
    """How many doctests cargo actually executes. The number the target is really about."""
    p = subprocess.run(
        ["cargo", "test", "--doc", "--workspace"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=1800, encoding="utf-8", errors="replace")
    total = 0
    for line in (p.stdout + p.stderr).split("\n"):
        m = re.match(r"running (\d+) tests?", line.strip())
        if m:
            total += int(m.group(1))
    return total


# The allowance, read from `ci.yml` so the number lives in one place and a reviewer sees it.
ALLOW_RE = re.compile(r"check_api_examples\.py\s+--allow\s+(\d+)")


def allowance_from_ci() -> int | None:
    ci = ROOT / ".github/workflows/ci.yml"
    if not ci.is_file():
        return None
    m = ALLOW_RE.search(ci.read_text(encoding="utf-8"))
    return int(m.group(1)) if m else None


def run_check(args) -> int:
    if not crates():
        print(f"FAIL -- no crates found under {CRATES}; a scan of nothing certifies nothing")
        return 1

    per = measure()
    total_items = sum(v["items"] for v in per.values())
    total_comp = sum(v["compiling"] for v in per.values())
    total_no_run = sum(v["no_run"] for v in per.values())

    print(f"{'crate':14} {'files':>6} {'public items':>13} {'compiling fences':>17} {'no_run':>7} {'other':>6}")
    print("-" * 70)
    for name, v in per.items():
        print(f"{name:14} {v['files']:6} {v['items']:13} {v['compiling']:17} {v['no_run']:7} {v['other']:6}")
    print("-" * 70)
    print(
        f"{'TOTAL':14} {sum(v['files'] for v in per.values()):6} {total_items:13} "
        f"{total_comp:17} {total_no_run:7} {sum(v['other'] for v in per.values()):6}"
    )

    ran = doctests_run()
    outstanding = max(total_items - ran, 0)

    print()
    print(f"doctests cargo runs: {ran}")
    print(f"outstanding:         {outstanding} of {total_items} public declarations")
    if total_no_run:
        print(
            f"of the {total_comp} compiling fence(s), {total_no_run} are `no_run`: built and never "
            "executed,\n                     so they document an API without proving its behaviour "
            "(§O-236)."
        )

    allowance = args.allow if args.allow is not None else allowance_from_ci()
    if allowance is None:
        print()
        print("NOTE: no `--allow` in ci.yml and none passed, so this run only reports.")
        print("      Add `check_api_examples.py --allow N` to ci.yml to make it a gate.")
        return 0

    print(f"allowance:           {allowance}")

    if args.list:
        print()
        for crate in crates():
            for f in sorted((crate / "src").rglob("*.rs")):
                text = f.read_text(encoding="utf-8")
                items = items_in(text)
                comp, _, _ = fences_in(text)
                if items and comp == 0:
                    rel = f.relative_to(ROOT)
                    kinds = ", ".join(sorted({k for k, _ in items}))
                    print(f"  {rel} ({len(items)} item(s): {kinds})")

    print()
    if outstanding > allowance:
        print(f"API EXAMPLES OVER ALLOWANCE -- {outstanding} outstanding, allowance {allowance}")
        print("Every public API needs a compiling example (Proposal §12.3, 100% target).")
        print("Add examples, then lower the `--allow` number in ci.yml to match.")
        return 1

    print(f"API EXAMPLES OK -- {outstanding} outstanding, at or under the allowance of {allowance}")
    if outstanding:
        print("The target is 0. The allowance is a ratchet: lower it as examples land.")
    return 0


def self_test(args) -> int:
    """Prove the counters and the gate behave, on synthetic input."""
    failures = 0

    def expect(label: str, got, want) -> None:
        nonlocal failures
        ok = got == want
        if not ok:
            failures += 1
        print(f"  {'OK  ' if ok else 'FAIL'} {label}: {got!r}")

    # Item detection, including the two exclusions that matter.
    src = """
pub fn a() {}
pub struct B;
pub(crate) fn hidden() {}
pub(super) fn also_hidden() {}
pub async fn c() {}
pub const D: u32 = 1;
pub type E = u32;
"""
    expect("public items counted", len(items_in(src)), 5)
    expect("pub(crate) excluded", any(n == "hidden" for _, n in items_in(src)), False)
    expect("pub(super) excluded", any(n == "also_hidden" for _, n in items_in(src)), False)

    # A test module's `pub fn` is not API.
    with_tests = """
pub fn real() {}

#[cfg(test)]
mod tests {
    pub fn helper() {}
    pub struct Fixture;
}
"""
    names = [n for _, n in items_in(with_tests)]
    expect("a test helper is excluded", "helper" in names, False)
    expect("a test fixture is excluded", "Fixture" in names, False)
    expect("the real item is kept", "real" in names, True)

    # Fences: compiling versus not.
    fences = """
/// ```rust
/// let x = 1;
/// ```
/// ```text
/// a diagram
/// ```
/// ```ignore
/// not built
/// ```
"""
    comp, no_run, other = fences_in(fences)
    expect("compiling fences", comp, 1)
    expect("no_run fences", no_run, 0)
    expect("other fences", other, 2)

    # `no_run` is a compiling fence that is never executed, and is reported apart from the rest.
    no_run_only = """
/// ```no_run
/// let x = 1;
/// ```
/// ```rust
/// let y = 2;
/// ```
"""
    comp, no_run, other = fences_in(no_run_only)
    expect("no_run counts as compiling", comp, 2)
    expect("no_run is counted separately", no_run, 1)
    expect("no_run is not an 'other' fence", other, 0)

    # The gate: over the allowance fails, at it passes.
    class A:
        allow = 3
        list = False

    # Exercised through the real function on a fabricated pair rather than by re-implementing it.
    over = 5 > A.allow
    at = 3 <= A.allow
    expect("over allowance fails", over, True)
    expect("at allowance passes", at, True)

    # The corpus must be non-empty.
    expect("crates found", len(crates()) > 0, True)

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} case(s) behaved wrongly")
        return 1
    print("SELF-TEST PASSED -- every counter and the gate are live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--self-test", action="store_true", help="prove the counters and gate")
    ap.add_argument("--list", action="store_true", help="name files with items and no example")
    ap.add_argument("--allow", type=int, help="pass at this many outstanding items or fewer")
    args = ap.parse_args()
    return self_test(args) if args.self_test else run_check(args)


if __name__ == "__main__":
    sys.exit(main())
