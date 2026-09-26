#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Find a `pub` item nothing in the workspace references — `pub` is what hides dead code.

    python tools/check_public_reachability.py [--self-test] [--list] [--allow N]

# Why this exists, and what it would have caught

Twelve rounds of this goal have found controls that were **written, tested and never called**:
`AuditStream`, the exports, `recheck`, `Redactor`, the redaction *wiring*, `TenantLabels`, the log
*format*, and a whole `span` module. Every one was found by **grepping for callers** — a manual
habit, and a slow one.

`§O-311` found the mechanical cause. A `pub` item is **reachable from outside the crate**, so
`clippy`'s `dead_code` lint does not apply to it. A module written with `pub` items:

  * said nothing to `clippy`, however unused it was;
  * was counted by `check_api_examples` as *API to be documented* — 17 declarations, 17 examples.

**`pub` disabled the one check that would have named it.** This tool restores that check.

# What it measures, and why it is a ratchet rather than a threshold

For every `pub fn`/`struct`/`enum`/`trait`/`type`/`const`/`static` in `crates/*/src`, it counts
occurrences of the name across the workspace's Rust sources — excluding the declaration itself.

**A count of zero is a candidate, not a defect.** The item is either dead or intended for a consumer
outside this repository, and only a human can say which. So:

  1. **Rule A gates absolutely**: a `pub` item inside a module that is **not** `pub` is unreachable
     from outside *by construction* — the `pub` is a lie about its own visibility, and it silences
     `dead_code` for no reason. There are no false positives; this is the one case the tool refuses.
  2. **Rule B is a ratchet**: the count of unreferenced `pub` items must not **grow** past the
     recorded allowance. A new module with no caller raises it immediately; the existing 22 are a
     known, reviewable baseline. The allowance lives in `ci.yml`, like `check_api_examples`'s, so a
     reviewer sees the number in one place.

# Why the baseline is honest rather than convenient

Measured when this tool was written: **2060 `pub` declarations, 22 referenced nowhere.** The
allowance is that measurement, not a round number, and lowering it is the work — the same discipline
`check_api_examples` states for its own.

# The reference corpus

`crates/*/src`, `crates/*/tests` and `examples/*/src`. **Not** the tools (Python does not reference a
Rust item), and not `docs/` (prose naming a symbol is not a use). A wider corpus would make the
count smaller and the tool quieter, which is the wrong direction for a check whose whole purpose is
to be loud about a symbol nobody calls.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# A public declaration. `pub(crate)` and `pub(super)` are **excluded** — they are already the
# narrower thing, which is what this tool wants a caller-less item to become.
DECL = re.compile(
    r"^\s*pub (?:const |async |unsafe )?(fn|struct|enum|trait|type|const|static)\s+([A-Za-z_]\w*)",
    re.M,
)

# A module declaration, to find items whose `pub` cannot be reached.
MODULE = re.compile(r"^\s*(pub(?:\([^)]*\))? )?mod (\w+)", re.M)

# Where a reference can legitimately appear.
CORPUS_GLOBS = (
    "crates/*/src/**/*.rs",
    "crates/*/tests/**/*.rs",
    "examples/*/src/**/*.rs",
)


def sources() -> list[Path]:
    """Every Rust file in the reference corpus, sorted for determinism."""
    out: list[Path] = []
    for pattern in CORPUS_GLOBS:
        out.extend(ROOT.glob(pattern))
    return sorted(set(out))


def declarations() -> list[tuple[Path, str, str]]:
    """`(file, kind, name)` for every public declaration in `crates/*/src`."""
    out: list[tuple[Path, str, str]] = []
    for path in sorted(ROOT.glob("crates/*/src/**/*.rs")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in DECL.finditer(text):
            out.append((path, m.group(1), m.group(2)))
    return out


IDENT = re.compile(r"[A-Za-z_]\w*")


def identifier_counts() -> dict[Path, Counter[str]]:
    """Every identifier in every corpus file, counted **once**.

    # Why this is a separate pass

    The first version ran one regex per *(declaration, file)* pair -- **2060 x 120** -- which took
    minutes and made the self-test exceed the shell's own timeout. Counting identifiers once per file
    turns every later lookup into a dict access, and the result is identical because a reference is
    a whole identifier.
    """
    return {
        p: Counter(IDENT.findall(p.read_text(encoding="utf-8", errors="replace")))
        for p in sources()
    }


def unreferenced() -> list[tuple[Path, str, str]]:
    """The declarations whose name appears nowhere in the corpus but their own declaration."""
    counts = identifier_counts()
    out: list[tuple[Path, str, str]] = []
    for path, kind, name in declarations():
        uses = sum(c.get(name, 0) for c in counts.values())
        uses -= counts.get(path, Counter()).get(name, 0) and 1  # the declaration itself
        if uses <= 0:
            out.append((path, kind, name))
    return out


def visibility_lies(unref: list[tuple[Path, str, str]]) -> list[tuple[Path, str]]:
    """The **intersection**: unreferenced items whose enclosing module is not `pub`.

    # Why the intersection and not either half

    **Either condition alone has a legitimate reading.** A `pub` item inside a private module that is
    *used* is merely redundantly `pub` — `dead_code` does not fire because the item is live, and the
    tool's first version reported **7** of those as defects. An item that is unreferenced but
    genuinely exported is a judgement call about published API, which is what the ratchet is for.

    **Both together** is the defect `§O-311` names: the `pub` cannot be reached from another crate,
    *and* nothing calls the item — so `pub` silenced exactly the lint that would have said so. There
    are no false positives in that intersection, and the fix is one word.
    """
    out: list[tuple[Path, str]] = []
    # The unreferenced names, by file, so the module walk only has to ask about those.
    wanted: dict[Path, set[str]] = {}
    for path, _kind, name in unref:
        wanted.setdefault(path, set()).add(name)

    for path, names in wanted.items():
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in MODULE.finditer(text):
            visibility, module = m.group(1), m.group(2)
            if visibility and visibility.startswith("pub") and "(" not in visibility:
                continue  # a plain `pub mod` exports what it contains
            start = text.find("{", m.end())
            if start < 0:
                continue
            depth = 0
            end = len(text)
            for i in range(start, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            for d in DECL.finditer(text[start:end]):
                if d.group(2) in names:
                    out.append((path, f"{module}::{d.group(2)}"))
    return out


def check_declaration(
    unref: list[tuple[Path, str, str]], declared_map: dict[tuple[str, str], str]
) -> list[str]:
    """Fail on a stale entry, and on an unreferenced item that is not declared.

    Both directions, because either alone is half a check: a declaration that no longer applies is a
    claim about a tree that has moved, and an item with no declaration is one nobody has decided
    about.
    """
    problems: list[str] = []
    live = {(str(p.relative_to(ROOT)).replace("\\", "/"), n) for p, _k, n in unref}
    for key in sorted(set(declared_map) - live):
        problems.append(
            f"STALE: `{key[1]}` in {key[0]} is declared unreferenced but is now referenced or gone "
            f"-- remove its entry, because a stale exclusion is a claim about a tree that has moved"
        )
    for key in sorted(live - set(declared_map)):
        problems.append(
            f"UNDECLARED: `{key[1]}` in {key[0]} is referenced nowhere and is not in "
            f"tools/public-reachability-allow.txt -- wire it, narrow it to `pub(crate)`, or declare "
            f"it with a reason"
        )
    return problems


def check(unreferenced_count: int, lies: int, allowance: int) -> list[str]:
    """The decision procedure, as a pure function, so `--self-test` can drive it.

    `lies` is the count of items that are **both** unreferenced and inside a module that is not
    `pub` -- the intersection, because either condition alone has a legitimate reading. An item in a
    private module that is *used* is merely redundantly `pub`; an item that is unreferenced but
    exported is a judgement call about published API. **Both together** is the defect `§O-311`
    describes: `pub` silenced `dead_code` for something nothing calls.
    """
    problems: list[str] = []
    if lies:
        problems.append(
            f"{lies} unreferenced `pub` item(s) live in a module that is not `pub`: the visibility "
            f"is unreachable AND the item is dead, so `pub` silenced the lint that would have named "
            f"it. Use `pub(crate)`, or delete it"
        )
    if unreferenced_count > allowance:
        problems.append(
            f"{unreferenced_count} public declaration(s) are referenced nowhere in the workspace, "
            f"over the allowance of {allowance}. Either wire the new one, or narrow it to "
            f"`pub(crate)` — a `pub` item nothing calls is what this check exists to find"
        )
    return problems


DECLARATION = ROOT / "tools" / "public-reachability-allow.txt"


def declared() -> dict[tuple[str, str], str]:
    """The declaration: `(path, name) -> decision`, read from the allow file.

    # Why the allowance is a file and not a number

    `--allow 22` said *how many* and nothing about *which*: a new unreferenced item and a removed one
    cancelled out, and the set could not be reviewed without re-deriving it. The file names every
    entry, so the checker can fail on a **stale** one -- an item that has since gained a caller, or
    that no longer exists. **A stale exclusion is itself a defect**, which is the same rule
    `check_checklist_counts.py` and `check_gate_parity.py` apply to their own declarations.
    """
    out: dict[tuple[str, str], str] = {}
    for line in DECLARATION.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        out[(parts[0], parts[1])] = parts[2]
    return out


def validate(listing: bool, override: int | None) -> int:
    unref = unreferenced()
    lies = visibility_lies(unref)
    total = len(declarations())
    declared_map = declared()

    unreviewed = sum(1 for d in declared_map.values() if d == "unreviewed")

    print(f"public declarations        : {total}")
    print(f"referenced nowhere         : {len(unref)}")
    print(f"`pub` in a non-`pub` module: {len(lies)}")
    print(f"declared, with a reason    : {len(declared_map)} ({unreviewed} still `unreviewed`)")
    if listing:
        for path, kind, name in unref:
            key = (str(path.relative_to(ROOT)).replace("\\", "/"), name)
            decision = declared_map.get(key, "UNDECLARED")
            print(f"  {decision:12} {key[0]}  {kind} {name}")
        for path, what in lies:
            print(f"  VISIBILITY   {path.relative_to(ROOT)}  {what}")

    problems = check_declaration(unref, declared_map)
    problems += check(len(unref), len(lies), override if override is not None else len(unref))

    print("")
    if problems:
        print(f"PUBLIC REACHABILITY FAILED -- {len(problems)} problem(s):")
        for p_ in problems:
            print(f"  FAIL  {p_}")
        return 1
    print(
        f"PUBLIC REACHABILITY OK -- {len(unref)} declared, none stale, "
        f"{unreviewed} awaiting a decision"
    )
    return 0


def self_test() -> int:
    failures = 0

    def case(name: str, got, want) -> None:
        nonlocal failures
        ok = got == want
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}: {got!r}")
        if not ok:
            failures += 1

    # The decision procedure, both rules and both directions.
    case("at the allowance passes", check(22, 0, 22), [])
    case("over the allowance fails", len(check(23, 0, 22)), 1)
    case("a visibility lie fails even at the allowance", len(check(22, 1, 22)), 1)
    case("under the allowance passes", check(0, 0, 22), [])
    case("no allowance and no lies passes", check(99, 0, 99), [])

    # The declaration regex: `pub(crate)` is NOT public and must be excluded.
    src = "pub fn a() {}\npub(crate) fn b() {}\npub(super) fn c() {}\npub struct D;\npub const E: u8 = 1;\n"
    case("public items counted, narrower ones excluded", len(DECL.findall(src)), 3)

    # The visibility rule: `pub` inside `pub(crate) mod` is a lie; inside `pub mod` is not.
    good = "pub mod m {\n    pub fn fine() {}\n}\n"
    bad = "pub(crate) mod m {\n    pub fn lied() {}\n}\n"
    case("a `pub mod` is not a lie", len(_lies_in(good, {"fine"})), 0)
    # `lied` is unreferenced AND in a `pub(crate)` module: the intersection, and the defect.
    case("an unreferenced `pub` in a `pub(crate) mod` is a lie", len(_lies_in(bad, {"lied"})), 1)
    # The same module, but the item IS referenced: merely redundant, not a defect.
    case("a referenced `pub` in a `pub(crate) mod` is not a lie", len(_lies_in(bad, {"other"})), 0)

    # The real workspace must currently pass.
    real = unreferenced()
    lies = visibility_lies(real)
    declared_map = declared()
    problems = check_declaration(real, declared_map)
    print(
        f"  {'OK  ' if not problems else 'DEAD'}  the real workspace's declaration is not stale "
        f"({len(real)} unreferenced, {len(declared_map)} declared, {len(lies)} lie(s))"
    )
    if problems:
        failures += 1
        for p_ in problems[:2]:
            print(f"        {p_}")

    # Staleness, both directions, on synthetic input.
    live = [(ROOT / "crates" / "a" / "src" / "x.rs", "fn", "live_one")]
    case("a declared and live item is fine", check_declaration(live, {("crates/a/src/x.rs", "live_one"): "published-api"}), [])
    case("a declared item that is now referenced is STALE", len(check_declaration([], {("crates/a/src/x.rs", "gone"): "published-api"})), 1)
    case("an undeclared unreferenced item fails", len(check_declaration(live, {})), 1)

    total = 11
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) behaved wrongly")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s); both rules are live")
    return 0


def _lies_in(text: str, names: set[str]) -> list[str]:
    """`visibility_lies` over a string rather than the tree, for the self-test."""
    out: list[str] = []
    for m in MODULE.finditer(text):
        visibility, name = m.group(1), m.group(2)
        if visibility and visibility.startswith("pub") and "(" not in visibility:
            continue
        start = text.find("{", m.end())
        if start < 0:
            continue
        depth = 0
        end = len(text)
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        for d in DECL.finditer(text[start:end]):
            if d.group(2) in names:
                out.append(f"{name}::{d.group(2)}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--self-test", action="store_true", help="prove both rules are live")
    ap.add_argument("--list", action="store_true", help="print every unreferenced declaration")
    ap.add_argument("--allow", type=int, default=None, help="the recorded baseline")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return validate(listing=args.list, override=args.allow)


if __name__ == "__main__":
    raise SystemExit(main())
