#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check that the two gates run the same checkers, beyond a declared list of divergences.

    python tools/check_gate_parity.py [--self-test] [--list]

`ci.yml` and `docker/entrypoint.sh` are both gates, and the repository's rule is *"when you add a
checker, add it to BOTH"*. That rule is stated about a dozen times across the checklist and the
handbook and **was enforced by nothing** until this file.

# What it was like without this

Measured on 2026-09-25 (`§O-286`): `ci.yml` invoked **84** checker commands and the bridge invoked
**65**, with **20** in one and not the other and **1** in the other and not the one. Two of the
twenty had a documented reason; **eighteen did not**, and the divergence had accumulated without
anyone deciding it. Seven turned out to be pure Python that passed in the image and had simply been
forgotten; the remaining thirteen have a real reason and are now **declared in `entrypoint.sh`**
with a reason each (`§O-288`).

# Why the declaration is parsed rather than duplicated

The list lives in `docker/entrypoint.sh` as a comment block, and this file reads it. Writing the
list a second time here would be a second answer to one question — the defect shape this repository
keeps recording — and the two would drift. **The declaration is the data.**

# What is checked

  1. Every invocation in `ci.yml` runs in `docker/entrypoint.sh`, **or** is declared.
  2. Every invocation in the bridge runs in `ci.yml`, **or** is declared. (One is: the bridge runs
     `check_sbom.py --self-test`, which CI does not need because it runs the `sbom` half.)
  3. **A declared entry that no longer diverges is a failure.** An exclusion for a checker that has
     since been added to both gates is a stale exemption — the same shape as
     `check_checklist_counts.py` validating the declaration against the document rather than only
     the arithmetic. A list that only grows is a list that stops meaning anything.
  4. Vacuity fails: if either gate yields no invocations, the comparison proved nothing.

# Why the "declared" match is a prefix

The declaration writes `tools/fault_inject_*.py (8 cmds)` and
`tools/check_api_examples.py (2 cmds)` — a glob and a count, not eight and two lines. A parser that
required exact strings would fail on a correct declaration, so a declared token matches an
invocation when the invocation's script path is the token or matches the token as a glob, and the
declared count is then checked against how many it actually covers. **The count is the part that
catches a glob which silently stopped covering something.**
"""

from __future__ import annotations

import argparse
import fnmatch
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
CI = ROOT / ".github" / "workflows" / "ci.yml"
ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"

# `run: python tools/foo.py --bar` in a workflow, and a bare `python3 tools/foo.py` in the shell
# script. Both are normalised to `tools/foo.py --bar` with runs of whitespace collapsed, because
# the two files spell the interpreter differently (`python` vs `python3`) and that difference is
# not what this check is about.
CI_INVOCATION = re.compile(r"run:\s*python3?\s+(tools/[\w./-]+[^\n]*)")
BRIDGE_INVOCATION = re.compile(r"^\s*python3?\s+(tools/[\w./-]+[^\n]*)", re.MULTILINE)

# A declared entry: an indented comment naming a tool — **possibly with arguments**, because
# `tools/check_sbom.py sbom` and `tools/check_sbom.py --self-test` are different commands and the
# declaration distinguishes them. The reason follows after two or more spaces, which is what
# separates a declaration from a sentence that merely mentions a tool.
#
# The first version of this pattern was `tools/[\w./*-]+\.py`, which cannot match
# `tools/check_sbom.py sbom` — so two real declarations were invisible to the parser and the
# checker reported them as undeclared. **A parser that cannot express its own input is the defect
# it exists to find** (`§O-291`).
DECLARED = re.compile(
    r"^#\s+(tools/[\w./*-]+\.py(?:\s+(?:--)?[\w./*=-]+)?)(?:\s*\((\d+)\s+cmds?\))?\s{2,}\S",
    re.MULTILINE,
)

# The comment block that carries the declaration, bounded by its own heading. Parsing the whole
# file would pick up any `tools/*.py` mentioned in prose elsewhere -- and this file's subject is
# exactly the difference between a *declaration* and a *mention*.
DECLARATION_HEADING = "# # What this bridge does NOT run"
# The declaration has two halves: commands CI runs and the bridge does not, then a second heading
# for the reverse. **Direction matters and is part of the claim** -- `tools/check_sbom.py sbom` is
# ci-only and `tools/check_sbom.py --self-test` is bridge-only, and a checker that treated them
# alike would accept each in the other's section. That is what the first version did.
REVERSE_HEADING = "And **one divergence in the other direction**"
DECLARATION_END = "# Run clippy with the toolchain version CI actually uses."


def invocations(text: str, pattern: re.Pattern[str]) -> list[str]:
    """Normalised `tools/...` invocations, de-duplicated and sorted."""
    out = {
        re.sub(r"\s+", " ", m.group(1).strip().rstrip("\\").strip())
        for m in pattern.finditer(text)
    }
    return sorted(out)


def declaration() -> tuple[list[tuple[str, int | None]], list[tuple[str, int | None]]]:
    """`(ci-only, bridge-only)` declarations, each entry `(tool token, declared count or None)`.

    Direction is read from the block's own structure rather than inferred, so a declaration filed
    under the wrong heading is caught instead of quietly satisfied.
    """
    text = ENTRYPOINT.read_text(encoding="utf-8", errors="replace")
    start = text.find(DECLARATION_HEADING)
    if start < 0:
        return [], []
    end = text.find(DECLARATION_END, start)
    block = text[start : end if end > 0 else len(text)]

    split = block.find(REVERSE_HEADING)
    if split < 0:
        ci_only_block, bridge_only_block = block, ""
    else:
        ci_only_block, bridge_only_block = block[:split], block[split:]

    def entries(chunk: str) -> list[tuple[str, int | None]]:
        return [(m.group(1), int(m.group(2)) if m.group(2) else None) for m in DECLARED.finditer(chunk)]

    return entries(ci_only_block), entries(bridge_only_block)


def covers(token: str, invocation: str) -> bool:
    """Whether a declared token covers an invocation.

    Matched on the **script path plus any declared argument**, so `tools/check_sbom.py sbom`
    covers that command and `tools/check_sbom.py --self-test` covers its twin — two invocations
    whose script is identical and whose behaviour is not.

    A token naming only the script (`tools/check_wit.py`, `tools/fault_inject_*.py`) covers every
    invocation of it, which is what a declaration without arguments means.
    """
    if " " in token:
        # A declared argument: the invocation must carry it, not merely start with the script.
        return invocation == token or invocation.startswith(token + " ")
    return fnmatch.fnmatch(invocation.split(" ")[0], token)


def check(
    ci: list[str],
    bridge: list[str],
    ci_only: list[tuple[str, int | None]],
    bridge_only: list[tuple[str, int | None]],
) -> list[str]:
    """The decision procedure, as a pure function, so `--self-test` can drive it.

    `ci_only` declares commands CI runs and the bridge does not; `bridge_only` declares the
    reverse. The direction is checked, not just the membership.
    """
    problems: list[str] = []

    if not ci or not bridge:
        return [
            f"vacuity: ci.yml yielded {len(ci)} invocation(s) and the bridge {len(bridge)}; a "
            f"comparison of nothing certifies nothing"
        ]

    only_ci = [i for i in ci if i not in bridge]
    only_bridge = [i for i in bridge if i not in ci]

    for inv in only_ci:
        if not any(covers(token, inv) for token, _count in ci_only):
            problems.append(
                f"`{inv}` runs in ci.yml and not in docker/entrypoint.sh, and is not declared "
                f"under '{DECLARATION_HEADING}'. Add it to the bridge, or declare it there with a "
                f"reason"
            )
    for inv in only_bridge:
        if not any(covers(token, inv) for token, _count in bridge_only):
            problems.append(
                f"`{inv}` runs in docker/entrypoint.sh and not in ci.yml, and is not declared "
                f"under '{REVERSE_HEADING}'. The bridge is allowed to be the wider gate, but not "
                f"silently"
            )

    # A declaration in the wrong direction is satisfied by nothing and excuses nothing.
    for inv in only_ci:
        if any(covers(t, inv) for t, _ in bridge_only):
            problems.append(
                f"`{inv}` is declared as bridge-only but diverges in the other direction "
                f"(ci.yml runs it, the bridge does not). Direction is part of the claim"
            )
    for inv in only_bridge:
        if any(covers(t, inv) for t, _ in ci_only):
            problems.append(
                f"`{inv}` is declared as ci-only but diverges in the other direction "
                f"(the bridge runs it, ci.yml does not). Direction is part of the claim"
            )

    # Every declared token must still be doing work.
    for label, declared, actual in (
        ("ci-only", ci_only, only_ci),
        ("bridge-only", bridge_only, only_bridge),
    ):
        for token, count in declared:
            hits = [i for i in actual if covers(token, i)]
            if not hits:
                problems.append(
                    f"`{token}` is declared {label} but no longer diverges -- either it is now in "
                    f"both gates (remove the declaration) or it was renamed (fix the declaration). "
                    f"A stale exemption is a defect in its own right"
                )
                continue
            if count is not None and count != len(hits):
                problems.append(
                    f"`{token}` declares {count} command(s) but covers {len(hits)}: {hits}. The "
                    f"count is what catches a glob that silently stopped covering something"
                )

    return problems


def collect():
    ci_only, bridge_only = declaration()
    return (
        invocations(CI.read_text(encoding="utf-8", errors="replace"), CI_INVOCATION),
        invocations(ENTRYPOINT.read_text(encoding="utf-8", errors="replace"), BRIDGE_INVOCATION),
        ci_only,
        bridge_only,
    )


def validate(verbose: bool) -> int:
    ci, bridge, ci_only, bridge_only = collect()
    print(f"ci.yml invocations        : {len(ci)}")
    print(f"bridge invocations        : {len(bridge)}")
    print(f"declared ci-only          : {len(ci_only)}")
    for token, count in ci_only:
        print(f"  declared  {token}{f' ({count} cmds)' if count else ''}")
    print(f"declared bridge-only      : {len(bridge_only)}")
    for token, count in bridge_only:
        print(f"  declared  {token}{f' ({count} cmds)' if count else ''}")

    problems = check(ci, bridge, ci_only, bridge_only)
    print("")
    if problems:
        print(f"GATE PARITY FAILED -- {len(problems)} problem(s):")
        for p in problems:
            print(f"  FAIL  {p}")
        return 1
    print("GATE PARITY OK -- the two gates agree beyond the declared divergences")
    return 0


def self_test() -> int:
    failures = 0

    def case(
        name: str,
        ci: list[str],
        bridge: list[str],
        ci_only,
        bridge_only,
        expect: str | None,
    ) -> None:
        nonlocal failures
        problems = check(ci, bridge, ci_only, bridge_only)
        ok = (not problems) if expect is None else any(expect in p for p in problems)
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            for p in problems[:2]:
                print(f"        got: {p}")

    A, B = "tools/a.py", "tools/b.py"
    AB = "tools/a.py --self-test"
    case("a checker in both gates passes", [A, B], [A, B], [], [], None)
    case("a checker missing from the bridge is caught", [A, B], [B], [], [], "not declared")
    case("a checker missing from CI is caught", [A], [A, B], [], [], "wider gate")
    case("a declared ci-only divergence is accepted", [A, B], [B], [(A, None)], [], None)
    case("a declared bridge-only divergence is accepted", [B], [A, B], [], [(A, None)], None)
    case(
        "a declaration in the WRONG direction is caught",
        [A, B],
        [B],
        [],
        [(A, None)],
        "other direction",
    )
    case("a stale declaration is caught", [A, B], [A, B], [(A, None)], [], "no longer diverges")
    case(
        "a glob declaration covers its members",
        ["tools/fault_inject_x.py", "tools/fault_inject_y.py", B],
        [B],
        [("tools/fault_inject_*.py", 2)],
        [],
        None,
    )
    case(
        "a glob whose count is wrong is caught",
        ["tools/fault_inject_x.py", "tools/fault_inject_y.py", B],
        [B],
        [("tools/fault_inject_*.py", 3)],
        [],
        "declares 3",
    )
    case(
        "a declared ARGUMENT is distinguished from its twin",
        [A, AB, B],
        [B],
        [(AB, None)],
        [],
        "not declared",
    )
    case("an empty gate fails rather than passing", [], [A], [], [], "vacuity")

    # The real repository must currently agree.
    ci, bridge, ci_only, bridge_only = collect()
    real = check(ci, bridge, ci_only, bridge_only)
    ok = not real
    print(f"  {'OK  ' if ok else 'DEAD'}  the real gates agree ({len(ci)} vs {len(bridge)} invocations)")
    if not ok:
        failures += 1
        for p in real[:3]:
            print(f"        {p}")

    total = 12
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every rule is live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--self-test", action="store_true", help="prove the checks are live")
    ap.add_argument("--list", action="store_true", help="print the declared divergences")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if args.list:
        ci_only, bridge_only = declaration()
        for token, count in ci_only:
            print(f"ci-only      {token}{f' ({count} cmds)' if count else ''}")
        for token, count in bridge_only:
            print(f"bridge-only  {token}{f' ({count} cmds)' if count else ''}")
        return 0
    return validate(verbose=True)


if __name__ == "__main__":
    raise SystemExit(main())
