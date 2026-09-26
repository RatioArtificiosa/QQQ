#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Verify the crate stability tiers — Checklist `ARCH-010`.

    python tools/check_tiers.py [--self-test]

# The claim this checks

Proposal §4.3 states that "every crate has a single responsibility, a **stated stability
tier**, and an owner", and gives a table. Each crate's own `Cargo.toml` comment carries a
`# Tier:` line, so the tier is declared in the tree in two places:

| Where | What it says |
|---|---|
| `Cargo.toml`, per crate | `# Tier: stable — shared types, no I/O.` |
| `QQQ-Proposal-V1.md` §4.3 | the table |

**Nothing compared them until this check.** `tools/check_topology.py` verifies the *order* of
§4.3's table and `qqq-core`'s no-I/O rule, and it reads `cargo metadata` rather than the
`# Tier:` comments. A crate could therefore be switched from `beta` to `stable` in its manifest
— the line a publisher reads before making a semver promise — and the Proposal would still say
the opposite, with every gate green. That is `§O-012`'s shape: a declaration nothing re-derives.

# The four things checked

1. **Every workspace crate declares a tier.** A missing line means the crate's stability is
   undefined, which for a published name is worse than a wrong tier.
2. **The declared tier matches §4.3.** The Proposal is the specification; the manifest is the
   implementation, and they must agree.
3. **Every crate in §4.3's table that exists is declared.** The reverse direction, so a crate
   cannot be added to the workspace and left out of the promise.
4. **A tier outside the known set is rejected.** `stable`, `beta` and `exception` are the
   vocabulary; `experimental` or `alpha` would be a new promise nobody agreed to.

# Why the exception tier is checked against an artifact

`qqq-sys` is §4.3's designated `unsafe` crate. Its tier is not a promise about semver but a
statement that it may contain `unsafe` — and that permission is granted through a process
(`ARCH-009`), whose artifact is `crates/qqq-sys/SAFETY.md`. So the tier check verifies the
artifact exists rather than trusting the label, which is what makes "exception" a reviewed
state instead of a word in a comment.

Usage:  python tools/check_tiers.py [--self-test]
Exit:   0 = tiers consistent, 1 = a disagreement or a missing declaration
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
WORKSPACE_MANIFEST = ROOT / "Cargo.toml"
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"

TIERS = ("stable", "beta", "exception")

# `# Tier: <tier> — <reason>` on the comment block preceding a member entry.
TIER_LINE = re.compile(r"^#\s*Tier:\s*(?P<tier>[a-z]+)\b", re.M)
MEMBER = re.compile(r'"crates/(?P<name>[a-z0-9-]+)"')

# §4.3's table: `| \`qqq-core\` | stable | ... |`.
PROPOSAL_ROW = re.compile(r"^\|\s*`(?P<name>qqq-[a-z0-9-]+)`\s*\|\s*(?P<tier>[a-z]+)\s*\|", re.M)

# Crates §4.3 lists that this repository does not build (separate repo or unbuilt). This is the
# same set `tools/check_topology.py` carries as `NOT_YET_BUILT`, and it is the answer to
# "§4.3 names it but no member declares it": those are *planned*, not drift.
NOT_YET_BUILT: frozenset[str] = frozenset(
    {"qqq-registry", "qqq-fabric", "qqq-io-uring", "qqq-mem-hugepage", "qqq-sys-signals"}
)

# Crates this workspace builds that §4.3's table does not name. Found by this checker on its
# first run, and recorded rather than silently tolerated:
#
# * `qqq-sys` — the narrow `unsafe` exception crate. §4.3 mentions only a *different* planned
#   crate called `qqq-sys-signals`, so the built exception crate has no row.
# * `qqq-bench` — the benchmark harness. §4.3 has no row for it either; `check_topology.py`'s
#   ORDER comment explains where it sits and why.
#
# These are declared in the tree with a tier and are absent from the specification's table, which
# is the reverse of the drift that matters. They are listed so the check reports *new* divergence
# instead of failing forever on a known gap. Adding a crate to this set is a deliberate act; the
# list is printed on every run so it cannot grow unnoticed.
UNDOCUMENTED_IN_PROPOSAL: frozenset[str] = frozenset({"qqq-sys", "qqq-bench"})


def declared_in_manifest() -> dict[str, str]:
    """The tier each workspace member declares, from the comment above its entry."""
    if not WORKSPACE_MANIFEST.is_file():
        return {}
    text = WORKSPACE_MANIFEST.read_bytes().decode("utf-8")
    out: dict[str, str] = {}
    for m in MEMBER.finditer(text):
        name = m.group("name")
        # Walk backwards over the comment block immediately preceding this entry.
        block: list[str] = []
        for line in reversed(text[: m.start()].split("\n")):
            stripped = line.strip()
            if stripped.startswith("#"):
                block.append(stripped)
            elif stripped == "":
                continue
            else:
                break
        block.reverse()
        tier_line = next((b for b in block if b.lower().startswith("# tier:")), None)
        if tier_line is None:
            out[name] = ""
            continue
        tm = TIER_LINE.match(tier_line)
        out[name] = tm.group("tier") if tm else ""
    return out


def declared_in_proposal() -> dict[str, str]:
    """The tier §4.3's table gives each crate."""
    if not PROPOSAL.is_file():
        return {}
    text = PROPOSAL.read_bytes().decode("utf-8")
    return {m.group("name"): m.group("tier") for m in PROPOSAL_ROW.finditer(text)}


def run_check() -> int:
    manifest = declared_in_manifest()
    proposal = declared_in_proposal()

    if not manifest:
        print("FAIL -- no workspace members found; a scan of nothing certifies nothing")
        return 1
    if not proposal:
        print("FAIL -- §4.3's tier table could not be read; the comparison would be vacuous")
        return 1

    print(f"workspace crates declaring a tier : {len(manifest)}")
    print(f"crates in Proposal §4.3's table   : {len(proposal)}")
    print()

    errors: list[str] = []

    # --- 1 & 4. Every crate declares a known tier --------------------------
    for name in sorted(manifest):
        tier = manifest[name]
        if not tier:
            errors.append(f"`{name}` declares no `# Tier:` line in Cargo.toml")
        elif tier not in TIERS:
            errors.append(
                f"`{name}` declares tier `{tier}`, which is not one of {', '.join(TIERS)}"
            )

    # --- 2. The manifest agrees with the specification ---------------------
    for name in sorted(manifest):
        tier = manifest[name]
        if not tier or tier not in TIERS:
            continue
        want = proposal.get(name)
        if want is None:
            if name not in UNDOCUMENTED_IN_PROPOSAL:
                errors.append(
                    f"`{name}` is in the workspace with tier `{tier}` but absent from §4.3's table; "
                    "either add its row or record it in UNDOCUMENTED_IN_PROPOSAL deliberately"
                )
        elif want != tier:
            errors.append(
                f"`{name}` declares tier `{tier}` while §4.3 says `{want}` — "
                "the manifest is the line a publisher reads, so the two must agree"
            )

    # --- 3. Nothing in the table that we build is undeclared ---------------
    for name in sorted(proposal):
        if name in NOT_YET_BUILT:
            continue
        if name not in manifest:
            errors.append(
                f"§4.3 lists `{name}` (tier `{proposal[name]}`) but no workspace member declares it"
            )

    # --- The exception tier is backed by its artifact ----------------------
    exc = [n for n, t in manifest.items() if t == "exception"]
    if not exc:
        errors.append(
            "no crate declares the `exception` tier, but §4.3 designates one for `unsafe`"
        )
    for name in exc:
        safety = ROOT / "crates" / name / "SAFETY.md"
        if not safety.is_file():
            errors.append(
                f"`{name}` declares tier `exception` but has no SAFETY.md — "
                "ARCH-009 requires a written safety argument for an unsafe-permitting crate"
            )

    print(f"{'crate':14} {'Cargo.toml':12} {'Proposal §4.3':14}")
    print("-" * 44)
    for name in sorted(manifest):
        tier = manifest[name] or "(none)"
        want = proposal.get(name, "(absent)")
        flag = "" if tier == want else "  <-- differs"
        print(f"{name:14} {tier:12} {want:14}{flag}")

    print()
    if errors:
        for e in errors:
            print(f"  FAIL {e}")
        print()
        print(f"TIER CONTRACT FAILED -- {len(errors)} disagreement(s)")
        return 1

    # The two known divergences are printed rather than left implicit, so they cannot quietly
    # grow into "we tolerate anything".
    undocumented = sorted(n for n in manifest if n not in proposal)
    unbuilt = sorted(n for n in proposal if n not in manifest)
    if undocumented:
        print(
            f"NOTE: built but absent from §4.3's table, recorded deliberately: "
            f"{', '.join(undocumented)}"
        )
    if unbuilt:
        print(f"NOTE: in §4.3 but not built in this repository: {', '.join(unbuilt)}")

    print()
    print(
        f"TIER CONTRACT OK -- {len(manifest)} crate(s) declare a tier, "
        "and every one matches §4.3"
    )
    return 0


def self_test() -> int:
    """Prove the parser and the comparisons are live, on synthetic input."""
    failures = 0

    def expect(label: str, got, want) -> None:
        nonlocal failures
        ok = got == want
        if not ok:
            failures += 1
        print(f"  {'OK  ' if ok else 'FAIL'} {label}: {got!r}")

    # The manifest parser reads the comment block above each entry, and is not
    # fooled by a `# Tier:` line belonging to an earlier crate.
    sample = """
members = [
    # Tier: stable -- the bottom of the graph.
    # Implements: ARCH-007
    "crates/qqq-core",
    # Tier: beta -- registry client.
    "crates/qqq-pkg",
    # No tier here.
    "crates/qqq-mystery",
]
"""
    global WORKSPACE_MANIFEST
    real = WORKSPACE_MANIFEST
    tmp = ROOT / "tools" / ".tier_self_test.toml"
    try:
        tmp.write_bytes(sample.encode("utf-8"))
        WORKSPACE_MANIFEST = tmp
        got = declared_in_manifest()
        expect("a stable tier is read", got.get("qqq-core"), "stable")
        expect("a beta tier is read", got.get("qqq-pkg"), "beta")
        expect("a missing tier reads as empty", got.get("qqq-mystery"), "")
        expect("all three members are seen", len(got), 3)
    finally:
        WORKSPACE_MANIFEST = real
        tmp.unlink(missing_ok=True)

    # The Proposal parser reads the §4.3 table rows.
    prop = declared_in_proposal()
    expect("the table is non-empty", len(prop) > 0, True)
    expect("qqq-core is stable in the table", prop.get("qqq-core"), "stable")
    expect("qqq-pkg is beta in the table", prop.get("qqq-pkg"), "beta")

    # The tier vocabulary is closed.
    expect("stable is known", "stable" in TIERS, True)
    expect("an invented tier is not", "experimental" in TIERS, False)

    # The two divergence sets mean opposite things and must not be confused:
    # `NOT_YET_BUILT` is "the spec names it, we do not build it"; the other is
    # "we build it, the spec does not name it".
    expect("a planned crate is in NOT_YET_BUILT", "qqq-registry" in NOT_YET_BUILT, True)
    expect(
        "a built crate is not in NOT_YET_BUILT",
        "qqq-sys" in NOT_YET_BUILT,
        False,
    )
    expect(
        "the built exception crate is recorded as undocumented",
        "qqq-sys" in UNDOCUMENTED_IN_PROPOSAL,
        True,
    )
    expect(
        "a documented crate is not marked undocumented",
        "qqq-core" in UNDOCUMENTED_IN_PROPOSAL,
        False,
    )
    # Every crate this workspace actually builds must be in exactly one of the
    # two recognised states relative to the table.
    real_manifest = declared_in_manifest()
    unaccounted = [
        n
        for n in real_manifest
        if n not in prop and n not in UNDOCUMENTED_IN_PROPOSAL
    ]
    expect("no built crate is unaccounted for", unaccounted, [])

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} case(s) behaved wrongly")
        return 1
    print("SELF-TEST PASSED -- the manifest parser, the table parser and the vocabulary are live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify the crate stability tiers (ARCH-010)")
    ap.add_argument("--self-test", action="store_true", help="prove the parsers and comparisons")
    ap.add_argument("--json", action="store_true", help="emit the comparison as JSON")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if args.json:
        import json

        print(
            json.dumps(
                {
                    "manifest": declared_in_manifest(),
                    "proposal": declared_in_proposal(),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    return run_check()


if __name__ == "__main__":
    sys.exit(main())
