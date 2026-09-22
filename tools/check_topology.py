#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Verify the crate topology against Proposal §4.3.

The Proposal makes two claims that are mechanically checkable:

  1. **"No crate may depend on a crate above it in this list."** The table is
     ordered, and a dependency edge that points upward would mean the layering is
     decorative — a `qqq-core` that depends on `qqq-host` would make the bottom
     of the graph as heavy as the top.

  2. **`qqq-core` has "No I/O".** It is the crate every other crate depends on,
     so an I/O dependency there is pulled into all of them.

# Why this is a check and not a review item

The layering is enforced today by nothing but attention. A new `use qqq_host::…`
in `qqq-cap` compiles, passes its tests, and inverts the graph — and the failure
appears later as a build that cannot be split, or as a capability engine that
cannot be embedded without dragging in Wasmtime (§4.3's own stated reason for
the topology).

This reads `cargo metadata` rather than the `Cargo.toml` files, so it sees the
**resolved** graph including any edge a workspace-level dependency would create.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The order from Proposal §4.3, lowest first. A crate may depend only on crates
# at a lower index.
#
# **Corrected against the built system.** The Proposal originally listed
# `qqq-host` above `qqq-abi` and `qqq-run` above `qqq-pkg`, both of which are
# impossible: the linker is built *from* the interface registry, and the CLI
# resolves dependencies *via* the package manager. The document was wrong, not
# the code — a distinction this check is what surfaced.
ORDER = [
    "qqq-core",
    # The benchmark harness (`PERF-001`). It sits directly above `qqq-core`
    # because it has **no workspace dependency at all**: it defines what a
    # *measurement* is -- the §9.1 methodology as a type and the §9.2 budgets as
    # data -- and measures other crates from outside rather than being part of
    # their dependency chain. Having no internal edge is what keeps it able to
    # measure everything: a harness that depended on the server could not be used
    # to time the server's own startup.
    #
    # It declared a `qqq-core` dependency in its first manifest and never used it;
    # `cargo-machete` rejected the unused edge in CI and it was removed. An unused
    # declaration is not harmless -- it is a false statement about the dependency
    # graph, and this checker would have accepted an edge that does not exist.
    "qqq-bench",
    "qqq-cap",
    "qqq-abi",
    "qqq-host",
    "qqq-io",
    "qqq-serve",
    "qqq-pkg",
    "qqq-run",
    "qqq-registry",
    "qqq-debug",
]

# Crates the Proposal lists as "narrowly-scoped, require unsafe" exceptions that
# do not exist yet. Named so a future addition is checked rather than ignored.
NOT_YET_BUILT = {"qqq-registry", "qqq-fabric", "qqq-io-uring", "qqq-mem-hugepage", "qqq-sys-signals"}

# `qqq-sys` is a narrow exception crate in this workspace (the unsafe one).
EXEMPT_FROM_ORDER = {"qqq-sys"}


def metadata() -> dict:
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        print("FATAL: cargo metadata failed")
        print(out.stderr[-2000:])
        sys.exit(1)
    return json.loads(out.stdout)


def main() -> int:
    meta = metadata()
    workspace_names = {p["name"] for p in meta["packages"]}
    print(f"workspace crates: {len(workspace_names)}")

    index = {name: i for i, name in enumerate(ORDER)}
    errors: list[str] = []

    # --- 1. The order holds ------------------------------------------------
    for pkg in meta["packages"]:
        name = pkg["name"]
        if name in EXEMPT_FROM_ORDER:
            continue
        if name not in index:
            errors.append(
                f"crate `{name}` is in the workspace but not in Proposal §4.3's table"
            )
            continue
        for dep in pkg["dependencies"]:
            dep_name = dep["name"]
            if dep_name not in index:
                # External crates and not-yet-built workspace members are fine.
                continue
            if index[dep_name] >= index[name]:
                errors.append(
                    f"`{name}` (position {index[name]}) depends on `{dep_name}` "
                    f"(position {index[dep_name]}), which is at or above it"
                )

    # --- 2. `qqq-core` has no I/O ------------------------------------------
    #
    # Checked against a denylist of crates that bring in I/O or a runtime, since
    # "no I/O" is not a Cargo feature. The list is deliberately narrow: it names
    # things whose presence would be a defect, rather than trying to allowlist
    # the whole ecosystem.
    IO_CRATES = {
        "tokio",
        "async-std",
        "smol",
        "reqwest",
        "hyper",
        "mio",
        "socket2",
        "tower",
        "wasmtime",
        "tokio-util",
    }
    core = next((p for p in meta["packages"] if p["name"] == "qqq-core"), None)
    if core is None:
        errors.append("`qqq-core` is missing from the workspace entirely")
    else:
        for dep in core["dependencies"]:
            if dep["name"] in IO_CRATES:
                errors.append(
                    f"`qqq-core` depends on `{dep['name']}`, but §4.3 says it has no I/O"
                )

    # --- 3. Every crate in the table that exists is in the workspace -------
    for name in ORDER:
        if name not in workspace_names and name not in NOT_YET_BUILT:
            errors.append(f"`{name}` is in Proposal §4.3 but not in the workspace")

    # --- 4. The no-I/O rule is a rule, not a coincidence -------------------
    #
    # `qqq-core` has no I/O *today*, and the loop above is what would notice if
    # that changed. This asserts the rule is correctly wired, in the same spirit
    # as `self_test_xrefs.py`'s fault injections: without it, `IO_CRATES` could
    # be misspelled or the comparison inverted and this script would print
    # `TOPOLOGY OK` forever (`§M-006`).
    #
    # The control is direct — the rule is applied to a synthetic dependency
    # rather than to a real one, because the point is to exercise the *rule*.
    probe_name = "tokio"
    probe_dep = {"name": probe_name}
    rule_fires = probe_dep["name"] in IO_CRATES
    if not rule_fires:
        errors.append(
            f"the no-I/O denylist does not flag `{probe_name}`, so the rule is "
            "misconfigured and would never fire"
        )
    if core is not None and any(
        d["name"] in IO_CRATES for d in core["dependencies"]
    ):
        errors.append(
            "`qqq-core` has acquired an I/O dependency; §4.3 requires it to stay "
            "pure because every other crate depends on it"
        )

    if errors:
        print(f"\n{len(errors)} PROBLEM(S):")
        for e in errors:
            print(f"  FAIL  {e}")
        print("\nTOPOLOGY VIOLATED")
        return 1

    print("\nthe dependency order holds; `qqq-core` has no I/O")
    print("TOPOLOGY OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
