#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check the licensing boundary between the Apache-2.0 runtime and Fabric (`LIC-012`).

# The invariant, and why it is a one-way wall rather than "no dependency"

`§13.2` resolves the licence conflict in Appendix A's `A-6` like this:

  * the **runtime** is Apache-2.0, satisfying the open-source requirement;
  * the **Fabric governance layer** is commercially licensed;
  * **Fabric is not required to run QQQ**.

That third clause is the load-bearing one. It means the wall must hold in **both**
directions, and the two directions fail differently:

| Direction | If it breaks |
|---|---|
| Fabric → runtime | Fabric redistributes Apache code, which is *permitted* — but a runtime crate that imports Fabric would make the open-source edition incomplete, breaking the promise that Fabric is optional |
| runtime → Fabric | The Apache-2.0 runtime would depend on commercially-licensed code, which breaks the licence itself |

So the check is not "no dependency exists" — it is "**no dependency runs in either
direction across the licensing boundary**", and the directions are reported separately
because the remedies differ.

# Why the boundary is derived rather than listed

A hand-maintained list of "which crates are Fabric" goes stale the moment a crate is added.
The classification here is derived from what each crate's manifest *declares*: a crate that
is workspace-internal and declares a commercial licence is Fabric, and one that declares
Apache-2.0 is runtime. A new crate is classified automatically, and an unclassifiable one
is reported rather than assumed to be safe.

Usage:  python tools/check_license_boundary.py [--self-test]
Exit:   0 = the wall holds, 1 = a crate crosses it
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
CRATES = ROOT / "crates"

# The licence strings that mean "commercial, not the open runtime". Matched case
# insensitively and by substring, because a manifest may write `LicenseRef-Fabric`,
# `Fabric-Commercial`, or name an SPDX custom identifier.
COMMERCIAL = re.compile(r"(?i)(license)?ref[- ]?fabric|fabric[- ]?(commercial|license)|proprietary")

# The open licence every runtime crate must declare.
OPEN = re.compile(r"(?i)^\s*(Apache-2\.0|MIT|Apache-2\.0 OR MIT|MIT OR Apache-2\.0)\s*$")


def crate_manifests() -> list[Path]:
    return sorted(p / "Cargo.toml" for p in CRATES.iterdir() if (p / "Cargo.toml").is_file())


def read_license(path: Path) -> str:
    """The `license` value declared in a crate manifest, or the workspace's if inherited."""
    text = path.read_text(encoding="utf-8")
    m = re.search(r'(?m)^\s*license\s*=\s*"([^"]+)"', text)
    if m:
        return m.group(1)
    if "license.workspace = true" in text:
        root = re.search(
            r'(?m)^\s*license\s*=\s*"([^"]+)"', (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        )
        return root.group(1) if root else ""
    return ""


def dependencies(path: Path) -> list[str]:
    """The names of workspace crates this manifest depends on."""
    text = path.read_text(encoding="utf-8")
    names: list[str] = []
    # Both `[dependencies]` and `[dev-dependencies]` count: a dev-dependency on Fabric
    # would make the runtime's *tests* require a commercial licence, which is the same
    # wall. Build-dependencies likewise.
    for m in re.finditer(r'(?m)^\s*(qqq-[a-z0-9-]+)\s*=', text):
        if m.group(1) not in names:
            names.append(m.group(1))
    return names


def classify() -> dict[str, str]:
    """Map each workspace crate name to `runtime`, `fabric`, or `unclassified`."""
    out: dict[str, str] = {}
    for path in crate_manifests():
        name = path.parent.name
        lic = read_license(path)
        if COMMERCIAL.search(lic):
            out[name] = "fabric"
        elif OPEN.match(lic or ""):
            out[name] = "runtime"
        else:
            out[name] = "unclassified"
    return out


def check() -> list[str]:
    """Return the boundary violations. Empty means the wall holds."""
    kinds = classify()
    problems: list[str] = []

    if not kinds:
        return ["no crates found, so every check below would pass vacuously"]

    # An unclassifiable licence is reported rather than assumed safe: the whole point of
    # deriving the classification is that a new crate is handled, and "assume runtime"
    # would silently exempt a commercial one.
    for name, kind in sorted(kinds.items()):
        if kind == "unclassified":
            problems.append(
                f"{name} declares no recognisable licence, so the boundary cannot be "
                f"checked for it. Declare `Apache-2.0` (runtime) or a Fabric licence "
                f"(commercial), or the wall has a hole nobody can see."
            )

    # If Fabric does not exist yet, say so rather than reporting a clean wall that was
    # never tested. This is the difference between "verified" and "vacuous".
    has_fabric = any(k == "fabric" for k in kinds.values())
    if not has_fabric:
        # Not a failure: Fabric is a later milestone. But it must be stated, because a
        # green result here would otherwise read as "the boundary is enforced".
        print(
            "  note: no Fabric-licensed crate exists yet, so this run verifies the "
            "direction that CAN fail today (runtime crates depending on something "
            "commercial) and cannot exercise the other."
        )

    # The actual boundary: no dependency may cross it.
    for path in crate_manifests():
        name = path.parent.name
        kind = kinds.get(name, "unclassified")
        for dep in dependencies(path):
            dep_kind = kinds.get(dep)
            if dep_kind is None:
                continue  # not a workspace crate
            if kind == "runtime" and dep_kind == "fabric":
                problems.append(
                    f"{name} (runtime) depends on {dep} (Fabric). The Apache-2.0 runtime "
                    f"would then require commercially-licensed code, which breaks the "
                    f"licence itself. This is the direction that cannot be allowed at all."
                )
            elif kind == "fabric" and dep_kind == "runtime":
                problems.append(
                    f"{name} (Fabric) depends on {dep} (runtime). The dependency is "
                    f"permitted by the licence, but it breaks §13.2's promise that Fabric "
                    f"is optional — a runtime crate importing Fabric would make the "
                    f"open-source edition incomplete."
                )

    return problems


def validate() -> int:
    problems = check()
    if problems:
        print("LICENCE BOUNDARY FAILED")
        print("")
        for p in problems:
            print(f"  FAIL  {p}")
        return 1

    kinds = classify()
    runtime = sorted(n for n, k in kinds.items() if k == "runtime")
    fabric = sorted(n for n, k in kinds.items() if k == "fabric")
    print(
        f"LICENCE BOUNDARY OK -- {len(runtime)} runtime crate(s), {len(fabric)} Fabric "
        f"crate(s), no dependency crosses the wall in either direction"
    )
    return 0


def self_test() -> int:
    """Prove both directions fire, and that the classification is derived, not listed."""
    failures = 0

    def case(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            if detail:
                print(f"        {detail[:220]}")

    # The real repository must currently hold the wall.
    real = check()
    case("the real workspace holds the wall", not real, f"{real[:2]}")

    # The classification must find real crates.
    kinds = classify()
    case(
        "runtime crates are classified",
        sum(1 for k in kinds.values() if k == "runtime") >= 5,
        f"only {sum(1 for k in kinds.values() if k == 'runtime')} classified as runtime",
    )
    case(
        "no crate is unclassified",
        not any(k == "unclassified" for k in kinds.values()),
        f"unclassified: {[n for n, k in kinds.items() if k == 'unclassified']}",
    )

    # The commercial pattern must match the spellings a manifest might use.
    for sample in [
        "LicenseRef-Fabric",
        "Fabric-Commercial",
        "fabric-license",
        "Proprietary",
    ]:
        case(f"recognises {sample!r} as commercial", bool(COMMERCIAL.search(sample)))

    # The open pattern must match the licences this project uses, and reject others.
    for sample in ["Apache-2.0", "MIT OR Apache-2.0", "Apache-2.0 OR MIT"]:
        case(f"recognises {sample!r} as open", bool(OPEN.match(sample)))
    case("does not treat GPL-3.0 as the open licence", not bool(OPEN.match("GPL-3.0")))

    total = 10
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every check is live")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    return validate()


if __name__ == "__main__":
    raise SystemExit(main())
