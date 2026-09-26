#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""check_toolchain.py -- the toolchain version must be the same everywhere it is stated.

Why this exists
---------------

Observations §O-121: CI ran `dtolnay/rust-toolchain@stable` while this machine ran
1.97.1. `stable` is a moving target, so `clippy -- -D warnings` passed locally and
failed in CI on a lint that one toolchain has and the other does not. The fix was to
state the version in every place that needs it.

Stating a version in four places creates a new failure mode: **three of them get
updated.** `dtolnay/rust-toolchain@master` requires an explicit `toolchain:` input
(an action input cannot reference a file), so the version cannot live in one place
and be read from there. This checker is the substitute for that: it fails when the
statements disagree, and it names every location so the fix is one edit round.

It also verifies the *relationship* between the two distinct numbers:

* **`rust-toolchain.toml`** -- the toolchain the workspace is built and linted with.
* **`Cargo.toml`'s `rust-version`** -- the MSRV, the oldest toolchain that works.

These are deliberately different (linting with the MSRV would prevent adopting any
new lint), and the MSRV must be the *older* of the two. A CI job builds with the
MSRV separately (`§O-122`); here we only assert the ordering, because a build
running an *older* toolchain than the MSRV claim is the contradiction.

Usage
-----

    python tools/check_toolchain.py [--self-test]
"""

from __future__ import annotations

import argparse
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


REPO = Path(__file__).resolve().parent.parent

#: Files that may state the pinned toolchain, with the pattern that states it.
#:
#: The MSRV job in `ci.yml` deliberately pins a *different* channel (the MSRV), and
#: is excluded by its own marker rather than by a line number — see `MSRV_JOB`.
#:
#: **`release.yml` was missing from this list.** The `ci.yml` comment above the check
#: says the version "is stated in four places"; there were **five** — `release.yml`
#: installs a toolchain twice, to build the released binaries and to rebuild them for
#: verification. Neither was compared to anything, and both read
#: `dtolnay/rust-toolchain@stable` — the moving target this whole file exists to
#: prevent, on the one workflow whose output is a published artifact rather than a
#: verdict. A guard is only as wide as its file list (`§O-282`).
PIN_SITES = [
    ("rust-toolchain.toml", re.compile(r'^\s*channel\s*=\s*"([^"]+)"', re.MULTILINE)),
    (".github/workflows/ci.yml", re.compile(r'^\s*toolchain:\s*"([^"]+)"', re.MULTILINE)),
    (".github/workflows/advisories.yml", re.compile(r'^\s*toolchain:\s*"([^"]+)"', re.MULTILINE)),
    (".github/workflows/release.yml", re.compile(r'^\s*toolchain:\s*"([^"]+)"', re.MULTILINE)),
]

#: Workflows that must never name a *moving* channel.
#:
#: `dtolnay/rust-toolchain@stable` names whatever `stable` is on the day the job runs,
#: so the same commit builds with a different compiler next week. That is the defect
#: `rust-toolchain.toml` documents at length and the one that cost `§O-121` four red CI
#: jobs. Every workflow is in scope, not just the ones that carry a `toolchain:` input:
#: the failure is the *use of a moving channel*, which `@stable` expresses without any
#: `toolchain:` line at all — which is exactly how `release.yml` escaped the list above.
WORKFLOWS = (".github/workflows",)

#: Anchored on the **YAML key**, not the bare string.
#:
#: The first version matched `dtolnay/rust-toolchain@stable` anywhere in a line and flagged
#: three comments that exist to *document the anti-pattern* — `ci.yml:743` ("This step read
#: `dtolnay/rust-toolchain@stable`, which names whatever…") and two of this change's own
#: explanations — plus it would have made writing about the defect impossible. A guard that
#: fires on the prose describing what it forbids is one that gets worked around rather than
#: kept. Requiring `uses:` keeps it pointed at the thing that installs a toolchain.
MOVING_CHANNEL = re.compile(r"^\s*(?:-\s*)?uses:\s*dtolnay/rust-toolchain@stable\b")

#: A block that explicitly overrides the pin and must NOT be compared to it.
#:
#: The `msrv` job exists precisely to build with something other than the pinned
#: toolchain. It marks itself with this comment, so the exclusion is a property of
#: the job's purpose rather than of where it happens to sit in the file.
MSRV_JOB = re.compile(r"# *msrv-exempt", re.IGNORECASE)

#: The MSRV declaration.
CARGO = "Cargo.toml"
MSRV = re.compile(r'^\s*rust-version\s*=\s*"([^"]+)"', re.MULTILINE)


def minor(v: str) -> tuple[int, ...]:
    """The comparable part of a version string, ignoring non-numeric suffixes."""
    out = []
    for part in v.split("."):
        digits = re.match(r"\d+", part)
        if digits is None:
            break
        out.append(int(digits.group()))
    return tuple(out)


def collect() -> tuple[list[tuple[str, str]], int]:
    """Every stated pin, and the number of pin sites that stated nothing.

    A `toolchain:` line within a few lines after an `msrv-exempt` marker belongs to
    a job that means to use a different version, and is skipped. The window is
    short on purpose: the marker must be adjacent to the input it excuses, so a
    stray marker elsewhere in the file cannot silently disable the check.
    """
    found: list[tuple[str, str]] = []
    missing = 0
    for rel, pattern in PIN_SITES:
        path = REPO / rel
        if not path.exists():
            missing += 1
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        exempt: set[int] = set()
        for i, line in enumerate(lines):
            if MSRV_JOB.search(line):
                exempt.update(range(i, min(i + 12, len(lines))))
        for m in pattern.finditer(text):
            line_no = text.count("\n", 0, m.start())
            if line_no in exempt:
                continue
            found.append((rel, m.group(1)))
    return found, missing


def run(verbose: bool = True) -> list[str]:
    problems: list[str] = []
    pins, missing = collect()

    if missing:
        problems.append(f"{missing} pin site(s) do not exist -- the pattern or the path is wrong")

    if not pins:
        # Anti-vacuity: a check that found nothing must fail, not pass.
        problems.append(
            "no toolchain pin found anywhere -- the check would pass while inspecting nothing"
        )
        return problems

    versions = {v for _, v in pins}
    if len(versions) > 1:
        detail = ", ".join(f"{rel}={v}" for rel, v in pins)
        problems.append(
            f"the pinned toolchain disagrees across {len(versions)} values ({detail}); "
            f"`dtolnay/rust-toolchain@master` needs an explicit channel, so these must be "
            f"edited together"
        )
    elif verbose:
        for rel, v in pins:
            print(f"  OK    {rel}: {v}")

    # The MSRV must be declared, and must not be newer than the pinned toolchain.
    cargo = REPO / CARGO
    text = cargo.read_text(encoding="utf-8", errors="replace")
    m = MSRV.search(text)
    if m is None:
        problems.append(f"{CARGO} declares no `rust-version` (the MSRV) -- required for publication")
        return problems
    msrv = m.group(1)
    pinned = sorted(versions)[0]

    if minor(msrv) > minor(pinned):
        problems.append(
            f"the MSRV ({msrv}) is newer than the pinned toolchain ({pinned}); the build would "
            f"use a toolchain older than the one Cargo.toml promises works"
        )
    elif verbose:
        print(f"  OK    {CARGO}: rust-version = {msrv}, pinned toolchain {pinned}")

    # A `stable`/`nightly` channel pin defeats the purpose of pinning.
    for rel, v in pins:
        if v in {"stable", "nightly", "beta"}:
            problems.append(
                f"{rel} pins the moving channel `{v}`: that is what caused §O-121, and it makes "
                f"the local and CI toolchains diverge silently"
            )

    # A moving channel in ANY workflow — including one that never states a `toolchain:`
    # input.
    #
    # `release.yml` used `dtolnay/rust-toolchain@stable` twice and was invisible to every rule
    # above: it stated no version to collect, so `collect()` never saw it, so the comparison
    # never ran and the rule just above never inspected it. **The defect is the use of a
    # moving channel**, and `@stable` expresses that without stating anything at all — which is
    # precisely how it escaped a guard whose subject is stated versions (`§O-282`).
    moving: list[str] = []
    for root in WORKFLOWS:
        for path in sorted((REPO / root).glob("*.yml")):
            text = path.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(text.split("\n"), 1):
                if MOVING_CHANNEL.search(line):
                    moving.append(f"{path.relative_to(REPO)}:{i}")
    if moving:
        problems.append(
            "a workflow names the moving channel `dtolnay/rust-toolchain@stable`, which is "
            "whatever `stable` is on the day the job runs — the same commit then builds with a "
            "different compiler next week, which is what cost §O-121 four red CI jobs. Use "
            "`@master` with an explicit `toolchain:` input. Found at: " + ", ".join(moving)
        )
    elif verbose:
        print("  OK    no workflow names a moving Rust channel")

    return problems


def self_test() -> int:
    """Fault-inject: disagreeing pins, a moving channel, and a too-new MSRV."""
    import shutil
    import tempfile

    global REPO, PIN_SITES
    print("self-test: fault injection")
    failures = 0
    tmp = Path(tempfile.mkdtemp(prefix="qqq-toolchain-"))
    saved_repo, saved_sites = REPO, PIN_SITES
    try:
        REPO = tmp
        (tmp / ".github" / "workflows").mkdir(parents=True)

        def build(
            pin_toml: str,
            pin_ci: str,
            pin_adv: str,
            msrv: str,
            pin_rel: str = 'with:\n  toolchain: "1.98"',
        ) -> None:
            (tmp / "rust-toolchain.toml").write_text(pin_toml, encoding="utf-8")
            (tmp / ".github/workflows/ci.yml").write_text(pin_ci, encoding="utf-8")
            (tmp / ".github/workflows/advisories.yml").write_text(pin_adv, encoding="utf-8")
            # `release.yml` is a pin site too. It was missing from `PIN_SITES` entirely, so
            # nothing compared it — and the anti-vacuity rule then reported a missing site the
            # moment it was added, which is how this fixture came to write it (`§O-282`).
            (tmp / ".github/workflows/release.yml").write_text(pin_rel, encoding="utf-8")
            (tmp / "Cargo.toml").write_text(
                f'[workspace]\nrust-version = "{msrv}"\n', encoding="utf-8"
            )

        good = 'channel = "1.98"'
        good_ci = 'with:\n  toolchain: "1.98"'
        good_adv = 'with:\n  toolchain: "1.98"'

        build(good, good_ci, good_adv, "1.97")
        if run(verbose=False):
            print(f"  FAIL  a consistent set was reported broken: {run(verbose=False)}")
            failures += 1
        else:
            print("  OK    a consistent set passes")

        # Injection 1: CI drifted from the file.
        build(good, 'with:\n  toolchain: "1.99"', good_adv, "1.97")
        if any("disagrees" in p for p in run(verbose=False)):
            print("  OK    a drifted CI pin is detected")
        else:
            print("  FAIL  drift was not detected")
            failures += 1

        # Injection 2: a moving channel.
        build(good, 'with:\n  toolchain: "stable"', good_adv, "1.97")
        if any("moving channel" in p for p in run(verbose=False)):
            print("  OK    a moving channel is detected")
        else:
            print("  FAIL  `stable` was accepted")
            failures += 1

        # Injection 3: an MSRV newer than the pinned toolchain.
        build(good, good_ci, good_adv, "2.0")
        if any("newer than the pinned" in p for p in run(verbose=False)):
            print("  OK    an MSRV newer than the pin is detected")
        else:
            print("  FAIL  a too-new MSRV was accepted")
            failures += 1

        # Injection 6: `release.yml` drifts from the pin. This site was absent from
        # `PIN_SITES`, so no rule compared it; the case exists to prove it now is (`§O-282`).
        build(good, good_ci, good_adv, "1.97", 'with:\n  toolchain: "1.99"')
        if any("disagrees" in p for p in run(verbose=False)):
            print("  OK    a drifted release.yml pin is detected")
        else:
            print("  FAIL  release.yml drift was not detected")
            failures += 1

        # Injection 7: a moving channel expressed as `uses: ...@stable`, which states no
        # `toolchain:` input at all and so was invisible to every version-comparison rule.
        # This is the exact form `release.yml` shipped.
        build(good, good_ci, good_adv, "1.97", "uses: dtolnay/rust-toolchain@stable")
        if any("moving channel" in p for p in run(verbose=False)):
            print("  OK    a `uses: ...@stable` install is detected")
        else:
            print("  FAIL  `uses: ...@stable` was accepted")
            failures += 1

        # Injection 4: no pin anywhere (the vacuity case).
        (tmp / "rust-toolchain.toml").write_text("# nothing\n", encoding="utf-8")
        (tmp / ".github/workflows/ci.yml").write_text("steps: []\n", encoding="utf-8")
        (tmp / ".github/workflows/advisories.yml").write_text("steps: []\n", encoding="utf-8")
        (tmp / ".github/workflows/release.yml").write_text("steps: []\n", encoding="utf-8")
        if any("inspecting nothing" in p for p in run(verbose=False)):
            print("  OK    finding no pin at all is refused as vacuous")
        else:
            print("  FAIL  the vacuity case was not detected")
            failures += 1

        # Injection 5: no MSRV declared.
        build(good, good_ci, good_adv, "1.97")
        (tmp / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        if any("no `rust-version`" in p for p in run(verbose=False)):
            print("  OK    a missing MSRV is detected")
        else:
            print("  FAIL  a missing MSRV was accepted")
            failures += 1
    finally:
        REPO, PIN_SITES = saved_repo, saved_sites
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print(f"\nSELF-TEST FAILED -- {failures} injection(s) not detected")
        return 1
    print("\nSELF-TEST PASSED -- every fault is detected")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    problems = run(verbose=not args.quiet)
    if problems:
        for p in problems:
            print(f"  FAIL  {p}")
        print(f"\nTOOLCHAIN FAILED -- {len(problems)} problem(s)")
        return 1
    print("\nTOOLCHAIN OK -- every stated version agrees")
    return 0


if __name__ == "__main__":
    sys.exit(main())
