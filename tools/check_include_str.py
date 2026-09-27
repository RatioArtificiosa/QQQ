#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check every `include_str!` under `crates/` resolves inside the production image's COPY set.

    python tools/check_include_str.py
    python tools/check_include_str.py --self-test
    python tools/check_include_str.py --list

# Why this exists

`new.rs` embedded the repository's `rust-toolchain.toml` with `include_str!`, and that broke
`docker/Dockerfile.prod`: the image copies an **allowlist**, the file was not on it, and the build
died with `couldn't read ... rust-toolchain.toml: No such file or directory`. `Production image
(SEC-029)` was the only red job of the twelve in run `36326245198`, while `cargo fmt`, clippy, the
workspace suite and the whole Python gate were green **locally**, because on the developer's machine
the file exists.

    A COMPILE-TIME DEPENDENCY ON A FILE IS A DEPENDENCY ON EVERY BUILD CONTEXT THAT FILE HAS TO
    APPEAR IN.

`Dockerfile.prod` says so itself, twice: the `wit/` files were added to that COPY list for exactly
this reason, and the crate-stub list is called out there as *"the second time in this file's short
life that enumerating was the mistake"*. This checker is what makes the third time impossible,
rather than closing it with one more line.

# What it checks

Every `include_str!("…")` in a `.rs` file under `crates/` resolves to a path that some `COPY` in
`docker/Dockerfile.prod` brings into the image. A source operand is either the exact file or a
directory prefix of it.

# The three false positives the first version reported, and why each is written down

The instrument was checked against the code before its output was believed, three times:

* It read only the **first** source of each `COPY`, so `COPY Cargo.toml Cargo.lock ./` hid
  `Cargo.lock` and `qqq-host/src/config.rs`'s `include_str!("../../../Cargo.lock")` looked missing.
* It scanned **raw text**, so the doc comment in `new.rs` that *quotes* the old
  `include_str!("../../../rust-toolchain.toml")` looked like a live one -- the same class as
  `§O-363`, in the tool written the same round.
* It compared `str(Path)`, which on Windows is `wit\\qqq-crypto.wit`, against the Dockerfile's POSIX
  `wit/` -- **46** false positives from a comparison of two different syntaxes.

And a fourth, found while promoting it: the image's last `COPY` is written across two lines, so a
line-based parser never saw its sources. **A parser that cannot express its own input is the defect
it exists to find** (`§O-291`).

# Why the anti-vacuity check is first

The first fix for the masked-text problem reported **0** `include_str!` sites and said OK. A scan of
nothing certifies nothing (`§O-280`), so zero sites is a failure rather than a pass.

Usage:  python tools/check_include_str.py [--self-test|--list]
Exit:   0 = every site resolves inside a copied path, 1 = at least one does not
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


# This tool's own stdout must be able to encode what it prints. On a Windows console the stream
# inherits `cp1252`, so a character read from a source file -- which this file reads as UTF-8 --
# raises `UnicodeEncodeError` inside `print` and the tool dies while reporting its result. `§O-291`.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
DOCKERFILE = ROOT / "docker" / "Dockerfile.prod"
CRATES = ROOT / "crates"

sys.path.insert(0, str(TOOLS))
from check_api_examples import mask_source  # noqa: E402

# `COPY` followed by everything else on the logical line; the operands are split out after the
# `\`-continuations are joined.
COPY = re.compile(r"^COPY\s+(?P<rest>\S.*)$")
# `--from=build`, `--chown=65532:65532`: instruction flags, not source operands.
FLAG = re.compile(r"^--\S+$")

INCLUDE_CALL = re.compile(r"include_str!\(")
OPERAND = re.compile(r'\s*"([^"]+)"')


def logical_lines(text: str) -> list[str]:
    """Dockerfile lines with `\\`-continuations joined.

    # Why this is not optional

    The image's last `COPY` is written across two lines:

        COPY --from=build --chown=65532:65532 \\
            /src/target/x86_64-unknown-linux-musl/release/qqqai /usr/local/bin/qqqai

    A line-based parser sees the first line with no destination, drops it, and never sees the
    second -- so a source declared there would be invisible.
    """
    out: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            pending += line[:-1]
            continue
        out.append(pending + line)
        pending = ""
    if pending:
        out.append(pending)
    return out


def copied_paths(text: str) -> list[str]:
    """Every **source** operand of every `COPY` in the production Dockerfile.

    Flags are not sources and the **last** operand is the destination. A `COPY` with fewer than two
    operands is skipped rather than guessed at: a line this parser cannot read must not be silently
    reported as a source, because that would make the checker *more* permissive than the image.
    """
    out: list[str] = []
    for line in logical_lines(text):
        m = COPY.match(line)
        if not m:
            continue
        parts = m.group("rest").split()
        while parts and FLAG.match(parts[0]):
            parts.pop(0)
        if len(parts) < 2:
            continue
        out.extend(parts[:-1])
    return out


def include_sites(rel_file: str, source: str) -> list[tuple[str, str]]:
    """`(rel_file, operand)` for every **live** `include_str!` in one source file.

    The call is located in the MASKED text, so an `include_str!` quoted inside a doc comment is
    prose rather than a dependency -- and the operand is then read from the ORIGINAL text at the
    same offset. `mask_source` preserves length and line structure, so the offsets align.
    """
    out: list[tuple[str, str]] = []
    masked = mask_source(source)
    for m in INCLUDE_CALL.finditer(masked):
        op = OPERAND.match(source[m.end() :])
        if op:
            out.append((rel_file, op.group(1)))
    return out


def resolves_outside(rel_file: str, needle: str) -> bool:
    """Whether an operand escapes the repository root."""
    try:
        ((ROOT / rel_file).parent / needle).resolve().relative_to(ROOT)
    except ValueError:
        return True
    return False


def problems(copied: list[str], sites: list[tuple[str, str]]) -> list[str]:
    """The decision procedure, as a pure function, so `--self-test` can drive it.

    Every source operand is a path in the Dockerfile's POSIX spelling (`wit/`, `crates/`), so the
    comparison is made in that spelling. Comparing `str(Path)` on Windows against it reported 46
    false positives.
    """
    out: list[str] = []
    for rel_file, needle in sites:
        if resolves_outside(rel_file, needle):
            out.append(f"{rel_file}  ->  {needle}   (resolves outside the repository)")
            continue
        rel = ((ROOT / rel_file).parent / needle).resolve().relative_to(ROOT)
        rel_posix = rel.as_posix()
        if not any(
            c.rstrip("/") == rel_posix or rel_posix.startswith(c.rstrip("/") + "/") for c in copied
        ):
            out.append(f"{rel_file}  ->  {needle}   (resolves to {rel_posix}, not copied)")
    return out


def vacuity(sites: list[tuple[str, str]]) -> str | None:
    """The anti-vacuity rule, as a pure function: a scan that found nothing measured nothing."""
    if not sites:
        return (
            "no `include_str!` sites were found under crates/, so this check measured nothing -- "
            "either the scan is broken or the scan is of nothing"
        )
    return None


def collect() -> tuple[list[str], list[tuple[str, str]]]:
    copied = copied_paths(DOCKERFILE.read_text(encoding="utf-8", errors="replace"))
    sites: list[tuple[str, str]] = []
    for f in sorted(CRATES.rglob("*.rs")):
        rel = f.relative_to(ROOT).as_posix()
        sites.extend(include_sites(rel, f.read_text(encoding="utf-8", errors="replace")))
    return copied, sites


def validate(show_list: bool) -> int:
    copied, sites = collect()
    if show_list:
        print(f"COPY sources in {DOCKERFILE.name}:")
        for c in copied:
            print(f"    {c}")
        print(f"\ninclude_str! sites under crates/: {len(sites)}")
        for rel, needle in sites:
            print(f"    {rel}  ->  {needle}")
        return 0

    print(f"COPY sources in {DOCKERFILE.name} : {len(copied)}")
    for c in copied:
        print(f"    {c}")
    print()
    print(f"include_str! sites under crates/ : {len(sites)}")

    vac = vacuity(sites)
    if vac:
        print(f"FAIL -- {vac}")
        return 1

    bad = problems(copied, sites)
    if bad:
        print("NOT PRESENT IN THE IMAGE'S COPY SET:")
        for p in bad:
            print(f"  {p}")
        return 1
    print("INCLUDE_STR OK -- every include_str! resolves inside a path the production image copies")
    return 0


def self_test() -> int:
    """Prove each rule bites, on synthetic input, without touching the repository."""
    failures = 0

    def case(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            if detail:
                print(f"        {detail}")

    # --- the COPY parser -----------------------------------------------------
    dockerfile = (
        "# a comment mentioning COPY elsewhere\n"
        "COPY Cargo.toml Cargo.lock ./\n"
        "COPY --chown=65532:65532 crates/ crates/\n"
        "COPY --from=build --chown=65532:65532 \\\n"
        "    /src/target/x86_64-unknown-linux-musl/release/qqqai /usr/local/bin/qqqai\n"
        "COPY wit/ wit/\n"
        "RUN echo COPY not_a_copy\n"
    )
    got = copied_paths(dockerfile)
    case(
        "every source of a multi-operand COPY is read, not just the first",
        "Cargo.toml" in got and "Cargo.lock" in got,
        f"got {got}",
    )
    case("a `--chown` flag is not a source", "--chown=65532:65532" not in got, f"got {got}")
    case(
        "a COPY continued across two lines is read",
        "/src/target/x86_64-unknown-linux-musl/release/qqqai" in got,
        f"got {got}",
    )
    case("a directory source is read", "crates/" in got and "wit/" in got, f"got {got}")
    case("a commented COPY is not a source", "not_a_copy" not in got, f"got {got}")

    # --- the decision procedure ----------------------------------------------
    copied = ["Cargo.toml", "Cargo.lock", "crates/", "wit/"]
    case(
        "a site inside a copied directory passes",
        problems(copied, [("crates/qqq-abi/src/wit.rs", "../../../wit/qqq-abi.wit")]) == [],
    )
    case(
        "a site outside every copied path is caught -- the real defect",
        len(problems(copied, [("crates/qqq-run/src/new.rs", "../../../rust-toolchain.toml")])) == 1,
    )
    case(
        "a site resolving outside the repository is caught",
        len(problems(copied, [("crates/x/src/lib.rs", "../../../../etc/passwd")])) == 1,
    )
    case(
        "a copied file matches exactly, not only by directory prefix",
        problems(copied, [("crates/qqq-host/src/config.rs", "../../../Cargo.lock")]) == [],
    )
    case(
        "a directory prefix does not match a sibling with the same stem",
        len(problems(["wit/"], [("crates/x/src/lib.rs", "../../../wits-and-means/x.wit")])) == 1,
    )

    # --- anti-vacuity --------------------------------------------------------
    case("zero sites is a failure, not a pass", vacuity([]) is not None)
    case("one site is not vacuous", vacuity([("a.rs", "b")]) is None)

    # --- and the real tree must pass ----------------------------------------
    copied_real, sites_real = collect()
    real = vacuity(sites_real) is None and not problems(copied_real, sites_real)
    case(
        f"the real tree passes ({len(sites_real)} site(s), {len(copied_real)} copied source(s))",
        real,
    )

    total = 13
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every rule is live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--self-test", action="store_true", help="prove the rules are live")
    ap.add_argument("--list", action="store_true", help="print every site and every copied source")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return validate(show_list=args.list)


if __name__ == "__main__":
    raise SystemExit(main())
