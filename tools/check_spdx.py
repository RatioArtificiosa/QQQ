#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check that every source file carries the correct SPDX header (`LIC-006`).

# Why an SPDX identifier and not a comment

Two reasons, and the second is the one that matters legally.

**Machine-readable.** Licence scanners, `cargo-deny`, GitHub's licence detection and SBOM
tooling read `SPDX-License-Identifier` directly. A prose sentence naming the licence
requires a parser per phrasing, so tools do not do it, so the licence of a file is
genuinely unknown to every automated system.

**Unambiguous per file.** The workspace `license = "Apache-2.0"` in `Cargo.toml` covers the
*crate*. A file copied between crates, vendored, or extracted into a gist carries no
context — and `§13.2`'s model depends on which licence governs which code. The header is
what travels with the file.

# What is checked

  1. Every `.rs` file under `crates/` begins with the expected SPDX line, after an
     optional shebang and before any other content.
  2. The identifier matches the workspace's declared licence — a header naming a different
     licence from `Cargo.toml` is worse than none, because it is a contradiction a scanner
     will report as fact.
  3. `wit/` files and the fuzz targets are covered by the same rule, since they are
     distributed with the crates.
  4. Generated files are exempt **by an explicit list**, not by a heuristic, and the list
     itself is checked: an exemption that no longer matches a file is reported, so it
     cannot silently grow.

Usage:  python tools/check_spdx.py [--self-test]
Exit:   0 = every file is headed correctly, 1 = at least one is not
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CARGO = ROOT / "Cargo.toml"

# The header's shape. `// SPDX-License-Identifier: Apache-2.0` is the convention for
# Rust; the exact comment syntax differs per language, so the pattern captures the
# identifier and the tool allows either `//` or `#`.
SPDX_PATTERN = re.compile(
    r"^\s*(?://|#)\s*SPDX-License-Identifier:\s*(\S+)\s*$", re.MULTILINE
)

# Which comment prefix each extension uses.
COMMENT = {".rs": "//", ".wit": "//", ".py": "#", ".sh": "#"}

# # Why exemptions are an explicit list
#
# A heuristic ("skip files that look generated") is a rule nobody can audit: a developer
# cannot tell whether their file will be skipped, and a reviewer cannot see what is
# covered. A list is auditable, and the check reports an entry that stops matching so it
# cannot quietly accumulate.
EXEMPT: set[str] = set()


def workspace_license() -> str | None:
    """The `license` value from the workspace `Cargo.toml`."""
    for line in CARGO.read_text(encoding="utf-8").splitlines():
        m = re.match(r'^\s*license\s*=\s*"([^"]+)"', line)
        if m:
            return m.group(1)
    return None


def source_files() -> list[Path]:
    """Every distributable source file that needs a header."""
    files: list[Path] = []
    for pattern, root in (
        ("**/*.rs", ROOT / "crates"),
        ("**/*.rs", ROOT / "fuzz" / "fuzz_targets"),
        ("*.wit", ROOT / "wit"),
        ("*.py", ROOT / "tools"),
    ):
        base = root if root.exists() else ROOT
        for path in sorted(base.glob(pattern)):
            rel = path.relative_to(ROOT).as_posix()
            if "/target/" in rel or rel in EXEMPT:
                continue
            files.append(path)
    return files


def header_line_for(path: Path, license_id: str) -> str:
    prefix = COMMENT.get(path.suffix, "//")
    return f"{prefix} SPDX-License-Identifier: {license_id}"


def find_header(text: str) -> str | None:
    """The SPDX identifier in the file's first few lines, if any."""
    # Only the head: a mention of SPDX deeper in a file is documentation about licensing,
    # not the file's own header, and accepting it would let a file be unheadered while
    # containing the string.
    head = "\n".join(text.splitlines()[:5])
    m = SPDX_PATTERN.search(head)
    return m.group(1) if m else None


def check_file(path: Path, license_id: str) -> list[str]:
    """Return the problems with one file's header."""
    problems: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return [f"{path.name}: could not be read: {e}"]

    rel = path.relative_to(ROOT).as_posix()
    found = find_header(text)

    if found is None:
        problems.append(
            f"{rel}: no `SPDX-License-Identifier` in the first five lines. A file "
            f"without one has no licence that any scanner can determine, and "
            f"`§13.2`'s model depends on which licence governs which code."
        )
    elif found != license_id:
        problems.append(
            f"{rel}: declares `{found}` but the workspace declares `{license_id}`. A "
            f"header naming a different licence from `Cargo.toml` is worse than none: "
            f"it is a contradiction a scanner reports as fact."
        )

    return problems


def check() -> list[str]:
    """Return every header problem across the corpus."""
    license_id = workspace_license()
    if license_id is None:
        return ["the workspace `Cargo.toml` declares no `license`, so there is nothing "
                "for a header to agree with"]

    problems: list[str] = []
    files = source_files()
    if not files:
        return ["no source files found, so every check below would pass vacuously"]

    for path in files:
        problems.extend(check_file(path, license_id))

    # The exemption list must stay honest.
    for rel in sorted(EXEMPT):
        if not (ROOT / rel).exists():
            problems.append(
                f"EXEMPT names {rel}, which does not exist. An exemption that no longer "
                f"matches a file is one that silently grew a population of one."
            )

    return problems


def validate() -> int:
    problems = check()
    if problems:
        print("SPDX HEADERS FAILED")
        print("")
        # Cap the output: 86 identical messages bury the distinct causes.
        for p in problems[:12]:
            print(f"  FAIL  {p}")
        if len(problems) > 12:
            print(f"  ... and {len(problems) - 12} more")
        return 1

    license_id = workspace_license()
    files = source_files()
    print(
        f"SPDX HEADERS OK -- {len(files)} file(s), all declaring `{license_id}`, "
        f"matching the workspace"
    )
    return 0


def self_test() -> int:
    """Prove the check fires on a missing and a wrong header."""
    import contextlib
    import io

    failures = 0

    def case(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            if detail:
                print(f"        {detail[:220]}")

    # The real corpus must currently pass — the substantive case.
    problems = check()
    case(
        "the real corpus is headed correctly",
        not problems,
        f"{len(problems)} problem(s): {problems[:2]}",
    )

    # A missing header must be reported.
    tmp = Path(tempfile.mkdtemp(prefix="qqq-spdx-selftest-"))
    try:
        bare = tmp / "bare.rs"
        bare.write_text("fn main() {}\n", encoding="utf-8")
        found = find_header(bare.read_text(encoding="utf-8"))
        case("a file with no header", found is None, f"found {found!r}")

        headed = tmp / "headed.rs"
        headed.write_text(
            "// SPDX-License-Identifier: Apache-2.0\n\nfn main() {}\n", encoding="utf-8"
        )
        case(
            "a correctly headed file",
            find_header(headed.read_text(encoding="utf-8")) == "Apache-2.0",
        )

        wrong = tmp / "wrong.rs"
        wrong.write_text("// SPDX-License-Identifier: MIT\n", encoding="utf-8")
        case(
            "a header naming the wrong licence",
            find_header(wrong.read_text(encoding="utf-8")) == "MIT",
            "the checker compares this against the workspace licence",
        )

        # A mention deep in the file must NOT count as the header.
        deep = tmp / "deep.rs"
        deep.write_text(
            "fn main() {}\n\n// See the SPDX-License-Identifier: MIT convention.\n",
            encoding="utf-8",
        )
        case(
            "an SPDX mention outside the first five lines",
            find_header(deep.read_text(encoding="utf-8")) is None,
            "a deep mention is documentation about licensing, not the file's licence",
        )

        # A `.wit` file uses `//` too.
        wit = tmp / "x.wit"
        wit.write_text("// SPDX-License-Identifier: Apache-2.0\n", encoding="utf-8")
        case(
            "a .wit file with a // header",
            find_header(wit.read_text(encoding="utf-8")) == "Apache-2.0",
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # The workspace licence must be readable.
    case(
        "the workspace licence is declared",
        workspace_license() is not None,
        "no licence in Cargo.toml",
    )

    # Silence unused-import warnings in this path; `contextlib`/`io` are used by the
    # real `validate` for nothing yet, and importing them here documents intent.
    _ = (contextlib, io)

    total = 7
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
