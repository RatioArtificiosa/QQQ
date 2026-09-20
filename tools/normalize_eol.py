#!/usr/bin/env python3
"""Normalize the working tree to LF, matching what `.gitattributes` commits.

# Why this exists

`core.autocrlf=true` is set on Windows, and `.gitattributes` pins `eol=lf`. That
combination means Git *commits* LF while the working tree may hold CRLF: a file
edited by a tool that writes CRLF shows as modified against an index that holds
LF, even though `git diff` shows no content change.

The symptom is confusing and recurring — `git status` reports three documents
modified after a commit that included them, and `tools/audit_requirements.py`'s
"working tree clean" check fails on a tree that has no real change in it.

# Why this matters beyond tidiness

This repository is byte-sensitive: `qqq.lock` carries a covering hash over its
own bytes, and the content store compares digests. A file whose line endings
differ between what was committed and what is on disk produces a different
digest for the same logical content.

For the three Markdown documents specifically the stakes are lower — nothing
hashes them — but a dirty tree hides real changes, and "the tree is dirty
because of line endings" is exactly the excuse that makes a genuine uncommitted
edit easy to miss.

# Usage

    python tools/normalize_eol.py          # report and fix
    python tools/normalize_eol.py --check  # report only, exit 1 if any file drifts

`--check` is suitable for CI: it fails if a committed text file would check out
with the wrong endings.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Extensions that are text and must be LF in the working tree. Derived from
# `.gitattributes` rather than guessed: everything is `text=auto eol=lf` except
# the Windows-native script types, which stay CRLF.
TEXT_SUFFIXES = {
    ".md", ".rs", ".toml", ".lock", ".json", ".wit", ".py", ".yml", ".yaml",
    ".sh", ".txt", ".html", ".css", ".js", ".ts",
}
KEEP_CRLF = {".ps1", ".cmd", ".bat"}


def git_files() -> list[Path]:
    """Every tracked file, via Git rather than a directory walk.

    A walk would touch untracked scratch files and build output. The question is
    only about files that are committed.
    """
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return [ROOT / p for p in out.stdout.split("\0") if p]


def main() -> int:
    check_only = "--check" in sys.argv

    drifted: list[Path] = []
    for path in git_files():
        suffix = path.suffix.lower()
        if suffix in KEEP_CRLF or (suffix and suffix not in TEXT_SUFFIXES):
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        # Only a file containing CRLF is a problem. A file with no LF at all
        # (a single-line file, or an empty one) is left alone.
        if b"\r\n" not in raw:
            continue

        drifted.append(path)
        if not check_only:
            # Normalize CRLF -> LF. A lone CR (old Mac line ending) is not
            # touched: it never appears in this repository, and rewriting it
            # would be acting on a guess.
            path.write_bytes(raw.replace(b"\r\n", b"\n"))

    if not drifted:
        print("all tracked text files use LF")
        return 0

    verb = "would normalize" if check_only else "normalized"
    print(f"{verb} {len(drifted)} file(s) from CRLF to LF:")
    for path in drifted:
        print(f"  {path.relative_to(ROOT)}")

    if check_only:
        print(
            "\nRun `python tools/normalize_eol.py` to fix. The committed bytes "
            "are already LF; this is the working tree drifting."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
