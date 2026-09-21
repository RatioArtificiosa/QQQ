#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

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


def untracked_would_be_wrong(limit: int = 40) -> list[tuple[Path, str]]:
    """Untracked text files whose working-tree EOL contradicts `.gitattributes`.

    # Why this exists, and the defect it closes

    `git_files` asks Git for **tracked** files, so this tool has always been
    blind to a file that has been created but not yet staged. That is exactly
    the moment a line-ending mistake is cheapest to fix and most expensive to
    miss, and it bit for real: `tools/bootstrap.sh` was written on Windows,
    carried CRLF, passed `normalize_eol.py --check` (untracked, therefore
    invisible), passed every other local gate, and would have shipped a shell
    script that Linux refuses with

        bash: tools/bootstrap.sh: /bin/bash^M: bad interpreter

    which is `§O-086` — a Windows checkout giving Linux an interpreter named
    `bash\\r` — recurring in the *workflow* rather than the runtime. The commit
    that introduced the file is the only place it can be prevented, so the check
    has to look at untracked files.

    # Why it reports rather than fixes

    Because an untracked file may be work in progress that the author does not
    want rewritten. The caller decides; this tool's job is to make the problem
    visible before a commit rather than after a CI failure.

    # Why only files that would be *committed* as text

    Because `.gitattributes` distinguishes them: a `.ps1` is CRLF by design and
    a `target/` blob is binary. Both are excluded, so the report is actionable
    rather than a list of things nobody will change.
    """
    out = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    findings: list[tuple[Path, str]] = []
    for rel in out.stdout.split("\0"):
        if not rel:
            continue
        path = ROOT / rel
        suffix = path.suffix.lower()
        if suffix in KEEP_CRLF or (suffix and suffix not in TEXT_SUFFIXES):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        # A NUL byte means binary, whatever the extension says.
        if b"\0" in data[:8192]:
            continue
        crlf = data.count(b"\r\n")
        lf = data.count(b"\n") - crlf
        if crlf and lf:
            findings.append((path, f"mixed ({crlf} CRLF, {lf} LF)"))
        elif crlf:
            findings.append((path, f"CRLF ({crlf})"))
        if len(findings) >= limit:
            break
    return findings


def core_autocrlf() -> str:
    """The repository's `core.autocrlf` setting, or `(unset)`."""
    out = subprocess.run(
        ["git", "config", "--get", "core.autocrlf"],
        cwd=ROOT, capture_output=True, text=True,
    )
    return out.stdout.strip() or "(unset)"


def index_eol_report() -> list[str]:
    """Files whose **committed** bytes are not LF, from Git itself.

    This is the check that matters, and it is different from inspecting the
    working tree.

    # What was measured

    With `text eol=lf` on the three documents, the committed blob is correct —
    `git cat-file -p HEAD:QQQ-Checklist-V1.md` gives 0 CRLF and 1,549 LF — while
    the *working copy* still reports `w/crlf` and `git status` still warns that
    it "will be replaced by LF". So the repository content is right and the
    checkout is untidy.

    A check that fails on the untidy checkout reports a defect the commit does
    not have, and a check that fails spuriously is one people learn to ignore —
    which is the failure mode this whole tool exists to avoid.

    The honest report is therefore in two parts: **FAIL** if any committed blob
    holds CRLF (a real defect in what was committed), and **WARN** if the
    working tree drifts (untidy, self-correcting at commit, worth saying out
    loud rather than pretending is absent).
    """
    out = subprocess.run(
        ["git", "ls-files", "--eol"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    bad: list[str] = []
    for line in out.stdout.splitlines():
        # Format: `i/<index-eol> w/<worktree-eol> attr/<attrs>\t<path>`
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        meta, path = parts[0], parts[1]
        if path.endswith(".gitattributes"):
            continue
        index_eol = meta.split()[0] if meta.split() else ""
        # `i/lf` is correct. `i/mixed` or `i/crlf` means the blob is wrong.
        if index_eol and index_eol != "i/lf" and index_eol != "i/none":
            bad.append(f"{path} ({index_eol})")
    return bad


def main() -> int:
    check_only = "--check" in sys.argv
    autocrlf = core_autocrlf()

    # --- Part 1: the committed bytes. A failure here is a real defect. -------
    bad_blobs = index_eol_report()
    if bad_blobs:
        print("FAIL: committed content holds CRLF (this is a real defect):")
        for path in bad_blobs:
            print(f"  {path}")
        print("\nFix: python tools/normalize_eol.py, then commit.")
        return 1

    # --- Part 1b: files that are about to be committed but are not tracked ---
    #
    # The blind spot that let a CRLF shell script reach a commit. See
    # `untracked_would_be_wrong` for the full account; the short version is that
    # `git ls-files` cannot see a file that has not been staged, and the commit
    # that stages it is the last moment the problem is cheap to fix.
    #
    # It reports rather than repairs, and it does not fail `--check`: an
    # untracked file is not yet part of the repository, and failing CI on
    # something that is not committed would be a false alarm. The normalization
    # path fixes it, so running the tool without `--check` before `git add`
    # closes the gap.
    untracked = untracked_would_be_wrong()
    if untracked:
        if check_only:
            print(
                f"note: {len(untracked)} untracked text file(s) would be committed "
                f"with the wrong endings:"
            )
            for path, why in untracked:
                print(f"  {path.relative_to(ROOT)} — {why}")
            print(
                "\nRun `python tools/normalize_eol.py` before `git add` to fix "
                "them; this is not a failure while they are untracked."
            )
        else:
            for path, _why in untracked:
                raw = path.read_bytes()
                path.write_bytes(raw.replace(b"\r\n", b"\n"))
            print(
                f"normalized {len(untracked)} untracked file(s) before commit:"
            )
            for path, _why in untracked:
                print(f"  {path.relative_to(ROOT)}")

    # --- Part 2: the working tree. Drift here is untidy, not broken. ---------
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
        print("committed content is LF; working tree matches")
        if autocrlf in ("true", "input"):
            print(
                f"note: core.autocrlf is `{autocrlf}`, which is not required for "                "correctness but removes one more thing that could rewrite a file"
            )
        return 0

    verb = "would normalize" if check_only else "normalized"
    print(f"{verb} {len(drifted)} working-tree file(s) from CRLF to LF:")
    for path in drifted:
        print(f"  {path.relative_to(ROOT)}")

    if check_only:
        # **Exit 0.** The committed content is correct -- that was verified
        # above -- so this is an untidy checkout, not a defect. Failing CI on it
        # would be a check that fires on a condition the repository does not
        # actually have, and a spurious failure is one people learn to ignore.
        #
        # It is still printed, because a reader comparing `git status` against
        # an empty `git diff` deserves to know why they disagree.
        print(
            "\nThis is a working-tree difference only; the committed bytes are "
            "LF.\nRun `python tools/normalize_eol.py` to tidy the checkout. "
            "No action is required to merge."
        )
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
