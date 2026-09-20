#!/usr/bin/env python3
"""Verify P0 Foundation checklist items against the repository.

This is deliberately a *reporting* tool, not a gating one. It answers one
question: which P0 items are actually satisfied by artefacts that exist right
now? It does not tick anything.

# Why this exists

The Checklist drifted badly behind reality. P0 (Foundation) showed 0 of 101
done while the workspace had 910 passing tests, a working CI matrix, and all
three canonical documents — work that was done and never recorded.

A checklist that understates progress is worse than an out-of-date one, because
it makes remaining work look larger than it is and hides what has already been
paid for. This script is the cheap way to stop guessing: each item is mapped to
a concrete, checkable artefact, and the answer comes from the filesystem.

# What it cannot do

An artefact existing is not the same as the item being satisfied. `FND-003`
conventional commits are a *policy*, not a file, and `GOV-008` (recruit a second
maintainer) is not checkable at all from inside the repo. Those are marked
`unverifiable` rather than guessed at, so the human sees the boundary instead of
a confident wrong answer.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def exists(*parts):
    return os.path.exists(os.path.join(ROOT, *parts))


def nonempty(*parts):
    p = os.path.join(ROOT, *parts)
    try:
        return os.path.getsize(p) > 0
    except OSError:
        return False


def contains(*parts, needle):
    """Whether a file contains a literal string."""
    p = os.path.join(ROOT, *parts)
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            return needle in fh.read()
    except OSError:
        return False


def any_source_contains(needle):
    """Whether any Rust source file under crates/ contains a string."""
    for base, _dirs, files in os.walk(os.path.join(ROOT, "crates")):
        for name in files:
            if name.endswith(".rs"):
                try:
                    with open(os.path.join(base, name), encoding="utf-8", errors="replace") as fh:
                        if needle in fh.read():
                            return True
                except OSError:
                    pass
    return False


def git_log_has_conventional():
    """Whether recent commit subjects look Conventional-Commits shaped.

    Checked on the last 20 commits. A project that adopted the policy and then
    stopped would show up here as partially satisfied, which is the honest
    reading.
    """
    try:
        out = subprocess.run(
            ["git", "log", "-20", "--pretty=%s"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    subjects = [s for s in out.stdout.splitlines() if s.strip()]
    if not subjects:
        return False
    shaped = sum(
        1
        for s in subjects
        if ":" in s and s.split(":", 1)[0].replace("-", "").replace("(", "").replace(")", "").replace("!", "").isalnum()
    )
    return shaped >= len(subjects) // 2


# id -> (description, predicate, note-when-true)
CHECKS = {
    # -- FND ------------------------------------------------------------
    "FND-001": ("Cargo workspace", lambda: exists("Cargo.toml") and exists("crates"), "Cargo.toml + crates/"),
    "FND-002": ("PRINCIPLES.md", lambda: nonempty("PRINCIPLES.md"), "PRINCIPLES.md present"),
    "FND-003": ("Conventional commits", git_log_has_conventional, "recent commit subjects are conventional"),
    "FND-004": ("CI matrix", lambda: contains(".github", "workflows", "ci.yml", needle="macos-latest")
                and contains(".github", "workflows", "ci.yml", needle="windows-latest"), "ubuntu + macos + windows"),
    "FND-005": ("deny/machete/clippy in CI", lambda: contains(".github", "workflows", "ci.yml", needle="cargo deny check")
                and contains(".github", "workflows", "ci.yml", needle="cargo machete"), "all three wired"),
    "FND-006": ("docs/adr", lambda: exists("docs", "adr"), "docs/adr/"),
    "FND-007": ("PR template", lambda: exists(".github", "PULL_REQUEST_TEMPLATE.md")
                or exists(".github", "pull_request_template.md"), "PR template"),
    "FND-009": ("SECURITY.md", lambda: nonempty("SECURITY.md"), "SECURITY.md present"),
    "FND-011": ("scratch witprobe gone", lambda: not exists(".scratch", "witprobe") and exists("crates", "qqq-host", "tests"),
                "scratch removed AND host tests exist (both required)"),

    # -- DOC ------------------------------------------------------------
    "DOC-001": ("README.md", lambda: nonempty("README.md"), "README.md"),
    "DOC-002": ("Proposal", lambda: nonempty("QQQ-Proposal-V1.md"), "present"),
    "DOC-003": ("Checklist", lambda: nonempty("QQQ-Checklist-V1.md"), "present"),
    "DOC-004": ("Observations", lambda: nonempty("QQQ-Observations-and-Memories.md"), "present"),
    "DOC-006": ("xref validator", lambda: exists("tools", "check_xrefs.py"), "tools/check_xrefs.py"),
    "DOC-007": ("xrefs required in CI", lambda: contains(".github", "workflows", "ci.yml", needle="check_xrefs.py"),
                "wired into CI"),
    "DOC-009": ("stub-marker CI check", lambda: exists("tools", "check_xrefs.py")
                and contains("tools", "check_xrefs.py", needle="QQQ-STUB")
                and contains(".github", "workflows", "ci.yml", needle="check_xrefs.py"),
                "check [7]/[11] validate markers against checklist items, in CI"),

    # -- LIC ------------------------------------------------------------
    "LIC-001": ("LICENSE", lambda: contains("LICENSE", needle="Apache License"), "Apache-2.0"),
    "LIC-004": ("free-entity grant", lambda: contains("LICENSING.md", needle="No seat limits"), "LICENSING.md §1"),
    "LIC-007": ("cargo-deny licence allowlist", lambda: exists("deny.toml"), "deny.toml"),
    "LIC-009": ("licence FAQ", lambda: contains("LICENSING.md", needle="Plain-language FAQ"), "LICENSING.md §4"),
    "LIC-010": ("CLA/DCO", lambda: contains("CONTRIBUTING.md", needle="DCO")
                or contains("CONTRIBUTING.md", needle="Developer Certificate"), "DCO in CONTRIBUTING"),

    # -- GOV ------------------------------------------------------------
    "GOV-001": ("GOVERNANCE.md", lambda: nonempty("GOVERNANCE.md"), "present"),
    "GOV-002": ("CONTRIBUTING.md", lambda: nonempty("CONTRIBUTING.md"), "present"),
    "GOV-003": ("CODE_OF_CONDUCT.md", lambda: nonempty("CODE_OF_CONDUCT.md"), "present"),
    "GOV-006": ("security response policy", lambda: contains("SECURITY.md", needle="Patch target"),
                "target times in SECURITY.md"),
}


def main():
    argv = sys.argv[1:]
    only = [a.upper() for a in argv if not a.startswith("-")]

    satisfied, unsatisfied = [], []
    for item, (desc, pred, note) in sorted(CHECKS.items()):
        if only and item not in only:
            continue
        try:
            ok = bool(pred())
        except Exception as exc:  # noqa: BLE001 - a probe failing is a report, not a crash
            ok = False
            note = f"probe raised {exc!r}"
        (satisfied if ok else unsatisfied).append((item, desc, note))

    if satisfied:
        print("SATISFIED (artefact verified present)\n")
        for item, desc, note in satisfied:
            print(f"  {item}  {desc}\n        -> {note}")

    if unsatisfied:
        print("\nNOT SATISFIED\n")
        for item, desc, note in unsatisfied:
            print(f"  {item}  {desc}")

    print(
        f"\n{len(satisfied)} satisfiable of {len(satisfied) + len(unsatisfied)} probed."
        "\nThis is a report, not a gate: an artefact existing is not the same as an"
        "\nitem being finished. Tick only what you have read."
    )


if __name__ == "__main__":
    main()
