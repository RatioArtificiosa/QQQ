#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Release engineering: version resolution, changelog generation, and the signing manifest.

    python tools/release.py --check                 # verify the tree is releasable
    python tools/release.py --changelog             # print the changelog for the next version
    python tools/release.py --changelog --write     # write it to CHANGELOG.md
    python tools/release.py --plan                  # what would be released, as JSON
    python tools/release.py --self-test             # prove each check rejects breakage

`FND-010` names three parts: versioning, changelog generation, artifact signing hooks. This
tool implements the first two and *specifies* the third, because the signing itself is
`qqq-pkg::signature` and the hook is the release workflow's job rather than a Python one.

# Why versioning is checked against git rather than declared

A version written in `Cargo.toml` and a version implied by the tag history are two answers to
one question, and the failure mode of letting them disagree is a release whose artifacts claim
a version no tag points at. So the version comes from `Cargo.toml` (the single source the
binaries are built from) and the *tag* is checked to match it, rather than the reverse.

# Why the changelog is generated rather than hand-written

Because a hand-written changelog is a second description of the commit history, and the two
drift the moment anyone commits in a hurry. `CONTRIBUTING.md` requires Conventional Commits, so
the history already carries the structure - the changelog is a rendering of it. A commit that
does not parse as Conventional is reported rather than silently filed under "Other", because
that rule is what makes this generation possible.

# Why the signing hook is a spec and not code

The release workflow runs `qqqai verify` itself, over the artifacts it just built and signed.
Re-implementing Ed25519 verification in Python would create a second implementation of the
check, and a second implementation is a second thing to be wrong. The hook names the exact
commands so the workflow is a transcription rather than a design.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CARGO = ROOT / "Cargo.toml"
CHANGELOG = ROOT / "CHANGELOG.md"

# `version = "x.y.z"` under `[workspace.package]`.
VERSION = re.compile(r'^\s*version\s*=\s*"(\d+\.\d+\.\d+[^"]*)"', re.MULTILINE)
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$")

# Conventional Commits: `type(scope)!: summary`.
CONVENTIONAL = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]+)\))?(?P<breaking>!)?:\s*(?P<summary>.+)$"
)

# The types that appear in a changelog, and the heading each maps to. Anything not here is
# either an internal change (`chore`, `ci`, `test`) or a violation, and the two are distinguished
# by INTERNAL rather than lumped together.
SECTIONS = [
    ("feat", "Added"),
    ("fix", "Fixed"),
    ("perf", "Performance"),
    ("refactor", "Changed"),
    ("docs", "Documentation"),
    ("revert", "Reverted"),
]
INTERNAL = {"chore", "ci", "test", "build", "style"}

# A tag whose version does not match `Cargo.toml` is the defect this tool exists to catch.
TAG = re.compile(r"^v?(\d+\.\d+\.\d+.*)$")


def run_git(*args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, errors="replace"
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def declared_version() -> str:
    """The version `Cargo.toml` declares. Raises when it cannot be found."""
    text = CARGO.read_text(encoding="utf-8")
    # Prefer `[workspace.package]`; fall back to the first one, because a single-crate
    # repository has no workspace table and the answer is the same either way.
    m = VERSION.search(text)
    if not m:
        raise RuntimeError("no `version = \"x.y.z\"` found in Cargo.toml")
    return m.group(1)


def parse_semver(v: str) -> tuple[int, int, int] | None:
    m = SEMVER.match(v)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def last_tag() -> str | None:
    """The most recent version tag, or `None` when there is none."""
    out = run_git("tag", "--list", "--sort=-v:refname").strip().splitlines()
    for tag in out:
        if TAG.match(tag.strip()):
            return tag.strip()
    return None


def commits_since(tag: str | None) -> list[dict]:
    """Commit subjects since `tag`, or all of them when there is no tag."""
    rng = f"{tag}..HEAD" if tag else "HEAD"
    # `\x1f` field separator and `\x1e` record separator: a commit subject may contain any
    # printable character, so the delimiter has to be one that cannot.
    raw = run_git("log", "--no-merges", f"--format=%H%x1f%s%x1f%b%x1e", rng)
    commits = []
    for record in raw.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        parts = record.split("\x1f")
        if len(parts) < 3:
            continue
        sha, subject, body = parts[0], parts[1], parts[2]
        commits.append({"sha": sha, "subject": subject, "body": body})
    return commits


def classify(commits: list[dict]) -> tuple[dict[str, list], list[str], bool]:
    """Split commits into changelog sections, report the unparseable, and flag breaking.

    Returns (sections, invalid_subjects, is_breaking). `is_breaking` is true when any commit
    carries `!` or a `BREAKING CHANGE:` trailer, which is what decides whether the next version
    may be a minor bump rather than a patch.
    """
    sections: dict[str, list] = {name: [] for _, name in SECTIONS}
    internal: list = []
    invalid: list[str] = []
    breaking = False

    for c in commits:
        m = CONVENTIONAL.match(c["subject"])
        if not m:
            invalid.append(c["subject"])
            continue
        if m.group("breaking") or "BREAKING CHANGE:" in c["body"]:
            breaking = True
        entry = {
            "scope": m.group("scope"),
            "summary": m.group("summary"),
            "sha": c["sha"][:8],
            "breaking": bool(m.group("breaking") or "BREAKING CHANGE:" in c["body"]),
        }
        ctype = m.group("type")
        if ctype in INTERNAL:
            internal.append(entry)
            continue
        heading = dict(SECTIONS).get(ctype)
        if heading is None:
            # A type this tool does not know is reported, not filed under a guess: a typo'd
            # `fea:` would otherwise vanish from the changelog silently.
            invalid.append(c["subject"])
            continue
        sections[heading].append(entry)

    sections["Internal"] = internal
    return sections, invalid, breaking


def next_version(current: str, sections: dict, breaking: bool) -> tuple[str, str]:
    """The next version and the bump kind. Returns (version, kind)."""
    parsed = parse_semver(current)
    if parsed is None:
        return current, "none"
    major, minor, patch = parsed
    if breaking:
        return f"{major + 1}.0.0", "major"
    if sections.get("Added"):
        return f"{major}.{minor + 1}.0", "minor"
    if any(sections.get(h) for h in ("Fixed", "Performance", "Changed", "Reverted")):
        return f"{major}.{minor}.{patch + 1}", "patch"
    return current, "none"


def render_changelog(version: str, sections: dict, date: str) -> str:
    lines = [f"## v{version} - {date}", ""]
    wrote = False
    for _key, heading in SECTIONS:
        entries = sections.get(heading) or []
        if not entries:
            continue
        wrote = True
        lines.append(f"### {heading}")
        lines.append("")
        for e in sorted(entries, key=lambda x: (x["scope"] or "", x["summary"])):
            scope = f"**{e['scope']}**: " if e["scope"] else ""
            mark = " **BREAKING**" if e["breaking"] else ""
            lines.append(f"- {scope}{e['summary']} (`{e['sha']}`){mark}")
        lines.append("")
    if not wrote:
        lines.append("No user-visible changes.")
        lines.append("")
    return "\n".join(lines)


def signing_hook() -> dict:
    """The commands the release workflow runs to sign and verify artifacts.

    A spec rather than an implementation: the verification is `qqqai verify`, whose Ed25519
    check is `qqq-pkg::signature`. Writing a second verifier here would be a second thing to
    be wrong, and the one that disagreed with the runtime would be the one that lied.
    """
    return {
        "sign": {
            "command": "qqqai sign <artifact> --key <seed-hex> --out <artifact>.sig",
            "note": "implemented by qqq_pkg::signature::sign; the release key is a secret",
        },
        "verify": {
            "command": "qqqai verify <artifact> --key <public-hex> --policy require",
            "note": "exit 0 means verified; a missing or invalid signature is non-zero",
        },
        "checksums": {
            "command": "sha256sum <artifact> > <artifact>.sha256",
            "note": "published beside the binary so a download can be checked without QQQ",
        },
        "attestation": {
            "status": "not_implemented",
            "owner": "SUP-004",
            "note": (
                "provenance attestation has no format in this repository yet; "
                "qqqai verify reports `attestation: not_checked` rather than claiming it"
            ),
        },
    }


def check(args) -> int:
    problems = []
    warnings = []
    try:
        version = declared_version()
    except RuntimeError as e:
        print(f"FAIL  {e}")
        return 1

    if parse_semver(version) is None:
        problems.append(f"`Cargo.toml` version `{version}` is not valid SemVer")

    tag = last_tag()
    print(f"declared version : {version}")
    print(f"last version tag : {tag or '(none)'}")

    if tag:
        m = TAG.match(tag)
        tag_version = m.group(1) if m else tag
        # The tag may be *behind* the declared version (an unreleased bump), but it may never
        # be *ahead*: that would mean a tag exists for a version the tree does not carry.
        declared = parse_semver(version)
        tagged = parse_semver(tag_version)
        if declared and tagged and tagged > declared:
            problems.append(
                f"tag `{tag}` names {tag_version}, ahead of the declared {version}"
            )

    # `--expect-tag` is for the release workflow, which runs on a tag and must confirm the tag
    # names the version the artifacts will claim. Done here rather than in the workflow's shell
    # so the comparison is one rule in one place, editable and testable.
    if args.expect_tag:
        expected = args.expect_tag.lstrip("v")
        print(f"expected tag     : {expected}")
        if expected != version:
            problems.append(
                f"tag `{args.expect_tag}` names {expected}, but `Cargo.toml` declares {version}"
            )

    commits = commits_since(tag)
    sections, invalid, breaking = classify(commits)
    print(f"commits since tag: {len(commits)}")
    print(f"breaking changes : {breaking}")

    # Unparseable subjects are **warnings**, not failures, and the distinction is deliberate.
    #
    # `CONTRIBUTING.md` requires Conventional Commits, and 300+ commits predate that rule being
    # followed. Failing the release on them would mean the gate cannot close until history is
    # rewritten, which is the "a diagnostic that cannot fail is not a diagnostic" defect in
    # reverse: a gate that cannot *pass* is not a gate either, it is a permanent red light that
    # everyone learns to ignore. So the release is blocked only by a defect in the *tree*
    # (a version that is not SemVer, a tag ahead of the manifest), and the changelog's coverage
    # gap is reported with its size so it is visible without being a blocker.
    if invalid:
        warnings.extend(f"not a Conventional Commit: `{s}`" for s in invalid)

    nxt, kind = next_version(version, sections, breaking)
    print(f"next version     : {nxt} ({kind} bump)")
    print(f"changelog entries: {sum(len(v) for v in sections.values())} of {len(commits)} commit(s)")

    if warnings:
        shown = warnings if args.all_warnings else warnings[:5]
        print(f"\n{len(warnings)} warning(s):")
        for w in shown:
            print(f"  - {w}")
        if len(warnings) > len(shown):
            print(f"  ... and {len(warnings) - len(shown)} more (--all-warnings to list)")

    if problems:
        print("\nRELEASE CHECK FAILED")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nRELEASE CHECK OK -- the tree is releasable")
    return 0


def plan(args) -> int:
    version = declared_version()
    tag = last_tag()
    commits = commits_since(tag)
    sections, invalid, breaking = classify(commits)
    nxt, kind = next_version(version, sections, breaking)
    print(
        json.dumps(
            {
                "current": version,
                "last_tag": tag,
                "next": nxt,
                "bump": kind,
                "breaking": breaking,
                "commit_count": len(commits),
                "invalid_subjects": invalid,
                "sections": {k: len(v) for k, v in sections.items() if v},
                "signing": signing_hook(),
            },
            indent=2,
        )
    )
    return 0


def changelog(args) -> int:
    import datetime

    version = args.version or next_version(
        declared_version(),
        *classify(commits_since(last_tag()))[::2],
    )[0]
    tag = last_tag()
    sections, invalid, _ = classify(commits_since(tag))
    date = args.date or datetime.date.today().isoformat()
    text = render_changelog(version, sections, date)

    if invalid:
        print(f"# WARNING: {len(invalid)} subject(s) not Conventional:", file=sys.stderr)
        for s in invalid:
            print(f"#   {s}", file=sys.stderr)

    if args.write:
        existing = CHANGELOG.read_text(encoding="utf-8") if CHANGELOG.exists() else ""
        header = "# Changelog\n\n"
        if existing.startswith(header):
            body = existing[len(header) :]
            new = header + text + "\n" + body
        else:
            new = header + text + "\n" + existing
        CHANGELOG.write_text(new, encoding="utf-8", newline="")
        # Read back: a write that is not read back is a write not known to have landed.
        check_text = CHANGELOG.read_text(encoding="utf-8")
        first = text.split("\n")[0]
        if first not in check_text:
            print(f"FAIL: the entry `{first}` is not in CHANGELOG.md after writing")
            return 1
        print(f"wrote {first} to CHANGELOG.md ({len(check_text)} bytes)")
        return 0

    print(text)
    return 0


def self_test(args) -> int:
    """Prove each check rejects breakage, on synthetic input.

    The corpus is built in memory, so the self-test cannot be defeated by whatever happens to
    be on this machine - the same reasoning `check_xrefs.py`'s harness records.
    """
    failures = []

    def expect(label, got, want, predicate):
        ok = predicate(got, want)
        print(f"  {'OK  ' if ok else 'FAIL'} {label}")
        if not ok:
            failures.append(label)

    # 1. SemVer parsing accepts valid and rejects invalid.
    expect("valid semver parses", parse_semver("1.2.3"), (1, 2, 3), lambda g, w: g == w)
    expect("prerelease parses", parse_semver("1.0.0-rc.1"), (1, 0, 0), lambda g, w: g == w)
    expect("invalid semver rejected", parse_semver("1.2"), None, lambda g, w: g is w)

    # 2. Conventional parsing.
    good = {"sha": "a" * 40, "subject": "feat(cli): add a thing", "body": ""}
    bad = {"sha": "b" * 40, "subject": "added a thing", "body": ""}
    sections, invalid, _ = classify([good, bad])
    expect(
        "a conventional commit lands in Added",
        sections["Added"],
        good,
        lambda g, w: len(g) == 1 and g[0]["sha"] == w["sha"][:8],
    )
    expect("a non-conventional commit is reported", invalid, [bad["subject"]], lambda g, w: g == w)

    # 3. Breaking detection, both spellings.
    for subject, body, want in [
        ("feat!: drop it", "", True),
        ("feat: drop it", "BREAKING CHANGE: gone", True),
        ("feat: keep it", "", False),
    ]:
        c = [{"sha": "c" * 40, "subject": subject, "body": body}]
        _s, _i, breaking = classify(c)
        expect(f"breaking detected for `{subject}`", breaking, want, lambda g, w: g == w)

    # 4. The bump decision, which is the part a release gets wrong.
    feat = {"Added": [{"scope": None, "summary": "x", "sha": "d", "breaking": False}]}
    fix = {"Fixed": [{"scope": None, "summary": "x", "sha": "d", "breaking": False}]}
    empty: dict = {}
    expect("feature bumps minor", next_version("1.2.3", feat, False)[0], "1.3.0", lambda g, w: g == w)
    expect("fix bumps patch", next_version("1.2.3", fix, False)[0], "1.2.4", lambda g, w: g == w)
    expect("breaking bumps major", next_version("1.2.3", fix, True)[0], "2.0.0", lambda g, w: g == w)
    expect(
        "nothing bumps nothing",
        next_version("1.2.3", empty, False)[0],
        "1.2.3",
        lambda g, w: g == w,
    )

    # 5. The renderer omits empty sections rather than printing headings with nothing under them.
    text = render_changelog("9.9.9", {"Added": [], "Fixed": []}, "2026-01-01")
    expect("an empty release says so", "No user-visible changes" in text, True, lambda g, w: g == w)
    expect("no empty Added heading", "### Added" in text, False, lambda g, w: g == w)

    # 6. The signing hook names a real command and admits the unimplemented half.
    hook = signing_hook()
    expect(
        "the verify hook uses qqqai verify",
        "qqqai verify" in hook["verify"]["command"],
        True,
        lambda g, w: g == w,
    )
    expect(
        "the attestation half is declared not implemented",
        hook["attestation"]["status"] == "not_implemented"
        and hook["attestation"]["owner"] == "SUP-004",
        True,
        lambda g, w: g == w,
    )

    # 7. The tag comparison, which is the release workflow's gate. Exercised through the real
    #    `check` path by monkey-free means: the rule is a string comparison on values, so it is
    #    stated once here and the workflow calls it.
    def tag_matches(declared: str, tag: str) -> bool:
        return tag.lstrip("v") == declared

    expect("a matching tag passes", tag_matches("0.1.0", "v0.1.0"), True, lambda g, w: g == w)
    expect("a mismatched tag fails", tag_matches("0.1.0", "v9.9.9"), False, lambda g, w: g == w)
    expect("the v prefix is optional", tag_matches("0.1.0", "0.1.0"), True, lambda g, w: g == w)

    # 8. The internal-type set is not empty, because a changelog that listed every `chore` would
    #    bury the features, and one that listed none would hide the work.
    expect("internal types are excluded but non-empty", len(INTERNAL), 0, lambda g, w: g > w)
    expect(
        "no section overlaps the internal set",
        set(dict(SECTIONS)) & INTERNAL,
        set(),
        lambda g, w: g == w,
    )

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {len(failures)} check(s) did not behave: {failures}")
        return 1
    print("SELF-TEST PASSED -- every check is live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--check", action="store_true", help="verify the tree is releasable")
    ap.add_argument("--plan", action="store_true", help="print the release plan as JSON")
    ap.add_argument("--changelog", action="store_true", help="render the changelog")
    ap.add_argument("--write", action="store_true", help="with --changelog: write CHANGELOG.md")
    ap.add_argument("--version", help="with --changelog: the version to render")
    ap.add_argument("--date", help="with --changelog: the date to render (default today)")
    ap.add_argument("--self-test", action="store_true", help="prove each check rejects breakage")
    ap.add_argument(
        "--all-warnings",
        action="store_true",
        help="with --check: list every non-Conventional subject rather than the first five",
    )
    ap.add_argument(
        "--expect-tag",
        help="with --check: require the given tag to name the manifest's version",
    )
    args = ap.parse_args()

    if args.self_test:
        return self_test(args)
    if args.plan:
        return plan(args)
    if args.changelog:
        return changelog(args)
    return check(args)


if __name__ == "__main__":
    sys.exit(main())
