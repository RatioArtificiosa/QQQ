#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# checklist-citations-exempt: this file's subject IS fabricated references. It
# documents and reproduces the harness's injections (`HOST-999`, `OQ-099` --
# not-a-checklist-item), so every mention of one is a description of a fault
# rather than a citation of an item. Declared once, per `§O-204`.
"""Prove the canonical documents are at rest, so a commit cannot capture a
fault injection that a harness is about to undo — `§O-204`.

# The failure this exists to prevent

`tools/self_test_xrefs.py` proves its checks are live by **mutating the three
canonical documents**, running the validator, and restoring them. Between the
mutation and the restore the working tree contains a deliberate fault —
`HOST-999` in the Proposal, a renamed heading in the Observations, a stripped
citation block in the checklist.

If a `git add` runs inside that window, the index captures the injected bytes.
The harness then restores the file on disk, so the working tree, `git status`
and `--check-clean` all look right, while the staged blob is the fault. Commit
`0a9e2eb` in this repository did exactly that; the evidence is in `§O-204`.

# Why a digest and not another marker scan

Every existing guard asks *"is a known fault text present?"* — `--check-clean`
scans a marker list, and `check_xrefs.py` asks whether citations resolve (which
the injected `HOST-999` legitimately does not, so it is the thing under test, not
a guard). A marker scan can only find faults it already knows.

A digest asks a different question: *"is this file the bytes we agreed on?"* It
needs no marker list, and it catches a fault nobody has thought of, including one
introduced by a tool that has no marker vocabulary at all.

# Usage

    python tools/check_corpus_at_rest.py --record     # record the digests
    python tools/check_corpus_at_rest.py --verify     # refuse if any changed
    python tools/check_corpus_at_rest.py              # same as --verify
    python tools/check_corpus_at_rest.py --self-test

The record lives in a JSON file under `tools/`. It holds SHA-256 per document
plus the file's byte length, so a truncation and a substitution are both visible.

Exit: 0 = at rest (or self-test passed), 1 = changed or a case failed.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
RECORD = ROOT / "tools" / "corpus_at_rest.json"

# The documents the harness mutates. Named explicitly rather than globbed: a glob
# would silently stop covering a document that was renamed, which is the failure
# this whole file is about.
DOCUMENTS = [
    "QQQ-Proposal-V1.md",
    "QQQ-Checklist-V1.md",
    "QQQ-Observations-and-Memories.md",
]


def digest_of(path: pathlib.Path) -> dict[str, object]:
    """The file's bytes as a length and a SHA-256, read once."""
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def current(root: pathlib.Path) -> dict[str, dict[str, object]]:
    return {name: digest_of(root / name) for name in DOCUMENTS}


def record(root: pathlib.Path = ROOT, record_path: pathlib.Path = RECORD) -> int:
    snap = current(root)
    record_path.write_text(
        json.dumps(snap, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"recorded {len(snap)} document digest(s) to {record_path.name}")
    for name, d in snap.items():
        print(f"  {name}: {d['bytes']} bytes  {str(d['sha256'])[:16]}…")
    return 0


def verify(
    root: pathlib.Path = ROOT,
    record_path: pathlib.Path = RECORD,
    quiet: bool = False,
) -> int:
    """Refuse unless every document matches its recorded digest.

    `quiet` suppresses the per-document and diagnosis output. The self-test needs
    the verdict and not the narration: eleven cases each printing a full
    diagnosis turn a readable transcript into a wall of text, and a transcript
    nobody reads is how a failing case gets skimmed past.
    """
    def say(*args: object) -> None:
        if not quiet:
            print(*args)

    def complain(*args: object) -> None:
        if not quiet:
            print(*args, file=sys.stderr)

    if not record_path.exists():
        complain(
            f"NO RECORD: {record_path.name} does not exist. Run "
            f"`python tools/check_corpus_at_rest.py --record` first."
        )
        return 1

    expected = json.loads(record_path.read_text(encoding="utf-8"))
    actual = current(root)

    problems: list[str] = []
    for name in DOCUMENTS:
        if name not in expected:
            problems.append(f"{name}: not in the record")
            continue
        e, a = expected[name], actual[name]
        if e["sha256"] == a["sha256"] and e["bytes"] == a["bytes"]:
            say(f"  at rest  {name}")
            continue
        if e["bytes"] != a["bytes"]:
            detail = f"length {e['bytes']} -> {a['bytes']}"
        else:
            detail = (
                f"same length, different bytes "
                f"({str(e['sha256'])[:16]}… -> {str(a['sha256'])[:16]}…)"
            )
        problems.append(f"{name}: {detail}")

    if problems:
        complain("")
        complain(
            "CORPUS NOT AT REST -- a canonical document changed since its digest "
            "was recorded:"
        )
        for p in problems:
            complain(f"  {p}")
        complain("")
        complain(
            "  If a fault-injection harness is running, wait for it to finish and "
            "re-check."
        )
        complain(
            "  If the change is intended, re-record: "
            "`python tools/check_corpus_at_rest.py --record`."
        )
        return 1

    say(
        f"CORPUS AT REST -- {len(DOCUMENTS)} document(s) match their recorded digests"
    )
    return 0


# --------------------------------------------------------------------------
# Self-test: the injections the real harness applies must each be caught.
# --------------------------------------------------------------------------

# (description, file, old, new) -- the real substitutions, copied from
# `self_test_xrefs.py`'s marker table so a case that stops matching the harness
# is visible as a self-test failure rather than as silent non-coverage.
INJECTIONS = [
    (
        "the Proposal citing a dangling checklist ID",
        "QQQ-Proposal-V1.md",
        "`HOST-001`",
        "`HOST-999`",
    ),
    (
        "the Proposal citing a bad Observations decision",
        "QQQ-Proposal-V1.md",
        "`§D-003`",
        "`§D-099`",
    ),
    (
        "a checklist open question renamed",
        "QQQ-Checklist-V1.md",
        "**OQ-012**",
        "**OQ-099**",
    ),
    (
        "a trivial single-byte change",
        "QQQ-Observations-and-Memories.md",
        "## 4. MISTAKES AND FIXES",
        "## 4. MISTAKES AND FIXES ",
    ),
]


def self_test() -> int:
    """Run every case against a temporary copy, never the repository."""
    cases = 0
    failures = 0

    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = pathlib.Path(tmp)
        for name in DOCUMENTS:
            (tmp_root / name).write_bytes((ROOT / name).read_bytes())
        rec = tmp_root / "corpus_at_rest.json"

        def check(name: str, ok: bool, detail: str = "") -> None:
            nonlocal cases, failures
            cases += 1
            if ok:
                print(f"  ok    {name}")
            else:
                failures += 1
                print(f"  FAIL  {name}" + (f": {detail}" if detail else ""))

        # 1. Recording succeeds and verify accepts an untouched copy.
        record(tmp_root, rec)
        check("record then verify on an unchanged tree exits 0", verify(tmp_root, rec, quiet=True) == 0)

        # 2. Each real injection is caught.
        for desc, fname, old, new in INJECTIONS:
            target = tmp_root / fname
            original = target.read_bytes()
            text = original.decode("utf-8")
            if text.count(old) < 1:
                check(f"{desc}: the anchor {old!r} exists in {fname}", False,
                      f"{old!r} appears {text.count(old)} times")
                continue
            target.write_bytes(text.replace(old, new, 1).encode("utf-8"))
            caught = verify(tmp_root, rec, quiet=True) == 1
            target.write_bytes(original)
            check(f"caught: {desc}", caught)

        # 3. A same-length substitution is caught (the length field alone would
        #    not see it, which is why the digest is the primary signal).
        target = tmp_root / "QQQ-Checklist-V1.md"
        original = target.read_bytes()
        text = original.decode("utf-8")
        same_len = text.replace("`qqqai`", "`qqqa1`", 1)
        check("a same-length substitution differs in length", len(same_len) == len(text))
        target.write_bytes(same_len.encode("utf-8"))
        caught = verify(tmp_root, rec, quiet=True) == 1
        target.write_bytes(original)
        check("caught: a same-length substitution by digest", caught)

        # 4. Truncation is caught.
        target = tmp_root / "QQQ-Proposal-V1.md"
        original = target.read_bytes()
        target.write_bytes(original[: len(original) // 2])
        caught = verify(tmp_root, rec, quiet=True) == 1
        target.write_bytes(original)
        check("caught: a truncated document", caught)

        # 5. A missing record is refused rather than treated as clean.
        check("a missing record exits 1", verify(tmp_root, tmp_root / "nope.json", quiet=True) == 1)

        # 6. Anti-vacuity: deleting a document must not read as "at rest".
        target = tmp_root / "QQQ-Checklist-V1.md"
        original = target.read_bytes()
        target.unlink()
        missing_caught = False
        try:
            missing_caught = verify(tmp_root, rec, quiet=True) == 1
        except OSError:
            missing_caught = True
        target.write_bytes(original)
        check("caught: a deleted document", missing_caught)

        # 7. After every restore the copy verifies again.
        check("the copy is at rest after all restores", verify(tmp_root, rec, quiet=True) == 0)

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} of {cases} case(s) failed", file=sys.stderr)
        return 1
    print(f"SELF-TEST PASSED -- {cases} case(s), including every real injection")
    return 0


def main(argv: list[str]) -> int:
    args = set(argv[1:])
    if "--self-test" in args:
        return self_test()
    if "--record" in args:
        return record()
    if "--verify" in args or not args:
        return verify()
    print(f"unknown argument(s): {' '.join(sorted(args))}", file=sys.stderr)
    print("usage: check_corpus_at_rest.py [--record|--verify|--self-test]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
