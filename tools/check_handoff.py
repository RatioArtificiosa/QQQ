#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""The hand-off gate: one command that asserts the properties a hand-off needs.

Every invariant here is one a verification round was actually refuted on, or one that
would void the CI evidence for the bytes being handed over:

  1. the working tree is clean (`git status --porcelain` empty)
  2. HEAD equals `origin/main`
  3. the recorded corpus digests match **both** the working tree and the committed
     blobs -- a document ahead of the commit is a hand-off failure even though
     `git diff` on identical bytes can look empty
  4. no fault-injection marker is left applied anywhere the harness can inject
  5. no stale `.self_test_xrefs.lock` from a killed sweep
  6. the CI run for HEAD is green on every job, with `skipped` allowed only where the
     workflow's own `if:` excludes the event

# Why this exists as one command rather than a list of instructions

Rounds were lost to checks that existed and were not run: a document 10 bytes ahead of
the validated blob, and a leftover from a killed sweep -- `**OQ-099**`
(not-a-checklist-item) in the checklist. Both are caught here, and catching them takes one
command rather than remembering six. `§O-260`.

# Why the rules are pure functions

`porcelain_problems`, `digest_problems`, `marker_problems` and `ci_problems` take
already-gathered inputs and return the problems they find. That is what makes
`--self-test` able to inject a broken tree, a stale digest, an applied marker and a
red run **without touching the repository** -- the alternative would be a self-test
that dirties the very tree this gate exists to certify. `§O-261`.

Usage:
    python tools/check_handoff.py
    python tools/check_handoff.py --self-test
    python tools/check_handoff.py --no-ci     # skip the CI read-back (offline)
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import sys as _sys

_sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_corpus_at_rest import DOCUMENTS, current  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
LOCK = ROOT / ".self_test_xrefs.lock"


# ---------------------------------------------------------------------------
# Pure rules. Each takes gathered input and returns problems; none of them
# touches the filesystem, so the self-test can inject a bad input safely.
# ---------------------------------------------------------------------------


def porcelain_problems(text: str) -> list[str]:
    """Problems from `git status --porcelain`. Any output is a problem."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []
    shown = ", ".join(ln.strip() for ln in lines[:6])
    more = f" (+{len(lines) - 6} more)" if len(lines) > 6 else ""
    return [f"the working tree is dirty: {shown}{more}"]


def digest_problems(
    recorded: dict[str, str],
    worktree: dict[str, str],
    committed: dict[str, str],
) -> list[str]:
    """Problems where recorded, working-tree and committed digests disagree.

    Checked in both directions because the two hand-off failures this gate exists for
    are different: a document *ahead* of its commit (the working tree disagrees with
    the freed blobs, so CI validated different bytes), and a record *behind* both (the
    `--record` step was skipped after an intended edit).
    """
    problems: list[str] = []
    for name in sorted(set(recorded) | set(worktree) | set(committed)):
        rec = recorded.get(name)
        wt = worktree.get(name)
        cm = committed.get(name)
        if rec is None:
            problems.append(f"{name}: no digest is recorded")
            continue
        if wt != rec:
            problems.append(
                f"{name}: the working tree ({str(wt)[:12]}) is not what is recorded "
                f"({rec[:12]}) -- re-record with `--record` if the edit was intended"
            )
        if cm != rec:
            problems.append(
                f"{name}: the committed blob ({str(cm)[:12]}) is not what is recorded "
                f"({rec[:12]}) -- the record must describe the bytes CI validated"
            )
    return problems


def eol_problems(rows: list[tuple[str, str, str]]) -> list[str]:
    """Problems from `git ls-files --eol`, as `(path, working, wanted)` triples.

    # Why this is a hand-off invariant

    This catches a working-tree file whose bytes differ from the committed blob in a way
    `git status` cannot see. `.gitattributes` pins `eol=lf` for tracked text, so git
    normalizes on commit and on comparison: a file rewritten with CRLF on disk is
    reported by `git status --porcelain` as **clean**, while the local bytes are not the
    bytes CI validated. That is round 1's failure in a different disguise -- "a canonical
    document 10 bytes ahead of the CI-validated blob" is the same divergence, a local
    copy that is not what was checked -- and `git status` is exactly the instrument that
    misses it.

    It also has a live cause on this project: `Path.write_text` translates `\\n` to
    `os.linesep`, so a fault-injection script that restores a file through it leaves CRLF
    behind on Windows. That is `write_text_lf`'s documented trap, and it caught this
    file's author. The check is cheap, so it runs every hand-off.
    """
    problems = []
    for path, working, wanted in rows:
        if working != wanted:
            problems.append(
                f"{path}: the working tree is {working} but the attribute wants {wanted} "
                f"-- run `python tools/normalize_eol.py`"
            )
    return problems


def marker_problems(found: list[tuple[str, str, str]]) -> list[str]:
    """Problems from applied fault-injection markers: (marker, file, source)."""
    return [
        f"an injection is still applied: {marker!r} in {file} ({source})"
        for marker, file, source in found
    ]


def ci_problems(jobs: list[dict[str, object]], event: str, workflow: str) -> list[str]:
    """Problems from a CI run's jobs.

    Every job must be `success`, or `skipped` for a reason the workflow states itself.
    A job that never ran, was cancelled, or was skipped for no visible reason is a
    problem: "green on all jobs" is not a claim anyone may assume.
    """
    if not jobs:
        return ["the run reports no jobs, so no job can be confirmed green"]

    problems: list[str] = []
    succeeded = 0
    for job in jobs:
        name = str(job.get("name", "?"))
        conclusion = job.get("conclusion") or job.get("status") or "unknown"
        if conclusion == "success":
            succeeded += 1
            continue
        if conclusion == "skipped" and _skip_is_justified(name, event, workflow):
            continue
        problems.append(f"job {name!r} is {conclusion}")

    if not succeeded:
        problems.append("no job succeeded, so the run proves nothing")
    return problems


def _workflow_job_blocks(text: str) -> dict[str, str]:
    """Map every job id in a GitHub Actions workflow to its block of lines."""
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        top = re.match(r"^  ([A-Za-z_][A-Za-z0-9_.-]*):\s*$", line)
        if top:
            current = top.group(1)
            blocks[current] = []
            continue
        if current is None:
            continue
        if line and not line.startswith("  "):
            current = None
            continue
        blocks[current].append(line)
    return {k: "\n".join(v) for k, v in blocks.items()}


def _skip_is_justified(job_name: str, event: str, workflow: str) -> bool:
    """Whether the workflow's own `if:` explains a skip on this event.

    The justification is a guard naming an event **other** than the one that ran: the
    job was not meant to run, so its absence is the workflow working, not a job that
    failed to start. `dco: if: github.event_name == 'pull_request'` justifies a skip on
    a `push` run and nothing else.
    """
    for job_id, block in _workflow_job_blocks(workflow).items():
        declared = re.search(r"^\s+name:\s*(.+?)\s*$", block, re.M)
        display = declared.group(1).strip() if declared else job_id
        stem = display.split("(")[0].strip()
        if not (
            job_name == display
            or (stem and job_name.startswith(stem))
            or job_id.lower() == job_name.lower()
        ):
            continue
        guard = re.search(r"^\s+if:\s*(.+?)\s*$", block, re.M)
        if not guard:
            return False
        names = re.findall(r"github\.event_name\s*==\s*'([^']+)'", guard.group(1))
        return bool(names) and event not in names
    return False


# ---------------------------------------------------------------------------
# Drivers: gather the real inputs and apply the rules above.
# ---------------------------------------------------------------------------


def _git(*args: str) -> tuple[int, str]:
    p = subprocess.run(
        ["git", *args], cwd=str(ROOT), capture_output=True, text=True, check=False
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _committed_digests() -> dict[str, str]:
    """sha256 of each document as committed at HEAD."""
    out: dict[str, str] = {}
    for name in DOCUMENTS:
        code, text = _git("show", f"HEAD:{name}")
        out[name] = hashlib.sha256(text.encode("utf-8")).hexdigest() if code == 0 else ""
    return out


EOL_RE = re.compile(
    r"^i/(\S+)\s+w/(\S+)\s+attr/(\S+)(?:\s+eol=(\S+))?\s+(.+)$"
)


def _eol_rows() -> list[tuple[str, str, str]]:
    """`(path, working eol, wanted eol)` for every tracked file, from git.

    `want` falls back to `lf` when the attributes name no `eol=`: `eol=lf` and
    `text=auto` both mean the committed form is LF in this repository, so a working-tree
    file that is not LF is a divergence either way.
    """
    out = subprocess.run(
        ["git", "ls-files", "--eol"], cwd=str(ROOT),
        capture_output=True, text=True, check=False,
    )
    rows: list[tuple[str, str, str]] = []
    for line in out.stdout.splitlines():
        m = EOL_RE.match(line)
        if not m:
            continue
        _indexed, working, _attrs, want, path = m.groups()
        rows.append((path, working, (want or "lf").lower()))
    return rows


def _recorded_digests() -> dict[str, str]:
    path = ROOT / "tools" / "corpus_at_rest.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    docs = doc.get("documents", doc)
    out: dict[str, str] = {}
    for name in DOCUMENTS:
        entry = docs.get(name)
        if isinstance(entry, dict):
            out[name] = str(entry.get("sha256", ""))
        elif isinstance(entry, str):
            out[name] = entry
    return out


def _applied_markers() -> list[tuple[str, str, str]]:
    """Every injection marker currently present, using the harness's own rule.

    The rule is imported rather than restated. A second copy of "where is this marker
    applied" is exactly how the original drifted: the harness declared the open-question
    marker `**OQ-099**` (not-a-checklist-item) line-anchored while the mutation lands
    mid-line, so its own guard could not see the leftover it existed for (`§O-261`). One
    definition, one place to be right.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "self_test_xrefs", ROOT / "tools" / "self_test_xrefs.py"
    )
    assert spec and spec.loader
    st = importlib.util.module_from_spec(spec)
    _sys.modules["self_test_xrefs"] = st
    spec.loader.exec_module(st)

    found: list[tuple[str, str, str]] = []
    for marker, path, source, line_start in st.INJECTION_MARKERS:
        if path.exists() and st.marker_is_present(path, marker, line_start):
            found.append((marker, path.name, source))
    return found


def _ci_jobs() -> tuple[list[dict[str, object]], str, str]:
    """The jobs of the most recent CI run for HEAD, its event, and a note.

    Returns `([], event, note)` when the run cannot be read, and the caller treats a
    non-empty note with no jobs as a problem. That direction matters: an unreadable run
    is reported as unverifiable rather than as green (`§O-258`'s principle, applied to
    the CI oracle).
    """
    listed = subprocess.run(
        ["gh", "run", "list", "--limit", "20", "--json",
         "databaseId,headSha,status,conclusion,event"],
        cwd=str(ROOT), capture_output=True, text=True, check=False,
    )
    if listed.returncode != 0 or not listed.stdout.strip():
        return [], "", "`gh run list` produced nothing (offline, or not authenticated)"
    try:
        runs = json.loads(listed.stdout)
    except json.JSONDecodeError:
        return [], "", "`gh run list` did not return JSON"

    _, head = _git("rev-parse", "HEAD")
    head = head.strip()
    if not head:
        return [], "", "HEAD could not be resolved"

    for run in runs:
        sha = str(run.get("headSha", ""))
        if not (sha.startswith(head[:12]) or head.startswith(sha[:12])):
            continue
        event = str(run.get("event", ""))
        if run.get("status") != "completed":
            return [], event, f"run {run['databaseId']} is {run.get('status')}"
        jobs = subprocess.run(
            ["gh", "api",
             f"repos/RatioArtificiosa/QQQ/actions/runs/{run['databaseId']}/jobs?per_page=100"],
            cwd=str(ROOT), capture_output=True, text=True, check=False,
        )
        if jobs.returncode != 0:
            return [], event, f"the jobs of run {run['databaseId']} could not be read"
        try:
            return json.loads(jobs.stdout).get("jobs", []), event, ""
        except json.JSONDecodeError:
            return [], event, "the jobs list did not return JSON"
    return [], "", f"no CI run for HEAD {head[:12]} was found"


def run_checks(include_ci: bool = True, quiet: bool = False) -> int:
    def say(msg: str) -> None:
        if not quiet:
            print(msg)

    problems: list[str] = []

    # 1. Clean tree.
    _, porcelain = _git("status", "--porcelain")
    found = porcelain_problems(porcelain)
    problems += found
    say(f"  {'ok  ' if not found else 'FAIL'}  the working tree is clean")

    # 2. HEAD == origin/main.
    _, head = _git("rev-parse", "HEAD")
    _, remote = _git("rev-parse", "origin/main")
    head, remote = head.strip(), remote.strip()
    synced = head == remote and bool(head)
    if not synced:
        problems.append(f"HEAD {head[:12]} is not origin/main {remote[:12] or '(absent)'}")
    say(f"  {'ok  ' if synced else 'FAIL'}  HEAD equals origin/main")

    # 3. Digests: recorded == worktree == committed.
    #
    # `current()` returns `{bytes, sha256}` per document, so it is reduced to the digest
    # before comparison. Comparing the record's digest against that *mapping* was a real
    # bug in the first version of this function: the rule reported every document as
    # drifted, because a dict is never equal to a hex string, and the message printed
    # `{'bytes': 40` where the digest belonged.
    worktree = {name: str(entry.get("sha256", "")) for name, entry in current(ROOT).items()}
    digests = digest_problems(_recorded_digests(), worktree, _committed_digests())
    problems += digests
    say(f"  {'ok  ' if not digests else 'FAIL'}  recorded digests match the tree and HEAD")

    # 4. Working-tree EOL agrees with the attributes, so the bytes on disk are the bytes
    #    git would commit -- which `git status` cannot tell you, because it normalizes.
    eol = eol_problems(_eol_rows())
    problems += eol
    say(f"  {'ok  ' if not eol else 'FAIL'}  every tracked file's EOL matches its attribute")

    # 5. No applied injection.
    markers = _applied_markers()
    mprob = marker_problems(markers)
    problems += mprob
    say(f"  {'ok  ' if not mprob else 'FAIL'}  no fault injection is left applied")

    # 6. No stale lock.
    stale = LOCK.exists()
    if stale:
        problems.append(f"a stale lock is present: {LOCK.name} (a sweep was killed)")
    say(f"  {'ok  ' if not stale else 'FAIL'}  no stale sweep lock")

    # 7. CI green for HEAD.
    if include_ci:
        jobs, event, note = _ci_jobs()
        if note and not jobs:
            problems.append(f"the CI run could not be read: {note}")
            say(f"  FAIL  the CI run for HEAD could not be read ({note})")
        else:
            workflow = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.exists() else ""
            cprob = ci_problems(jobs, event, workflow)
            problems += cprob
            green = len([j for j in jobs if j.get("conclusion") == "success"])
            say(f"  {'ok  ' if not cprob else 'FAIL'}  CI for HEAD is green "
                f"({green}/{len(jobs)} jobs, event {event or '?'})")
    else:
        say("  --    the CI read-back was skipped (--no-ci)")

    print()
    if problems:
        print(f"HAND-OFF BLOCKED -- {len(problems)} problem(s):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"HAND-OFF OK -- HEAD {head[:12]} is clean, at rest, and green")
    return 0


# ---------------------------------------------------------------------------
# Self-test: inject a broken input into each rule.
# ---------------------------------------------------------------------------


def self_test() -> int:
    """Prove each rule fires on a broken input and stays quiet on a good one."""
    cases = 0
    failures = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal cases, failures
        cases += 1
        if ok:
            print(f"  ok    {name}")
        else:
            failures += 1
            print(f"  FAIL  {name}" + (f": {detail}" if detail else ""))

    # 1. porcelain.
    check("a clean tree passes", porcelain_problems("") == [])
    check("a modified file is caught", porcelain_problems(" M QQQ-Checklist-V1.md") != [])
    check("an untracked file is caught", porcelain_problems("?? scratch.txt") != [])

    # 2. digests.
    good = {"A.md": "aaaa"}
    check("agreeing digests pass",
          digest_problems(good, {"A.md": "aaaa"}, {"A.md": "aaaa"}) == [])
    check("a document ahead of its commit is caught",
          digest_problems(good, {"A.md": "aaaa"}, {"A.md": "bbbb"}) != [])
    check("a record behind the tree is caught",
          digest_problems(good, {"A.md": "bbbb"}, {"A.md": "aaaa"}) != [])
    check("a missing record is caught", digest_problems({}, {"A.md": "aaaa"}, {}) != [])

    # The driver must reduce `current()`'s `{bytes, sha256}` mapping to digests before
    # handing it to the rule. Feeding the raw mapping in made the first version report
    # every document as drifted, because a dict is never equal to a hex string -- a bug
    # that announced itself as `{'bytes': 40` where a digest belonged.
    #
    # The shape is *synthetic*, not taken from the live tree. An earlier version of this
    # case called `current(ROOT)` and `_recorded_digests()`, which made `--self-test`
    # fail whenever the corpus was legitimately mid-edit -- conflating "the rule works"
    # with "the tree is at rest". The second claim belongs to `run_checks`, which has its
    # own digest rule; a self-test must be runnable on a dirty tree.
    raw = {"A.md": {"bytes": 40, "sha256": "aaaa"}}
    reduced = {name: str(entry.get("sha256", "")) for name, entry in raw.items()}
    check("the driver's digest reduction turns {bytes, sha256} into the digest",
          reduced == {"A.md": "aaaa"}
          and digest_problems({"A.md": "aaaa"}, reduced, reduced) == [])
    check("the RAW current() mapping is refused rather than silently passed",
          digest_problems({"A.md": "aaaa"}, raw, raw) != [])

    # 3. EOL: a working-tree file must be the EOL its attribute names. `git status`
    #    cannot see this, because it normalizes before comparing.
    check("a matching LF file passes", eol_problems([("a.rs", "lf", "lf")]) == [])
    check("a matching CRLF file passes (the .ps1 case)",
          eol_problems([("b.ps1", "crlf", "crlf")]) == [])
    check("an LF file rewritten as CRLF is caught",
          eol_problems([("a.rs", "crlf", "lf")]) != [])
    check("a CRLF file rewritten as LF is caught",
          eol_problems([("b.ps1", "lf", "crlf")]) != [])
    check("a mixed file is caught", eol_problems([("a.rs", "mixed", "lf")]) != [])

    # 4. markers.
    check("no markers passes", marker_problems([]) == [])
    # The token is deliberately not an `AREA-NNN` shape. `marker_problems` is a rule about
    # strings, so a synthetic marker exercises it fully, and keeping a real injected ID
    # out of this file means it needs no `not-a-checklist-item` exemption -- the source
    # trees are scanned for citations, and a test that fabricates one is a test that
    # trips its own gate.
    check("an applied marker is caught",
          marker_problems([("**INJECTED-MARKER**", "QQQ-Checklist-V1.md", "check [9]")]) != [])

    # 4. CI. The workflow text below is the shape of the real guard, so the
    #    justification rule is exercised rather than described.
    wf = "jobs:\n  dco:\n    name: DCO\n    if: github.event_name == 'pull_request'\n    runs-on: ubuntu-latest\n  rust:\n    name: Rust\n    runs-on: ubuntu-latest\n"
    ok_jobs = [{"name": "DCO", "conclusion": "skipped"},
               {"name": "Rust", "conclusion": "success"}]
    check("a justified skip passes", ci_problems(ok_jobs, "push", wf) == [])
    check("the same skip is UNjustified on its own event",
          ci_problems(ok_jobs, "pull_request", wf) != [])
    check("a failure is caught",
          ci_problems([{"name": "Rust", "conclusion": "failure"}], "push", wf) != [])
    check("a cancelled job is caught",
          ci_problems([{"name": "Rust", "conclusion": "cancelled"}], "push", wf) != [])
    check("an unexplained skip is caught",
          ci_problems([{"name": "Mystery", "conclusion": "skipped"},
                       {"name": "Rust", "conclusion": "success"}], "push", wf) != [])
    check("a run with no jobs is caught", ci_problems([], "push", wf) != [])
    check("an all-red run is caught",
          ci_problems([{"name": "Rust", "conclusion": "failure"}], "push", wf) != [])

    # 5. The workflow parser itself, on the real file, must find the DCO guard.
    real = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.exists() else ""
    check("the real workflow justifies the real DCO skip",
          _skip_is_justified("DCO", "push", real),
          "§O-255 says DCO is pull_request-only; if this fails the rule is not reading it")
    dco_block = _workflow_job_blocks(real).get("dco", "")
    check("the real dco block was parsed", "pull_request" in dco_block)

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} of {cases} case(s) failed", file=sys.stderr)
        return 1
    print(f"SELF-TEST PASSED -- {cases} case(s), every rule is live")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    return run_checks(include_ci="--no-ci" not in argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
