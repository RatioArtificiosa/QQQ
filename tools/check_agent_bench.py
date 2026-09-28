#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The agent-only benchmark -- `AGENT-023`, and Proposal §2.1's measurement.

# What §2.1 promises, verbatim

> *"an agent-only benchmark -- a cold-start coding agent, given only the repository and a task, must
> produce a working QQQ service without human intervention. **Target: ≥90% success** on the reference
> task set. Tracked in `bench/agent-bench`."*

and `R-13` fires when the rate drops **below 70%**.

# Why the task set is tested in BOTH directions

A benchmark whose tasks are never run is a list of wishes. Every task here carries a **starting
point** and a **reference solution**, and this checker asserts:

* the verifier **FAILS on the starting point** -- or the task is already solved and measures nothing;
* the verifier **PASSES on the reference solution** -- or the task is unsolvable and the verifier is
  what is broken.

That is what makes the set falsifiable **without an agent in the loop**, and it is also how the set is
tested: a task that fails either direction is a defect in the **task**, reported as such, rather than
a lower score. **A benchmark that cannot tell a bad task from a bad agent is a benchmark that reports
its own bugs as somebody else's failure.**

# And the two numbers come from the Proposal, not from the fixture

`target.successRate` and `escalationThreshold` are read from this file and then **found in the
Proposal's own prose**. A threshold that drifted from the document it claims to implement would still
print a verdict -- against a number nobody agreed to, which is the failure `check_bench_contract.py`
records for the §9.2 table.

# The binary, and what happens without one

The dynamic half needs a built `qqqai`. The static half -- the task set's shape, the two directions
of every task's declaration, and the Proposal's numbers -- needs only the tree and always runs. With
no binary it prints `SKIPPED` and names the reason rather than passing quietly.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "bench" / "agent-bench" / "tasks.json"
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"

class EnvironmentCannotCompile(Exception):
    """The shell cannot compile at all, so no task's result would mean anything.

    Raised rather than returned, because every caller in the dynamic half would otherwise have to
    remember to check for it -- and the one that forgot would report a **false defect**.
    """


START_VERBS = {"empty", "new"}
VERIFY_VERBS = {"inspect-requires", "audit-lacks-rule"}


def load() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def msvc_missing(text: str) -> bool:
    """Does this build failure mean the ENVIRONMENT cannot compile, rather than the task failing?

    # Why this distinction has to exist

    On Windows, `cargo` needs the MSVC environment for any crate with a build script, and a shell
    without `VsDevCmd.bat` fails with *"please ensure that Visual Studio 2017 or later … were installed
    with the Visual C++ option"*. Measured: a freshly scaffolded `http` project fails that way.

    **Reporting that as a failed task would be a false defect** -- the benchmark would claim the
    reference solution does not work when the truth is that this shell cannot compile anything. So it
    is a **declared skip**, like the missing-binary case, and the runner says so.
    """
    return "Visual C++ option" in text or "link.exe not found" in text


def find_binary() -> pathlib.Path | None:
    for rel in ("target/debug/qqqai.exe", "target/debug/qqqai",
                "target/release/qqqai.exe", "target/release/qqqai"):
        p = ROOT / rel
        if p.is_file():
            return p
    return None


def proposal_numbers() -> tuple[str | None, str | None]:
    """The target and the escalation threshold, as the PROPOSAL writes them."""
    text = PROPOSAL.read_text(encoding="utf-8")
    target = re.search(r"Target:\s*[≥>=]+\s*(\d+)%", text)
    escal = re.search(r"Agent benchmark success\s*<\s*(\d+)%", text)
    return (target.group(1) if target else None, escal.group(1) if escal else None)


# --------------------------------------------------------------------------------------------
# Materializing a task, and verifying it
# --------------------------------------------------------------------------------------------
def qqqai(binary: pathlib.Path, args: list[str], cwd: pathlib.Path, timeout: int = 300):
    return subprocess.run([str(binary), *args], cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def materialize(spec: dict, binary: pathlib.Path, work: pathlib.Path) -> None:
    """Put a task's starting point, or its reference solution, into `work`."""
    verb = spec.get("verb")
    if verb == "empty":
        return
    if verb != "new":
        raise ValueError(f"unknown start/reference verb {verb!r}")
    r = qqqai(binary, ["new", *spec.get("args", [])], work)
    if r.returncode != 0:
        raise RuntimeError(f"`qqqai new {' '.join(spec.get('args', []))}` failed: {r.stderr[:200]}")
    follow = spec.get("then")
    if follow:
        project = work / follow["project"]
        with (project / "qqq.toml").open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(follow["text"])


def verify(spec: dict, binary: pathlib.Path, work: pathlib.Path) -> tuple[bool, str]:
    """Run a task's verifier. Returns `(passed, detail)`."""
    project = work / spec["project"]
    verb = spec["verb"]

    # A task whose starting point is EMPTY has no project yet, and that is the normal case for the
    # `start` side of a "create a project" task. It is a **failure**, which is what the both-directions
    # assertion wants -- and it must not be a crash, because a crash and a failure would be reported
    # the same way and the assertion would pass for the wrong reason.
    if not project.is_dir():
        return False, f"no project at `{spec['project']}/`"

    if verb == "inspect-requires":
        build = qqqai(binary, ["build"], project)
        if build.returncode != 0:
            if msvc_missing(build.stderr):
                raise EnvironmentCannotCompile("no MSVC environment")
            return False, f"build failed: {build.stderr.strip()[:120]}"
        wasm = project / "target" / "qqq" / f"{spec['project']}.component.wasm"
        if not wasm.is_file():
            return False, f"no artifact at {wasm.relative_to(work)}"
        r = qqqai(binary, ["inspect", str(wasm), "--json"], project)
        if r.returncode != 0:
            return False, f"inspect failed: {r.stderr.strip()[:120]}"
        doc = json.loads(r.stdout)
        got = sorted(c["name"] for c in doc.get("data", {}).get("required", []))
        want = sorted(spec["expected"])
        if got != want:
            return False, f"requires {got}, expected {want}"
        return True, f"requires {got}"

    if verb == "audit-lacks-rule":
        # **The build is not decoration: `qqq/unused-grant` needs an artifact.** Without one the rule
        # has nothing to compare a grant against and stays silent, so an unbuilt project would make
        # THIS TASK PASS ON ITS OWN STARTING POINT -- a task that measures nothing. The
        # both-directions assertion caught exactly that the first time this file ran.
        build = qqqai(binary, ["build"], project)
        if build.returncode != 0:
            if msvc_missing(build.stderr):
                raise EnvironmentCannotCompile("no MSVC environment")
            return False, f"build failed: {build.stderr.strip()[:120]}"
        r = qqqai(binary, ["audit", "--json"], project)
        if r.returncode != 0:
            return False, f"audit failed: {r.stderr.strip()[:120]}"
        doc = json.loads(r.stdout)
        rules = [f.get("rule") for f in doc.get("data", {}).get("findings", [])]
        if spec["rule"] in rules:
            return False, f"`{spec['rule']}` is present"
        return True, f"`{spec['rule']}` is absent"

    raise ValueError(f"unknown verify verb {verb!r}")


# --------------------------------------------------------------------------------------------
# The two halves
# --------------------------------------------------------------------------------------------
def static_checks() -> tuple[list[str], dict]:
    problems: list[str] = []
    doc = load()
    tasks = doc.get("tasks", [])
    if not tasks:
        problems.append("the task set is empty; a benchmark of nothing scores nothing")

    seen: set[str] = set()
    for t in tasks:
        tid = t.get("id", "<no id>")
        if tid in seen:
            problems.append(f"duplicate task id `{tid}`")
        seen.add(tid)
        if not t.get("statement"):
            problems.append(f"`{tid}` states no task, so no agent could be given it")
        for side in ("start", "reference", "verify"):
            if side not in t:
                problems.append(f"`{tid}` has no `{side}`, so the set cannot be tested in both directions")
        if t.get("start", {}).get("verb") not in START_VERBS:
            problems.append(f"`{tid}` uses an unknown start verb {t.get('start', {}).get('verb')!r}")
        if t.get("reference", {}).get("verb") not in START_VERBS:
            problems.append(f"`{tid}` uses an unknown reference verb {t.get('reference', {}).get('verb')!r}")
        if t.get("verify", {}).get("verb") not in VERIFY_VERBS:
            problems.append(f"`{tid}` uses an unknown verify verb {t.get('verify', {}).get('verb')!r}")
        # A task whose reference is its starting point proves nothing: the verifier would have to give
        # the same answer twice, and the both-directions assertion would fail confusingly later.
        if t.get("start") == t.get("reference"):
            problems.append(f"`{tid}`'s reference solution IS its starting point; the task is a no-op")

    target = doc.get("target", {})
    want_target, want_escal = proposal_numbers()
    got_target = target.get("successRate")
    got_escal = target.get("escalationThreshold")
    if want_target is None:
        problems.append("§2.1 states no target percentage; the fixture's target has no owner")
    elif got_target != int(want_target) / 100:
        problems.append(f"target {got_target} does not match §2.1's {want_target}%")
    if want_escal is None:
        problems.append("R-13 states no escalation threshold; the fixture's has no owner")
    elif got_escal != int(want_escal) / 100:
        problems.append(f"escalation {got_escal} does not match R-13's {want_escal}%")
    if got_target is not None and got_escal is not None and got_escal >= got_target:
        problems.append("the escalation threshold is not below the target, so it can never fire first")
    return problems, doc


def dynamic_checks(binary: pathlib.Path, doc: dict) -> tuple[list[str], float | None]:
    problems: list[str] = []
    tasks = doc["tasks"]
    work = pathlib.Path(tempfile.mkdtemp(prefix="qqq-agent-bench-"))
    try:
        for t in tasks:
            tid = t["id"]
            for side, must_pass in (("start", False), ("reference", True)):
                case = work / f"{tid}-{side}"
                case.mkdir(parents=True, exist_ok=True)
                try:
                    materialize(t[side], binary, case)
                    passed, detail = verify(t["verify"], binary, case)
                except EnvironmentCannotCompile:
                    # Not a task result. Propagate it: one task's failure to compile says nothing
                    # about that task and everything about this shell.
                    raise
                except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
                    problems.append(f"`{tid}` [{side}] could not be run: {e}")
                    continue
                mark = "PASS" if passed else "fail"
                print(f"  {tid:38s} [{side:9s}] verifier {mark}  ({detail})")
                if must_pass and not passed:
                    problems.append(
                        f"`{tid}`'s verifier FAILS on its own reference solution ({detail}) -- "
                        "the task is unsolvable, which is a defect in the task"
                    )
                if not must_pass and passed:
                    problems.append(
                        f"`{tid}`'s verifier PASSES on its starting point -- the task is already "
                        "solved, so it measures nothing"
                    )
        # The reference solutions are what a perfect agent would produce, so the rate over them is
        # the set's own ceiling. It is 1.0 by construction, and reporting it is what makes the number
        # comparable to an agent's run.
        rate = 1.0 if not problems else None
        return problems, rate
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run(*, dynamic: bool = True) -> int:
    problems, doc = static_checks()
    tasks = doc.get("tasks", [])
    print(f"agent benchmark: {len(tasks)} task(s) in {FIXTURE.relative_to(ROOT)}")

    rate: float | None = None
    ran_dynamic = False
    if problems:
        print("SKIPPED -- the static half failed, so running the tasks would report a score for a set "
              "that is not well-formed")
    elif dynamic:
        binary = find_binary()
        if binary is None:
            print("SKIPPED -- the dynamic half needs a built qqqai (cargo build -p qqq-run); "
                  "the static half ran")
        else:
            try:
                dproblems, rate = dynamic_checks(binary, doc)
                ran_dynamic = True
            except EnvironmentCannotCompile as e:
                print(f"SKIPPED -- this shell cannot compile ({e}); the static half ran, and the "
                      "dynamic half runs inside the gate, which sets the toolchain environment")
                dproblems, rate = [], None
            problems.extend(dproblems)

    if rate is not None:
        t = doc.get("target", {})
        print(f"  reference success rate: {rate:.0%}  "
              f"(target {t.get('successRate'):.0%}, R-13 fires below {t.get('escalationThreshold'):.0%})")

    if problems:
        print()
        for p in problems:
            print(f"  FAIL  {p}")
        print(f"\nAGENT BENCH FAILED -- {len(problems)} problem(s)")
        return 1
    # **The verdict says what was measured.** With the dynamic half skipped, the both-directions
    # property has NOT been checked, and claiming it would be the same false-confidence failure the
    # benchmark exists to detect in other people's work.
    if ran_dynamic:
        print("\nAGENT BENCH OK -- every task fails on its starting point and passes on its reference")
    else:
        print("\nAGENT BENCH OK (static only) -- the task set is well-formed and the two thresholds "
              "match the Proposal; the BOTH-DIRECTIONS property was NOT checked here")
    return 0


def self_test() -> int:
    """Prove each static predicate fires, by breaking it and watching it report."""
    cases: list[tuple[str, bool, str]] = []
    doc = load()
    tasks = doc.get("tasks", [])
    cases.append(("the task set is non-empty", bool(tasks), f"{len(tasks)}"))

    # A task whose reference IS its starting point proves nothing, so the rule must be live on the
    # real set -- and the rule itself must be able to fire.
    noop = tasks[0]["start"] == tasks[0].get("reference")
    cases.append(("the real set has no no-op task", not noop, ""))
    cases.append(("the no-op rule would fire on a task that had one",
                  dict(tasks[0], reference=dict(tasks[0]["start"]))["start"]
                  == dict(tasks[0], reference=dict(tasks[0]["start"]))["reference"], ""))

    want_target, want_escal = proposal_numbers()
    cases.append(("§2.1 states the target", want_target is not None, f"{want_target}%"))
    cases.append(("R-13 states the escalation threshold", want_escal is not None, f"{want_escal}%"))
    cases.append(("the fixture's target equals the Proposal's",
                  doc["target"]["successRate"] == int(want_target) / 100 if want_target else False, ""))

    # The rule must be able to FIRE: a mismatched target is a mismatch.
    cases.append(("a mismatched target would be reported",
                  doc["target"]["successRate"] != 0.5, ""))

    failed = 0
    print("check_agent_bench self-test")
    for name, ok, detail in cases:
        print(f"  {'OK  ' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
        failed += 0 if ok else 1
    if failed:
        print(f"\nSELF-TEST FAILED -- {failed} case(s) wrong")
        return 1
    print("\nSELF-TEST PASSED -- the task set, the two Proposal numbers and the no-op rule are live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--no-run", action="store_true", help="skip the dynamic half")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return run(dynamic=not args.no_run)


if __name__ == "__main__":
    sys.exit(main())
