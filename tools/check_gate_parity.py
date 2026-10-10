#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check that the two gates run the same checkers, beyond a declared list of divergences.

    python tools/check_gate_parity.py [--self-test] [--list]

`ci.yml` and `docker/entrypoint.sh` are both gates, and the repository's rule is *"when you add a
checker, add it to BOTH"*. That rule is stated about a dozen times across the checklist and the
handbook and **was enforced by nothing** until this file.

# What it was like without this

Measured on 2026-09-25 (`§O-286`): `ci.yml` invoked **84** checker commands and the bridge invoked
**65**, with **20** in one and not the other and **1** in the other and not the one. Two of the
twenty had a documented reason; **eighteen did not**, and the divergence had accumulated without
anyone deciding it. Seven turned out to be pure Python that passed in the image and had simply been
forgotten; the remaining thirteen have a real reason and are now **declared in `entrypoint.sh`**
with a reason each (`§O-288`).

# Why the declaration is parsed rather than duplicated

The list lives in `docker/entrypoint.sh` as a comment block, and this file reads it. Writing the
list a second time here would be a second answer to one question — the defect shape this repository
keeps recording — and the two would drift. **The declaration is the data.**

# What is checked

  1. Every invocation in `ci.yml` runs in `docker/entrypoint.sh`, **or** is declared.
  2. Every invocation in the bridge runs in `ci.yml`, **or** is declared. (One is: the bridge runs
     `check_sbom.py --self-test`, which CI does not need because it runs the `sbom` half.)
  3. **A declared entry that no longer diverges is a failure.** An exclusion for a checker that has
     since been added to both gates is a stale exemption — the same shape as
     `check_checklist_counts.py` validating the declaration against the document rather than only
     the arithmetic. A list that only grows is a list that stops meaning anything.
  4. Vacuity fails: if either gate yields no invocations, the comparison proved nothing.
  5. **Every `tools/check_*.py` is invoked in at least one gate.**

# Why rule 5 exists, and why rules 1-4 could not find this

Rules 1-4 compare the two gates **to each other**. A checker in *neither* gate is invisible to
every one of them: there is no divergence to detect, because both gates agree -- on running
nothing. Measured when this rule was added, **two** checkers were in that state:

| Checker | What it enforces | State |
|---|---|---|
| `tools/check_schema_conformance.py` | the published schema against the Rust source's `#[serde(rename)]` and optionality markers (`CON-001`, `CON-016`) | in neither gate |
| `tools/check_subprocess_encoding.py` | no `subprocess` call decodes with the locale's encoding (`§O-268`) | in neither gate |

Both passed when run by hand. `§O-292` claimed the second was *"registered in both gates"*, which
is the failure this rule exists to make impossible: **a claim about a gate is worth exactly as much
as the gate's ability to contradict it.**

    A GUARD IS ONLY AS WIDE AS ITS FILE LIST AND ONLY AS NARROW AS ITS PATTERN.

This file was narrow in both directions at once, which is the shape `§O-282` records.

# Why the "declared" match is a prefix

The declaration writes `tools/fault_inject_*.py (8 cmds)` and
`tools/check_api_examples.py (2 cmds)` — a glob and a count, not eight and two lines. A parser that
required exact strings would fail on a correct declaration, so a declared token matches an
invocation when the invocation's script path is the token or matches the token as a glob, and the
declared count is then checked against how many it actually covers. **The count is the part that
catches a glob which silently stopped covering something.**
"""

from __future__ import annotations

import argparse
import fnmatch
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


ROOT = Path(__file__).resolve().parent.parent
CI = ROOT / ".github" / "workflows" / "ci.yml"
ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"

# `run: python tools/foo.py --bar` in a workflow, and a bare `python3 tools/foo.py` in the shell
# script. Both are normalised to `tools/foo.py --bar` with runs of whitespace collapsed, because
# the two files spell the interpreter differently (`python` vs `python3`) and that difference is
# not what this check is about.
#
# # Why the CI pattern is not `run:\s*python`
#
# It was, and it could not see a `run: |` block -- the command is on the NEXT line, indented, with
# no `run:` in front of it. Measured: `ci.yml` carries **116** command lines and this pattern saw
# **97**. The three it missed were `tools/check_handoff.py --self-test`,
# `tools/check_corpus_at_rest.py` and `tools/self_test_xrefs.py --prove-isolation`, and the first
# two of those are real ci-only divergences that this checker therefore never reported. **A guard
# is only as narrow as its pattern, and this one was narrower than the file it reads** (`§O-282`).
#
# So the pattern is anchored on the COMMAND, not on the YAML key: optional `run:`, optional
# indentation, then `python`. A comment (`# python tools/x.py`) and a step name
# (`- name: … (tools/check_gate_parity.py)`) still do not match, because neither reaches `python`
# at the start of a line.
CI_INVOCATION = re.compile(r"^\s*(?:run:\s*)?python3?\s+(tools/[\w./-]+[^\n]*)", re.MULTILINE)

# The bridge's shell script spells the interpreter `python3` and carries no `run:` key at all, so
# the optional `run:` group above simply never matches there and **one pattern serves both
# sources**. It is *derived* rather than re-typed deliberately: two identical literals named
# differently invite the next reader to edit one and not the other, and a guard whose two halves
# silently disagree is the exact failure `§O-365` records. A name that must not be assumed to
# differ should not be spelled twice.
BRIDGE_INVOCATION = CI_INVOCATION

# A declared entry: an indented comment naming a tool — **possibly with arguments**, because
# `tools/check_sbom.py sbom` and `tools/check_sbom.py --self-test` are different commands and the
# declaration distinguishes them. The reason follows after two or more spaces, which is what
# separates a declaration from a sentence that merely mentions a tool.
#
# The first version of this pattern was `tools/[\w./*-]+\.py`, which cannot match
# `tools/check_sbom.py sbom` — so two real declarations were invisible to the parser and the
# checker reported them as undeclared. **A parser that cannot express its own input is the defect
# it exists to find** (`§O-291`).
DECLARED = re.compile(
    r"^#\s+(tools/[\w./*-]+\.py(?:\s+(?:--)?[\w./*=-]+)?)(?:\s*\((\d+)\s+cmds?\))?\s{2,}\S",
    re.MULTILINE,
)

# The comment block that carries the declaration, bounded by its own heading. Parsing the whole
# file would pick up any `tools/*.py` mentioned in prose elsewhere -- and this file's subject is
# exactly the difference between a *declaration* and a *mention*.
DECLARATION_HEADING = "# # What this bridge does NOT run"
# The declaration has two halves: commands CI runs and the bridge does not, then a second heading
# for the reverse. **Direction matters and is part of the claim** -- `tools/check_sbom.py sbom` is
# ci-only and `tools/check_sbom.py --self-test` is bridge-only, and a checker that treated them
# alike would accept each in the other's section. That is what the first version did.
REVERSE_HEADING = "And **one divergence in the other direction**"
DECLARATION_END = "# Run clippy with the toolchain version CI actually uses."


def invocations(text: str, pattern: re.Pattern[str]) -> list[str]:
    """Normalised `tools/...` invocations, de-duplicated and sorted."""
    out = {
        re.sub(r"\s+", " ", m.group(1).strip().rstrip("\\").strip())
        for m in pattern.finditer(text)
    }
    return sorted(out)


def checkers() -> list[str]:
    """Every `tools/check_*.py` the tree ships, by file name.

    This is the third input, and the one rules 1-4 never had: the two gates compared **to each
    other** cannot notice a checker that neither of them runs.
    """
    return sorted(p.name for p in (ROOT / "tools").glob("check_*.py"))


def declaration() -> tuple[list[tuple[str, int | None]], list[tuple[str, int | None]]]:
    """`(ci-only, bridge-only)` declarations, each entry `(tool token, declared count or None)`.

    Direction is read from the block's own structure rather than inferred, so a declaration filed
    under the wrong heading is caught instead of quietly satisfied.
    """
    text = ENTRYPOINT.read_text(encoding="utf-8", errors="replace")
    start = text.find(DECLARATION_HEADING)
    if start < 0:
        return [], []
    end = text.find(DECLARATION_END, start)
    block = text[start : end if end > 0 else len(text)]

    split = block.find(REVERSE_HEADING)
    if split < 0:
        ci_only_block, bridge_only_block = block, ""
    else:
        ci_only_block, bridge_only_block = block[:split], block[split:]

    def entries(chunk: str) -> list[tuple[str, int | None]]:
        return [(m.group(1), int(m.group(2)) if m.group(2) else None) for m in DECLARED.finditer(chunk)]

    return entries(ci_only_block), entries(bridge_only_block)


def covers(token: str, invocation: str) -> bool:
    """Whether a declared token covers an invocation.

    Matched on the **script path plus any declared argument**, so `tools/check_sbom.py sbom`
    covers that command and `tools/check_sbom.py --self-test` covers its twin — two invocations
    whose script is identical and whose behaviour is not.

    A token naming only the script (`tools/check_wit.py`, `tools/fault_inject_*.py`) covers every
    invocation of it, which is what a declaration without arguments means.
    """
    if " " in token:
        # A declared argument: the invocation must carry it, not merely start with the script.
        return invocation == token or invocation.startswith(token + " ")
    return fnmatch.fnmatch(invocation.split(" ")[0], token)


def check(
    ci: list[str],
    bridge: list[str],
    ci_only: list[tuple[str, int | None]],
    bridge_only: list[tuple[str, int | None]],
    scripts: list[str] | tuple[str, ...] = (),
) -> list[str]:
    """The decision procedure, as a pure function, so `--self-test` can drive it.

    `ci_only` declares commands CI runs and the bridge does not; `bridge_only` declares the
    reverse. The direction is checked, not just the membership.

    `scripts` is every `tools/check_*.py` in the tree. It defaults to empty so the cases that are
    about the two-gate comparison can be written without naming a tree.
    """
    problems: list[str] = []

    if not ci or not bridge:
        return [
            f"vacuity: ci.yml yielded {len(ci)} invocation(s) and the bridge {len(bridge)}; a "
            f"comparison of nothing certifies nothing"
        ]

    only_ci = [i for i in ci if i not in bridge]
    only_bridge = [i for i in bridge if i not in ci]

    for inv in only_ci:
        if not any(covers(token, inv) for token, _count in ci_only):
            problems.append(
                f"`{inv}` runs in ci.yml and not in docker/entrypoint.sh, and is not declared "
                f"under '{DECLARATION_HEADING}'. Add it to the bridge, or declare it there with a "
                f"reason"
            )
    for inv in only_bridge:
        if not any(covers(token, inv) for token, _count in bridge_only):
            problems.append(
                f"`{inv}` runs in docker/entrypoint.sh and not in ci.yml, and is not declared "
                f"under '{REVERSE_HEADING}'. The bridge is allowed to be the wider gate, but not "
                f"silently"
            )

    # A declaration in the wrong direction is satisfied by nothing and excuses nothing.
    for inv in only_ci:
        if any(covers(t, inv) for t, _ in bridge_only):
            problems.append(
                f"`{inv}` is declared as bridge-only but diverges in the other direction "
                f"(ci.yml runs it, the bridge does not). Direction is part of the claim"
            )
    for inv in only_bridge:
        if any(covers(t, inv) for t, _ in ci_only):
            problems.append(
                f"`{inv}` is declared as ci-only but diverges in the other direction "
                f"(the bridge runs it, ci.yml does not). Direction is part of the claim"
            )

    # Every declared token must still be doing work.
    for label, declared, actual in (
        ("ci-only", ci_only, only_ci),
        ("bridge-only", bridge_only, only_bridge),
    ):
        for token, count in declared:
            hits = [i for i in actual if covers(token, i)]
            if not hits:
                problems.append(
                    f"`{token}` is declared {label} but no longer diverges -- either it is now in "
                    f"both gates (remove the declaration) or it was renamed (fix the declaration). "
                    f"A stale exemption is a defect in its own right"
                )
                continue
            if count is not None and count != len(hits):
                problems.append(
                    f"`{token}` declares {count} command(s) but covers {len(hits)}: {hits}. The "
                    f"count is what catches a glob that silently stopped covering something"
                )

    # Rule 5: a checker that no gate runs certifies nothing. Rules 1-4 compare the gates to each
    # other and are blind to this **by construction** -- two gates that both run nothing agree
    # perfectly, so there is no divergence for them to report.
    invoked = {i.split(" ")[0] for i in [*ci, *bridge]}
    for name in scripts:
        if f"tools/{name}" not in invoked:
            problems.append(
                f"`tools/{name}` is invoked in NEITHER gate. A checker no gate runs is a checker "
                f"that certifies nothing, and rules 1-4 cannot see it because they compare the two "
                f"gates to each other. Add it to `ci.yml` and `docker/entrypoint.sh`"
            )

    return problems


# A gate that calls the single gate (`I-08` phase 1) runs everything that
# gate runs. Anchored on the command position like `CI_INVOCATION`, so a
# comment merely mentioning `cargo xtask ci` does not expand.
# A bare `--help` (or any trailing argument) must NOT expand: it names
# the gate without executing it, and crediting coverage to a mention
# is the fixture-that-cannot-fail in gate form. A trailing `#` shell comment
# after a real invocation still expands: neither gate strips trailing
# comments before this search, so requiring bare end-of-line would silently
# credit a real gate with zero coverage. A shell operator after a real
# invocation (`&&`, `||`, `;`, `|`, `&`, `>`, `<`, with or without
# surrounding spaces) still expands for the same reason: it chains the
# gate, it does not name it. The operator -- not an argument -- is what
# keeps `--help` rejected, and a `#` opens a comment only after whitespace.
# This pattern is identical in `tools/check_conformance.py` by design: two
# spellings of one rule would drift, and parity must cover the executed
# invocation, not a differently-matched one.
XTASK_CALL = re.compile(
    r"^\s*(?:run:\s*)?cargo\s+xtask\s+ci(?:\s*$|\s+#.*$|\s*(?:&&|\|\||[;|&><]).*$)",
    re.MULTILINE,
)


def xtask_coverage() -> list[str]:
    """The python invocations `cargo xtask ci` runs, via `cargo xtask list`.

    Fails loudly rather than certifying nothing: an unreadable gate cannot
    be compared, and a comparison that silently skipped the single gate
    would pass two empty hands as agreement (rule 4's shape).
    """
    import subprocess

    out = subprocess.run(
        ["cargo", "xtask", "list"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if out.returncode != 0:
        raise RuntimeError(f"`cargo xtask list` failed: {out.stderr.strip()}")
    lines = sorted({l.strip() for l in out.stdout.splitlines() if l.strip().startswith("tools/")})
    if not lines:
        raise RuntimeError("`cargo xtask list` yielded no tools/ lines; certifying nothing")
    return lines


def expand_gate(text: str, invs: list[str], coverage: list[str] | None = None) -> list[str]:
    """Pure: `invs` plus the single gate's coverage when `text` calls it.

    `coverage` is injectable so `--self-test` can drive this without cargo;
    the live path passes `None` and reads the real `cargo xtask list`.
    """
    if not XTASK_CALL.search(text):
        return invs
    lines = coverage if coverage is not None else xtask_coverage()
    return sorted(set(invs) | set(lines))


def collect():
    ci_only, bridge_only = declaration()
    ci_text = CI.read_text(encoding="utf-8", errors="replace")
    bridge_text = ENTRYPOINT.read_text(encoding="utf-8", errors="replace")
    ci = expand_gate(ci_text, invocations(ci_text, CI_INVOCATION))
    bridge = expand_gate(bridge_text, invocations(bridge_text, BRIDGE_INVOCATION))
    return (
        ci,
        bridge,
        ci_only,
        bridge_only,
        checkers(),
    )


def validate(verbose: bool) -> int:
    # A gate that cannot be read cannot be compared: `collect()` raises
    # `RuntimeError` when `cargo xtask list` fails, and that becomes a FAIL
    # verdict here rather than a traceback where a verdict belongs.
    try:
        ci, bridge, ci_only, bridge_only, scripts = collect()
    except RuntimeError as e:
        print(f"FAIL  cannot compare gates: {e}")
        return 1
    print(f"ci.yml invocations        : {len(ci)}")
    print(f"bridge invocations        : {len(bridge)}")
    print(f"check_*.py in tools/      : {len(scripts)}")
    print(f"declared ci-only          : {len(ci_only)}")
    for token, count in ci_only:
        print(f"  declared  {token}{f' ({count} cmds)' if count else ''}")
    print(f"declared bridge-only      : {len(bridge_only)}")
    for token, count in bridge_only:
        print(f"  declared  {token}{f' ({count} cmds)' if count else ''}")

    problems = check(ci, bridge, ci_only, bridge_only, scripts)
    print("")
    if problems:
        print(f"GATE PARITY FAILED -- {len(problems)} problem(s):")
        for p in problems:
            print(f"  FAIL  {p}")
        return 1
    print("GATE PARITY OK -- the two gates agree beyond the declared divergences")
    return 0


def self_test() -> int:
    failures = 0

    def case(
        name: str,
        ci: list[str],
        bridge: list[str],
        ci_only,
        bridge_only,
        expect: str | None,
        scripts: list[str] | None = None,
    ) -> None:
        nonlocal failures
        problems = check(ci, bridge, ci_only, bridge_only, scripts or [])
        ok = (not problems) if expect is None else any(expect in p for p in problems)
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            for p in problems[:2]:
                print(f"        got: {p}")

    def simple(name: str, ok: bool, detail: str = "") -> None:
        """A case that is not about `check()` -- the pattern itself, for instance."""
        nonlocal failures
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            if detail:
                print(f"        {detail}")

    A, B = "tools/a.py", "tools/b.py"
    AB = "tools/a.py --self-test"
    case("a checker in both gates passes", [A, B], [A, B], [], [], None)
    case("a checker missing from the bridge is caught", [A, B], [B], [], [], "not declared")
    case("a checker missing from CI is caught", [A], [A, B], [], [], "wider gate")
    case("a declared ci-only divergence is accepted", [A, B], [B], [(A, None)], [], None)
    case("a declared bridge-only divergence is accepted", [B], [A, B], [], [(A, None)], None)
    case(
        "a declaration in the WRONG direction is caught",
        [A, B],
        [B],
        [],
        [(A, None)],
        "other direction",
    )
    case("a stale declaration is caught", [A, B], [A, B], [(A, None)], [], "no longer diverges")
    case(
        "a glob declaration covers its members",
        ["tools/fault_inject_x.py", "tools/fault_inject_y.py", B],
        [B],
        [("tools/fault_inject_*.py", 2)],
        [],
        None,
    )
    case(
        "a glob whose count is wrong is caught",
        ["tools/fault_inject_x.py", "tools/fault_inject_y.py", B],
        [B],
        [("tools/fault_inject_*.py", 3)],
        [],
        "declares 3",
    )
    case(
        "a declared ARGUMENT is distinguished from its twin",
        [A, AB, B],
        [B],
        [(AB, None)],
        [],
        "not declared",
    )
    case("an empty gate fails rather than passing", [], [A], [], [], "vacuity")

    # The pattern itself. A `run: |` block puts the command on the NEXT line, indented, with no
    # `run:` in front of it -- which is what the first version could not read, and it saw 97 of
    # ci.yml's 116 command lines because of it. A comment and a step name must still not count.
    workflow = (
        "      - name: a step (tools/check_named.py)\n"
        "        run: python tools/check_inline.py\n"
        "      - name: a block\n"
        "        run: |\n"
        "          python tools/check_block.py --self-test\n"
        "          # python tools/check_commented.py\n"
    )
    seen = invocations(workflow, CI_INVOCATION)
    simple(
        "the pattern sees a `run: |` block, and not a comment or a step name",
        seen == ["tools/check_block.py --self-test", "tools/check_inline.py"],
        f"got {seen}",
    )

    # Rule 5: the tree is a third input, and rules 1-4 cannot see an orphan by construction.
    case(
        "a checker in NEITHER gate is caught",
        [A, B],
        [A, B],
        [],
        [],
        "NEITHER gate",
        scripts=["a.py", "orphan.py"],
    )
    case(
        "a checker in both gates satisfies the tree rule",
        [A, B],
        [A, B],
        [],
        [],
        None,
        scripts=["a.py", "b.py"],
    )
    case(
        "a checker declared ci-only still satisfies the tree rule",
        [A, B],
        [B],
        [(A, None)],
        [],
        None,
        scripts=["a.py"],
    )
    case(
        "an orphan cannot be excused by declaring it",
        [A],
        [A],
        [(B, None)],
        [],
        "NEITHER gate",
        scripts=["b.py"],
    )

    # The real repository must currently agree.
    simple(
        "a gate calling xtask expands to the union",
        expand_gate("      - name: gate\n        run: cargo xtask ci", ["tools/a.py"], ["tools/b.py --self-test"])
        == ["tools/a.py", "tools/b.py --self-test"],
        "the single gate must contribute its coverage to both sides",
    )
    simple(
        "a gate not calling xtask is unchanged",
        expand_gate("run: python tools/a.py", ["tools/a.py"], ["tools/b.py"]) == ["tools/a.py"],
        "expansion must not invent coverage",
    )
    simple(
        "a comment mentioning xtask does not expand",
        expand_gate("# both gates call cargo xtask ci one day", ["tools/a.py"], ["tools/b.py"])
        == ["tools/a.py"],
        "the pattern is anchored on the command position",
    )
    simple(
        "a --help mention does not expand",
        expand_gate("        run: cargo xtask ci --help", ["tools/a.py"], ["tools/b.py"])
        == ["tools/a.py"],
        "naming the gate is not executing it",
    )
    simple(
        "a ci invocation with a trailing comment expands",
        expand_gate(
            "      - name: gate\n        run: cargo xtask ci  # the single gate",
            ["tools/a.py"],
            ["tools/b.py --self-test"],
        )
        == ["tools/a.py", "tools/b.py --self-test"],
        "a # comment after a real invocation is still an invocation",
    )
    simple(
        "a bridge invocation with a trailing comment expands",
        expand_gate(
            "cargo xtask ci  # the single gate",
            ["tools/a.py"],
            ["tools/b.py --self-test"],
        )
        == ["tools/a.py", "tools/b.py --self-test"],
        "the bridge keeps trailing comments, so the matcher must accept them",
    )
    simple(
        "a --help mention with a trailing comment does not expand",
        expand_gate(
            "        run: cargo xtask ci --help  # usage",
            ["tools/a.py"],
            ["tools/b.py"],
        )
        == ["tools/a.py"],
        "a comment does not turn naming the gate into executing it",
    )
    simple(
        "a ci invocation chained with && expands",
        expand_gate(
            "      - name: gate\n        run: cargo xtask ci && echo done",
            ["tools/a.py"],
            ["tools/b.py --self-test"],
        )
        == ["tools/a.py", "tools/b.py --self-test"],
        "chaining executes the gate; only arguments withhold coverage",
    )
    simple(
        "a bridge invocation with || expands",
        expand_gate(
            "cargo xtask ci || echo fallback",
            ["tools/a.py"],
            ["tools/b.py --self-test"],
        )
        == ["tools/a.py", "tools/b.py --self-test"],
        "a fallback still executes the gate first",
    )
    simple(
        "an invocation with a flag does not expand",
        expand_gate("cargo xtask ci --flag", ["tools/a.py"], ["tools/b.py"])
        == ["tools/a.py"],
        "an argument names a different invocation, operator or not",
    )

    # The live gates must read cleanly: an unreadable gate is a self-test
    # failure, not a traceback escaping the suite.
    try:
        ci, bridge, ci_only, bridge_only, scripts = collect()
    except RuntimeError as e:
        print(f"  DEAD  the live gates are unreadable: {e}")
        failures += 1
        ci = None
    if ci is not None:
        real = check(ci, bridge, ci_only, bridge_only, scripts)
        ok = not real
        print(
            f"  {'OK  ' if ok else 'DEAD'}  the real gates agree "
            f"({len(ci)} vs {len(bridge)} invocations, {len(scripts)} checker(s))"
        )
        if not ok:
            failures += 1
            for p in real[:3]:
                print(f"        {p}")

    # A cargo failure fails the gate without a traceback: the comparison
    # cannot run against an unreadable gate. None of these depend on what
    # the live gates currently contain -- an earlier version called the
    # real `validate()` under the failing shim, which only exercised the
    # failure path while both live gates still invoked the single gate.
    import subprocess as _sp
    from unittest import mock as _mock

    def _boom(*a, **k):
        return _sp.CompletedProcess(args=a, returncode=1, stdout="", stderr="boom")

    # Unit level: an input that invokes the single gate propagates the
    # coverage failure as `RuntimeError`.
    with _mock.patch.object(_sp, "run", _boom):
        try:
            expand_gate("cargo xtask ci", ["tools/a.py"], None)
            print("  FAIL  a coverage failure expanded instead of raising")
            failures += 1
        except RuntimeError:
            print("  OK    a coverage failure raises instead of expanding")
    # Gate level: a `collect()` failure becomes a FAIL verdict, not an
    # escape, with no live files read.
    with _mock.patch.object(sys.modules[__name__], "collect") as _collect:
        _collect.side_effect = RuntimeError("boom")
        try:
            if validate(verbose=False) == 1:
                print("  OK    a collect failure fails the gate without a traceback")
            else:
                print("  FAIL  a collect failure did not fail the gate")
                failures += 1
        except RuntimeError as e:
            print(f"  FAIL  a collect failure escaped as a traceback: {e}")
            failures += 1

    total = 29
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every rule is live")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--self-test", action="store_true", help="prove the checks are live")
    ap.add_argument("--list", action="store_true", help="print the declared divergences")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if args.list:
        ci_only, bridge_only = declaration()
        for token, count in ci_only:
            print(f"ci-only      {token}{f' ({count} cmds)' if count else ''}")
        for token, count in bridge_only:
            print(f"bridge-only  {token}{f' ({count} cmds)' if count else ''}")
        return 0
    return validate(verbose=True)


if __name__ == "__main__":
    raise SystemExit(main())
