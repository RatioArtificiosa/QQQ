#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check the cross-language conformance fixture, and print the parity matrix (`TEST-010`).

    python tools/check_conformance.py [--matrix] [--self-test]

`conformance/suite.json` is the checked-in fixture behind Proposal §2.4 (NN-4). It makes three
commitments checkable, and this file checks all three:

  1. **WIT is the source of truth.** Every conformance case names the checker that enforces it, and
     this file requires that checker to exist **and to be registered in BOTH gates**. A case whose
     enforcement is not wired is an obligation nothing keeps -- the shape this repository keeps
     recording, where a control covers what it was pointed at and not what it was supposed to
     guarantee.

  2. **Parity is measured.** `--matrix` prints the language x capability parity matrix.

  3. **Every gap has an owner and a date.** Proposal §6.10: *"Any gap requires a written exception
     with an owner and a date."* A gap with no owner is a gap nobody owns, and a matrix that lists
     such gaps reports a problem and assigns it to no one. This file fails on exactly that.

# The status is DERIVED, not declared-and-trusted

A language's `status` is not taken on faith. `supported` must agree with
`qqq_run::build::toolchain_for` returning `Some` for that language, and `gap` with it returning
`None`. The language that function names is read out of `build.rs` by parsing its own guard, so the
fixture and the code cannot drift.

**And the parse is self-guarding.** If the guard's shape changes -- zero matches, or more than one --
this file fails loudly rather than passing vacuously against a source it no longer understands.
That is `§O-280`'s rule applied to a reader: an instrument that silently reads nothing measures
nothing.

# Why this is not `check_gate_parity.py` again

That file compares the two gates to each other. This one asks a different question: *for each
conformance obligation, is its enforcement present in both?* A checker can be in both gates and
enforce nothing this suite claims, and a case can be claimed with no checker at all. The two files
look at different edges.

Usage:  python tools/check_conformance.py [--matrix] [--self-test]
Exit:   0 = the fixture agrees with the code and every obligation is enforced, 1 = it does not
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# This tool's stdout must encode what it prints. On a Windows console the stream inherits `cp1252`
# and a non-ASCII character read from a source file raises inside `print` (`§O-291`).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "conformance" / "suite.json"
MANIFEST_RS = ROOT / "crates" / "qqq-cap" / "src" / "manifest.rs"
BUILD_RS = ROOT / "crates" / "qqq-run" / "src" / "build.rs"
WIT_DIR = ROOT / "wit"
GATES = {
    "ci.yml": ROOT / ".github" / "workflows" / "ci.yml",
    "entrypoint.sh": ROOT / "docker" / "entrypoint.sh",
}

VALID_STATUS = ("supported", "gap")

# `pub const LANGUAGES: [&'static str; 5] = ["rust", "ts", "go", "python", "cpp"];`
LANGUAGES_RE = re.compile(r"LANGUAGES:\s*\[&'static str;\s*\d+\]\s*=\s*\[([^\]]*)\]")

# The guard that decides which languages have a driver:
#     if language != "rust" {
#         return None;
#     }
# The driver decision is a named constant, not a guard buried in `toolchain_for`.
DRIVEN_RE = re.compile(r"pub const DRIVEN: &\[&str\] = &\[([^\]]*)\]")

# `package qqq:fs@1.0.0;` -> `qqq:fs`
PACKAGE_RE = re.compile(r"^\s*package\s+([A-Za-z0-9_:\-]+)\s*@", re.MULTILINE)


def read_languages() -> list[str]:
    """The five language ids, from the one place that declares them."""
    text = MANIFEST_RS.read_text(encoding="utf-8")
    m = LANGUAGES_RE.search(text)
    if not m:
        raise SystemExit(
            "FATAL: could not find `LANGUAGES: [&'static str; N] = [...]` in "
            f"{MANIFEST_RS.relative_to(ROOT)}. The declaration moved or changed shape; this "
            "checker must be updated rather than allowed to pass against a source it cannot read."
        )
    return re.findall(r'"([^"]+)"', m.group(1))


def read_supported() -> str:
    """The one language `qqqai build` can drive, parsed from `build::DRIVEN`.

    # Why this reads a named constant now

    It used to read `if language != "..."` -- a string comparison inside a branch of `toolchain_for`. **That
    worked and was the wrong thing to read**: `BuildSpec::supports_language` is named as though it decides
    which languages are supported, and it does not (`an_unimplemented_language_is_declared_not_faked` passes
    for `"ts"`). **Reading the constant makes the dependency explicit**: a refactor that moves the decision
    moves the constant, and the checker fails loudly if there is not exactly one.

    **The failure mode this preserves is the one it was written for: passing here must never mean reading
    nothing and reporting agreement.**
    """
    text = BUILD_RS.read_text(encoding="utf-8")
    found = DRIVEN_RE.findall(text)
    if len(found) != 1:
        raise SystemExit(
            f"FATAL: expected exactly one `pub const DRIVEN: &[&str] = &[...]` in "
            f"{BUILD_RS.relative_to(ROOT)}, found {len(found)}. The driver decision is what this checker "
            "reads to decide which languages are supported, so it must be updated. **Passing here would "
            "mean reading nothing and reporting agreement.**"
        )
    ids = re.findall(r'\"([a-z]+)\"', found[0])
    if len(ids) != 1:
        raise SystemExit(
            f"FATAL: `DRIVEN` names {len(ids)} language(s) ({', '.join(ids)}). This checker's whole subject "
            "is `toolchain_for` returning `None` for a language with no driver, so a second driven language "
            "means the claim it guards has changed and this file must be updated with it."
        )
    return ids[0]


def read_wit_packages() -> set[str]:
    """Every `qqq:<name>` package declared under `wit/`."""
    packages: set[str] = set()
    for path in sorted(WIT_DIR.glob("*.wit")):
        m = PACKAGE_RE.search(path.read_text(encoding="utf-8"))
        if m:
            packages.add(m.group(1))
    return packages


def read_gate_invocations() -> dict[str, str]:
    """Each gate's text with COMMENTS STRIPPED.

    # Why comments are stripped rather than searched around

    `docker/entrypoint.sh` carries the declared-divergence list **as a comment block**, and that
    block names script paths. Searching the raw file would count a path mentioned only in the
    declaration as *invoked* -- so an obligation could be "enforced" by a sentence. The guard would
    then be exactly as wide as the file and exactly as narrow as the comment, which is `§O-282`.
    """
    stripped: dict[str, str] = {}
    for name, path in GATES.items():
        text = path.read_text(encoding="utf-8")
        kept = []
        for line in text.splitlines():
            if name == "entrypoint.sh":
                if line.lstrip().startswith("#"):
                    continue
                kept.append(line)
            else:
                # YAML: drop a `#` that starts a comment (preceded by whitespace or at line start).
                kept.append(re.sub(r"(?:(?<=\s)|^)#.*$", "", line))
        stripped[name] = expand_single_gate("\n".join(kept))
    return stripped


# A gate that calls the single gate (`I-08` phase 1) enforces everything that
# gate enforces. Anchored on the command position so a comment merely
# mentioning `cargo xtask ci` does not expand (comments are stripped above,
# so this matches real invocations only).
# A bare `--help` (or any trailing argument) must NOT expand: it names
# the gate without executing it, and crediting coverage to a mention
# is the fixture-that-cannot-fail in gate form. A trailing `#` shell comment
# after a real invocation still expands: the bridge keeps trailing comments
# (only full-line `#` lines are dropped above), so requiring bare
# end-of-line would silently credit a real gate with zero coverage.
# A shell operator after a real invocation (`&&`, `||`, `;`, `|`, `&`, `>`,
# `<`, with or without surrounding spaces) still expands for the same
# reason: it chains the gate, it does not name it. The operator -- not an
# argument -- is what keeps `--help` and `--flag` rejected, and a `#` opens
# a comment only after whitespace (`ci#x` is a word, not a comment).
# This pattern is identical in `tools/check_gate_parity.py` by design: two
# spellings of one rule would drift, and parity must cover the executed
# invocation, not a differently-matched one.
XTASK_CALL = re.compile(
    r"^\s*(?:run:\s*)?cargo\s+xtask\s+ci(?:\s*$|\s+#.*$|\s*(?:&&|\|\||[;|&><]).*$)",
    re.MULTILINE,
)


def xtask_invocations() -> list[str]:
    """The normalized invocations `cargo xtask ci` runs, via `cargo xtask list`.

    Fails loudly: an obligation certified against an unreadable gate is the
    fixture-that-cannot-fail in checker form.
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


def expand_single_gate(text: str, coverage=None) -> str:
    """Append the single gate's coverage when `text` really invokes it.

    `coverage` is injectable so `--self-test` can drive this without cargo;
    the live path passes `None` and reads the real `cargo xtask list`. A
    cargo failure is a `FATAL` `SystemExit` (the file's idiom for an
    unreadable gate, see `load()`), not an uncaught `RuntimeError`: a
    traceback where a verdict belongs is noise the gate cannot act on.
    """
    if XTASK_CALL.search(text):
        if coverage is not None:
            lines = coverage
        else:
            try:
                lines = xtask_invocations()
            except RuntimeError as e:
                raise SystemExit(f"FATAL: {e}") from e
        return text + "\n" + "\n".join(lines)
    return text


def failure_mode_demo(script: str, ci_text: str) -> str | None:
    """The invocation in `ci.yml` that demonstrates this checker's own failure mode, or `None`.

    # Why BOTH forms are accepted

    Measured across the six WIT-surface checkers: **three** are proven by a
    `tools/fault_inject_*.py` harness (`wit_since`, `wit_errors`, `no_ambient`) and **two** carry
    `--self-test` (`wit_bindings`, `wit_style`). Both are the repository's convention, so requiring
    only one would fail three correct checkers -- a guard "only as narrow as its pattern" (`§O-282`)
    in the direction that rejects good input. **The sixth had neither, and that is the defect this
    rule exists to find.**

    # And why the first version of this rule was wrong

    It required `--self-test` for every case, which flagged four checkers that are correctly proven
    another way. **The rule was written from the one example I had read**, not from the convention --
    so it was measured against the whole set before being kept.

    # Why `ci.yml` and not both gates

    `ci.yml` is the gate that runs on every push, and the fault-injection harnesses are partly
    covered by the declared divergence list in `entrypoint.sh` (`tools/fault_inject_*.py (8 cmds)`).
    Requiring the demonstration in `ci.yml` asks the question that matters -- *has this checker's
    failure mode ever been demonstrated in a gate that runs?* -- without re-litigating
    `check_gate_parity.py`'s job.
    """
    if f"{script} --self-test" in ci_text:
        return f"{script} --self-test"

    name = Path(script).name
    for prefix in ("check_", "audit_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    injector = f"tools/fault_inject_{name.removesuffix('.py')}.py"
    if injector in ci_text:
        return injector
    return None


def validate(fixture: dict, *, languages: list[str], supported: str,
             packages: set[str], gates: dict[str, str]) -> list[str]:
    """Every problem with the fixture, as a list of sentences."""
    problems: list[str] = []

    if not isinstance(fixture, dict):
        return ["the fixture is not a JSON object"]
    if fixture.get("version") != 1:
        problems.append(f"`version` must be 1, found {fixture.get('version')!r}")
    if not fixture.get("target"):
        problems.append("`target` is missing; the suite must say which target it conforms to")

    # -- languages ---------------------------------------------------------
    entries = fixture.get("languages")
    if not isinstance(entries, list) or not entries:
        return problems + ["`languages` must be a non-empty list"]

    seen: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(f"a language entry is not an object: {entry!r}")
            continue
        lang = entry.get("id")
        if lang not in languages:
            problems.append(
                f"`{lang}` is not one of the languages the code declares ({', '.join(languages)}). "
                "A language in the fixture that the build cannot name is a language the suite is "
                "not about."
            )
            continue
        if lang in seen:
            problems.append(f"`{lang}` appears twice; a duplicate row makes the matrix lie")
        seen.append(lang)

        status = entry.get("status")
        if status not in VALID_STATUS:
            problems.append(f"`{lang}` has status {status!r}; expected one of {VALID_STATUS}")
            continue

        # 3. THE RULE THAT DECAYS. Every gap is owned and dated.
        if status == "gap":
            for field in ("owner", "target", "reason"):
                if not entry.get(field):
                    problems.append(
                        f"`{lang}` is a gap with no `{field}`. Proposal §6.10 requires a written "
                        "exception with an owner and a date; **an unowned gap is a gap nobody owns**, "
                        "and a matrix that lists one reports a problem and assigns it to no one."
                    )
        else:
            for field in ("owner", "target"):
                if entry.get(field):
                    problems.append(
                        f"`{lang}` is supported but carries a `{field}`; only a gap can be excepted"
                    )

        # THE DERIVATION. Declared status must agree with the code that decides.
        expect = "supported" if lang == supported else "gap"
        if status != expect:
            problems.append(
                f"`{lang}` is declared `{status}` but `build::toolchain_for` says `{expect}` "
                f"(it gives a driver to `{supported}` alone). **The fixture and the code disagree "
                "about what this language can do**, and CI must not pass until one of them moves."
            )

    missing = [lang for lang in languages if lang not in seen]
    if missing:
        problems.append(
            f"the suite does not mention {', '.join(missing)}. A language absent from the parity "
            "matrix is a language whose parity is not measured -- which reads identically to one "
            "with no gaps."
        )

    # -- capabilities ------------------------------------------------------
    caps = fixture.get("capabilities")
    if not isinstance(caps, list) or not caps:
        problems.append("`capabilities` must be a non-empty list")
        caps = []
    for cap in caps:
        if cap not in packages:
            problems.append(
                f"`{cap}` is not a package declared under wit/. A capability the runtime does not "
                "publish cannot be a conformance obligation."
            )
    if len(set(caps)) != len(caps):
        problems.append("`capabilities` contains a duplicate")

    # -- cases -------------------------------------------------------------
    cases = fixture.get("cases")
    if not isinstance(cases, list) or not cases:
        problems.append("`cases` must be a non-empty list")
        cases = []
    case_ids: list[str] = []
    for case in cases:
        if not isinstance(case, dict):
            problems.append(f"a case is not an object: {case!r}")
            continue
        cid = case.get("id")
        if not cid:
            problems.append("a case has no `id`")
            continue
        if cid in case_ids:
            problems.append(f"case `{cid}` appears twice")
        case_ids.append(cid)
        cap = case.get("capability")
        if cap != "core" and cap not in caps:
            problems.append(f"case `{cid}` names capability `{cap}`, which is not in `capabilities`")
        if not case.get("summary"):
            problems.append(f"case `{cid}` has no `summary`")

        # `kind` separates an obligation the FIXTURE defines from one a built guest is RUN against
        # (`TEST-016`). A definition case names the checker that enforces it; an execution case names
        # the runner that executes it. These are different questions -- *is this enforced* versus
        # *does a guest pass this* -- and a case that answers both would be a case that answers
        # neither clearly.
        #
        # **The default is `definition`**, so the six cases that predate the field keep their meaning
        # and a forgotten `kind` cannot silently become an execution case that nothing runs. The
        # default is the safe one for the same reason a missing `enforced_by` is an error below.
        kind = case.get("kind", "definition")
        if kind not in ("definition", "execution"):
            problems.append(
                f"case `{cid}` has `kind` `{kind}`, which is neither `definition` nor `execution`"
            )
        if kind == "execution":
            runner = case.get("runner")
            if not runner:
                problems.append(
                    f"case `{cid}` is an execution case with no `runner`. **An obligation nothing "
                    "executes is enforced by nobody** -- the same defect as a checker no gate "
                    "invokes, one level down."
                )
            elif not (ROOT / runner).exists():
                problems.append(f"case `{cid}` is run by `{runner}`, which does not exist")
            if case.get("enforced_by"):
                problems.append(
                    f"case `{cid}` is an execution case and also names `enforced_by`. A case is one "
                    "or the other: claiming both makes it look enforced twice while it may be run "
                    "once, or not at all."
                )
            continue
        if case.get("runner"):
            problems.append(
                f"case `{cid}` is a definition case and names `runner`. A case is one or the other."
            )

        # 1. THE OBLIGATION IS ENFORCED, IN BOTH GATES.
        script = case.get("enforced_by")
        if not script:
            problems.append(
                f"case `{cid}` names no `enforced_by`. **A conformance obligation with no checker "
                "is a claim, not a control.**"
            )
            continue
        if not (ROOT / script).exists():
            problems.append(f"case `{cid}` is enforced by `{script}`, which does not exist")
            continue
        for gate, text in gates.items():
            if script not in text:
                problems.append(
                    f"case `{cid}` is enforced by `{script}`, which is **not invoked in {gate}**. "
                    "The repository's rule is that a checker goes in BOTH gates; an obligation "
                    "enforced in one is enforced in whichever one happens to run."
                )
        if failure_mode_demo(script, gates["ci.yml"]) is None:
            problems.append(
                f"case `{cid}`'s checker `{script}` has **no demonstrated failure mode** in ci.yml: "
                f"neither `{script} --self-test` nor a `tools/fault_inject_*.py` harness for it is "
                "invoked. A checker nobody has watched fail is a checker nobody has seen work -- and "
                "an obligation whose enforcement cannot fail is not an obligation."
            )

    # -- exceptions --------------------------------------------------------
    exceptions = fixture.get("exceptions")
    if exceptions is None:
        problems.append("`exceptions` is missing; it must be present, even when empty")
        exceptions = []
    if not isinstance(exceptions, list):
        problems.append("`exceptions` must be a list")
        exceptions = []
    for exc in exceptions:
        if not isinstance(exc, dict):
            problems.append(f"an exception is not an object: {exc!r}")
            continue
        if exc.get("language") not in languages:
            problems.append(f"exception names language {exc.get('language')!r}, which is unknown")
        if exc.get("capability") not in caps:
            problems.append(f"exception names capability {exc.get('capability')!r}, which is unknown")
        for field in ("owner", "target", "reason"):
            if not exc.get(field):
                problems.append(
                    f"exception {exc.get('language')!r}/{exc.get('capability')!r} has no `{field}`"
                )

    # -- vacuity -----------------------------------------------------------
    if not any(e.get("status") == "supported" for e in entries if isinstance(e, dict)):
        problems.append(
            "no language is `supported`. A suite in which nothing is implemented has no pass to "
            "measure and would report a clean matrix while proving nothing."
        )
    if not any(e.get("status") == "gap" for e in entries if isinstance(e, dict)):
        problems.append(
            "no language is a `gap`. Either the multi-language claim is complete -- in which case "
            "LANG-009..040 are done and this fixture is stale -- or the statuses are wrong."
        )

    return problems


def render_matrix(fixture: dict) -> str:
    """The parity matrix: language x capability x supported, with every gap owned and dated."""
    caps = fixture.get("capabilities", [])
    exceptions = {
        (e.get("language"), e.get("capability")): e
        for e in fixture.get("exceptions", [])
        if isinstance(e, dict)
    }
    out = ["PARITY MATRIX -- language x capability x supported", ""]
    width = max((len(c) for c in caps), default=8)
    header = "  " + "capability".ljust(width) + "  " + "  ".join(
        f"{e.get('id', '?'):>10}" for e in fixture.get("languages", [])
    )
    out.append(header)
    out.append("  " + "-" * (len(header) - 2))
    for cap in caps:
        cells = []
        for entry in fixture.get("languages", []):
            lang = entry.get("id")
            if (lang, cap) in exceptions:
                cells.append(f"{'exception':>10}")
            elif entry.get("status") == "supported":
                cells.append(f"{'yes':>10}")
            else:
                cells.append(f"{'GAP':>10}")
        out.append("  " + cap.ljust(width) + "  " + "  ".join(cells))
    out.append("")
    for entry in fixture.get("languages", []):
        if entry.get("status") == "gap":
            out.append(
                f"  GAP  {entry.get('id'):<8} owner={entry.get('owner')!r} "
                f"target={entry.get('target')!r}"
            )
    for exc in fixture.get("exceptions", []):
        out.append(
            f"  EXC  {exc.get('language')}/{exc.get('capability')} "
            f"owner={exc.get('owner')!r} target={exc.get('target')!r}"
        )
    out.append("")
    out.append(
        "  Every gap above is owned and dated (Proposal §6.10). An unowned gap fails this checker."
    )
    return "\n".join(out)


def load() -> dict:
    if not FIXTURE.exists():
        raise SystemExit(f"FATAL: {FIXTURE.relative_to(ROOT)} does not exist")
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def self_test(fixture: dict, ctx: dict) -> int:
    """Inject one fault at a time and confirm each is DETECTED.

    A self-test that only shows the happy path proves the parser runs, not that the rules bite.
    Each injection below targets a different rule, and the run fails if any injection is *not*
    caught -- which is what makes this a measurement rather than a demonstration.
    """
    import copy

    def gates_without(script: str, gate: str) -> dict[str, str]:
        """The gate texts with one invocation REMOVED."""
        g = dict(ctx["gates"])
        g[gate] = g[gate].replace(script, "")
        return g

    def gates_without_self_test(script: str) -> dict[str, str]:
        """The gate texts with one checker's `--self-test` REMOVED."""
        g = dict(ctx["gates"])
        g["ci.yml"] = g["ci.yml"].replace(f"{script} --self-test", "")
        return g

    injections: list[tuple[str, dict, dict]] = []

    f = copy.deepcopy(fixture)
    f["languages"][1].pop("owner", None)
    injections.append(("a gap with no owner", f, ctx))

    f = copy.deepcopy(fixture)
    f["languages"][1]["status"] = "supported"
    injections.append(("a status that disagrees with build::toolchain_for", f, ctx))

    f = copy.deepcopy(fixture)
    f["cases"][0]["enforced_by"] = "tools/check_not_a_real_checker.py"
    injections.append(("a case enforced by a script that does not exist", f, ctx))

    # **The invocation is REMOVED from a gate rather than a one-gate-only checker being named.**
    #
    # The first version of this injection pointed `enforced_by` at a checker believed to be in one
    # gate only. It reported **NOT DETECTED**, and the checker was right: that script is in both
    # gates, so there was nothing to detect. **The injection had not injected what it claimed** --
    # `§O-280`'s rule, which this file applies to itself. Naming a real divergent checker also
    # decays: the day someone adds it to the second gate, the injection silently stops injecting.
    # Removing the invocation cannot decay.
    f = copy.deepcopy(fixture)
    injections.append((
        "a case whose checker is invoked in only ONE gate",
        f,
        {**ctx, "gates": gates_without("tools/check_wit.py", "entrypoint.sh")},
    ))

    f = copy.deepcopy(fixture)
    injections.append((
        "a case whose checker has no demonstrated failure mode",
        f,
        {**ctx, "gates": gates_without_self_test("tools/check_wit.py")},
    ))

    f = copy.deepcopy(fixture)
    f["capabilities"] = f["capabilities"] + ["qqq:not_a_package"]
    injections.append(("a capability the runtime does not publish", f, ctx))

    f = copy.deepcopy(fixture)
    for entry in f["languages"]:
        entry["status"] = "gap"
        entry.setdefault("owner", "x")
        entry.setdefault("target", "x")
        entry.setdefault("reason", "x")
    injections.append(("every language a gap (vacuity)", f, ctx))

    f = copy.deepcopy(fixture)
    f["cases"] = []
    injections.append(("no cases at all (vacuity)", f, ctx))

    # `TEST-016`. An execution case is run by a `runner`, not enforced by a checker, so the rule
    # that catches an unenforced definition case does not reach it. This is the case that would
    # otherwise be an obligation the fixture reports and nothing executes.
    f = copy.deepcopy(fixture)
    for case in f["cases"]:
        if case.get("kind") == "execution":
            del case["runner"]
            break
    injections.append(("an execution case with no runner", f, ctx))

    f = copy.deepcopy(fixture)
    for case in f["cases"]:
        if case.get("kind") == "execution":
            case["enforced_by"] = "tools/check_wit.py"
            break
    injections.append(("an execution case claiming a checker as well as a runner", f, ctx))

    f = copy.deepcopy(fixture)
    f["languages"].pop()
    injections.append(("a language missing from the matrix", f, ctx))

    failures = 0
    for label, mutated, mutated_ctx in injections:
        problems = validate(mutated, **mutated_ctx)
        if problems:
            print(f"  OK    detected: {label}")
        else:
            print(f"  FAIL  NOT DETECTED: {label}")
            failures += 1

    # A `--help` mention must not expand: it names the gate without executing
    # it, and crediting coverage to a mention is the fixture-that-cannot-fail
    # in gate form.
    _help_text = "      - name: gate\n        run: cargo xtask ci --help"
    if expand_single_gate(_help_text, ["tools/a.py"]) == _help_text:
        print("  OK    a --help mention does not expand")
    else:
        print("  FAIL  a --help mention expanded to coverage it never ran")
        failures += 1
    _real_text = "      - name: gate\n        run: cargo xtask ci"
    if "tools/a.py" in expand_single_gate(_real_text, ["tools/a.py"]):
        print("  OK    a real invocation expands")
    else:
        print("  FAIL  a real invocation did not expand")
        failures += 1
    # The bridge keeps trailing `#` comments (only full-line comments are
    # dropped), so a real invocation with one must still expand -- otherwise
    # a live gate is silently credited with zero coverage.
    _bridge_comment = "cargo xtask ci  # the single gate"
    if "tools/a.py" not in expand_single_gate(_bridge_comment, ["tools/a.py"]):
        print("  FAIL  a bridge invocation with a trailing comment did not expand")
        failures += 1
    else:
        print("  OK    a bridge invocation with a trailing comment expands")
    # A comment does not rescue a non-invocation: `--help` names the gate
    # without executing it, comment or not.
    _help_comment = "      - name: gate\n        run: cargo xtask ci --help  # usage"
    if expand_single_gate(_help_comment, ["tools/a.py"]) == _help_comment:
        print("  OK    a --help mention with a trailing comment does not expand")
    else:
        print("  FAIL  a --help mention with a trailing comment expanded")
        failures += 1
    # A shell operator chains the gate instead of naming it: `&&`, `||`,
    # `;`, `|` all execute `cargo xtask ci`, so they expand -- while a
    # trailing argument still must not.
    for _label, _text, _want_expand in (
        ("chained with &&", "cargo xtask ci && echo done", True),
        ("chained with ;", "      - name: gate\n        run: cargo xtask ci; echo done", True),
        ("fallback with ||", "cargo xtask ci || echo fallback", True),
        ("piped", "cargo xtask ci | tee log", True),
        ("flagged", "cargo xtask ci --flag", False),
    ):
        _expanded = "tools/a.py" in expand_single_gate(_text, ["tools/a.py"])
        if _expanded == _want_expand:
            print(f"  OK    {_label} {'expands' if _want_expand else 'does not expand'}")
        else:
            print(f"  FAIL  {_label}: expanded={_expanded}, want={_want_expand}")
            failures += 1
    # A cargo failure is a FATAL verdict, not a traceback: the gate is
    # unreadable, and an obligation certified against it would be the
    # fixture-that-cannot-fail. `--self-test` itself never touches cargo
    # (every case above passes `coverage` explicitly); this forces the live
    # path with a failing `cargo` shim.
    import subprocess as _sp
    from unittest import mock as _mock

    def _boom(*a, **k):
        return _sp.CompletedProcess(args=a, returncode=1, stdout="", stderr="boom")

    with _mock.patch.object(_sp, "run", _boom):
        try:
            expand_single_gate("      - name: gate\n        run: cargo xtask ci", None)
            print("  FAIL  a cargo failure expanded instead of raising FATAL")
            failures += 1
        except SystemExit as e:
            if "FATAL" in str(e.code):
                print("  OK    a cargo failure raises FATAL, not a traceback")
            else:
                print(f"  FAIL  cargo failure raised SystemExit without FATAL: {e.code!r}")
                failures += 1

    # And the premise: the unmodified fixture must be clean, or every detection above is noise.
    clean = validate(fixture, **ctx)
    if clean:
        print("  FAIL  the unmodified fixture is not clean, so the detections above prove nothing:")
        for p in clean:
            print(f"          {p}")
        failures += 1
    else:
        print("  OK    the unmodified fixture is clean")

    print()
    if failures:
        print(f"SELF-TEST FAILED -- {failures} injection(s) went undetected")
        return 1
    print(f"SELF-TEST PASSED -- {len(injections)} fault(s) injected, every one detected")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the conformance fixture.")
    parser.add_argument("--matrix", action="store_true", help="print the parity matrix")
    parser.add_argument("--self-test", action="store_true", help="inject faults and confirm detection")
    args = parser.parse_args()

    fixture = load()
    languages = read_languages()
    supported = read_supported()
    packages = read_wit_packages()
    gates = read_gate_invocations()
    ctx = {"languages": languages, "supported": supported, "packages": packages, "gates": gates}

    if args.self_test:
        return self_test(fixture, ctx)

    if args.matrix:
        print(render_matrix(fixture))
        print()

    print("QQQ conformance suite (TEST-010)")
    print("=" * 60)
    print(f"  languages   : {len(languages)} declared by the code, "
          f"{len(fixture.get('languages', []))} in the fixture")
    print(f"  supported   : {supported} (from build::toolchain_for's own guard)")
    print(f"  capabilities: {len(packages)} package(s) under wit/, "
          f"{len(fixture.get('capabilities', []))} in the fixture")
    _cases = fixture.get("cases", [])
    _definition = sum(1 for c in _cases if c.get("kind", "definition") == "definition")
    print(
        f"  cases       : {len(_cases)} ({_definition} definition, each naming its enforcing "
        f"checker; {len(_cases) - _definition} execution, each naming its runner)"
    )
    print(f"  exceptions  : {len(fixture.get('exceptions', []))}")
    print("-" * 60)

    problems = validate(fixture, **ctx)
    if problems:
        print("CONFORMANCE FIXTURE INVALID:")
        for p in problems:
            print(f"  - {p}")
        print()
        print(f"CONFORMANCE FAILED -- {len(problems)} problem(s)")
        return 1

    print("CONFORMANCE FIXTURE OK -- statuses agree with the code, every gap is owned and dated, "
          "and every obligation is enforced in both gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
