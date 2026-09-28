#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify `docs/agent-cookbook.md` — `AGENT-024`.

The catalogue (`docs/errors.md`) is checked for completeness: every code has a cause and a
remediation. **Nothing checked that a code can be produced.** This checker does, and it does it by
re-deriving every classification from the tree rather than trusting the page.

# The four kinds, and what each one is checked against

| Kind | Predicate this checker enforces |
|---|---|
| `cli` | the reproducer is **executed** and the code appears in its output |
| `test` | the code is named in at least one file under `crates/*/tests/` |
| `src` | the code is named in a non-test `.rs` file, and in **no** test file |
| `unreachable` | the code is named **nowhere** in the Rust tree |

`src` and `unreachable` are the two that make the page worth having, and `unreachable` is a
**negative** predicate: it asserts an absence, which is the only way to keep a claim that nothing
emits a code from rotting.

# Why the `cli` reproducers live here and not in the page

Because a reproducer has to be **run**, and a page cannot run itself. The table below is the
executable form; the page is the readable form; and the checker asserts the two sets are **equal**, so
they cannot drift apart in either direction.

# The binary, and what happens without it

The `cli` half needs a built `qqqai`. The **static** half — `test`, `src`, `unreachable` — needs only
the tree, and always runs. When there is no binary the dynamic half prints a loud `SKIPPED` line
naming the reason rather than passing quietly, which is the difference between a declared skip and a
silent one.
"""

from __future__ import annotations

import argparse
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
CATALOGUE = ROOT / "docs" / "errors.md"
COOKBOOK = ROOT / "docs" / "agent-cookbook.md"

CODE = re.compile(r"QQQ-\d{4}")
HEADING = re.compile(r"^#{2,3}\s+`?(QQQ-\d{4})`?")

# The two STRUCTURED shapes a code can appear in, one per section. Parsing prose instead would read a
# code that the text merely *mentions* -- `QQQ-7004` is discussed in the `cli` section precisely
# because it is NOT a `cli` code, and a parser that took every code in the section counted it as one.
# A guard that reads a different language than the document writes measures something else (`§O-361`).
CLI_HEADING = re.compile(r"^###\s+`(QQQ-\d{4})`", re.MULTILINE)
TABLE_ROW = re.compile(r"^\|\s*`(QQQ-\d{4})`", re.MULTILINE)

KINDS = ("cli", "test", "src", "unreachable")

# The section headings that carry each kind's codes, matched case-insensitively on a fragment.
SECTION = {
    "cli": "the `cli` reproducers",
    "test": "the `test` reproducers",
    "src": "the `src`-only codes",
    "unreachable": "the `unreachable` codes",
}

# --------------------------------------------------------------------------------------------
# The executable form of the five `cli` reproducers. `setup` is applied to a freshly scaffolded
# project, then `args` are run, and the assertion is that `code` appears in the output.
# --------------------------------------------------------------------------------------------
CLI_REPRODUCERS: dict[str, tuple[str, list[str]]] = {
    "QQQ-1001": ("break_source", ["build"]),
    "QQQ-2001": ("break_toml", ["build"]),
    "QQQ-2002": ("add_unknown_key", ["build"]),
    "QQQ-6004": ("none", ["migrate"]),
    "QQQ-7001": ("none", ["build", "--nonsense-flag"]),
}


def catalogue_codes() -> list[str]:
    """Every code `docs/errors.md` declares, in file order."""
    out: list[str] = []
    for line in CATALOGUE.read_text(encoding="utf-8").split("\n"):
        m = HEADING.match(line)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


def cookbook_kinds() -> dict[str, str]:
    """`code -> kind` as the page declares it, read from the four sections.

    Only the **structured** shapes count: an `### ` heading for the `cli` section, a table row
    elsewhere. A code that a paragraph merely mentions is not a member of the section it is mentioned
    in -- see `CLI_HEADING`.
    """
    text = COOKBOOK.read_text(encoding="utf-8")
    # Split on the `## ` headings so a code is attributed to the section it appears under.
    parts = re.split(r"^##\s+", text, flags=re.MULTILINE)
    found: dict[str, str] = {}
    for part in parts[1:]:
        title = part.split("\n", 1)[0].strip().lower()
        kind = next((k for k, frag in SECTION.items() if frag in title), None)
        if kind is None:
            continue
        pattern = CLI_HEADING if kind == "cli" else TABLE_ROW
        for code in pattern.findall(part):
            found.setdefault(code, kind)
    return found


def catalogue_names() -> dict[str, str]:
    """`code -> variant name`, from `docs/errors.md`. The tree raises the NAME, not the code."""
    out: dict[str, str] = {}
    for line in CATALOGUE.read_text(encoding="utf-8").split("\n"):
        m = HEADING.match(line)
        if not m:
            continue
        rest = line[m.end():]
        n = re.search(r"`([A-Za-z][A-Za-z0-9]*)`", rest)
        if n:
            out.setdefault(m.group(1), n.group(1))
    return out


# The enum DECLARATION names every variant, so it cannot count as a use. Without this exclusion the
# variant predicate would match all 43 codes and certify nothing -- the same defect in the other
# direction, which is why the exclusion is asserted rather than assumed.
DECLARATION = ROOT / "crates" / "qqq-core" / "src" / "error.rs"


def _without_declaration(text: str) -> str:
    start = text.find("pub enum ErrorCode {")
    if start == -1:
        return text
    end = text.find("\n}", start)
    if end == -1:
        return text
    return text[:start] + text[end:]


def rust_tree() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """`(in_tests, in_src)` -- where each code's VARIANT is used under `crates/`.

    Keyed by the **code**, resolved through the variant name, because that is how the tree writes it.
    A site in the enum declaration does not count.
    """
    names = catalogue_names()
    by_name: dict[str, set[str]] = {}
    for path in (ROOT / "crates").rglob("*.rs"):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        rel = path.relative_to(ROOT).as_posix()
        body = _without_declaration(text) if path == DECLARATION else text
        for name in set(re.findall(r"\b([A-Z][A-Za-z0-9]*)\b", body)):
            by_name.setdefault(name, set()).add(rel)

    in_tests: dict[str, set[str]] = {}
    in_src: dict[str, set[str]] = {}
    for code, name in names.items():
        for rel in by_name.get(name, ()):
            bucket = in_tests if "/tests/" in rel else in_src
            bucket.setdefault(code, set()).add(rel)
    return in_tests, in_src


def find_binary() -> pathlib.Path | None:
    for rel in ("target/debug/qqqai.exe", "target/debug/qqqai", "target/release/qqqai.exe",
                "target/release/qqqai"):
        p = ROOT / rel
        if p.is_file():
            return p
    return None


def run_cli_reproducers(binary: pathlib.Path, problems: list[str]) -> int:
    """Execute every `cli` reproducer; return how many were run."""
    work = pathlib.Path(tempfile.mkdtemp(prefix="qqq-cookbook-"))
    ran = 0
    try:
        scaffold = subprocess.run(
            [str(binary), "new", "p", "--language", "rust", "--template", "http"],
            cwd=work, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=180,
        )
        proj = work / "p"
        if not (proj / "qqq.toml").is_file():
            problems.append(f"could not scaffold a project: {scaffold.stderr.strip()[:200]}")
            return 0
        good_toml = (proj / "qqq.toml").read_text(encoding="utf-8")
        # The scaffold names the source after the project (`src/p.rs`), not `lib.rs`. Finding it by
        # glob rather than by a remembered name is the difference between a reproducer that breaks
        # the crate and one that writes a second file cargo never compiles.
        sources = sorted((proj / "src").glob("*.rs"))
        if not sources:
            problems.append("the scaffolded project has no source file under src/")
            return 0
        source = sources[0]
        good_lib = source.read_text(encoding="utf-8")

        for code, (setup, args) in sorted(CLI_REPRODUCERS.items()):
            (proj / "qqq.toml").write_text(good_toml, encoding="utf-8", newline="\n")
            source.write_text(good_lib, encoding="utf-8", newline="\n")
            if setup == "break_toml":
                (proj / "qqq.toml").write_text("this is not toml [[[\n", encoding="utf-8",
                                               newline="\n")
            elif setup == "add_unknown_key":
                with (proj / "qqq.toml").open("a", encoding="utf-8", newline="\n") as fh:
                    fh.write("unknown_top_level_key = 1\n")
            elif setup == "break_source":
                source.write_text("this is not rust\n", encoding="utf-8", newline="\n")
            try:
                p = subprocess.run([str(binary), *args], cwd=proj, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=120)
            except subprocess.TimeoutExpired:
                problems.append(f"{code}: the reproducer timed out")
                continue
            ran += 1
            out = (p.stdout or "") + (p.stderr or "")
            if code not in out:
                seen = sorted(set(CODE.findall(out))) or ["<no code>"]
                problems.append(
                    f"{code}: its `cli` reproducer did not produce it (saw {', '.join(seen)})"
                )
        return ran
    finally:
        shutil.rmtree(work, ignore_errors=True)


def classify(
    declared: list[str],
    kinds: dict[str, str],
    in_tests: dict[str, set[str]],
    in_src: dict[str, set[str]],
    cli_reproducers: dict[str, str] | None = None,
) -> list[str]:
    """Every static problem `declared`, `kinds` and the Rust tree imply.

    # Why this is a function rather than the body of `check`

    Because a predicate that is only reachable through `check` can only ever be tested against the
    **real tree**, and the real tree is well-formed -- so `self_test` could assert that the data is
    clean and never that the checker would say so about data that is not. **`§O-375`: a rule that
    cannot fire is worse than no rule.** Taking the four inputs as **parameters** is what lets the
    self-test hand in a mutated copy and require a problem back.

    `cli_reproducers` defaults to this module's `CLI_REPRODUCERS`, and a caller may pass a different
    table to ask what the checker would say about a disagreement.
    """
    problems: list[str] = []
    if cli_reproducers is None:
        cli_reproducers = CLI_REPRODUCERS

    # --- completeness, both directions -------------------------------------------------------
    missing = [c for c in declared if c not in kinds]
    extra = [c for c in kinds if c not in declared]
    if missing:
        problems.append(f"declared by the catalogue and absent from the cookbook: {missing}")
    if extra:
        problems.append(f"in the cookbook and not in the catalogue: {extra}")

    # --- the static predicates ---------------------------------------------------------------
    for code, kind in sorted(kinds.items()):
        if kind == "test" and not in_tests.get(code):
            problems.append(f"{code}: declared `test` and named in no file under crates/*/tests/")
        elif kind == "src":
            if not in_src.get(code):
                problems.append(f"{code}: declared `src` and named in no non-test .rs file")
            if in_tests.get(code):
                problems.append(
                    f"{code}: declared `src` (no test reproduces it) and a test names it: "
                    f"{sorted(in_tests[code])[0]}"
                )
        elif kind == "unreachable":
            where = sorted(in_src.get(code, set()) | in_tests.get(code, set()))
            if where:
                problems.append(
                    f"{code}: declared `unreachable` and named in {len(where)} file(s), "
                    f"e.g. {where[0]}"
                )

    # --- the page and the checker cannot disagree about which codes are `cli` -----------------
    cli_codes = sorted(c for c, k in kinds.items() if k == "cli")
    if set(cli_codes) != set(cli_reproducers):
        problems.append(
            "the page's `cli` set and this checker's executable table differ: "
            f"page={cli_codes} table={sorted(cli_reproducers)}"
        )

    return problems


def check(*, run_cli: bool = True) -> int:
    declared = catalogue_codes()
    kinds = cookbook_kinds()
    if not declared:
        print("FAIL -- docs/errors.md declares no codes; a scan of nothing certifies nothing")
        return 1

    in_tests, in_src = rust_tree()
    problems = classify(declared, kinds, in_tests, in_src)

    # --- the executable predicate, which is the one part that needs a process -----------------
    ran = 0
    cli_codes = sorted(c for c, k in kinds.items() if k == "cli")
    if cli_codes:
        binary = find_binary()
        if binary is None or not run_cli:
            print("SKIPPED -- the `cli` half needs a built qqqai "
                  "(cargo build -p qqq-run); the static half ran")
        else:
            ran = run_cli_reproducers(binary, problems)

    counts = {k: sum(1 for v in kinds.values() if v == k) for k in KINDS}
    print(f"catalogue codes      : {len(declared)}")
    for k in KINDS:
        print(f"  {k:12s}         : {counts[k]}")
    print(f"cli reproducers run  : {ran}")

    if problems:
        print()
        for p in problems:
            print(f"  FAIL  {p}")
        print(f"\nAGENT COOKBOOK FAILED -- {len(problems)} problem(s)")
        return 1
    print(f"\nAGENT COOKBOOK OK -- {len(declared)} code(s) classified, {ran} reproducer(s) executed")
    return 0


def self_test() -> int:
    """Prove each predicate **fires**, by handing the classifier a mutated copy."""
    cases: list[tuple[str, bool, str]] = []
    declared = catalogue_codes()
    kinds = cookbook_kinds()
    in_tests, in_src = rust_tree()

    def copies() -> tuple[list[str], dict[str, str], dict[str, set[str]], dict[str, set[str]]]:
        # Fresh copies per case, so one mutation cannot leak into the next.
        return (
            list(declared),
            dict(kinds),
            {k: set(v) for k, v in in_tests.items()},
            {k: set(v) for k, v in in_src.items()},
        )

    def fires(name: str, mutate) -> None:
        """The real data is clean, the mutation is not, and the classifier says so."""
        d, k, t, s = copies()
        clean = classify(d, k, t, s)
        cases.append((f"the real tree is clean ({name} control)", not clean, f"{clean[:1]}"))
        d, k, t, s = copies()
        mutate(d, k, t, s)
        broken = classify(d, k, t, s)
        cases.append((name, bool(broken), broken[0] if broken else "NO PROBLEM RAISED"))

    cases.append(("the catalogue is non-empty", len(declared) == 43, f"{len(declared)}"))
    cases.append(("every declared code is classified", all(c in kinds for c in declared), ""))

    # --- each mutation must produce a problem, and the real tree must not ---------------------

    def an_untested_test_code(d, k, t, s) -> None:
        code = next(c for c, kind in k.items() if kind == "test")
        t.pop(code, None)

    fires("a `test` code named in no test file is reported", an_untested_test_code)

    def a_src_code_named_by_a_test(d, k, t, s) -> None:
        code = next(c for c, kind in k.items() if kind == "src")
        t.setdefault(code, set()).add("crates/qqq-run/tests/injected.rs")

    fires("a `src` code named by a test is reported", a_src_code_named_by_a_test)

    def a_missing_catalogue_code(d, k, t, s) -> None:
        k.pop(next(c for c in d if c in k), None)

    fires("a catalogue code absent from the cookbook is reported", a_missing_catalogue_code)

    def a_code_not_in_the_catalogue(d, k, t, s) -> None:
        k["QQQ-9999"] = "src"
        s["QQQ-9999"] = {"crates/qqq-run/src/injected.rs"}

    fires("a cookbook code absent from the catalogue is reported", a_code_not_in_the_catalogue)

    def an_unreachable_code_that_is_named(d, k, t, s) -> None:
        # **Synthesised, because the real taxonomy has ZERO `unreachable` codes** -- the first version
        # of this case did `next(... for kind == "unreachable")` and raised `StopIteration`. That is
        # itself the reason the case matters: the branch is unexercised by the tree, so only a
        # constructed input can show it fires. The code is added to the catalogue AND the cookbook so
        # the completeness predicates stay silent and the `unreachable` one is the problem reported.
        code = "QQQ-9998"
        d.append(code)
        k[code] = "unreachable"
        s.setdefault(code, set()).add("crates/qqq-run/src/injected.rs")

    fires("an `unreachable` code named in the tree is reported", an_unreachable_code_that_is_named)

    # The one case whose parameter is not the tree: a table that disagrees with the page.
    d, k, t, s = copies()
    disagreed = classify(d, k, t, s, cli_reproducers={})
    cases.append(("the `cli` set disagreeing with the table is reported",
                  bool(disagreed), disagreed[0] if disagreed else "NO PROBLEM RAISED"))

    failed = 0
    print("check_agent_cookbook self-test")
    for name, ok, detail in cases:
        print(f"  {'OK  ' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
        failed += 0 if ok else 1
    if failed:
        print(f"\nSELF-TEST FAILED -- {failed} case(s) wrong")
        return 1
    print("\nSELF-TEST PASSED -- every predicate fires on a mutated copy, and is silent on the real one")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--no-run", action="store_true",
                    help="skip the executable half (the static half still runs)")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return check(run_cli=not args.no_run)


if __name__ == "__main__":
    sys.exit(main())
