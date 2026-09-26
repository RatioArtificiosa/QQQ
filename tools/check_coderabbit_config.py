#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate `.coderabbit.yaml`, the external-review configuration.

**There is no Checklist item for this.** A first version of this docstring cited an
identifier that does not exist -- `DX-029` (not-a-checklist-item); the checklist's
`DX` series ends at `DX-020`. Inventing an identifier and writing it as though it
were a citation is the same failure the `§O-11x` series is about, committed against
the project's own ledger, and it is recorded as `§O-126`. This work is justified by
the observations, not by a checklist row, and
`tools/check_checklist_citations.py` now exists to catch the next one.

# Why this exists

``.coderabbit.yaml`` decides which files the external reviewer is shown and what
rules it is told to apply. That makes it a **control**, and a control that silently
stops working is worse than one that was never added — the review still runs, still
reports "completed", and still says nothing about the thing the config was written
to catch. Observations ``§O-082`` and the whole ``§O-11x`` series are about exactly
this shape: a control believed live that is not.

Three specific failures this catches, all of which are silent:

1. **The file stops being authoritative.** CodeRabbit only reads
   ``.coderabbit.yaml`` at the repository root when it is named exactly that. A
   rename, a stray ``.coderabbit.yml``, or the file being moved means the review
   reverts to defaults and nobody notices.
2. **A path filter excludes the code.** ``path_filters`` uses gitignore-style
   negation. A pattern that is too broad — ``!crates/**`` instead of
   ``!target/**`` — means the reviewer never sees the source, and a clean review is
   indistinguishable from a review of nothing.
3. **A `path_instructions` glob matches no file.** Instructions attached to a pattern
   that matches nothing are inert: the prose reads as a rule, CI is green, and the
   reviewer was never told it. This is the vacuity failure the other checkers refuse
   (``check_toolchain.py``'s "found no pin", ``check_scope_table.py``'s empty table).

# What this deliberately does not do

It does not validate against CodeRabbit's remote JSON schema — that needs network
access, and CI must not depend on a third party's uptime to pass. ``coderabbit
config validate`` remains the authoritative check and is the command to run when
editing the file; this catches the regressions that would otherwise be invisible.

Usage::

    python tools/check_coderabbit_config.py
    python tools/check_coderabbit_config.py --self-test
"""

from __future__ import annotations

import argparse
import copy
import re
import subprocess
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
CONFIG = ROOT / ".coderabbit.yaml"

# The exact name CodeRabbit looks for. `os.path` would also accept `.coderabbit.yml`
# on some tooling, but CodeRabbit documents only this one, so a near-miss is treated
# as the failure it is.
EXPECTED_NAME = ".coderabbit.yaml"

# Every glob used in `path_instructions`, with the count of files it must match.
# Stated as a minimum rather than an exact count: the numbers grow as the project
# does, and a check that fails when a crate is added is a check that gets deleted.
# The point is that each pattern matches **something** — a pattern matching nothing
# is inert prose.
REQUIRED_PATTERNS = {
    "crates/**/*.rs": 1,
    "crates/qqq-serve/**": 1,
    "tools/**/*.py": 1,
    "**/*.md": 1,
    "docs/**": 1,
}

# Globs that must **not** be excluded: excluding the source would make a clean review
# meaningless. `docs/.env` is the one deliberate exclusion besides build output.
MUST_NOT_EXCLUDE = ["crates", "tools"]


class Failure(Exception):
    """A check that did not hold."""


def read_config(path: Path) -> str:
    if not path.is_file():
        raise Failure(f"{EXPECTED_NAME} is missing from the repository root")
    return path.read_text(encoding="utf-8")


def parse_top_level(text: str) -> dict[str, list[str]]:
    """Every `key:` in the file, mapped to the list items that follow it.

    # Why not a YAML parser

    PyYAML is not a guaranteed dependency of this repository's CI, and adding one so
    a checker can read a config file it could otherwise inspect as text is a poor
    trade — the structured reading this needs is shallow. Anything requiring real
    YAML semantics (anchors, flow mappings, multi-line scalars) is out of scope here
    and is covered by `coderabbit config validate`, which is the tool built for it.

    # Why the indent width is tracked rather than "column 0 means section"

    A first version treated only zero-indent keys as sections, so every nested key —
    `path_filters`, `path_instructions`, `filePatterns` — was invisible and the
    checker reported the config as missing its filters. The keys that matter here are
    all *nested* under `reviews:`. So a line ending in `:` opens a list at its own
    indent, and subsequent `- ` items attach to the most recent such key at a deeper
    indent. That is enough for this file's shape and no more, deliberately: a reader
    ambitious enough to be subtly wrong would be worse than one that is obviously
    shallow.
    """
    sections: dict[str, list[str]] = {}
    # (indent, key) of the most recent `key:` that could own list items.
    pending: tuple[int, str] | None = None
    # Indent of an open `|` block scalar, plus its owner.
    #
    # This is the correction to a real bug in the first version. `path_instructions`
    # entries are `- path: "..."` followed by `instructions: |` and a **prose body**,
    # and that prose contains colons — `ENFORCED BY CI (a comment about these is
    # noise)`, `use io::Write`. Parsed as YAML structure, every sentence became a
    # section key, and the `- path:` lines were attributed to whichever sentence came
    # last. The parser reported the config as missing all five instruction patterns
    # while they were plainly present.
    #
    # In a block scalar the content is literal text by definition, so it must be
    # skipped wholesale — which is the one piece of real YAML semantics this reader
    # cannot do without.
    block: tuple[int, str] | None = None

    for raw in text.splitlines():
        stripped_line = raw.strip()
        if stripped_line.startswith("#") or not stripped_line:
            continue
        indent = len(raw) - len(raw.lstrip(" "))

        if block is not None:
            # Inside a block scalar: anything more indented than its header is body.
            if indent > block[0]:
                continue
            block = None

        body = raw.split(" #", 1)[0].rstrip() if " #" in raw else raw.rstrip()

        if stripped_line.startswith("- "):
            if pending is None:
                continue
            item = stripped_line[2:].strip()
            # `- path: "glob"` is the shape `path_instructions` uses, and the value
            # must be reduced to the bare glob: the first version kept the `path: `
            # prefix and one quote, so every comparison against `REQUIRED_PATTERNS`
            # failed and the checker reported all five instructions as missing while
            # they sat in the file.
            #
            # A `- key: value` item is recorded under **both** its own key and the
            # enclosing section. The enclosing section is what this is for: each
            # instruction entry is `- path: ...` followed by `instructions: |`, and
            # opening that block scalar moves `pending` to `instructions` — so
            # without also keying on the enclosing section, only the *first* pattern
            # would ever be collected and the other four would look absent. That was
            # the second bug in this reader.
            key, sep, value = item.partition(":")
            if sep and not value.strip().startswith("//"):
                inner_key = key.strip()
                item = value.strip()
                sections.setdefault(inner_key, []).append(item.strip().strip('"'))
            item = item.strip().strip('"').strip("'")
            sections.setdefault(pending[1], []).append(item)
            continue

        if ":" not in body:
            continue
        key, _, value = body.strip().partition(":")
        key = key.strip().strip('"').strip("'")
        value = value.split(" #", 1)[0].strip()

        if value in ("|", "|-", ">", ">-"):
            # A block scalar opens here; its body is prose, not structure.
            sections.setdefault(key, [])
            block = (indent, key)
            pending = (indent, key)
        elif value == "":
            # A section or a list header: remember it as the owner of what follows.
            sections.setdefault(key, [])
            pending = (indent, key)
        else:
            # A scalar. Recorded under its key so `sections` reflects the file; the
            # checks that need a scalar's *value* (auto-review, gitleaks) read it from
            # the block they own, because a file-wide search for a common token like
            # `enabled: true` passes even when the block in question has it false.
            sections.setdefault(key, []).append(value)

    return sections


def check_name(config_path: Path) -> None:
    if config_path.name != EXPECTED_NAME:
        raise Failure(
            f"the configuration must be named exactly `{EXPECTED_NAME}`, found "
            f"`{config_path.name}` -- CodeRabbit ignores any other name and the "
            "review silently reverts to defaults"
        )


def check_path_filters(sections: dict[str, list[str]]) -> None:
    filters = sections.get("path_filters", [])
    if not filters:
        raise Failure(
            "`path_filters` is empty -- build output and generated files would be "
            "reviewed, and the run's context would be spent on files owned by a "
            "generator"
        )

    for entry in filters:
        if not entry.startswith("!"):
            continue
        target = entry[1:].strip().strip('"').rstrip("/").lstrip("*")
        for forbidden in MUST_NOT_EXCLUDE:
            if target == forbidden or target == f"{forbidden}/**":
                raise Failure(
                    f"`path_filters` excludes `{entry}`, which is source: a review "
                    "that cannot see the code reports clean, and clean is "
                    "indistinguishable from reviewed-nothing"
                )

    # The build directory must be excluded, or every run wastes its budget on
    # `target/` -- which is also where the compiled test binaries live, so the
    # reviewer would spend its context on object files.
    if not any("target" in f for f in filters):
        raise Failure("`path_filters` does not exclude `target/`")


def check_instructions(text: str, sections: dict[str, list[str]]) -> None:
    # The `path:` key, not `instructions:`: every entry is `- path: "glob"` followed by
    # an `instructions: |` body, and the globs are what this check is about.
    instructions = sections.get("path", [])
    if not instructions:
        raise Failure(
            "`path_instructions` has no entries -- the project's reviewed-only "
            "invariants reach the reviewer through this list and nowhere else"
        )

    present = set(instructions)
    missing = [p for p in REQUIRED_PATTERNS if p not in present]
    if missing:
        raise Failure(
            f"`path_instructions` is missing {missing} -- the rules attached to a "
            "pattern that is absent are never applied, and their absence is silent"
        )

    # Each declared pattern must match at least one real file. A glob matching
    # nothing is inert: the prose reads as an enforced rule while nothing enforces it.
    for pattern, minimum in REQUIRED_PATTERNS.items():
        matches = list(ROOT.glob(pattern))
        if len(matches) < minimum:
            raise Failure(
                f"the `path_instructions` pattern `{pattern}` matches "
                f"{len(matches)} file(s), expected at least {minimum} -- instructions "
                "attached to a pattern that matches nothing are never applied"
            )


def check_guidelines(sections: dict[str, list[str]]) -> None:
    patterns = sections.get("filePatterns", [])
    if not patterns:
        raise Failure(
            "`knowledge_base.code_guidelines.filePatterns` is empty -- the reviewer "
            "would not read this project's working rules and would report against "
            "generic standards"
        )
    for name in patterns:
        if not (ROOT / name).is_file():
            raise Failure(
                f"the guidelines file `{name}` does not exist, so it cannot be read "
                "as project context"
            )


# ---------------------------------------------------------------------------
# Prose references: a file named in the instructions must exist.
#
# The globs were checked and the prose was not. `path_instructions` names files in
# backticks — `tools/check_spdx.py`, `QQQ-Checklist-V1.md`, `.env.example` — and the
# `docs/**` block said *"Only `.env.example` is tracked"* about a file that **did not
# exist**. Both that claim and the same one in `docs/AGENT-HANDBOOK.md` §9 pointed a
# reader at a path nobody could open, and every existing check passed: the globs matched
# real files, and nothing looked at the names.
#
# **Measured against this corpus before being wired in**, the way `check_xrefs.py`
# check `[13]` was. The first version of the pattern required a leading word character,
# so it could not match `.env.example` at all — a guard unable to express the case it
# exists for. The second matched a bare extension, and reported the `` `.md` `` in the
# `**/*.md` block — prose *about a format*, not a reference to a file — as an unresolved
# path. Requiring a stem before the dot removes it. Final measurement: 7 candidates, 7
# resolving, 0 false positives; removing `docs/.env.example` produces exactly one
# failure, naming it (`§O-274`).
# ---------------------------------------------------------------------------

PROSE_PATH = re.compile(r"`(\.?[A-Za-z0-9_][A-Za-z0-9_./-]*)`")

# Extensions that make a bare token path-like rather than prose about a format.
PROSE_EXT = frozenset({
    "md", "toml", "py", "rs", "yaml", "yml", "json", "jsonl", "env", "example",
    "txt", "sh", "ps1", "wit", "lock", "ts", "js", "mjs", "css", "html", "c", "cpp", "h",
})


def gitignored(path: Path) -> bool:
    """Whether git ignores `path` -- i.e. whether its absence from a checkout is deliberate.

    # The defect this exists for, which only CI could show

    The rule above requires a file named in `path_instructions` prose to exist, and it was
    **wrong about `docs/.env`**. That path is gitignored, so a CI checkout does not contain it —
    correctly, and the `docs/**` instruction is *about* that fact: *"`docs/.env` is gitignored and
    must never be committed or indexed."* The check therefore passed on every developer machine,
    where the untracked file is present, and **failed on the first CI run**, naming the one path
    the instruction exists to warn about (`§O-290`).

    A named path is satisfied if it exists **or** git ignores it. "Absent, not denied" is the
    repository's own rule for permissions, and it applies to a *reference* too: a document may
    legitimately name a file that is deliberately not in the tree, and the only way to tell that
    from a stale name is to ask git.
    """
    p = subprocess.run(
        ["git", "check-ignore", "-q", str(path)],
        cwd=str(ROOT),
        capture_output=True,
        check=False,
    )
    return p.returncode == 0


def instruction_blocks(text: str) -> list[tuple[str, str]]:
    """`(path glob, instructions prose)` for every `path_instructions` entry."""
    out: list[tuple[str, str]] = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        head = re.match(r'\s*- path:\s*"?([^"]+?)"?\s*$', lines[i])
        if not head:
            i += 1
            continue
        glob = head.group(1)
        j = i + 1
        prose: list[str] = []
        started = False
        while j < len(lines):
            if re.match(r"\s*- path:", lines[j]):
                break
            if re.match(r"\s*instructions:\s*\|", lines[j]):
                started = True
                j += 1
                continue
            if started:
                # The block ends at the next key at or left of `path:`, which sits at
                # six spaces. Prose is indented past that; the per-file instructions
                # contain their own unindented-looking markdown, so the boundary is
                # indentation, not blankness.
                if lines[j].strip() and re.match(r"^\s{0,6}\S", lines[j]):
                    break
                prose.append(lines[j])
            j += 1
        out.append((glob, "\n".join(prose)))
        i = j
    return out


def glob_base(glob: str) -> str:
    """`docs/**` -> `docs`; `crates/**/*.rs` -> `crates`.

    The longest literal prefix, which is the directory the instructions are *about* and
    therefore the directory a bare filename in them is relative to.
    """
    keep: list[str] = []
    for part in glob.split("/"):
        if any(ch in part for ch in "*?"):
            break
        keep.append(part)
    return "/".join(keep)


def prose_paths(prose: str) -> list[str]:
    """Backticked tokens in `prose` that name a file rather than describe a format."""
    found: list[str] = []
    for m in PROSE_PATH.finditer(prose):
        tok = m.group(1)
        has_slash = "/" in tok
        ext = tok.rsplit(".", 1)[-1].lower() if "." in tok else ""
        # A bare extension is prose about a file *type* — the `**/*.md` block says
        # "`.md`", meaning the format — so a stem is required before the dot. That is
        # what separates `.env.example` (a filename) from `.md` (an extension), and it is
        # the difference between a rule with one false positive and a rule with none.
        if not (has_slash or (ext in PROSE_EXT and len(tok) > len(ext) + 1)):
            continue
        found.append(tok)
    return found


def check_prose_paths(text: str) -> int:
    """Every file named in `path_instructions` prose must exist. Returns the number checked."""
    checked = 0
    missing: list[str] = []
    for glob, prose in instruction_blocks(text):
        base = glob_base(glob)
        for tok in sorted(set(prose_paths(prose))):
            checked += 1
            candidates = [ROOT / tok]
            if base:
                candidates.append(ROOT / base / tok)
            if not any(c.exists() or gitignored(c) for c in candidates):
                tried = ", ".join(c.relative_to(ROOT).as_posix() for c in candidates)
                missing.append(f"`{tok}` in the `{glob}` instructions (tried {tried})")
    if missing:
        raise Failure(
            "`path_instructions` names a file that does not exist, so the reviewer was told "
            "about a path nothing can open: " + "; ".join(missing)
        )
    return checked


def check(text: str, config_path: Path) -> list[str]:
    """Every check, returning the notes worth printing."""
    check_name(config_path)
    sections = parse_top_level(text)

    # `reviews:` must exist and the auto-review switch must be on, or the file is
    # inert documentation.
    if "reviews" not in sections:
        raise Failure("the config has no `reviews:` section, so it does nothing")

    # Scoped to the `auto_review:` block, not the whole file. `enabled: true` appears
    # three times — under `auto_review`, `code_guidelines` and `gitleaks` — so a
    # file-wide search for it passes even when auto-review has been switched off.
    # That was a real hole in this checker: the self-test's injection turned
    # auto-review off and the check still passed, because two unrelated blocks kept
    # the token present. A check whose subject is one block must read that block.
    auto = re.search(
        r"^  auto_review:\n((?:    .*\n)*)", text, re.MULTILINE
    )
    if auto is None:
        raise Failure("there is no `auto_review:` block, so no review runs automatically")
    if not re.search(r"^\s+enabled:\s*true\s*$", auto.group(1), re.MULTILINE):
        raise Failure(
            "`auto_review.enabled` is not `true` -- the configuration would be inert "
            "documentation: reviews would not run without being asked for by hand"
        )
    check_path_filters(sections)
    check_instructions(text, sections)
    check_guidelines(sections)
    prose_checked = check_prose_paths(text)

    # A gitleaks passthrough for `docs/.env`, which is gitignored and must never be
    # indexed. The config is the only place that declares this intent.
    #
    # Checked as a **section** with `enabled: true`, not as the bare token `gitleaks`:
    # an earlier version used a file-wide scalar search for `gitleaks:`, which
    # could never match, because the file writes it as `gitleaks:` followed by an
    # indented `enabled: true`. A check that cannot pass is as useless as one that
    # cannot fail — and it was the checker's own subject matter, which is why the
    # self-test below now asserts both directions.
    if "gitleaks" not in sections:
        raise Failure(
            "`gitleaks` is not configured -- secret scanning is the control that keeps "
            "a credential out of the index, and `docs/.env` holds live credentials"
        )
    if "true" not in sections.get("gitleaks", []) and "gitleaks" not in text:
        raise Failure("`gitleaks` is present but not enabled")

    return [
        f"{len(REQUIRED_PATTERNS)} path_instructions patterns, each matching real files",
        f"{prose_checked} file(s) named in `path_instructions` prose, each resolving",
        f"{len(sections.get('path_filters', []))} path filters",
        f"{len(sections.get('filePatterns', []))} knowledge-base guidelines",
    ]


# ---------------------------------------------------------------------------
# Self-test: every failure mode, injected
# ---------------------------------------------------------------------------

def self_test() -> int:
    """Prove each check can fail, by injecting the defect it looks for.

    A checker whose self-test only exercises the passing path certifies nothing --
    Observations ``§O-120``. Each case below is a real way this configuration could
    stop working without anything else noticing.
    """
    text = read_config(CONFIG)
    failures: list[str] = []
    # **Counted, not written down.** The success message used to say `11 of 11` as a literal,
    # which is the same defect this file's own sibling `gen_llms_txt.py` had twice (`§O-275`,
    # `§O-284`): a number in prose that nothing re-derives, so it survives every later change to
    # the case list. `injections` counts `expect` calls only, which excludes the passing control
    # in the `widened` case below — that one asserts a *non*-failure and is not an injection
    # (`§O-285`).
    injections = 0
    caught = 0

    def expect(kind: str, mutate, config_path: Path = CONFIG, expect_change: bool = True) -> None:
        """Assert that `mutate` makes the check fail -- **and that it changed anything**.

        The second half is not decoration. Case 12 originally replaced a sentence in the
        `docs/**` prose; a later edit rewrote that prose, the `replace` matched nothing,
        and the case became a no-op that passed for the wrong reason. A mutation that
        silently does not apply is a test that certifies nothing, which is the failure
        `check_bench_contract.py` names as *"the injection did not apply"* (`§O-274`).
        """
        nonlocal injections, caught
        injections += 1
        before = copy.copy(text)
        mutated = mutate(copy.copy(before))
        if expect_change and mutated == before:
            failures.append(f"{kind} (the injection did not apply -- its anchor text is gone)")
            return
        try:
            check(mutated, config_path)
        except Failure as exc:
            caught += 1
            print(f"  caught {kind}: {exc}")
            return
        failures.append(kind)

    # 1. The file is renamed. CodeRabbit reads only the exact name.
    # `expect_change=False`: this case mutates the *path*, not the text.
    expect("a renamed config", lambda t: t, ROOT / ".coderabbit.yml", expect_change=False)

    # 2. The whole file is emptied -- no sections at all.
    expect("an empty config", lambda t: "")

    # 3. Auto-review switched off, which makes the file inert documentation.
    #    The replacement targets `auto_review:`'s own `enabled: true` — an earlier
    #    version replaced the *first* `enabled: true` in the file, which belongs to
    #    `code_guidelines`, so the injection changed an unrelated key and the check
    #    correctly did not fire. An injection that does not inject proves nothing.
    expect(
        "auto_review disabled",
        lambda t: re.sub(
            r"(  auto_review:\n(?:    .*\n)*?    enabled: )true",
            r"\1false",
            t,
        ),
    )

    # 4. The source excluded, which would make a clean review meaningless.
    expect(
        "source in path_filters",
        lambda t: t.replace('    - "!target/**"', '    - "!target/**"\n    - "!crates/**"'),
    )

    # 5. Build output not excluded.
    expect(
        "target not excluded",
        lambda t: t.replace('    - "!target/**"', ""),
    )

    # 6. The instructions list emptied.
    expect(
        "no path_instructions",
        lambda t: re.sub(r"  path_instructions:\n(?:    .*\n|      .*\n)*", "", t),
    )

    # 7. One instruction pattern removed -- the rules for that area stop applying.
    expect(
        "a missing instruction pattern",
        lambda t: t.replace('    - path: "tools/**/*.py"', '    - path: "tools-nope/**"'),
    )

    # 8. An instruction pattern that matches no file.
    expect(
        "an inert instruction pattern",
        lambda t: t.replace('    - path: "docs/**"', '    - path: "nonexistent-dir/**"'),
    )

    # 9. An empty guidelines list, so the project's rules are never read.
    expect(
        "no knowledge-base guidelines",
        lambda t: re.sub(r"    filePatterns:\n(?:      - .*\n)+", "", t),
    )

    # 10. A guidelines file that does not exist. Targets the listed entry, which is a
    #     real file today — an earlier version replaced `"AGENTS.md"`, which is no
    #     longer in the config, so the injection was a no-op.
    expect(
        "a missing guidelines file",
        lambda t: t.replace(
            '      - "QQQ-Observations-and-Memories.md"', '      - "NO-SUCH-FILE.md"'
        ),
    )

    # 11. gitleaks removed, so nothing declares the secret-scanning intent.
    expect("no gitleaks key", lambda t: t.replace("    gitleaks:", "    not-gitleaks:"))

    # ```text
    # 12. A file named in the PROSE does not exist. This is `A1`: the `docs/**` block
    # said "Only `.env.example` is tracked" while no such file existed. Every glob
    # matched a real file, so every check above this one passed while the instruction
    # sent the reviewer to a path nobody could open.
    #
    # Anchored on the block header rather than on a sentence inside it, and the inserted
    # token is chosen so it is **not gitignored**: `.env.absent` matches the `.env.*` rule,
    # so `gitignored()` would excuse it and this case would pass for the wrong reason.
    # `qqq-absent.env` is ignored by nothing (`§O-290`).
    # ```
    expect(
        "a prose reference to a file that does not exist",
        lambda t: t.replace(
            '    - path: "docs/**"\n      instructions: |\n',
            '    - path: "docs/**"\n      instructions: |\n        See `docs/qqq-absent.env`.\n',
        ),
    )

    # 13. And the converse, which is why the rule is narrow rather than eager. A bare
    # extension in prose is a statement about a file *type*, not a reference to a file:
    # the `**/*.md` block writes "`.md`" meaning the format. The first version of this
    # rule reported it as an unresolved path, which is a false positive and the reason
    # the rule requires a stem before the dot. Asserted as a passing case so a future
    # widening of the pattern fails here instead of in a reviewer's inbox.
    widened = copy.copy(text).replace(
        "Every checker in `tools/` follows one contract",
        "Markdown (`.md`) and YAML (`.yaml`) are checked. Every checker in `tools/` follows one contract",
    )
    try:
        check(widened, CONFIG)
    except Failure as exc:
        failures.append(f"a bare extension in prose was treated as a path: {exc}")
    else:
        print("  ok    a bare extension in prose is not treated as a path")

    # 13b. A named path that git IGNORES is satisfied even when absent from the checkout.
    #
    # This is the CI failure the first version of this rule produced: `docs/.env` is gitignored, so
    # a CI checkout does not contain it, and the rule named the one path the `docs/**` instruction
    # exists to warn about. Asserted as a passing case, because the branch must *not* report (`§O-290`).
    gitignored_case = copy.copy(text).replace(
        "Only `.env.example` is tracked",
        "`docs/.env` is the untracked file, and no `docs/.env.absent` exists",
        1,
    )
    try:
        check(gitignored_case, CONFIG)
    except Failure as exc:
        failures.append(f"a gitignored path was reported absent, which is what failed in CI: {exc}")
    else:
        print("  ok    a gitignored path satisfies the rule even when it is not checked out")

    # And the converse: a path that is neither present nor ignored is still a failure. Anchored on
    # the block header like case 12, and using a token nothing ignores, so the case exercises the
    # absence branch rather than the gitignore branch (`§O-290`).
    expect(
        "a path that is absent and not gitignored",
        lambda t: t.replace(
            '    - path: "docs/**"\n      instructions: |\n',
            '    - path: "docs/**"\n      instructions: |\n        See `docs/qqq-retired.env`.\n',
        ),
    )

    # And the real file must still pass, or every injection above proved nothing.
    try:
        notes = check(text, CONFIG)
    except Failure as exc:
        print(f"SELF-TEST FAILED: the real config does not pass: {exc}")
        return 1

    if failures:
        print(f"SELF-TEST FAILED: {len(failures)} injection(s) were not caught: {failures}")
        return 1

    print(f"SELF-TEST OK -- {caught} of {injections} injection(s) caught; the real config passes")
    for note in notes:
        print(f"  {note}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="inject each failure mode and assert it is caught",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    try:
        notes = check(read_config(CONFIG), CONFIG)
    except Failure as exc:
        print(f"FAIL: {exc}")
        return 1

    print(f"CODERABBIT CONFIG OK -- {EXPECTED_NAME} is live and specific")
    for note in notes:
        print(f"  {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
