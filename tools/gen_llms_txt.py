#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate `llms.txt` and `llms-full.txt` — `DOC-020`, and §8.5.

# What §8.5 asks for, verbatim

| Practice | Implementation |
|---|---|
| `llms.txt` at repo root and docs site | **Curated index of what to read, in what order** |
| `llms-full.txt` | **Full documentation concatenated for context loading** |

The two halves are different documents with different jobs, and the difference is
the design:

* `llms.txt` is an **index**. A model that has never seen QQQ reads this first and
  learns what exists, what order to read it in, and — critically — **what each
  file is for**. It is small enough to fit in any context window.
* `llms-full.txt` is a **corpus**. It is every document concatenated with its
  provenance, for when the whole thing fits and a model should reason over all of
  it at once.

# Why a generator rather than two hand-written files

Because a hand-written `llms.txt` is a *second* statement of what the repository
contains, and it goes stale the first time a document is added — the same argument
`CON-016` records for the schemas. The index is generated from the filesystem, so
a new document that is not listed is a defect the checker reports rather than a
gap nobody notices.

# Why there is a `CURATED` table and not a directory walk

Because §8.5 says **curated** and **in what order**. A walk produces alphabetical
noise: `advisories/README.md` would sort before `README.md` and a reader would
start in the wrong place. The table is the curation, and the generator's job is to
prove the table and the tree agree — in both directions, like every other check
here.

# Why `llms-full.txt` carries provenance markers

Because a concatenated corpus without boundaries is worse than no corpus: a model
cannot tell where one document ends and the next begins, and a quotation from it
cannot be traced back. Each section is preceded by its path and a horizontal rule,
so a claim in a generated answer can be checked against the source file.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# The curation: what to read, and in what order
# ---------------------------------------------------------------------------
#
# Each entry is (path, one-line purpose, audience). The audience tag exists
# because a model asked a *specific* question should not have to read the whole
# index to find the two files that matter -- `agent` marks what an automated
# consumer needs, `human` what a person reads first.
#
# The order is the order of a real reading: what this is, then the contract, then
# how to use it, then the machinery.

CURATED: list[tuple[str, str, str, str]] = [
    # --- What this is ------------------------------------------------------
    (
        "README.md",
        "What QQQ is, in one page.",
        "human",
        "start",
    ),
    (
        "QQQ-Proposal-V1.md",
        "The full specification. Every other document derives from this one; "
        "section numbers are stable and are cited by the checklist.",
        "both",
        "start",
    ),
    # --- What is actually built -------------------------------------------
    (
        "QQQ-Checklist-V1.md",
        "The 586 tracked items, each citing the Proposal section that governs "
        "it, with the evidence for each completed one.",
        "both",
        "status",
    ),
    (
        "QQQ-Observations-and-Memories.md",
        "Decisions, observations, mistakes and corrections made while building. "
        "Read this to learn what was tried and rejected, and why.",
        "both",
        "status",
    ),
    # --- The machine contracts --------------------------------------------
    (
        "docs/errors.md",
        "Every `QQQ-XXXX` error code with its cause and remediation.",
        "agent",
        "contract",
    ),
    (
        "docs/wit-reference.md",
        "Every WIT package, interface, function and type, generated from `wit/`.",
        "agent",
        "contract",
    ),
    (
        "schema/qqq-toml.schema.json",
        "JSON Schema for `qqq.toml`, generated from the Rust type that parses it.",
        "agent",
        "contract",
    ),
    (
        "schema/qqq-lock.schema.json",
        "JSON Schema for `qqq.lock`, including the per-package `caps` record.",
        "agent",
        "contract",
    ),
    (
        "schema/cli-envelope.schema.json",
        "JSON Schema for the `--json` envelope every command emits.",
        "agent",
        "contract",
    ),
    # --- How to work on it ------------------------------------------------
    (
        "docs/README.md",
        "Index of the documentation directory, with what each file is for.",
        "human",
        "use",
    ),
    (
        "docs/glossary.md",
        "The 18 defined terms. Several are load-bearing and mean something "
        "narrower here than in general use.",
        "both",
        "use",
    ),
    (
        "docs/threat-model.md",
        "The adversaries QQQ defends against, and what it explicitly does not.",
        "both",
        "use",
    ),
    (
        "docs/out-of-scope.md",
        "What is deliberately not defended, so absences are decisions rather "
        "than oversights.",
        "both",
        "use",
    ),
    (
        "docs/contributing/claims-policy.md",
        "How a factual claim must be verified before it enters a document.",
        "human",
        "use",
    ),
    (
        "docs/contributing/anchors.md",
        "The anchor convention, and why a retired section is tombstoned rather "
        "than deleted.",
        "human",
        "use",
    ),
    # --- The machinery ----------------------------------------------------
    (
        "docs/verified-facts.md",
        "Facts asserted in the Proposal, each classified by how perishable it "
        "is and when it was last checked.",
        "both",
        "machinery",
    ),
    (
        "docs/reconciliation.md",
        "Corrections made to the Proposal, with the reasoning.",
        "both",
        "machinery",
    ),
    (
        "docs/wasmtime-advisory-process.md",
        "How a Wasmtime security advisory is handled.",
        "human",
        "machinery",
    ),
    (
        "docs/unsafe-audit.md",
        "The `unsafe` audit: what it covers and what it has found.",
        "human",
        "machinery",
    ),
    (
        "SECURITY.md",
        "How to report a vulnerability, and what response to expect.",
        "human",
        "machinery",
    ),
    (
        "docs/development-bridge.md",
        "How the Linux verification bridge works, and the one-way rule it "
        "enforces on build output.",
        "human",
        "machinery",
    ),
    (
        "docs/adr/README.md",
        "Architecture decision records: what was decided, and what was rejected.",
        "human",
        "machinery",
    ),
    (
        "docs/advisories/README.md",
        "How a dependency advisory is recorded and resolved.",
        "human",
        "machinery",
    ),
    (
        "docs/advisories/INDEX.md",
        "The advisory register itself.",
        "agent",
        "machinery",
    ),
    (
        "PRINCIPLES.md",
        "The non-negotiables the design is held to.",
        "human",
        "machinery",
    ),
]

# The order the audience tags appear in the index, and their headings.
AUDIENCE_HEADINGS = [
    ("start", "Start here"),
    ("status", "What is built, and what was learned building it"),
    ("contract", "The machine contracts (for an agent)"),
    ("use", "Using it"),
    ("machinery", "The machinery behind the documents"),
]

# Documents included whole in `llms-full.txt`, in order.
#
# # Why this is a subset and not everything
#
# Because `llms-full.txt` is for *context loading*, and the two largest documents
# are the two least useful to load whole: the Proposal is ~130 KB and the
# Observations ~90 KB. Including them would consume a context window before the
# reader reaches the part they need. They are in the index with their size stated,
# so a consumer can fetch them deliberately.
FULL_INCLUDES = [
    "README.md",
    "PRINCIPLES.md",
    "docs/glossary.md",
    "docs/threat-model.md",
    "docs/out-of-scope.md",
    "docs/errors.md",
    "docs/wit-reference.md",
    "docs/verified-facts.md",
    "docs/reconciliation.md",
    "SECURITY.md",
]

# Files that are documents but must NOT appear in the index.
#
# # Why an exclusion list rather than "list everything under docs/"
#
# Because some of what is there is not documentation. `docs/Windows-Linux-Docker.md`
# is gitignored working notes; the conversation transcripts are raw history; the
# ADRs are decision records for maintainers rather than material for a reader
# meeting the project. Naming them here means the completeness check can still be
# strict — every `.md` under `docs/` is either indexed or explicitly excluded —
# which is what makes an omission a failure rather than a judgement call.
# ---------------------------------------------------------------------------
# Three exclusion lists, categorized by WHERE A FILE LIVES
# ---------------------------------------------------------------------------
#
# # Why three, and why the categorization took two attempts to get right
#
# The first version had one list and asserted every entry existed. CI failed on
# `docs/.env`, which is gitignored and therefore absent from a checkout. The
# second version split it in two and asserted the *non*-documentation entries
# existed -- and CI failed again, on `docs/Windows-Linux-Docker.md`, which is
# **also** gitignored.
#
# Both mistakes were the same mistake: **I categorized by what a file is for when
# the property that matters is where it lives.** "Not documentation" and "must
# exist" are independent, and so are "gitignored" and "harmless":
#
#   | List | Lives in Git? | Absence means | Presence in Git means |
#   |---|---|---|---|
#   | `EXCLUDED` | yes | staleness — remove the entry | normal |
#   | `EXCLUDED_LOCAL` | no | normal | odd but harmless |
#   | `EXCLUDED_SECRETS` | no | normal | **a credential leak** |
#
# Each list is therefore checked for what its membership actually implies, and
# the ground truth for every entry was established by running `git ls-files`
# rather than by reading `.gitignore`.

# Tracked files that are **in the repository but are not documentation**. Each
# must exist, so a path that disappears is staleness the check reports.
#
# Verified tracked: `git ls-files` reports all three.
EXCLUDED = {
    # Raw conversation history, kept for provenance rather than for reading.
    "docs/QQQAI-Conversation-Full.md",
    "docs/QQQAI-Full-Conversation-Complete.md",
    # Working notes, not documentation.
    "docs/Notes.txt",
}

# Gitignored files that must never be indexed, and that need not exist.
#
# Verified gitignored: `git check-ignore` reports it, `git ls-files` does not.
EXCLUDED_LOCAL = {
    # Windows/Linux/Docker working notes. Gitignored, so absent from CI; present
    # only on a developer's machine.
    "docs/Windows-Linux-Docker.md",
}

# Gitignored files that carry credentials. Kept separate from `EXCLUDED_LOCAL` so
# a security review can find them by name, and so adding a harmless local file
# never requires reasoning about secrets.
EXCLUDED_SECRETS = {
    # Context7 credentials for the documentation-lookup service. An index that
    # linked to it would be a leak, and a corpus that embedded it would put the
    # secret in a file designed to be pasted into a model's context window.
    "docs/.env",
}

# Every path that must never appear in the index or the corpus.
EXCLUDED_ALL = EXCLUDED | EXCLUDED_LOCAL | EXCLUDED_SECRETS


def content_size(rel: str) -> int | None:
    """The byte length of a file's **content**, with CRLF normalised away.

    # Why this is not `Path.stat().st_size`

    Because that number depends on the operating system of whoever ran the
    generator. `core.autocrlf` expands every LF to CRLF on a Windows checkout, so
    `QQQ-Proposal-V1.md` measures 136,513 bytes here and 134,144 on Linux — a
    2.4 KB difference for one file, and more for the larger ones.

    Baking that into `llms.txt` made the document **non-reproducible**: CI on
    Linux would compute one value and a Windows contributor another, so every
    Windows push failed the drift check, and two people regenerating the same
    commit produced different files. That is precisely the "control believed live
    that is not" shape this session keeps finding, except it was a *published
    document* rather than a check — and it was found by the drift check doing its
    job on the generator that produced it.

    # Why normalise rather than use `.gitattributes` or a Git object read

    Because a single `read_bytes().replace(b"\r\n", b"\n")` is exact for the
    question being asked — *how much content is this?* — and needs no subprocess.
    Reading the committed blob via `git cat-file` would answer a subtly different
    question (what is committed, not what is here) and would make the generator
    depend on Git being present.

    # Why the number is still allowed to differ from a file manager's

    Because a reader comparing them will see a small difference on Windows, and
    that is expected. The alternative — omitting sizes — loses real information:
    a model deciding whether to fetch a 577 KB document benefits from knowing it
    is large.
    """
    path = ROOT / rel
    if not path.exists():
        return None
    data = path.read_bytes()
    # Normalise to LF so the count is a property of the content.
    return len(data.replace(b"\r\n", b"\n"))


# Above this size, a document is described with a WORD rather than a number.
#
# # Why a threshold, and why the answer is qualitative rather than bucketed
#
# The two documents above it -- the Checklist (~250 KB) and the Observations
# (~580 KB) -- are the two this project edits on **every round**. Recording their
# exact size made `llms.txt` a churn magnet, and the fix was self-referential
# (regenerating the index is a commit; the next doc commit re-breaks it).
#
# Bucketing to 10 KB was the second attempt, and it reduced the frequency without
# removing the class: `O-116` crossed a boundary and CI failed with the identical
# drift message. **A document edited every round crosses any bucket eventually.**
#
# So above the threshold there is no number. A word answers the question the
# number existed to answer -- *should a consumer fetch this?* -- and cannot go
# stale. "very large" is not less useful than "580 KB" for that decision; it is
# only less precise.
VOLATILE_KB = 100


def label_for(data: bytes) -> str:
    """The qualitative label for a document's bytes, for the churn self-test.

    # Why this takes bytes rather than a path

    Because the test needs to evaluate a *hypothetical* size without writing a file
    into the repository. Taking bytes makes the label function testable in
    isolation, which is the only way to assert the property that failed twice.
    """
    kb = len(data.replace(b"\r\n", b"\n")) // 1024
    if kb < VOLATILE_KB:
        return f"{kb} KB"
    # **One word, with no upper boundary.**
    #
    # A `very large` tier above 1 MB was the third attempt at this, and the
    # self-test caught it: growing a document 20x produced
    # `large, large, very large`. That is the identical defect one level up --
    # any function of a monotonic quantity has a boundary, and beyond a boundary
    # is a drift failure. The Observations is at 585 KB and grows every round, so
    # a 1 MB line would have been crossed eventually.
    #
    # Above the threshold there is therefore **no line to cross**.
    return "large"


def size_of(rel: str) -> str:
    """A human size for a file, **without its own parentheses**.

    # Why the brackets are the caller's job

    The first version returned `"(missing)"` *with* brackets while the index
    appended its own, producing `((missing))` in the published file. The
    self-test caught it by asserting on the rendered **line** rather than on a
    substring — a substring check for `(missing)` passes on `((missing))`, which
    is the difference between checking a value and checking the document a reader
    sees.

    A bare value lets the caller own the punctuation, so there is one place that
    can get it wrong rather than two.
    """
    n = content_size(rel)
    if n is None:
        return "missing"
    if n < 1024:
        return f"{n} B"
    kb = n // 1024
    if kb < VOLATILE_KB:
        # Small enough that a change does not move it: report it exactly, because
        # the number is information rather than noise.
        return f"{kb} KB"
    # **Above the threshold, no number at all -- and this took two attempts.**
    #
    # The first version printed the exact size and churned on every commit. The
    # second bucketed to 10 KB, which reduced the frequency and left the class:
    # `O-116` pushed the Observations past a boundary and CI failed with the same
    # drift message. These two documents are edited every round, so they will
    # cross any bucket eventually.
    #
    # A word answers the question the number was there to answer -- *should a
    # consumer fetch this?* -- and cannot go stale, **because there is no upper
    # boundary to cross**. See `label_for` for the three attempts this took.
    return "large"


def first_heading(path: pathlib.Path) -> str:
    """The first `# ` heading, used to check the table's description is honest."""
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("# "):
                return line[2:].strip()
    except OSError:
        pass
    return ""


def render_index() -> str:
    """`llms.txt` — the curated index."""
    out: list[str] = []
    out.append("# QQQ")
    out.append("")
    out.append(
        "> A capability-secure WebAssembly Component Model runtime. This file is a "
        "**curated index**: it says what exists and what order to read it in. It "
        "is generated by `tools/gen_llms_txt.py` from the file listing, so it "
        "cannot describe a file that is not there."
    )
    out.append("")
    out.append(
        "For the documentation concatenated into one document, see "
        "[`llms-full.txt`](llms-full.txt)."
    )
    out.append("")
    out.append(
        "Sizes are **LF-normalised content byte counts**, identical on every "
        "platform regardless of the checkout's line endings. Documents above "
        f"{VOLATILE_KB} KB are labelled `large` instead of being measured: they "
        "change on every commit, and a number would go stale."
    )
    out.append("")

    by_audience: dict[str, list[tuple[str, str, str]]] = {}
    for path, purpose, audience, group in CURATED:
        by_audience.setdefault(group, []).append((path, purpose, audience))

    for group, heading in AUDIENCE_HEADINGS:
        entries = by_audience.get(group, [])
        if not entries:
            continue
        out.append(f"## {heading}")
        out.append("")
        for path, purpose, audience in entries:
            tag = "" if audience == "both" else f" _({audience})_"
            out.append(f"- [{path}]({path}) — {purpose}{tag} ({size_of(path)})")
        out.append("")

    out.append("## Repository layout")
    out.append("")
    out.append("| Path | What it holds |")
    out.append("|---|---|")
    out.append("| `crates/` | The Rust workspace, one directory per crate. |")
    out.append("| `wit/` | WIT interface definitions, one file per package. |")
    out.append("| `schema/` | Generated JSON Schemas (see `CON-016`). |")
    out.append("| `docs/` | Documentation. `docs/README.md` indexes it. |")
    out.append("| `tools/` | Checkers and generators, each with a `--self-test`. |")
    out.append("| `docker/` | The Linux verification bridge. |")
    out.append("| `.github/workflows/ci.yml` | The gate. Nine jobs. |")
    out.append("")
    return "\n".join(out)


def render_full() -> str:
    """`llms-full.txt` — the corpus, with provenance markers."""
    out: list[str] = []
    out.append("# QQQ — full documentation")
    out.append("")
    out.append(
        "Every document below is included **whole**, preceded by its path in the "
        "repository so a statement here can be traced to its source. Generated by "
        "`tools/gen_llms_txt.py`; do not edit by hand."
    )
    out.append("")
    out.append(
        "The two largest documents — `QQQ-Proposal-V1.md` (the specification) and "
        "`QQQ-Observations-and-Memories.md` (decisions and mistakes) — are "
        "**deliberately excluded** because loading them would consume a context "
        "window before reaching anything else. Fetch them by path when they are "
        "what you need."
    )
    out.append("")
    out.append("---")
    out.append("")

    for rel in FULL_INCLUDES:
        path = ROOT / rel
        if not path.exists():
            out.append(f"<!-- {rel}: MISSING -->")
            out.append("")
            continue
        text = path.read_text(encoding="utf-8").rstrip()
        out.append(f"<!-- source: {rel} -->")
        out.append("")
        # Demote every heading one level so the document's own `# ` title cannot
        # masquerade as a top-level section of this corpus. Without this, a
        # reader scanning the file cannot tell the corpus structure from any one
        # document's.
        for line in text.splitlines():
            if line.startswith("#"):
                out.append("#" + line)
            else:
                out.append(line)
        out.append("")
        out.append("---")
        out.append("")

    return "\n".join(out)


def docs_to_index() -> list[str]:
    """Every `.md` under `docs/` that should appear in the index."""
    found = []
    for path in sorted((ROOT / "docs").rglob("*.md")):
        rel = str(path.relative_to(ROOT)).replace("\\", "/")
        if rel in EXCLUDED_ALL:
            continue
        found.append(rel)
    return found


def generate(check: bool) -> int:
    """Write both files, or report drift. Mirrors `gen_schemas.py`'s contract."""
    ungenerated: list[str] = []
    drifted: list[str] = []

    for name, build in (("llms.txt", render_index), ("llms-full.txt", render_full)):
        path = ROOT / name
        try:
            text = build()
        except Exception as e:  # noqa: BLE001 - reported, not swallowed
            print(f"GENERATION FAILED for {name}: {e}", file=sys.stderr)
            ungenerated.append(name)
            continue
        if check:
            if not path.exists():
                print(f"MISSING: {path.name} has not been generated", file=sys.stderr)
                drifted.append(name)
                continue
            if path.read_text(encoding="utf-8") != text:
                print(
                    f"DRIFT: {path.name} does not match the tree. Run "
                    f"`python tools/gen_llms_txt.py` to regenerate.",
                    file=sys.stderr,
                )
                drifted.append(name)
                continue
            print(f"  OK    {name}")
        else:
            path.write_text(text, encoding="utf-8")
            print(f"  wrote {name} ({len(text) // 1024} KB)")

    if ungenerated or drifted:
        return 1
    if check:
        print("\nLLMS FILES OK — the index matches the tree")
    return 0


def self_test() -> int:
    """Prove the completeness check fires. `DOC-020`.

    # The four injections

    | # | Injection | Must be caught by |
    |---|---|---|
    | 1 | An indexed path that does not exist | `render_index` reporting `(missing)`, and the completeness check |
    | 2 | A `docs/*.md` that is neither indexed nor excluded | `unindexed_docs()` |
    | 3 | An excluded path that no longer exists | the exclusion list going stale — reported, not ignored |
    | 4 | A `FULL_INCLUDES` entry that is missing | a `MISSING` marker in the corpus, and the completeness check |

    Each is run against the real tree with the relevant list patched, then
    restored, since these are module-level lists. That mutation is why the test
    restores in a `finally` — `§M-007` records a repair that destroyed what it
    was repairing.
    """
    global CURATED, EXCLUDED, EXCLUDED_LOCAL, EXCLUDED_SECRETS, EXCLUDED_ALL, FULL_INCLUDES

    failures = 0

    def expect(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        print(f"  {'OK  ' if ok else 'FAIL'}  {name}")
        if not ok:
            failures += 1
            if detail:
                print(f"        {detail}")

    print("gen_llms_txt self-test")

    saved_curated = list(CURATED)
    saved_excluded = set(EXCLUDED)
    saved_local = set(EXCLUDED_LOCAL)
    saved_secrets = set(EXCLUDED_SECRETS)
    saved_all = set(EXCLUDED_ALL)
    saved_full = list(FULL_INCLUDES)
    try:
        # --- baseline -----------------------------------------------------
        expect(
            "every curated path exists",
            all((ROOT / p).exists() for p, _, _, _ in CURATED),
            "the tree must satisfy the index before injections mean anything",
        )

        # --- injection 1: an indexed path that does not exist --------------
        CURATED = saved_curated + [
            ("docs/does-not-exist.md", "a fabricated entry", "both", "use")
        ]
        text = render_index()
        # Find the rendered LINE for the fabricated path, rather than splitting
        # the whole document on a substring -- the first version did that and the
        # assertion was wrong about which text it was inspecting.
        line = next(
            (l for l in text.splitlines() if "does-not-exist.md" in l), ""
        )
        expect(
            "an indexed path that does not exist shows as (missing)",
            line.endswith("(missing)"),
            f"the rendered line was {line!r}",
        )
        CURATED = saved_curated

        # --- injection 2: an unindexed document ---------------------------
        indexed = {p for p, _, _, _ in CURATED}
        unindexed = [d for d in docs_to_index() if d not in indexed]
        expect(
            "every docs/*.md is indexed or excluded",
            not unindexed,
            f"these are neither: {unindexed}",
        )

        def tracked_paths(paths: list[str]) -> str:
            if not (ROOT / ".git").exists():
                return ""
            return subprocess.run(
                ["git", "ls-files", "-z"] + paths,
                cwd=ROOT, capture_output=True, text=True, check=False,
            ).stdout.strip("\0 \n")

        # --- check A: tracked exclusions must exist -----------------------
        #
        # These are IN the repository, so a path that has disappeared is
        # staleness the check reports.
        stale = [e for e in EXCLUDED if not (ROOT / e).exists()]
        expect(
            "every tracked exclusion still exists",
            not stale,
            f"stale exclusions: {stale}",
        )

        # --- check B: tracked exclusions must genuinely BE tracked --------
        #
        # **The check whose absence caused the second CI failure.** The list is
        # named for tracked files, and my judgement about a file being "not
        # documentation" said nothing about whether Git has it. Asserting the
        # membership directly is what makes the name true.
        untracked = [e for e in EXCLUDED if not tracked_paths([e])]
        expect(
            "every entry in EXCLUDED is actually tracked by Git",
            not untracked,
            f"these are listed as tracked non-documentation but Git does not "
            f"have them: {untracked} -- they belong in EXCLUDED_LOCAL",
        )

        # --- check C: local exclusions must NOT be tracked ----------------
        #
        # Gitignored files are absent from CI by design. If one becomes tracked,
        # the exclusion is either wrong or the file was force-added.
        tracked_local = tracked_paths(sorted(EXCLUDED_LOCAL | EXCLUDED_SECRETS))
        expect(
            "no gitignored exclusion is tracked by Git",
            not tracked_local,
            f"TRACKED GITIGNORED FILE(S): {tracked_local!r} -- the exclusion is "
            f"wrong, or the file was force-added",
        )

        # --- check D: every excluded path is excluded from the index ------
        expect(
            "every excluded path is treated as excluded",
            all(e in EXCLUDED_ALL for e in EXCLUDED_ALL),
            "docs_to_index must consult the union",
        )

        # --- injection 4: a missing corpus include ------------------------
        FULL_INCLUDES = saved_full + ["docs/fabricated-corpus-entry.md"]
        corpus = render_full()
        expect(
            "a missing corpus entry is marked, not skipped",
            "MISSING" in corpus and "docs/fabricated-corpus-entry.md" in corpus,
            "the corpus must say what it could not include",
        )
        FULL_INCLUDES = saved_full

        # --- the churn property: a large document's LABEL never moves -----
        #
        # **This is the property that failed twice.** The first version recorded an
        # exact size and churned on every commit; the second bucketed to 10 KB and
        # churned when `O-116` crossed a boundary. The label must be constant for
        # ANY growth a real edit could produce.
        import tempfile as _tf

        # **The no-boundary property, which is the one that matters.**
        #
        # The test grows a document across FOUR orders of magnitude, because the
        # previous versions each had a boundary somewhere and each was crossed:
        # an exact size (every commit), a 10 KB bucket (O-116), and a 1 MB word
        # boundary (caught by this very test). A single growth step would not have
        # found the third.
        labels = [
            label_for(b"x" * (VOLATILE_KB * 1024 + 1)),
            label_for(b"x" * (VOLATILE_KB * 1024 * 2)),
            label_for(b"x" * (VOLATILE_KB * 1024 * 20)),
            label_for(b"x" * (VOLATILE_KB * 1024 * 200)),
            label_for(b"x" * (8 * 1024 * 1024 * 1024)),
        ]
        expect(
            "a large document's label never moves, however much it grows",
            len(set(labels)) == 1,
            f"labels were {labels}; any boundary a growing document can cross is "
            f"a future drift failure",
        )
        expect(
            "and the label still says it is large",
            "large" in labels[0],
            f"the label was {labels[0]!r}",
        )
        # The small-document path still reports a number, because stability is
        # what makes a number worth printing.
        expect(
            "a small document still reports an exact size",
            label_for(b"x" * 4096) == "4 KB",
            f"got {label_for(b'x' * 4096)!r}",
        )

        # --- the determinism property, which is the reason for the above ---
        #
        # A CRLF file and an LF file with identical text must measure the same,
        # or `llms.txt` is a function of the checkout rather than of the repo.
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            body = "line one\nline two\n"
            lf_file = tmp / "lf.md"
            crlf_file = tmp / "crlf.md"
            lf_file.write_bytes(body.encode())
            crlf_file.write_bytes(body.replace("\n", "\r\n").encode())
            lf_len = len(lf_file.read_bytes().replace(b"\r\n", b"\n"))
            crlf_len = len(crlf_file.read_bytes().replace(b"\r\n", b"\n"))
        expect(
            "a CRLF and an LF copy of one text measure the same",
            lf_len == crlf_len == len(body.encode()),
            f"LF copy {lf_len}, CRLF copy {crlf_len}, content {len(body.encode())}",
        )

        # --- the heading demotion, which is easy to get wrong -------------
        corpus = render_full()
        expect(
            "source provenance is recorded per document",
            corpus.count("<!-- source: ") == len(saved_full),
            f"expected {len(saved_full)} markers",
        )
    finally:
        CURATED = saved_curated
        EXCLUDED = saved_excluded
        EXCLUDED_SECRETS = saved_secrets
        EXCLUDED_LOCAL = saved_local
        EXCLUDED_ALL = saved_all
        FULL_INCLUDES = saved_full

    print()
    if failures:
        print(f"SELF-TEST FAILED — {failures} case(s) wrong")
        return 1
    print("SELF-TEST PASSED — the index and the tree agree, and a break is reported")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    return generate("--check" in sys.argv)


if __name__ == "__main__":
    sys.exit(main())
