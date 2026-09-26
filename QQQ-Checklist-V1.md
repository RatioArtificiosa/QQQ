# QQQ — Implementation Checklist v1.0

> **Every item cites the exact Proposal section it implements. Every Proposal section cites its items.**
> This file is executable, dependency-ordered, and machine-checkable.

| Field | Value |
|---|---|
| **Document** | QQQ-Checklist-V1.md |
| **Version** | 1.0.0 |
| **Status** | Draft for founder review |
| **Date** | 2026-09-19 |
| **Companion** | [`QQQ-Proposal-V1.md`](./QQQ-Proposal-V1.md) · [`QQQ-Observations-and-Memories.md`](./QQQ-Observations-and-Memories.md) |

---

## 1. Areas

Each item ID is `AREA-NNN`. IDs are **never reused, never renumbered**; a dropped item becomes `AREA-NNN [DROPPED → AREA-MMM]`.

| Area | Meaning | Count | Owner role |
|---|---|---|---|
| `FND` | Foundation: repo, CI, process, tooling | 12 | Architect |
| `DOC` | Documentation, docs-as-code, cross-reference machinery | 21 | Tech writer |
| `MKT` | Market research, positioning, competitive analysis | 16 | Founder |
| `POS` | Product positioning and messaging | 6 | Founder |
| `ARCH` | Architecture decisions and crate topology | 16 | Systems lead |
| `HOST` | `qqq-host` execution engine | 24 | Systems engineer |
| `CAP` | Capability resolution pipeline | 16 | Security engineer |
| `SEC` | Security engineering, audits, hardening | 30 | Security engineer |
| `CON` | Contracts: WIT interfaces, manifest schema, versioning | 18 | Architect |
| `ABI` | WIT package authoring and binding generation | 16 | Runtime engineer |
| `SRV` | HTTP/application server | 21 | Systems engineer |
| `PKG` | Package manager and registry | 24 | Platform engineer |
| `SUP` | Supply chain: signing, provenance, SBOM | 12 | Security engineer |
| `DX` | Developer experience, CLI ergonomics, errors | 20 | DX engineer |
| `CLI` | CLI commands | 24 | DX engineer |
| `TEST` | Test runner and test infrastructure | 18 | Runtime engineer |
| `MIG` | Migration tooling | 14 | DX engineer |
| `AI` | `qqq:ai` inference capability | 10 | Runtime engineer |
| `LANG` | Language toolchains (5 languages) | 40 | Runtime engineer |
| `AGENT` | Agent face: MCP, schemas, machine contracts | 25 | Architect |
| `PERF` | Performance: benchmarks, budgets, optimizations | 27 | Performance engineer |
| `DET` | Determinism and replay | 16 | Systems engineer |
| `OBS` | Observability: logs, metrics, traces, audit | 18 | Platform engineer |
| `DIST` | Distribution and installation | 20 | Platform engineer |
| `GTM` | Go-to-market execution | 14 | Founder |
| `LIC` | Licensing | 12 | Founder + counsel |
| `GOV` | Governance and community | 14 | Founder |
| `PLAN` | Project management, milestones, tracking | 20 | Architect |
| `RISK` | Risk tracking and mitigation | 15 | Founder |
| `DOD` | Definition-of-done verification for V1 | 24 | Architect |
| `FUT` | Deferred / future work stubs | 12 | Architect |
| `OQ` | Open questions requiring a decision | 12 | Founder |

**Total: 587 items.**

### Status legend

| Symbol | Meaning |
|---|---|
| `[ ]` | Not started |
| `[~]` | In progress |
| `[x]` | Done and verified |
| `[!]` | Blocked (reason recorded in Observations) |
| `[-]` | Dropped / deferred (successor ID recorded) |

### Verification rule

CI runs `tools/check-xrefs/`, which fails the build if any item cites a Proposal anchor that does not exist, any Proposal section cites a nonexistent item ID, or any item lacks a Proposal citation.

---

## 2. Phase map

Items are grouped below by **phase**, because dependency order matters more than area for planning. Areas are the stable identity; phases are the schedule.

| Phase | Name | Milestone | Areas touched |
|---|---|---|---|
| **P0** | Foundation | M0 | FND, DOC, LIC, GOV, PLAN |
| **P1** | Heartbeat | M1 | HOST, ARCH, CON |
| **P2** | Capability engine | M2 | CAP, SEC |
| **P3** | HTTP | M3 | SRV, ABI |
| **P4** | DX v0 | M4 | DX, CLI, DIST |
| **P5** | Languages | M5, M8 | LANG |
| **P6** | Packages | M6 | PKG, SUP |
| **P7** | Agent face | M9 | AGENT, TEST, MIG |
| **P8** | Performance and determinism | M3–M10 | PERF, DET, OBS |
| **P9** | V1 release | M10, M11 | DOD, MKT, POS, GTM, RISK |
| **P10** | Beyond V1 | post-1.0 | FUT, AI, OQ |

---

## 3. P0 — Foundation (M0)

### FND — Foundation

- [x] **FND-001** Create the Cargo workspace with the crate topology from the proposal.
  → Done: `Cargo.toml` declares the workspace, with per-crate tier and Proposal-section comments.
  → **The naming invariant `§D-001` is now enforced rather than trusted.** The
    objective states that *"a build producing a `qqq` binary is a defect"*; that
    was previously verified once by hand (`cargo build -p qqq-run` yields
    `qqqai.exe` and no `qqq.exe`), and a verified-once fact decays. Four tests in
    `crates/qqq-core/tests/naming.rs` enforce it: every declared `[[bin]]` is
    `qqqai`; a crate with `src/main.rs` and no `[[bin]]` stanza is a violation
    (Cargo would name that binary after the package); no package is named `qqq`;
    and no document teaches a bare `qqq <subcommand>`. The last one scans for
    `qqq` followed by one of 26 known subcommands and excludes matches preceded
    by `qqqai` or `-`, because the brand appears legitimately everywhere and
    `qqq-` prefixes crate names — checking the property rather than the string.
    `tools/fault_inject_naming.py` injects a `qqq` binary, a `qqq new` doc
    example and a package named `qqq`; **all three are detected** (`§O-060`).
  → §4.3 Crate topology
- [x] **FND-002** Write `PRINCIPLES.md` at the repository root, containing the eight non-negotiables verbatim plus the operationalization table.
  → Done: `PRINCIPLES.md` at the repository root, with the operationalization table.
  → §2 The Eight Non-Negotiables, Operationalized
- [x] **FND-003** Adopt a Conventional-Commits-compatible commit policy with signed commits required on `main`.
  → Done: Conventional Commits used throughout; see `git log` and CONTRIBUTING.md §Commit messages.
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship
- [x] **FND-004** Build the CI matrix: Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64, Windows x86_64.
  → Done: `.github/workflows/ci.yml` — Rust on ubuntu, macos and windows.
  → §11.1 Install channels, in priority order
- [x] **FND-005** Add `cargo-deny` (licence and advisory policy), `cargo-machete` (unused deps), and `cargo-clippy` with `-D warnings` to CI.
  → Done: `cargo-deny`, `cargo-machete` and `clippy -D warnings` are all required CI steps, with the `continue-on-error` escape hatches removed now that `deny.toml` exists.
  → §2.2 NN-2 — Security and Isolation Are Non-Optional
- [x] **FND-006** Establish the ADR (Architecture Decision Record) process and template; create `docs/adr/`.
  → Done: `docs/adr/README.md` — the ADR process and template, pointing at the canonical register in Observations §2 rather than duplicating it.
  → §0.5 Identifier and anchor discipline
- [x] **FND-007** Add the PR template that requires naming any Principle the change touches.
  → Done: `.github/PULL_REQUEST_TEMPLATE.md` requires naming which of the eight Non-Negotiables the change touches, with the principle names taken from Proposal §2.
  → §2 The Eight Non-Negotiables, Operationalized
- [ ] **FND-008** Configure branch protection on `main`: required review, required CI, signed commits, linear history.
  → Partial: branch protection is a repository setting, not a file; it is not verifiable from inside the tree.
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship
- [x] **FND-009** Set up the security policy, `SECURITY.md`, and a private vulnerability reporting channel.
  → Done: `SECURITY.md` — the reporting channel and the patch-target table by severity.
  → §7.2 Adversary model
- [x] **FND-010** Establish the release-engineering pipeline: versioning, changelog generation, artifact signing hooks.
  → §11.1 Install channels, in priority order
  → Done, all three parts, each measured rather than asserted.
  → **Versioning** — `tools/release.py`. The version comes from `Cargo.toml` (the thing the
    binaries are built from) and the **tag is checked against it** rather than the reverse, so an
    artifact can never claim a version no tag points at. `--expect-tag` is the release workflow's
    gate, kept in the tool so the comparison is one rule in one place. Measured:
    `0.0.0 → 1.0.0`, a major bump, because the history contains `feat!` commits — the correct
    reading of a pre-1.0 tree whose first tagged release is 1.0.0.
  → **Changelog generation** — from Conventional Commits, which `CONTRIBUTING.md` already
    requires, so the history carries the structure and the changelog is a rendering of it.
    Measured: **324 commits, 232 entries across 5 sections**; `chore`/`ci`/`test`/`build`/`style`
    are collected as `Internal` rather than dropped or allowed to bury the features, and an
    unparseable subject is reported rather than filed under a guess.
  → **Artifact signing hooks** — `.github/workflows/release.yml`, five jobs
    (`releasable → build → sign → verify → publish`). The hook is a **spec**, not a
    re-implementation: the primitive is `qqq_pkg::signature::sign`, the verification is `qqqai
    verify`, and a Python copy of the format would be a second thing to be wrong. Two choices
    worth recording: **a missing signing key fails the job** (§11.1: "an installer that cannot be
    verified is an installer that will be backdoored eventually"), and **verification uses the
    product**, including a negative control asserting `qqqai verify` refuses an unsigned artifact
    under `--policy require` — so a verifier that always passed would not look identical.
  → **The attestation half is not faked.** `qqqai verify` reports
    `attestation: not_checked (owned by SUP-004)` and the workflow asserts that it does. A release
    page claiming attestation over nothing would be the worst place for that lie, since it is the
    artifact a user is asked to trust.
  → Verified: `python tools/release.py --self-test` **21/21**, each proved to reject breakage,
    including the negative control that `--expect-tag v9.9.9` fails against a `0.0.0` manifest;
    `--check` reports the tree releasable; and the workflow's two `qqqai verify` assertions were
    run against the real binary — the unsigned refusal exits non-zero with the digest reported,
    and the attestation gap prints with its owner.
- [x] **FND-011** Delete the scratch verification crate at `.scratch/witprobe` once its findings are folded into the test suite; port its three assertions into `crates/qqq-host/tests/`.
  → Done: `.scratch/witprobe` deleted; its four assertions ported to `crates/qqq-host/tests/engine.rs` with control cases (4 tests pass).
  → §0.4 How to read the cross-references
- [x] **FND-012** Install `wasm-tools` and the `wasmtime` CLI into the developer bootstrap script (both were found missing on the reference machine).
  → Done: `tools/bootstrap.sh` (bash) and `tools/bootstrap.ps1` (PowerShell),
    both with `--check` / `-Check` for CI. Measured on the reference machine
    before: **`wasm-tools 1.259.0` present, the `wasmtime` CLI absent** — so the
    item's premise was still exactly true.
  → **End-to-end proof rather than a claim.** `-Check` reported
    `the wasmtime CLI is not installed`, printed
    `cargo install wasmtime-cli --version ^48 --locked`, that command installed
    **`wasmtime-cli v48.0.2`**, and the re-check then passed:
    `wasmtime 48.0.2 (matches the pinned crate major)`. The detection, the
    remediation and the verification are the same loop, exercised for real.
  → **Every version comes from a file in the repository.** The first draft pinned
    wasmtime to `27.0.0` from memory; `Cargo.toml` says `wasmtime = "48"`,
    `Cargo.lock` resolves `48.0.2`, and `docs/reconciliation.md` records the pin
    as a deliberate correction. A script installing 27 would have produced a CLI
    that cannot instantiate the components the engine loads (`§O-113`).
  → **For `wasm-tools` — not a Rust dependency, so unpinnable — the check is
    CAPABILITY, not a version string**: it must parse every `wit/` file. A version
    is a proxy for *"will this work"*, and `§O-109` records four measurements of
    one property where three were proxies and all three were wrong.
  → **Two defects the script's own runs found, both fixed.** It first ran
    `wasm-tools component wit wit/` as a directory-wide check, which **correctly**
    fails — `wit/` holds 15 separate packages, each declaring its own `package` —
    and then blamed the tool (*"too old for this encoding"*), sending the reader
    to `cargo install --force`, which would not have helped. The diagnostic named
    the wrong cause: `§O-106`'s lesson for the fourth time this session. Now per
    file, matching `tools/check_wit.py`. And `bootstrap.sh` shipped with CRLF,
    which bash refused with ``syntax error near unexpected token `do\r'`` —
    `§O-086` recurring in the workflow rather than the runtime.
  → **Three outcomes, not two**: `ok` / `warn` / `fail`, because *present but
    wrong* and *absent* need different fixes (an upgrade versus an install), and
    reporting both as "not found" sends the reader to the wrong command — the
    same distinction `SEC-019`'s hardening report makes with four variants where
    a bool would collapse two real situations.
  → Auxiliary CI tools (`cargo-fuzz`, `cargo-cyclonedx`, `cargo-deny`,
    `cargo-machete`) are warnings rather than failures: a contributor can run
    `cargo test` without them and should not be blocked from starting, but should
    know before opening a PR that fails.
  → §12.1 The first ten minutes (a spec, not a wish)

### DOC — Documentation machinery

- [ ] **DOC-021** Keep the executive summary in the Proposal synchronised with reality: re-verify its three falsifiable claims against the benchmark suite and the security artifacts at every milestone, and correct them publicly when they no longer hold.
  → §0.1 Executive summary
- [x] **DOC-001** Create `README.md` — the public front door (see `QQQ-Observations-and-Memories.md §D-009` for the brief).
  → Done: `README.md` at the repository root.
  → §0.3 Document map
- [x] **DOC-002** Create `QQQ-Proposal-V1.md` as the canonical technical proposal.
  → Done: `QQQ-Proposal-V1.md`.
  → §0.3 Document map
- [x] **DOC-003** Create `QQQ-Checklist-V1.md` as the canonical work breakdown.
  → Done: `QQQ-Checklist-V1.md`.
  → §0.3 Document map
- [x] **DOC-004** Create `QQQ-Observations-and-Memories.md` as the institutional-memory record.
  → Done: `QQQ-Observations-and-Memories.md`.
  → §0.3 Document map
- [x] **DOC-005** Add a `docs/README.md` index that explains the three-document system and how to keep them in sync.
  → Done: `docs/README.md` — the three documents and their division of labour, the
    rule that a claim lives in the Proposal *or* the Observations and never both, the
    numbered checks each harness proves (listed with the harness that drives it, not
    from the validator's shorter docstring), and the change recipes.
  → The first draft listed twelve checks from the validator's module docstring; the
    self-test drives nine. Counting coverage from the thing that *exercises* it is the
    correction.
  → **2026-09-22 — the bare count is gone, because a bare count is what drifts.** This
    entry said `self_test_xrefs.py` exercises "nine" checks, and that was true of the
    only harness that existed. A second harness now covers four the in-place one cannot
    reach safely (`[3]` wants a repeated heading, `[5]` an uncited section, `[7]` and
    `[11]` a stub marker in a source file), so the page names both phases instead of a
    total. The failure this avoids is the one `SEC-020` records against itself: a number
    true when written, never tied to the tree, and wrong by the time anyone rereads it.
    `docs/README.md` tables each rule against the harness that proves it. Measured in
    `§O-187`.
  → §0.4 How to read the cross-references
- [x] **DOC-006** Build `tools/check-xrefs/` — the cross-reference validator described in the proposal.
  → Done: `tools/check_xrefs.py` — checks over the Proposal/Checklist/Observations graph.
  → §0.4 How to read the cross-references
- [x] **DOC-007** Wire `check-xrefs` into CI as a required check.
  → Done: `check_xrefs.py` and `self_test_xrefs.py` are both required steps in the `xrefs` CI job.
  → §0.4 How to read the cross-references
- [x] **DOC-008** Document the anchor derivation and stability rules in `docs/contributing/anchors.md`.
  → Done: `docs/contributing/anchors.md` — the exact five-step anchor algorithm
    (including that `§6.4` becomes `64-` and not `6-4-`, which surprises people),
    the stability and tombstone rules, the `AREA-NNN` identifier rules, the
    Observations prefixes, and the stub-marker convention.
  → Records that observations are **not renumbered** on insertion: a new one takes the
    next free number even when it belongs earlier. Renumbering would invalidate every
    existing citation to make a reading order nicer.
  → §0.5 Identifier and anchor discipline
- [x] **DOC-009** Implement the stub-marker convention (`// QQQ-STUB(<ID>): …`) and a CI check that every stub marker has a matching Observations entry.
  → Done: `QQQ-STUB(<ID>)` markers are validated against checklist items by `check_xrefs.py` checks [7] and [11], including the bidirectional case, as a required CI step.
  → §0.5 Identifier and anchor discipline
- [x] **DOC-010** Implement the tombstone convention for retired anchors and add a CI check that no anchor is silently deleted.
  → Done: `tools/check_tombstones.py` + a committed baseline of **93 Proposal anchors** in
    `.anchor-baseline.txt`. An anchor in the baseline that disappears without a tombstone
    fails the build, which is what makes "never deleted" enforceable rather than a rule
    people remember.
  → **Compared against a baseline, not against git.** A `git` diff detects *change*, so it
    fires on every legitimate in-progress edit and says nothing about deletion
    specifically. The baseline answers the actual question, and it only ever grows.
  → Also enforced: a tombstone must use the documented `(retired — see §X.Y)` form, must
    point at a section that **exists**, and no two live headings may derive one anchor.
  → **Three real bugs, all found by the self-test rather than by reading the code**, and
    all three were the same shape — a check whose input set excluded its target:
    1. The anchor derivation **dropped the section number**, producing `capability-engine`
       where the correct anchor is `64-capability-engine`. Every anchor it computed was
       wrong, and it was *internally consistent and consistently incorrect*, so only the
       synthetic cases caught it.
    2. The fixtures then disagreed with the code for the same reason, so two cases reported
       DEAD while the code was right. Fixtures now derive their anchors through the same
       helper as the parser, so they cannot encode a different rule.
    3. A heading marked `(retired)` with **no successor** was not recognised as retired at
       all, so the rule requiring a successor never fired on exactly the case it exists for.
  → The baseline had to be **rebuilt** rather than updated: `--update` unions, so the 93
    wrong entries written by the buggy derivation could not be removed by the check that
    owns them. The check correctly reported all 93 as disappeared, and the header records
    the history.
  → 7/7 self-test cases.
  → §0.5 Identifier and anchor discipline
- [x] **DOC-011** Publish `docs/glossary.md` generated from the Proposal glossary, with anchors.
  → Done: `tools/gen_glossary.py` generates it from the Proposal's §0.6 table;
    `tools/check_glossary.py` verifies it, in CI and in the bridge.
  → 18 terms, each linking to its Proposal anchor. The generated header says so, names
    the source and the command, and says not to hand-edit — a generated file that does
    not announce itself gets edited and then silently reverted.
  → The self-test covers **both** drift directions: a hand-edit to the output, and a
    new term in the source. The second is the one that actually happens, and the first
    version of a check like this often only tests the other. 4/4 cases.
  → §0.6 Glossary
- [x] **DOC-012** Add a CI check that every glossary term used in WIT doc comments exists in the glossary.
  → Done: `tools/check_glossary_usage.py` — scans all `///` lines in `wit/` (631
    across 13 files) for six curated *confusable pairs*: terms QQQ defines differently
    from the industry, where using the industry word is not a typo but a second
    vocabulary. `wasm module` → `component`, `plugin` → `component`, `permission` →
    `capability` and three more.
  → **Two rules were removed after their first run**, and that is the interesting part.
    `thread` and `container` both fired on ordinary English ("would force every
    consumer onto its own thread", "the container image is read-only"), where neither is
    a vocabulary mistake. A check that fires on prose gets disabled, and a disabled
    check is worth nothing, so a rule must catch a *mistake* rather than a word. The
    removal is recorded in the source rather than done silently, because the next person
    will reach for `thread` too.
  → Matching is word-boundary, so `containerisation` does not fire on `container`.
  → 14/14 self-test cases: every rule must fire on positive input, and the negative
    cases are the false positives that would have got it disabled.
  → §0.6 Glossary
- [x] **DOC-013** Maintain `docs/reconciliation.md` tracking every correction made to the source corpus, kept in sync with Appendix A.
  → Done: `tools/gen_reconciliation.py` regenerates the table between explicit
    `GENERATED:BEGIN`/`END` markers, so the file's prose — the part worth reading —
    survives regeneration. 6 corrections, matching Appendix A and the `§C` entries.
  → `tools/check_reconciliation.py` verifies all three agree and **refuses to generate
    from a drifted source**, so the generator can never be the thing that launders a
    disagreement into a third document. 5/5 self-test cases covering all three drift
    directions.
  → §0.4 How to read the cross-references
- [x] **DOC-014** Publish the vocabulary and claims rules as `docs/contributing/claims-policy.md`.
  → Done: `docs/contributing/claims-policy.md` — the four claim kinds (measured,
    derived, intended, absent) and the evidential requirement of each; the rules on
    numbers, modality, mechanism-naming and uncertainty; and the vocabulary table.
  → Bans **"should"** outright: it hides whether something happens or merely ought to.
    Distinguishes **verify** (the author ran a command) from **validate** (an adversary
    tried to break it) — which is why this project says the capability model is
    *verified*, and why the threat model's validation column reads `No` everywhere.
  → The first draft's example cited `cargo bench --bench instantiate`, which does not
    exist. Caught by running it, and kept in the document as the example of the exact
    failure the page warns about.
  → §0.5 Identifier and anchor discipline
- [x] **DOC-015** Add the "framework vs runtime" usage rule to the contributing guide.
  → §3.4 Positioning statement and the language we use
  → Done: a new "The words we use: runtime vs framework" section in `CONTRIBUTING.md`, placed
    directly after "Read these first" so it is read before any copy is written, with a two-row
    table giving the say/for/example for each word and three rules that apply to all copy
    (README, `docs/`, CLI help and error text, commit messages, issue replies).
  → The rule is stated as a positioning matter rather than a style preference, because that is
    what it is: Proposal §3.4 makes vocabulary discipline the only mitigation for risk `R-10`
    ("Framework" positioning confuses the market). The section names the canonical one-sentence
    positioning and points at §3.4's four vocabulary rules, so the guide defers to the Proposal
    rather than restating it and drifting.
  → The third rule covers the comparison words ("Bun-killer", "a faster Node") under the same
    principle — say what is true, and when the claim is about speed, say *measured*, give the
    number, and name the file — which is the rule a contributor is most likely to break in a
    commit message or a changelog entry.
  → Verified: `python tools/check_xrefs.py` passes (§ references resolve, no new anchor
    duplicates), and `python tools/gen_llms_txt.py --check` confirms the generated index still
    matches the tree after the edit.
  → §3.4 Positioning statement and the language we use
- [x] **DOC-016** Publish `docs/verified-facts.md` as the live, dated register of external facts the project depends on, with a re-verification cadence.
  → Done: `docs/verified-facts.md` — **30 facts** from the Proposal's Appendix B, each
    with its verification method and a **re-verification cadence**.
  → The cadence is per fact rather than one date for the whole register, because a
    register with a single "verified on" date rots as a whole: nobody knows which rows
    still hold, and finding out means re-verifying everything — expensive enough that
    it does not happen. Four classes: perishable (7 days), volatile (30), local (7),
    stable (180). Spread: 6 / 10 / 1 / 13.
  → The class is **derived from the fact's own text**, so a new row gets a plausible
    cadence without anyone remembering to classify it — and an unclassifiable row is
    reported rather than guessed at.
  → That report earned its place immediately: the first pass left **8 of 30 facts
    unclassified**, and every one was the same kind — an API or specification property
    (B-12's `epoch_interruption`, B-29's "a component may not export a memory"). Those
    need a cadence *more* than the version numbers do, because a version bump is noticed
    while an API property disappearing in a major release is exactly what a re-check
    catches.
  → A self-test case also caught a rule-ordering bug: `Local toolchain: rustc 1.97.1`
    classified as **perishable**, because the version-number rule fired before the
    local one. The cadence happened to match; the class was wrong, and a reader losing
    a machine property among the published ones cannot tell what they are looking at.
  → `LAST_VERIFIED` lives in the generator rather than the generated file, because
    bumping it is how a re-verification is *recorded* — an action, not a document edit.
  → 10/10 self-test cases.
  → §0.4 How to read the cross-references
- [x] **DOC-017** Generate the WIT reference documentation from `wit/` into Markdown, with per-language examples.
  → Done: `docs/wit-reference.md` — <!-- qqq:claim wit-packages -->15<!-- /qqq:claim --> packages,
    <!-- qqq:claim wit-interfaces -->22<!-- /qqq:claim --> interfaces,
    **<!-- qqq:claim wit-functions -->80<!-- /qqq:claim --> functions** and
    <!-- qqq:claim wit-types -->53<!-- /qqq:claim --> types, generated from `wit/` by
    `tools/gen_wit_reference.py` and verified by
    `tools/check_wit_reference.py` in CI and in the bridge. The page states its own
    counts in its first line, so these are read from there rather than carried: this
    entry said 13/20/71/47 until 2026-09-23, and only the entry was wrong.
  → **Per-language examples are deliberately NOT emitted**, and the page says so rather
    than showing plausible ones. A Rust or TypeScript example is only known correct once
    it compiles against the real bindings, and no `qqq-abi` consumer exists to compile
    against yet. An unbuildable example is documentation that *looks* verified; the
    section lands with `ABI-*`.
  → Two real parser bugs found by checking counts rather than eyeballing output: nested
    `record`/`enum` blocks ended an interface early (so `qqq:http http` reported **0
    functions** while exporting three), and `resource` methods at brace depth 2 were
    missed entirely (so the filesystem interface listed no way to use the filesystem).
    Both outputs were valid Markdown that looked plausible. 71 vs 2 functions.
  → A third: a variant's case docs leaked into the following resource's description.
  → 11/11 self-test cases, built to detect exactly those three.
  → §11.3 Documentation as a product surface
- [x] **DOC-018** Build the documentation freshness test: compile a sample project against the published docs and fail on drift.
  → §2.6 NN-6 - Human + Machine Documentation Parity
  → Done for the half that is decidable, and the other half is stated rather than implied.
  → **What already covered the generated documents.** Five of the published pages are
    generated — `errors.md`, `glossary.md`, `reconciliation.md`, `verified-facts.md`,
    `wit-reference.md` — and each has a generator with a `--check` half. Verified: all five
    run in `ci.yml` **and** `docker/entrypoint.sh`, so a generated page that drifts from its
    source already fails the build.
  → **What was not covered, and is now.** Hand-written documents asserting a count beside a
    tool that re-derives it. Measured: `docs/unsafe-audit.md`'s `.rs` file count drifted
    **four times in one working period** — 141→142, 142→143, 143→146, 146→147 — and
    every occurrence was caught by CI rather than locally. The Observations document had already
    named the rule: *"the failure is not the original number; it is that nothing re-derives a
    number printed beside a tool that re-derives it."*
  → `tools/check_doc_claims.py` implements that. A claim is **opt-in** and names a *resolver*
    rather than a number:
    `<!-- qqq:claim workspace-tests -->N<!-- /qqq:claim -->`. **Eight** resolvers exist —
    `crate-files`, `tools-python`, `workspace-tests`, `wit-files`, `wit-packages`,
    `wit-interfaces`, `wit-functions`, `wit-types` — each measured elsewhere in the tooling.
    Naming the resolver is what makes the check possible — the document says *which fact* it
    asserts — and a number in prose that is not a claim is left alone, so the check has no
    false positives to be disabled over.
  → **Five claims are now marked**, and this is the state as of 2026-09-25:
    `docs/stability.md` declares `wit-files`, and the `DOC-017` entry above declares
    `wit-packages`, `wit-interfaces`, `wit-functions` and `wit-types`. Verified by fault
    injection — changing one produces ``STALE  QQQ-Checklist-V1.md:386  `wit-types` says 54,
    the tree has 53`` and a non-zero exit. The WIT counts are **derived by the generator that
    renders them** rather than re-parsed (`§O-272`), because a hand count of the rendered page
    gave 61 functions and 72 types while the page itself said 80 and 53.
  → **Historical, dated 2026-09-25 and retained because it records a decision rather than an
    omission.** Before those markers existed, **no document carried a claim**, and that was the
    measured state: both candidates this item produced were already re-derived elsewhere —
    `docs/unsafe-audit.md`'s `.rs` file count by `tools/audit_unsafe.py --check-doc`
    (`SEC-020`, with its own self-test), and the error-catalogue count by
    `tools/gen_error_catalogue.py --check` (`DOC-019`). Marking either would have been a second
    mechanism for one number, which this entry's own concluding sentence forbids.
  → **A drift table has one re-derivable column and one frozen one, and the first edit conflated
    them.** Marking the `The entry said` column made the checker fail correctly on `2305` and
    `2249` — numbers that are *supposed* to be stale, because they record what was claimed at
    the time.
  → **The `workspace-tests` marker was then put on the `Measured` column, and removed after it
    failed CI twice.** Its value is a live count that is *supposed* to grow: 2546 became 2547 when
    the follow-up added an example, and 2549 one commit later, so a table recording what an audit
    found became a gate that failed whenever the project added a test. Updating the number only
    postponed it by one commit. The rows now carry the audit-time value with the command beside
    them, which is what every other row in that table does. `§O-235` and `§O-238` record both
    rounds.
  → Verified: self-test 8/8; the check reports `1 claim(s) match the tree`; and a **fault
    injection** changing the marked value from 147 to 146 fails with
    `` `crate-files` says 146, the tree has 147 ``, restored byte-for-byte from SHA-256 and
    green afterward. Wired into `ci.yml` and `docker/entrypoint.sh`.
  → **What this does not do, stated so the tick is not read as more than it is.** §2.6's
    literal mechanism is *"a CI job builds a sample project against the published docs"*. That is
    covered for the WIT and schema surfaces by `check_wit_reference.py` and
    `check_schema_conformance.py`, which compile against the generated artefacts; a separate
    sample-project build would re-derive what those already do. The freshness *measurement* §2.6
    names — *"zero doc-drift failures"* — is what CI now reports.
- [x] **DOC-019** Publish the error catalogue generator: every `QQQ-XXXX` code becomes a docs page with cause, fix and example.
  → Done: `docs/errors.md` — **42 codes**, generated from the `ErrorCode` enum's doc
    comments by `tools/gen_error_catalogue.py`, verified by
    `tools/check_error_catalogue.py` in CI and in the bridge.
  → Generated from the enum rather than written, so the catalogue **cannot** be missing
    a code the runtime can emit. The failure that prevents is specific: a new variant
    lands, the catalogue is not updated, and the user sent to it finds nothing.
  → The generator **refuses to emit** a variant with no cause or no
    `**Remediation:**` line, rather than producing a page with a blank Remedy section
    that satisfies the generator while failing §12.2's standard. All 42 currently pass.
  → Codes are grouped into eight documented ranges, so the first thing a reader learns
    is which subsystem failed.
  → 8/8 self-test cases, each a realistic mistake rather than a synthetic one: a
    variant added by copying a neighbour and dropping its doc comment, a duplicated
    code, a code outside every range, and an enum that is not where the parser looks.
  → §12.2 Error message design standard
- [x] **DOC-020** Publish `llms.txt` and `llms-full.txt` at the repository root and on the docs site.
  → Done: `tools/gen_llms_txt.py` (6-case self-test), `llms.txt` (4 KB index),
    `llms-full.txt` (96 KB corpus, 10 documents), wired into
    `.github/workflows/ci.yml` **and** `docker/entrypoint.sh`.
  → **The two files are different documents with different jobs, which is the
    design §8.5 implies.** `llms.txt` is a **curated index**: a model that has
    never seen QQQ reads it first and learns what exists, in what order, and what
    each file is *for* — small enough to fit any context window. `llms-full.txt`
    is a **corpus**: ten documents whole, each preceded by its repository path so
    a claim in a generated answer can be traced to its source.
  → **Generated rather than hand-written**, for the reason `CON-016` records for
    the schemas: a hand-written index is a *second* statement of what the
    repository contains, and it goes stale the first time a document is added.
    The completeness check proves the curation and the tree agree in **both**
    directions — every `docs/*.md` is either indexed or explicitly excluded, and
    no exclusion names a file that no longer exists.
  → **The self-test found three real gaps on its first run.** Four genuine
    documents were **unindexed** (`docs/adr/README.md`,
    `docs/advisories/INDEX.md`, `docs/advisories/README.md`,
    `docs/development-bridge.md`); one exclusion named a file that **does not
    exist** (`docs/env-example.md` — the real file is `docs/.env`); and the index
    rendered **`((missing))`** with doubled brackets because `size_of` wrapped its
    own value while the caller wrapped it again.
  → **The `.env` exclusion is a security control, not a judgement about what
    counts as documentation.** `docs/.env` holds credentials: an index linking to
    it would be a leak, and a corpus embedding it would put the secret in a file
    designed to be pasted into a model's context window. Verified **directly**
    rather than by trusting the generator's accounting — neither generated file
    mentions `.env`, neither carries secret-shaped text, and all 10 provenance
    markers are present.
  → **Why the two largest documents are deliberately excluded from the corpus.**
    `QQQ-Proposal-V1.md` is 133 KB and `QQQ-Observations-and-Memories.md` is
    577 KB; including them would consume a context window before a reader reached
    anything else. Both are in the index **with their size stated**, so a consumer
    can fetch them deliberately — which is the index doing its job rather than an
    omission.
  → **The corpus demotes every source heading by one level**, so a document's own
    `# ` title cannot masquerade as a top-level section of the concatenation. A
    reader scanning the file can then tell the corpus structure from any one
    document's.
  → §8.5 Making the codebase legible to machines

### LIC — Licensing

- [x] **LIC-001** Draft `LICENSE` (Apache-2.0) for the runtime repository.
  → Done: `LICENSE` — Apache-2.0.
  → §13.2 The licence model, and why NN-8 still holds
- [ ] **LIC-002** Obtain legal review of the Apache-2.0 grant and the irrevocability commitment for the V1 line.
  → Partial: no legal review has been obtained; this is an external action, not a repository artefact.
  → §13.2 The licence model, and why NN-8 still holds
- [ ] **LIC-003** Draft the Fabric commercial licence, choosing between BSL 1.1 with a change date, Elastic License 2.0, or a custom grant (open question `OQ-008`).
  → §13.2 The licence model, and why NN-8 still holds
- [x] **LIC-004** Define the free-entity grant precisely: individuals, solo developers, non-profits, and companies under $2M revenue.
  → Done: `LICENSING.md` §1 — the free-entity grant, stated without seat or revenue limits.
  → §13.2 The licence model, and why NN-8 still holds
- [ ] **LIC-005** Define the revenue-attestation mechanism for the free-tier boundary (open question `OQ-001`).
  → §13.2 The licence model, and why NN-8 still holds
- [x] **LIC-006** Add SPDX headers to every source file and a CI check that they are present and correct.
  → Done: **145 `.rs` files** under `crates/` and `fuzz/fuzz_targets/`, plus every
    `wit/*.wit` and every `tools/*.py`, now carry
    `SPDX-License-Identifier: Apache-2.0`.
   The 145 counts only the `.rs` population: `git ls-files` gives 145 there, 17 in
    `wit/` and 53 in `tools/`, 215 across the three. The entry's "and" read as a sum
    until 2026-09-23, when the three were counted separately and the number turned out
    to be exactly right for the population it actually describes.
   `tools/check_spdx.py` enforces it in CI and in the bridge.
  → The identifier must match the workspace's declared licence, because a header naming a
    different licence from `Cargo.toml` is **worse than none**: it is a contradiction a
    scanner reports as fact.
  → The header is looked for only in the **first five lines**. A mention of SPDX deeper in
    a file is documentation *about* licensing, not the file's own licence, and accepting it
    would let a file be unheadered while containing the string.
  → Placement preserves a **shebang** as line 1 — the kernel reads it — and Rustdoc
    attaches `//!` regardless of preceding `//` comments, which is why the header goes
    above it.
  → Exemptions are an **explicit list, not a heuristic**, and the checker reports an entry
    that stops matching a file, so the list cannot quietly grow a population of one.
  → 7/7 self-test cases: no header, correct header, wrong licence, a deep mention that must
    not count, a `.wit` file, and the workspace licence being readable.
  → §13.2 The licence model, and why NN-8 still holds
- [x] **LIC-007** Configure `cargo-deny` to enforce the dependency licence allowlist.
  → Done: `deny.toml` — the licence allowlist derived from `cargo metadata` over the real tree, with the copyleft branches of OR-expressions deliberately not listed.
  → §5.4 The lockfile — `qqq.lock`
- [ ] **LIC-008** File trademark applications for the mark in the relevant software classes (open question `OQ-008`).
  → §15 — Risk Register
- [x] **LIC-009** Publish a plain-language licence FAQ answering "can my company use this for free?" unambiguously.
  → Done: `LICENSING.md` §4 — the plain-language FAQ, including "can my company use this for free?".
  → §13.2 The licence model, and why NN-8 still holds
- [x] **LIC-010** Publish the contributor licence agreement or DCO policy and wire it into CI.
  → Done: CONTRIBUTING.md §Developer Certificate of Origin — DCO v1.1 with `git commit -s`, and why a DCO rather than a CLA.
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship
- [ ] **LIC-011** Reserve the fallback licence plan (fair-source with a change date) in writing, so it is never chosen under pressure.
  → §13.2 The licence model, and why NN-8 still holds
- [x] **LIC-012** Add a CI check that the runtime crates never depend on Fabric-licensed code in either direction.
  → Done: `tools/check_license_boundary.py` — classifies every crate by the licence its own
    manifest **declares** (Fabric credits or Apache-2.0), then asserts no dependency
    crosses the wall either way, with a distinct message per direction because the
    remedies differ: runtime → Fabric breaks the Apache-2.0 grant itself, while
    Fabric → runtime breaks §13.2's promise that Fabric is optional.
  → The classification is **derived, not listed**, so a new crate is classified
    automatically — and an **unclassifiable licence is reported** rather than assumed to
    be runtime, because "assume the safe kind" is how a commercial crate would slip
    through.
  → **Both directions proven, not asserted.** The repository has no Fabric crate yet, so a
    green run would only mean one side of the wall does not exist. A synthetic Fabric crate
    was created, wired in each direction, and the check caught both — then the workspace
    was restored and re-verified clean.
  → The check states the gap rather than hiding it: with no Fabric crate, it prints that it
    is verifying the direction that *can* fail today and cannot exercise the other. A green
    result that means "the other side does not exist yet" must say so.
  → 10/10 self-test cases, covering the commercial and open licence spellings a manifest
    might use (`LicenseRef-Fabric`, `Proprietary`, `MIT OR Apache-2.0`).
  → §4.3 Crate topology

### GOV — Governance

- [x] **GOV-001** Write `GOVERNANCE.md` before the first external contributor arrives.
  → Done: `GOVERNANCE.md`.
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship
- [x] **GOV-002** Write `CONTRIBUTING.md` with the full local development setup.
  → Done: `CONTRIBUTING.md` — setup, workflow, standards and the DCO.
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship
- [x] **GOV-003** Adopt and publish `CODE_OF_CONDUCT.md`.
  → Done: `CODE_OF_CONDUCT.md`, which CONTRIBUTING.md already linked to before it existed.
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship
- [ ] **GOV-004** Define the RFC process for changes to `PRINCIPLES.md` and to published anchors.
  → §0.5 Identifier and anchor discipline
- [ ] **GOV-005** Publish the deprecation policy with a minimum window (open question `OQ-012`).
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship
- [x] **GOV-006** Publish the security-response policy with target response and patch times.
  → Done: `SECURITY.md` — acknowledgement, assessment and patch targets by severity.
  → §7.2 Adversary model
- [ ] **GOV-007** Establish the main­tainer ladder and the criteria for commit rights.
  → §14.2 Team composition
- [ ] **GOV-008** Recruit a second maintainer before M5 to raise the bus factor above one (risk `R-15`).
  → §15 — Risk Register
- [ ] **GOV-009** Write the succession plan required by the Definition of Done.
  → §16 — Definition of Done for V1
- [ ] **GOV-010** Decide on Bytecode Alliance engagement and publish the decision as an ADR (open question `OQ-009`).
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship
- [ ] **GOV-011** Publish the release-cadence commitment and the support-version policy.
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship
- [ ] **GOV-012** Establish the public issue triage cadence and labels.
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship
- [ ] **GOV-013** Publish a public roadmap that is generated from this checklist.
  → §14.1 Milestones
- [ ] **GOV-014** Set up the community channels (Discussions, chat) with moderation policy.
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship

### PLAN — Project management

- [ ] **PLAN-001** Convert this checklist into a machine-readable backlog (JSON/YAML) that CI reads for status reporting.
  → §14.1 Milestones
- [ ] **PLAN-002** Build the milestone dashboard that reads backlog status and reports per-area and per-phase completion.
  → §14.1 Milestones
- [ ] **PLAN-003** Define the milestone exit criteria as executable checks, not prose.
  → §14.1 Milestones
- [ ] **PLAN-004** Establish the weekly architecture review and the fortnightly security review cadence.
  → §14.2 Team composition
- [ ] **PLAN-005** Establish the budget-tracking sheet matching §14.3 categories.
  → §14.3 Budget
- [ ] **PLAN-006** Write the raise narrative targeting the M3 evidence point, not M0 promises.
  → §14.3 Budget
- [ ] **PLAN-007** Define the cut-order procedure so scope cuts are mechanical and pre-agreed.
  → §14.4 What we would cut first, in order
- [ ] **PLAN-008** Establish the risk-review cadence against the register, with trigger monitoring.
  → §15 — Risk Register
- [ ] **PLAN-009** Define the definition-of-ready for a checklist item (clear acceptance test, no unresolved dependency).
  → §16 — Definition of Done for V1
- [ ] **PLAN-010** Define the definition-of-done for a checklist item (code, tests, docs, xref, observations updated).
  → §16 — Definition of Done for V1
- [ ] **PLAN-011** Track and publish the language-spike schedule starting at M1, not M8 (risk `R-02`).
  → §15 — Risk Register
- [ ] **PLAN-012** Establish the quarterly engine-upgrade sprint (Wasmtime), budgeted as recurring work (risk `R-03`).
  → §15 — Risk Register
- [ ] **PLAN-013** Set up the hardware reference specification for benchmarks and acquire or reserve it.
  → §9.1 The honest benchmark position
- [ ] **PLAN-014** Establish the on-call and incident-response process for the project itself, not just for users.
  → §7.2 Adversary model
- [ ] **PLAN-015** Create the decision log that feeds the Observations document.
  → §0.3 Document map
- [ ] **PLAN-016** Define the "three-document sync" ritual: every code change updates checklist status and, when relevant, observations.
  → §0.4 How to read the cross-references
- [ ] **PLAN-017** Publish an engineering-metrics page (build times, test durations, benchmark trends).
  → §9.2 The performance budget
- [ ] **PLAN-018** Establish the external-advisor bench for security and standards review.
  → §14.2 Team composition
- [ ] **PLAN-019** Define the scope-freeze gate before M7 and the criteria for passing it.
  → §14.4 What we would cut first, in order
- [ ] **PLAN-020** Track the runway-versus-milestone burn explicitly and alert at the six-month threshold (risk `R-09`).
  → §15 — Risk Register

### MKT — Market research

- [ ] **MKT-001** Produce a written, sourced analysis of Node.js's architectural constraints and their consequences.
  → §1.1 The problem, stated precisely
- [ ] **MKT-002** Produce the same for Bun, with primary sources only.
  → §1.1 The problem, stated precisely
- [ ] **MKT-003** Write and publish `docs/why-not-node-compat.md` explaining the deliberate refusal to run unmodified npm packages.
  → §1.2 What we are deliberately not solving
- [ ] **MKT-004** Write the equivalent justification for not embedding V8 or JavaScriptCore.
  → §1.2 What we are deliberately not solving
- [ ] **MKT-005** Interview 20 target users across the four segments; publish de-identified findings.
  → §3.1 Who this is for
- [ ] **MKT-006** Validate segment priority order with evidence rather than assumption.
  → §3.1 Who this is for
- [ ] **MKT-007** Build and maintain the nine-platform competitive matrix with dated evidence.
  → §3.2 The competitive set, honestly
- [ ] **MKT-008** Determine, for each competitor, whether they are a competitor or a potential customer.
  → §3.2 The competitive set, honestly
- [ ] **MKT-009** Establish the competitive-monitoring cadence and alerting on competitor capability changes (risk `R-06`).
  → §3.2 The competitive set, honestly
- [ ] **MKT-010** Commission an independent third-party benchmark of Node, Bun and the QQQ reference app, published verbatim including any losses.
  → §3.3 Where we win, where we lose, and where we might be lying to ourselves
- [ ] **MKT-011** Publish the "where we lose" page and keep it current.
  → §3.3 Where we win, where we lose, and where we might be lying to ourselves
- [ ] **MKT-012** Run a structured tagline decision process and record the outcome as an ADR.
  → §3.4 Positioning statement and the language we use
- [ ] **MKT-013** Establish the claims-substantiation register: every public claim mapped to its evidence.
  → §3.4 Positioning statement and the language we use
- [ ] **MKT-014** Verify or discard every competitor figure inherited from the source corpus (Appendix A items A-1, A-2).
  → §3.2 The competitive set, honestly
- [ ] **MKT-015** Establish the design-partner programme and sign the first three design partners before M3.
  → §3.1 Who this is for
- [ ] **MKT-016** Publish a quarterly "state of the runtime" report with honest progress and honest failures.
  → §3.3 Where we win, where we lose, and where we might be lying to ourselves

### POS — Positioning

- [ ] **POS-001** Ratify the canonical one-sentence positioning and use it verbatim on every surface.
  → §0.2 The thesis
- [ ] **POS-002** Write the four-shift narrative as a standalone, citable essay.
  → §0.2 The thesis
- [ ] **POS-003** Publish the three self-criticism items and re-examine them at every milestone.
  → §3.3 Where we win, where we lose, and where we might be lying to ourselves
- [ ] **POS-004** Establish the vocabulary-discipline lint: forbidden phrases in docs and blog posts.
  → §3.4 Positioning statement and the language we use
- [ ] **POS-005** Define the "agent sandbox" positioning as the beachhead and validate it with design partners.
  → §8.4 The "agent sandbox" reference architecture
- [ ] **POS-006** Resolve the TypeScript-versus-AssemblyScript naming question (open question `OQ-002`).
  → §6.10 Language toolchains — one per target language

---

## 4. P1 — Heartbeat (M1)

### ARCH — Architecture

- [x] **ARCH-001** Write the layered-architecture ADR fixing the nine layers and the authority-flow invariant.
  → Done: **`§D-010`** in Observations §2, written to the `docs/adr/README.md`
    template — decision, context, alternatives, consequences, revisit trigger —
    with the nine-layer diagram and the two invariants. It states *why* the
    layering is load-bearing rather than decorative: a second path to a
    capability would be a second policy, so the isolation claim requires exactly
    one gate.
  → It records the alternatives that were real (merging L5 into L4, splitting by
    platform, relying on crate boundaries alone) and the costs that are genuinely
    hard: **L5 must be correct or nothing is**, because there is no defence in
    depth *below* it by construction — which is why the per-instance linker and
    the call-time re-check (`ARCH-012`) are compensation rather than redundancy.
  → It names enforcement per invariant (four checks, not four assertions), which
    is the register's quality bar: a decision whose consequence is unenforced is
    a preference.
  → **The Proposal now cites it.** `check_xrefs.py` check `[10b]` failed the
    moment `§D-010` was added without a citation — the exact defect
    `docs/adr/README.md` documents as having once left six of nine decisions
    write-only. The check caught it before the commit, which is what makes it a
    check rather than a warning.
  → §4.1 The layer cake
- [x] **ARCH-002** Implement and test the invariant that authority only narrows downward.
  → Done: the invariant is enforced **structurally** — `GrantSet::narrow` is the
    only combinator that produces a grant set from a grant set, there is no
    union/widen/merge, and a search of the whole workspace source confirms it.
    The behavioural half is `qqq-cap`'s own `no_overlay_can_ever_widen`
    (`§O-050`), which starts from the empty set and tries all six (layer × mode)
    combinations against a hostile overlay holding every capability.
  → What this item adds is the half `qqq-cap` **cannot test about itself**: a
    future `GrantSet::union` or `add_capability` anywhere in the workspace would
    break the invariant **silently**, because no existing test would call it.
    `no_widening_constructor_on_grants_exists_anywhere` in
    `crates/qqq-core/tests/architecture.rs` scans every crate for the widening
    names and fails on the first; a positive control asserts the scanner found
    real `impl GrantSet` blocks, so a green result means "checked and clean"
    rather than "checked nothing".
  → §4.1 The layer cake
- [x] **ARCH-003** Implement the compile-time rule that a host function without a WIT definition cannot enter a release build.
  → Done: `crates/qqq-host/src/arch003.rs` — `registered_from_sources`,
    `wit_defines`, `wit_declares_function`, `dissenting_functions`,
    `Indeterminate`, `EXPECTED_REGISTRATIONS`. **10 tests**, all green.
  → **Measured before implementing**: all 8 host functions *do* appear in a WIT
    file, and **nothing enforced that**. The two mechanisms that looked like
    coverage check different things — `qqq-abi`'s
    `every_interface_has_wit_source` checks **interfaces** (a function inside one
    can still be undefined), and `SEC-011`'s boundary table is about input
    boundaries, not WIT presence. A ninth host function with no WIT definition
    would have compiled into a release build.
  → **Honest statement of the mechanism: this is a test, not a `const`
    assertion.** Five attempts at the compile-time form are recorded in
    `§O-111`, and the fourth **nearly shipped a rule that always passes** — a
    comment-skip off-by-one made the scanner return an empty list, whereupon
    "every registered function has a WIT definition" was **vacuously true** and
    the assertion *passed*. That is `§M-006`'s defect and it is worse than no
    check, because it gets cited as evidence. The rule is therefore enforced by a
    test in CI, which is where the workspace enforces every other invariant of
    this shape (`tools/audit_requirements.py` is the single gate).
  → **The anti-vacuity design is the substance of the item.** Three changes make
    this check unable to pass by finding nothing: `EXPECTED_REGISTRATIONS` is
    asserted **before** any WIT question; `Indeterminate` distinguishes *"the
    scan found no violations"* from *"the scan could not run"* as different
    return values, because a `usize` of dissenters cannot express the second; and
    `the_scan_is_not_vacuous` proves the scan found all 8 and includes `now` and
    `digest` by name.
  → **The registration scan is delegated to `arch012::scan`, not re-implemented.**
    The fourth failure's root cause was structural: **`func_wrap(` and its name
    literal are on different lines**, so a per-line scan can never see a name and
    a scan that refuses to cross a newline returns `None` for every real
    registration. `arch012::scan` slices from one `func_wrap(` to the *next*, so
    its window spans the break. `the_scanners_agree` pins the two together, and
    `the_expected_count_agrees_with_audited` pins `EXPECTED_REGISTRATIONS` to
    `arch012::AUDITED`, which is itself checked against the source in both
    directions.
  → Fault injection: `a_name_in_a_wit_doc_comment_is_not_a_definition` (a WIT
    doc comment mentioning `digest` is not a declaration),
    `every_declaration_form_is_recognised` (`func`, `async func`, `static func`,
    and a near-miss `nowhere` that must not match `now`), and
    `the_comment_and_test_skips_work` driven on a **fabricated** source containing
    a prose mention, a real registration and a test-only one.
  → §4.1 The layer cake
- [x] **ARCH-004** Add an architecture test that no crate depends on a crate above it in the topology.
  → Done: `no_crate_depends_on_a_crate_above_it` in
    `crates/qqq-core/tests/architecture.rs`, reading every crate's manifest and
    ranking each `qqq-*` edge against the §4.3 order. **`[dev-dependencies]`
    count**, because a dev-edge from `qqq-core` to `qqq-host` would make the
    bottom of the graph's *test suite* require the whole Wasmtime stack.
  → Complements `tools/check_topology.py` rather than duplicating it: the tool
    reads `cargo metadata` (the **resolved** graph, including edges a workspace
    dependency introduces) and this reads the manifest text (the **declared**
    graph). They answer different questions, and a shared list would make one
    inherit the other's blind spot.
  → Lives in `qqq-core` because these are statements about the *workspace*:
    `qqq-core` is the one crate everything depends on and that depends on
    nothing, so a test there cannot create a cycle — and `qqq-core` is this
    rule's own strictest case, asserted separately by
    `qqq_core_depends_on_no_other_qqq_crate`.
  → §4.3 Crate topology
- [x] **ARCH-005** Write the process-and-thread-model ADR including the explicit rejection of a Tokio replacement.
  → Done: **`§D-005`**, upgraded from a two-paragraph note to a full ADR on the
    `docs/adr/README.md` template. The decision is unchanged — Tokio
    multi-threaded with a sharded acceptor as the portable default, io_uring
    behind a Linux opt-in flag — but the *reasoning a future maintainer cannot
    recover from the code* is now written down: monoio/glommio are Linux-only,
    io_uring does not exist on macOS or Windows, so choosing them as the only
    backend makes QQQ unable to run on two of its five target platforms.
  → The tokio replacement is **rejected explicitly and permanently**, with the
    alternatives table recording *why*: it is a multi-year detour with no
    differentiation, because the differentiation is the capability layer rather
    than the event loop. A rejection recorded as "we might do it later" is how a
    detour gets funded.
  → Three costs are stated rather than glossed, and all three are live:
    Tokio's cooperative-budget semantics must not apply to guest-visible blocking
    (`HOST-017`, still open); the sharded acceptor is a userspace approximation
    because `SO_REUSEPORT` distributes differently per platform (`ARCH-006`); and
    two backends means a feature matrix that must not collapse to one tested path.
  → The revisit trigger is a **measurement** (`PERF-014` showing a reproducible
    io_uring advantage), not an intuition.
  → §4.2 Process and thread model
- [x] **ARCH-006** Implement the sharded acceptor (connection accepted and served on the same core).
  → §4.2 Process and thread model
  → Done: `qqq-io` — `Listener::accept_stream` with a bounded accept batch that yields at a
    fixed point, and round-robin shard assignment. Assignment is userspace rather than
    `SO_REUSEPORT`, because the kernel option distributes differently on macOS and Windows; the
    reasoning is in the crate documentation. 8 integration tests bind real sockets and prove the
    loop accepts, carries data, balances across shards, and stops on shutdown.
- [ ] **ARCH-007** Create all crates listed in the topology with correct names, tiers and empty implementations.
  → §4.3 Crate topology
- [x] **ARCH-008** Enforce `#![forbid(unsafe_code)]` on every crate except the three named exceptions.
  → Done: `every_non_exception_crate_forbids_unsafe_code` in
    `crates/qqq-core/tests/architecture.rs` reads the crate-level attribute of
    every workspace member and fails for a crate outside the exception list that
    lacks a bare `#![forbid(unsafe_code)]`.
  → **It found a real defect.** `qqq-debug` and `qqq-sys` both declared
    `#![cfg_attr(not(test), forbid(unsafe_code))]`, and the conditional form
    permits `unsafe` under `cfg(test)` — so the guarantee was a property of the
    build configuration rather than of the source, and `unsafe` introduced behind
    a `#[cfg(test)]` gate would have been silently legal. Neither crate contains
    a single `unsafe`, so the escape hatch was defensive rather than necessary.
    Both are now bare `forbid`s (`§O-059b`).
  → The test reports the **conditional** form separately from its absence, which
    is why it caught this: `#![forbid(unsafe_code)]` and a `cfg_attr`-wrapped one
    both contain the words, and a substring check would have accepted both.
  → The exception list is `qqq-sys`, `qqq-io-uring`, `qqq-mem-hugepage` and
    `qqq-sys-signals` — §4.3's three named crates plus the one this workspace
    carries. `the_unsafe_exception_was_granted_through_its_process` requires the
    exception to be granted through its **process** rather than by an edit: it
    asserts that `unsafe` is never permitted while no `SAFETY.md` exists beside
    it. The other three combinations are all legitimate points in the process —
    including the argument written **ahead** of the code, which is how it gets
    reviewed as a design decision rather than rationalised afterwards.
    `tools/fault_inject_safety_arg.py` injects the one violating state and
    asserts the check fires.
  → §4.3 Crate topology
  → §2.2 NN-2 — Security and Isolation Are Non-Optional
- [x] **ARCH-009** Write the safety argument document for each `unsafe`-permitting crate.
  → Done: `crates/qqq-sys/SAFETY.md` — a complete safety argument written **before**
    any `unsafe` exists, which is the order that makes it a design decision rather
    than a description of what was already built.
  → It answers the three questions a safety argument has to answer, and says so
    explicitly: **what invariant is asserted** (§2 — three rules, the third being
    "no `unsafe` block may span more than the call it exists for", because that is
    the rule that decays first); **who maintains it** (a five-point reviewer
    checklist in §5); and **how a mistake would be caught** (§6 — the enforcing
    tests, named individually, plus the one thing no test here *can* check, which
    is whether the argument is correct).
  → §3 states the hazards and their containment **and the hazard that is not
    contained**: `qqq-sys` cannot defend against a caller that obtained a pointer
    unsoundly elsewhere. The guarantee is local — it does not launder unsoundness
    from its callers — and that boundary is why a safe `fn` with an unchecked
    precondition would export a false guarantee upward.
  → §7 is a status ledger, and its honest state is that the argument is complete
    but the **grant is not**: the crate still forbids `unsafe`, no second
    maintainer exists (`GOV-008`, bus factor 1), and Miri is not configured. The
    ledger says no `unsafe` may be added until two of its rows change.
  → **One deviation from §4.3, recorded rather than left implicit.** The Proposal
    names three exception crates; this workspace merges them into one `qqq-sys`.
    The reasoning and the cost are in `§O-059f`: three crates is three documents
    and three places a policy drifts, and multiplying the paperwork that prevents
    drift is a poor way to prevent it — at the cost of a larger blast radius,
    mitigated by the process being test-enforced rather than crate-enforced.
  → §4.3 Crate topology
- [x] **ARCH-010** Publish the crate stability tiers and the API-stability contract per tier.
  → §4.3 Crate topology
  → Done, and the check found a real divergence on its first run.
  → **`docs/stability.md`** publishes the three tiers (`stable`, `beta`, `exception`), what each
    promises about breaking changes and notice, which crate is which, and the four surfaces with
    their own contracts (`CON-017`): WIT interfaces, the manifest, the lockfile, and CLI JSON —
    including the rule that `error.code` is permanent because agents match on it.
  → **The tier was an unverified declaration until this item.** Every crate carries a `# Tier:`
    line in the workspace manifest, and §4.3 carries a table, and **nothing compared them**:
    `check_topology.py` verifies the *order* of the table and reads `cargo metadata`, not the
    comments. A crate could be switched from `beta` to `stable` — the line a publisher reads
    before making a semver promise — with every gate green and the specification saying the
    opposite. `tools/check_tiers.py` now compares the two and fails on any disagreement.
  → **What its first run found.** `qqq-bench` and `qqq-sys` are built, declare a tier, and have
    **no row in §4.3's table**; `qqq-registry` and `qqq-fabric` have rows and are not built here.
    Both classes are recorded and reported on every run rather than tolerated silently, and one
    further error is fixed: the tier vocabulary is closed, so `experimental` or `alpha` is
    rejected rather than accepted as a promise nobody agreed to.
  → The `exception` tier is checked against the **artifact the process requires**,
    `crates/qqq-sys/SAFETY.md`, rather than the label — so it is a reviewed state, not a word in a
    comment. `qqq-sys` is designated for `unsafe` and currently contains none, because `nix` and
    `seccompiler` supply the primitives as safe functions.
  → Verified: `check_tiers.py` reports 11 crates, every tier matching; self-test 14/14; two
    **fault injections** (flipping `qqq-pkg` to `stable`, and deleting a `# Tier:` line) each
    fail with the specific message and restore byte-for-byte from SHA-256. Wired into `ci.yml`
    and `docker/entrypoint.sh`.
  → **Stated plainly:** the workspace is `0.0.0`, so these tiers describe the contract that comes
    into force at 1.0. Until then every crate is technically beta; the tier records the reviewed
    intent, which is why it is worth stating before it is enforceable. `CON-015` (deprecation
    mechanics) remains open, so `stable`'s "one minor release of notice" is a convention rather
    than a mechanism.
- [ ] **ARCH-011** Implement the fifteen-step request lifecycle as an instrumented pipeline.
  → §4.4 Request lifecycle — the detailed path
  → **Partial, and the item stays open because 13 of the fifteen steps are not done.** What
    landed is the honest accounting rather than a claim: `crates/qqq-serve/src/lifecycle.rs`
    carries `STAGES` — all fifteen of §4.4's steps, each with the file and symbol that performs
    it, a `Status`, and the `gap` that says what is missing — plus a test that verifies every
    named symbol still exists in the file it names, so a rename or a move cannot leave the table
    pointing at nothing.
  → **Measured: 2 implemented, 11 partial, 1 built-unwired, 1 absent.** The numbers are
    **derived, never hand-written**: `Summary::of` folds the table into `Counts`, `Counts`
    renders both the numbers and the step lists, and `the_documented_counts_match_the_table`
    asserts the module's prose against that rendering. Change one row's `Status` and the test
    fails until the documentation is corrected — that injection was run and is captured.
    `tools/check_lifecycle_counts.py` extends the same guarantee to *this entry*, which the
    test binary cannot read. `§O-244` records the defect and the fix.
  → **The four findings, each a decision or a debt rather than an oversight.**
    • **Step 4 `TENANT RESOLVE` — absent.** §4.4 maps *host/path → tenant → component ID +
    manifest rev*. There is no such mapping anywhere in the workspace: the router is **path-only**
    (`Route` has no host field), and the only tenant derivation in `qqq-serve` is `tenant_of`,
    which keys on the **client IP** for per-tenant limits. §4.4's claim that step 4 is the only
    place routing state lives currently describes intent.
    • **Step 15 `AUDIT APPEND` — built and unwired.** `AuditStream::record` is complete,
    hash-chained and append-only, and its only callers are its own tests. This is the gap that
    matters most for §4.4's security story: step 13 meters and step 15 records, and the
    recording half does not run.
    • **Steps 6 and 14 are accounting, not reuse.** §4.4's "pooled instance (≈µs)" and "linear
    memory is reset, not freed" do not hold: `Pool::acquire` charges a slot and `release` returns
    it, while the instance is created and dropped per request. `Acquired::pooled` means the idle
    count was non-zero, not that a guest was reused.
    • **Step 3 is path-only and allocates**, against §4.4's "no allocation on the hot path"; and
    steps 9 and 12 buffer the body into a `Vec<u8>`, so "body becomes a stream" and "streams pass
    through" are not true on the guest path.
  → **The instrumented half is real where the pipeline is not**, and its own gap is stated:
    `HttpMetrics::record_request` records latency, bytes and connections, and
    `qqq_host::Metrics::note_execution` records fuel, traps and peak memory, but **they are two
    registries with no common key**, and no handle peak reaches telemetry — so step 13 is
    three-quarters done.
  → Verified: 10 tests green; `clippy -D warnings` clean; the named-symbol audit passes against
    the real tree and has a **positive control** proving it reports a symbol that does not exist.
    **`audit` no longer skips an unaccountable row** (`§O-245`): a row that names neither a file
    nor a symbol is reported as `Missing::Unaccountable` rather than `continue`d past, so a row
    claiming `Implemented` while naming nothing can no longer pass. `Missing::is_defect`
    separates that from the legitimate empty shape of the one `Absent` row. Both injections —
    a restated count and an unaccountable row — were run and observed to fail.
    **`text.contains(symbol)` is kept as a named, recorded limit** (`§O-246`): it is satisfied by
    the symbol appearing in a comment or a string literal, and the disposition and its reason are
    in the observations document.
- [x] **ARCH-012** Implement the defence-in-depth re-check of grants at host-call time.
  → Done: `crates/qqq-host/src/arch012.rs` — `AUDITED` (8 measured rows),
    `Enforcement`, `AuditFinding`, `scan`, `audit`. **14 tests**, all green.
    `ambient::require` and `linker::recheck` are the per-call mechanisms.
  → **§4.4 step 11 says the grant set is "consulted twice … and it is
    non-negotiable"; the first two mechanisms were already there, and the third
    is what this item adds.** *Conditional registration*: an interface whose
    capability is absent is never bound, so its functions are **absent** rather
    than denied. *Per-call re-check*: `wall-clock.now`, `monotonic-clock.now`,
    `random.get` check directly; `hashing.digest`/`digest-many` reach
    `ambient::require` through `hash_data`. *Source-level totality*: `AUDITED` is
    cross-checked against the source in both directions, so a `func_wrap` added
    outside a gated registration path is a **test failure** rather than an
    unexamined call path — without it, "every host function re-checks" is a
    claim about today's source that nothing re-establishes tomorrow.
  → **Measuring whether this item held took four attempts and three were wrong
    (`§O-109`).** A grep for `grants.grants(` in each registration body reported
    **8 of 11 unchecked** — wrong, because the check is reached one layer down,
    which is `§O-071`'s lesson a fourth time: *a control judged by its prose
    rather than its reachability.* The scanner then invented **9** registrations
    from doc comments and test code (20 where the source has 8) — `§O-071`'s
    name-extractor bug verbatim, in code written an hour after recording it. And
    the table listed **11** rows where the source has **8**, because three were
    derived from the WIT's `hmac` interface without checking implementation;
    `audit` reported them `Stale`.
  → **The table disagreeing with its author on first run is the argument for the
    table.** A table that can never disagree with the code is documentation.
  → **A fifth finding came from a test refusing to pass:** two `(file, function)`
    pairs repeat (`wall-clock.now`/`monotonic-clock.now`, likewise the two
    `resolution`s), so a two-part key could **pass a row because its namesake was
    backed** — `monotonic-clock.now` losing its check while `wall-clock.now` kept
    one. The key is `(file, interface, function)`,
    `the_audited_identity_is_unique` pins that it is unique **and** pins that the
    two-part key collides.
  → Fault injection: an unlisted `func_wrap`, a row claiming an unbacked
    per-function re-check, and a stale row are each driven and each reported;
    `audit` takes the sources as an argument precisely so it can be driven with
    **fabricated** input — a checker that can only read the real tree can be
    observed to pass and never proven to detect (`§M-006`).
  → §4.4 Request lifecycle — the detailed path
- [x] **ARCH-013** Write the guest-concurrency ADR fixing the async-single-threaded default.
  → Done: **`§D-006`**, upgraded to a full ADR. It states a policy for all three
    guest concurrency models rather than only the default: async-single-threaded
    is **default and recommended**, shared-memory threads are **enabled but
    discouraged** behind an explicit manifest opt-in, and cooperative threads are
    **not enabled in V1** because they need stack switching, which Wasmtime still
    lists as work-in-progress (`FUT-004`).
  → The alternatives table records why thread-per-request-inside-one-instance is
    rejected: it requires shared linear memory, which defeats the per-instance
    memory accounting that makes a memory limit a **security** control rather than
    a tuning knob, and it makes fuel accounting inexact because two threads draw
    from one budget.
  → **The consequences are measured rather than predicted**, which is what makes
    this ADR worth its length. Implementing `HOST-016` established that the epoch
    yield needs a reactor able to spare a thread for the ticker — a
    **current-thread** runtime has none, so a yielding guest yields forever and
    the executor never advances. Observed as a hang, twice, in the test suite, and
    recorded as a real constraint on `qqq-serve` rather than a test artefact
    (`§O-056b`). An ADR written before that work could only have guessed at it.
  → §4.7 Concurrency model for guests
- [ ] **ARCH-014** Implement the manifest opt-in for shared memory, off by default.
  → §4.7 Concurrency model for guests
- [ ] **ARCH-015** Implement the artifact model: component + signed manifest envelope + AOT cache keying.
  → §4.6 Where the artifacts live and how they move
- [ ] **ARCH-016** Implement build-time component composition with load-time composition as fallback.
  → §4.6 Where the artifacts live and how they move

### HOST — Execution engine

- [x] **HOST-001** Implement `Host::bootstrap` with the engine configuration from the proposal.
  → Done: `qqq-host::config::EngineConfig`, with the component model enabled.
  → §6.1 `qqq-host` — the execution engine
- [x] **HOST-002** Implement `Host::load` — component compilation with AOT-first, JIT fallback.
  → Done: `PreparedComponent::compile` — one compiled component shared across instances.
  → §6.1 `qqq-host` — the execution engine
- [x] **HOST-003** Implement `Host::acquire` and `Host::release` over the pooling allocator.
  → Done: `Instance::create` builds a fresh store and instance per acquisition.
  → §6.1 `qqq-host` — the execution engine
- [x] **HOST-004** Configure and benchmark the pooling allocator; publish slot-memory accounting.
  → Done: `build_pooling` configures the pool from the manifest; instantiation measured p50 800 ns.
  → §6.1 `qqq-host` — the execution engine
- [x] **HOST-005** Implement epoch-based preemption as the default.
  → Done: Epoch deadline set in `Instance::create`; `epoch_tick_interval` derives the tick.
  → §6.1 `qqq-host` — the execution engine
- [x] **HOST-006** Implement fuel metering for exact accounting, opt-in per manifest.
  → Done: Fuel budget set before instantiation, so a long `start` cannot escape metering.
  → §6.1 `qqq-host` — the execution engine
- [x] **HOST-007** Implement `StoreLimits` binding from manifest limits.
  → Done: `StoreLimits` built from the manifest and bound via `Store::limiter`.
  → §6.1 `qqq-host` — the execution engine
- [x] **HOST-008** Implement the trap taxonomy: `QQQ-3001` memory, `QQQ-3002` fuel, `QQQ-3003` epoch.
  → Done: `qqq-host::trap` — QQQ-3001/3002/3003 plus the guest-bug codes.
  → §6.1 `qqq-host` — the execution engine
- [x] **HOST-009** Implement structured trap reporting with guest backtrace and DWARF source mapping when available.
  → Done. The **join** `Instance::run` and `run_measured` build a `Trap` from the real `wasmtime::Error` (`trap_from` takes the error, not a formatted string), so a real trap carries **frames** — Wasmtime's `WasmBacktrace`, resolved through the module's DWARF when `debug_info` is on. `qqqai run` sets it, so a live CLI trap names a file and line. Three tests trap a guest through the real path and assert on the structured frames; all three were **fault-injected** by dropping the frames and confirmed to fail.
  → The **detached** path is now wired too, which was the gap: `qqq-debug::resolve` resolves a serialized report against an extracted `SourceMap` (no engine), returning a `ResolveReport` that counts resolved / already-resolved / unmapped / no-offset and an `explain()` naming the gap. `qqq-run::trap_report` is the consumer — it parses the frame strings `Trap::to_error` attaches as causes and resolves them — and `dispatch_run_with_trap_report` extracts the map from the artifact before running. `emit_error_with_backtrace` adds an optional `backtrace` to the JSON envelope.
  → Two rules enforced: a frame the engine already resolved is **left alone** (Wasmtime read the same DWARF with its own loader), and a frame with no offset is **dropped, never guessed** — a bare name is indistinguishable from context prose.
  → 13 tests in `resolve`, 16 in `trap_report`. Fault-injected: making `lookup` guess the first entry fails exactly 1 test; restored byte-for-byte (hash + clean `git status`).
  → **Not claimed:** `qqqai build` still does not write the `SourceMap` **beside** the artifact, so resolving a report today re-reads the DWARF from the artifact each time. The resolution works and is reachable; the caching of the extracted map does not exist yet. Recorded rather than glossed.
  → §6.1 `qqq-host` — the execution engine
- [x] **HOST-010** Implement instance discarding on trap — trapped instances are never returned to the pool.
  → Done: `Instance::run` consumes `self`, so a trapped instance cannot be reused; `poison()` is the second mechanism.
  → §6.1 `qqq-host` — the execution engine
- [x] **HOST-011** Implement the panic hook converting host-function panics into traps, with severity-1 alerting.
  → Done: `crates/qqq-host/src/guard.rs` — `guard`/`guard_reporting` wrap a host
    function body in `catch_unwind`, converting a panic into a Wasmtime trap that
    names the interface. Wired into **all six** registered host functions
    (`qqq:clock` wall + monotonic, `qqq:crypto` random + hashing).
  → **A wrapper, not a `panic::set_hook`, and the distinction is the design.**
    A hook intercepts *reporting*, not unwinding: it cannot stop the panic, and
    it is process-wide, so it would also swallow panics in `qqq-serve` and
    `qqq-run` — turning genuine host bugs into silence everywhere. `catch_unwind`
    at the host/guest boundary is the only place the requirement applies.
  → **Why this is a security boundary and not robustness.** Every host function
    is a closure called from *inside* Wasmtime's execution of guest code, so a
    panic unwinds through the engine's frames and out into the host. `Cargo.toml`
    sets `panic = "abort"` for the release profile, so one guest finding one
    panicking host function kills the process — a denial of service against every
    tenant on the host. §7.2's adversary model explicitly includes hostile guests.
  → **The new code is `QQQ-6007 HostPanicContained`, a `6xxx` host fault and not
    a `3xxx` guest trap.** The guest did nothing wrong, and reporting a host bug
    as a guest trap would send an operator to inspect the wrong artifact — and
    would make an attacker's successful panic read as misbehaving guest code.
    The panic payload is **not** forwarded to the guest (it can contain host
    paths and guest-controlled data) but **is** kept for the log via
    `PanicReport`, with `is_severity_one()` unconditionally true.
  → **Enforcement, because a wrapper can be forgotten.** The guard compiles away
    to nothing when a host function does not panic, and no runtime test can
    manufacture a panic in production code — so
    `every_host_function_is_panic_guarded` counts `func_wrap(` against
    `guard::guard(` across every registration file, reading production code only
    (before `#[cfg(test)]`). It catches a **newly added** host function, not a
    known list. `tools/fault_inject_guard.py` proves the check is live: it
    removes one guard, asserts the test fails with
    *"registers 5 host functions but only 4 are wrapped"*, and restores the file
    — and it deliberately **refuses to report success when the injected source
    fails to compile**, since an injection that does not build proves nothing
    (`§O-048c`). Wired into CI.
  → §6.1 `qqq-host` — the execution engine
  → §2.2 NN-2 — Security and Isolation Are Non-Optional
- [x] **HOST-012** Implement pool-exhaustion backpressure with 503 and `Retry-After`, plus a saturation metric.
  → Done: `crates/qqq-host/src/pool.rs` — `Pool::acquire` returns `QQQ-6001`
    carrying `reason`, `capacity` and `retry-after` in its context, which
    `qqq-serve` renders as the 503. `Retry-After` is **computed from observed
    throughput rather than constant**, because a constant is wrong in both
    directions at once: too short and every refused client retries into the same
    saturation, too long and clients idle while capacity is free. It is floored
    at 1 s so a fast-but-saturated host never emits `Retry-After: 0`, which
    clients read as "retry immediately".
  → The plan is a **reservation via compare-exchange**, not load-then-store:
    two threads that both read `in_use == capacity - 1` would both decide there
    is room, and the pool would exceed its capacity under exactly the contention
    that makes capacity matter. Proven by
    `concurrent_acquires_never_exceed_capacity` — 16 threads × 500 attempts
    against a capacity of 8, asserting the observed peak never exceeds 8.
  → Draining is checked **before** capacity. A host mid-shutdown with a free
    slot that accepted work would be killed mid-request, which is the outcome
    draining exists to prevent; `a_draining_pool_refuses_even_with_free_capacity`
    pins that order, and asserts the error does **not** advise a retry.
  → A drain is orderly: releases still work, so in-flight work completes.
  → §6.1 `qqq-host` — the execution engine
  → §4.4 Request lifecycle — the detailed path
- [x] **HOST-013** Implement the AOT `.cwasm` cache with digest+config keying and safe invalidation.
  → Done: `aot_cache_key` keys by component digest, target triple and engine config.
  → §9.4 Specific optimizations planned
- [x] **HOST-014** Implement cross-tenant compiled-module deduplication keyed by artifact digest.
  → Done: `digest_of` content-addresses an artifact, so one module backs many tenants.
  → §9.4 Specific optimizations planned
- [x] **HOST-015** Use `*_async` Wasmtime APIs throughout, with the compile-time guard that prevents mixing sync and async.
  → Done: `Instance::create_async`, `run_async` and `run_async_measured` in
    `crates/qqq-host/src/instance.rs`, using `Linker::instantiate_async` and
    `TypedFunc::call_async` throughout. The synchronous trio is retained for the
    two callers that genuinely have no reactor (`qqqai run`, deterministic
    replay), and **not mixing them is enforced rather than documented**: the
    async constructor installs `epoch_deadline_async_yield_and_update`, which
    makes Wasmtime itself reject any synchronous entry on that store
    (`set_async_required` → `validate_sync_call`), and `ExecutionMode` records
    which path an instance was built for so the mismatch is a type-level
    question rather than a runtime one. Verified by a pair of tests that differ
    in exactly one variable — the entry point — and assert opposite outcomes.
  → §6.1 `qqq-host` — the execution engine
  → Correction to the note that stood here: it was right that the async path was
    missing and wrong about what that costs. A guest blocking in a host call
    blocks the calling thread only on the *synchronous* path; on the async path
    the reactor is free, which is the §4.2 requirement. Recorded in `§O-056`.
- [x] **HOST-016** Implement `epoch_deadline_async_yield_and_update` so a guest yield does not stall the reactor.
  → Done: installed in `ReadyStore::prepare` for async contexts only, with
    `EPOCH_YIELD_TICKS = 1`. A guest that exceeds its epoch deadline now yields
    and the deadline is extended, instead of trapping.
  → **The install is conditional, and that is load-bearing, not stylistic.**
    Read in Wasmtime's source: `epoch_deadline_async_yield_and_update` calls
    `set_async_required(Asyncness::Yes)`, and `validate_sync_call` — the first
    thing a synchronous entry point runs — then fails with *"store
    configuration requires that `*_async` functions are used instead"*. So the
    call does not merely take effect on async entry; **it forbids synchronous
    entry outright, from instantiation onwards.** Installing it unconditionally
    failed every synchronous test in the crate. An earlier comment claimed it
    was a no-op on the sync path; the compiler refuted that. `§O-056a`.
  → Verified by measurement, not by assertion: the test
    `an_epoch_expiry_yields_on_the_async_path` observes an infinite guest
    **still running** after four epoch ticks, and its control
    `an_epoch_expiry_traps_on_the_synchronous_path` observes the *same* guest on
    the *same* engine trapping `QQQ-3003 EpochDeadlineExceeded` at the first
    tick. Same guest, one variable, opposite outcomes.
  → Two traps avoided along the way, both recorded in `§O-056c`: the first two
    versions of the yield test failed on **fuel** (10 M and then 100 G, against
    a guest burning ~1 G per ms) and would have certified the wrong mechanism;
    and `#[tokio::test]`'s default **current-thread** runtime *deadlocked*
    rather than failing, because a yielding guest needs another thread to fire
    the tick timer — which is also a real constraint on `qqq-serve`
    (`§O-056b`).
  → §6.1 `qqq-host` — the execution engine
  → Corrected from `[!]` blocked: the block was `HOST-015`, which is now done.
    Recorded in `§O-051` as the first item found ticked that was not true;
    recorded in `§O-056` as the item that is now true.
- [ ] **HOST-017** Implement the invariant that guest-visible blocking host functions bypass host cooperative budgets.
  → §4.2 Process and thread model
  → **Still open, and the async path is what makes it meaningful.**
    `HOST-015` now supplies the mechanism it was waiting on: Tokio's cooperative
    budget applies to host functions, and WASI's `poll` calls opt out of it
    upstream. No host function in this crate is guest-visible-blocking yet —
    `qqq:clock` and `qqq:crypto` are both synchronous — so the invariant has no
    instance to hold for. It becomes live when `qqq-serve` binds the first
    awaiting host interface.
- [x] **HOST-018** Implement deterministic-mode engine configuration (NaN canonicalization, seeded RNG, fixed clock).
  → Done: `EngineConfig::deterministic` — fixed clock, seeded RNG, canonical NaN.
  → §10.5 Determinism — the feature nobody else has
- [x] **HOST-019** Implement instance metrics: acquire latency histogram, pool occupancy, trap counts by code.
  → Done: `crates/qqq-host/src/metrics.rs` — a lock-free `Metrics` recorder
    covering the Instance, Execution and Memory rows of §10.2: created,
    acquired, released, **discarded**, live, pool saturation, a fixed-bucket
    acquire-latency histogram with interpolation, fuel consumed, successful
    executions, traps by bounded label, per-instance peak memory, and a live
    memory gauge. `render_prometheus` emits all of it, defining the metric
    *names* once, beside the counters they describe.
  → **§10.2's cardinality discipline is enforced by the type system, not a
    lint.** The proposal asks for "a lint on metric definitions", which is hard
    to write and trivial to bypass because a label is a `&str` at the call site.
    `TrapLabel` is a closed enum mapping to fixed `ErrorCode`s, there is no
    `label(name, &str)` API at all, and a test asserts every label string is
    lowercase, non-empty and distinct. A guest cannot create a time series.
  → Two design points that are decisions rather than details:
    **discards are counted separately from releases** (a trap is a security
    event, and a discard rate is invisible inside a "requests succeeded" count);
    and **every series is emitted even at zero**, because a `kind` series that
    vanishes when there are no traps makes `rate()` return no data instead of
    zero, which is the ambiguity a security dashboard cannot afford.
  → Writing the tests found a **real double-count in my own code**:
    `note_created` and a non-pooled `note_acquire` both incremented `created`, so
    every cold start counted twice — in the one series a capacity planner would
    use to size a pool. The fix splits the responsibilities; `note_acquire`
    records latency for a fresh instance and increments counters only for a pool
    hit.
  → 18 unit tests including a concurrent-increment test (8 threads × 1000
    updates; no count lost), a histogram-exhaustiveness test (no observation
    dropped), and an exposition-format test that checks every sample line is
    `name value` with exactly one space and every family has both HELP and TYPE.
  → §10.2 Metrics that ship by default
- [x] **HOST-020** Write the Wasmtime upgrade runbook and the compatibility-test suite.
  → Done, both halves. **Runbook:** `docs/wasmtime-upgrade-runbook.md` — ten steps, each naming its evidence and what a failure looks like, scoped against `R-03`. It distinguishes the *planned* upgrade from the CVE path (`docs/wasmtime-advisory-process.md`, `SEC-014`), because a scheduled bump has no 72-hour clock and the dangerous upgrades are the ones that **pass**.
  → **Suite:** `crates/qqq-host/tests/compatibility.rs`, 6 rows. It traps real components on a real engine, takes the **actual** message, and asserts both that `classify_trap` maps it to the documented code *and* that the message still contains the substring the classifier keys on. The second assertion is the load-bearing one: it fails naming the vanished key.
  → **The gap it closes.** `classify_trap` matches substrings of Wasmtime's error text, so a reword silently drops a trap to its default code. Every existing unit test fed it a **hand-written** string, and `tests/engine.rs` asserted `contains("fuel") || contains("all fuel")` — a disjunction of known wordings, written to survive a reword and therefore unable to detect one.
  → Rows: fuel (`QQQ-3002`), epoch (`QQQ-3003`, the sharpest — Wasmtime's epoch message is a bare `interrupt` with no domain word to anchor on), `unreachable` (`QQQ-3006`), out-of-bounds, the limit-versus-bug distinction, and a version tripwire.
  → **Fault-injected**: changing the classifier's key to `trap: interruption` (what a reword looks like from this side) fails exactly 1 row; restored byte-for-byte with a hash check and a clean `git status`.
  → **Verified**: all 6 rows execute under CI's exact `cargo test --workspace --all-features` — confirmed by listing the discovered tests, not assumed. Gate clean at `4eeab7d`: 2415 workspace tests (was 2409), 57 guest tests.
  → **Limits stated, not implied**: the suite covers five failure modes, not every trap Wasmtime can produce, and a refused `memory.grow` is not a trap at all, so that row asserts a classification against a synthetic string rather than trapping a real engine. Both recorded in the runbook.
  → §15 — Risk Register
- [x] **HOST-021** Implement the module-preloading strategy for scale-out (compile on deploy, not on first request).
  → Done: `crates/qqq-host/src/preload.rs` — `preload(items, limits, engine_config,
    capacity)` compiles a whole set against **one** engine and returns a
    `PreloadReport` with per-item outcomes and timings. 12 unit tests.
  → **The cost it removes is real and specific.** §2.3 gives two budgets for the
    same operation: instantiation <= 100 µs warm-pool and **<= 5 ms
    cold-from-cache**. The second is an AOT `.cwasm` compiled ahead of time.
    Compiling from source is a different order of magnitude — Cranelift on a real
    component is tens to hundreds of milliseconds — so the first request to a
    freshly deployed host pays a cost no later request pays, and it appears as a
    latency spike on exactly the request an operator is watching after a deploy.
  → **One engine, not one per item.** An `Engine` holds the Cranelift compiler and
    the pooling allocator's *reservation*, which is expensive to construct and
    cheap to reuse. One per component would multiply the reservation by the
    component count — the over-commit failure `HOST-023` exists to prevent — and
    would make preloading **cost** memory rather than save latency.
  → **Partial success is the only useful outcome**, and the module is built around
    that judgement. A preloader that returned `Err` on the first bad artifact
    would leave an operator with *nothing* preloaded and one error, which is
    strictly worse than ninety-nine preloaded and one error. So `preload` returns
    `Err` only when the whole set cannot be admitted (a whole-set failure with no
    per-item outcome to report), and a bad component is reported in the report for
    the deploy tool to judge — it knows whether that component mattered.
  → **`failures()` is derived, not stored.** A stored count is a second source of
    truth for the same fact, and the two drifting is how `is_complete()` starts
    lying. Pinned by `the_failure_count_agrees_with_the_failed_iterator`.
  → **It does no file I/O.** The `.cwasm` bytes are handed back for the caller to
    write, which keeps the module testable without a filesystem and keeps §4.3's
    layering intact — `qqq-host` owns the engine, not the disk.
  → `cache_key_for` is exposed rather than left to the caller because the key must
    agree between the process that **writes** the cache and the process that
    **reads** it, and those are different deploys. A key computed differently in
    the two places is a cache that silently never hits — which makes an AOT cache
    look useless rather than broken. A test pins that the key changes with
    `EngineConfig`, so a deployment that switched to deterministic mode cannot
    load artifacts compiled under the other and break §10.5's bit-identical replay.
  → `PreloadItem`'s `Debug` is manual so a log line prints `4096 B` rather than
    the bytes — asserted by a test, because a 4 KB dump in a log is the kind of
    thing nobody notices until the log is unreadable.
  → §9.4 Specific optimizations planned
- [x] **HOST-022** Implement resource-handle table pooling and lifetime diagnostics.
  → Done: `crates/qqq-host/src/handles.rs` — `HandleTable<T>` with generation-tagged
    handles, slot reuse, limit enforcement and lifetime counters. 16 unit tests.
  → **The security property is the generation, not the table.** A handle the guest
    holds is guest-controlled input, and two attacks follow directly. **Forgery:**
    the guest passes `9999` when three handles exist. **Recycling:** the guest
    closes handle 3, the host reuses slot 3 for a *different* resource, and a
    stale copy of the old value now reaches a resource it never legitimately
    opened. Both are addressed by packing a generation counter beside the slot
    index (`| generation:32 | slot:32 |`), incremented on every free — so a
    recycled slot is **unaddressable** by the stale handle, turning a
    use-after-free into a clean `QQQ-3005`.
  → `a_recycled_slot_is_not_addressable_by_a_stale_handle` asserts the slot is
    genuinely reused (`old.slot() == new.slot()`, so the fixture really exercises
    recycling) and that the old handle is dead. Without the generation that test
    fails, which is what makes it a security test rather than a unit test.
  → **A wrapped generation refuses the slot rather than reusing it.** At
    `u32::MAX` the counter cannot advance, and racing it would re-validate an old
    handle — the same attack the generation exists to stop. The slot is retired
    and counted, so the wrap is an error rather than a silent unsoundness.
  → **The diagnostics distinguish a leak from churn, which a live count cannot.**
    A guest that opens 256 handles and closes 256 is healthy; a guest that never
    closes is leaking; both show the same `open()` value. `opened`/`closed`
    together make the leak visible, and `invalid` is the attack signature — a
    steady non-zero value means a guest is guessing handles, holding stale ones,
    or has a bug.
  → **`get_counted` exists because `get` cannot count.** `&self` cannot mutate a
    counter, and adding a `Cell` to every table for one diagnostic is the wrong
    trade. Rather than hide the asymmetry, the module documents it and offers the
    `&mut self` form for callers that want the metric accurate.
  → **`remove` assigns the next generation into the slot rather than clearing it
    then repopulating**, so the slot never passes through a state where an old
    handle would match.
  → Three defects found while writing it, all in the *test* rather than the code
    (`§O-064`): `the_table_never_exceeds_its_limit` called `insert` twice per
    iteration and panicked inside its own assertion helper; `get_mut` could not
    compile because it built the error while holding a mutable borrow of
    `slots`; and clippy's `unused_self` showed that the `invalid()` helper had a
    dead receiver left over from an earlier design. Each is recorded where it was
    found rather than silently corrected.
  → §4.5 The ABI boundary — what crosses and at what cost
- [x] **HOST-023** Implement `ResourcesRequired`-based admission control: refuse to load a component whose declared minimums exceed the host's capacity.
  → Done: `crates/qqq-host/src/admission.rs` — `admit(limits, capacity)` is a
    **pure function** of a component's declared requirements and a host's
    capacity, returning the computed reservation or a refusal naming both
    numbers. 13 unit tests.
  → **Why this matters more than it looks.** Wasmtime's pooling allocator is a
    *reservation*: `total_memories(n)` with `max_memory_size(m)` commits address
    space up front whether or not the instances exist. That makes a
    misconfiguration fatal in two directions — reserve too little and the pool
    refuses instances under load (`QQQ-6001`, with the cause three steps from the
    symptom), reserve too much and the *engine constructor* fails or the process
    is OOM-killed at startup. Both are decidable **before** the engine exists,
    from two numbers already known.
  → **`HostCapacity` is a value, not a query.** It is passed in rather than
    measured, so admission is testable without a machine of any particular size —
    a test that asserted "this fits" against the real host would pass or fail
    depending on the CI runner, which is the environment-dependent-check class
    `§O-058f` records. `Default` is deliberately **fixed** rather than derived
    from the host: a default that varied would make a manifest pass on a laptop
    and fail in a container, which is the bug this module exists to move
    *earlier*.
  → The **resident baseline** is subtracted rather than assumed free, because a
    reservation that ignores the runtime is exactly the one that passes admission
    and then dies. It saturates at zero rather than underflowing — a wrapped
    `available_bytes` would report petabytes and admit everything.
  → **Order is a decision, not an accident.** Degenerate limits (zero fuel,
    zero deadline, zero memory) are checked **first**, because a fuel budget of
    zero is not a tight limit — it is a guest that traps before its first
    instruction, and reporting that as a capacity problem sends an operator to
    resize a machine that was never too small. Pinned by
    `a_degenerate_limit_outranks_a_capacity_problem`, which uses a hopelessly
    over-committed host and asserts the *fuel* is what gets reported.
  → The reservation is `saturating_mul`, never `*`: a large per-instance size
    times a large count overflows `u64`, and a **wrapped product is a small
    number that passes every capacity check**. Pinned by
    `an_overflowing_reservation_cannot_wrap_into_fitting`.
  → **Writing that test found a wrong premise in the test, not the code**: the
    first version used `memory_budget_bytes: u64::MAX` and asserted a refusal,
    but that budget genuinely does fit a saturated reservation, so the refusal
    never happened. A test of the safety property has to use a budget where the
    difference is observable. Recorded in the test's own docs so the next author
    does not repeat it.
  → **The admission is now joined to the real engine path**, which is what makes
    it enforcement rather than a library. `build_pooling`'s documentation had
    claimed since it was written that *"the host refuses to start if that
    reservation is implausible"* — **and nothing implemented that refusal**.
    `config::build_engine(limits, engine_config, capacity)` is the join: it admits
    first, then applies the pooling configuration, then constructs the engine, and
    returns the admitted reservation alongside it. The two halves could not do it
    separately — the pool builder has no memory budget and the config builder has
    no manifest — so a caller using them independently would construct an engine
    for a component that cannot fit and discover it as an internal allocation
    failure naming no manifest field.
  → The ordering is pinned by `admits_before_constructing_the_engine`, which uses
    a host whose budget is below its own resident baseline (so it admits nothing
    at all) and asserts the refusal is **`QQQ-2005` from admission, not `QQQ-1002`
    from the engine config**. Asserting merely `is_err()` would pass even if the
    check ran *after* construction, which is the ordering the test exists to pin.
    The first version of that test did assert only `is_err()`, and would have
    passed for the wrong reason.
  → Two assertions had to be replaced when Wasmtime turned out to expose no
    `Engine::is_pooling_allocator`. Rather than weakening them, the engine is
    made to do **real work**: `precompile_component` on a minimal component
    exercises the allocation strategy, the component-model flag and the codegen
    backend at once, which is strictly stronger than reading a flag back (a flag
    can be set without the engine honouring it). The limitation is stated in the
    test rather than hidden: that proves neither configuration is *broken*, and
    cannot prove which strategy was selected — `build_pooling`'s sizing
    arithmetic is unit-tested directly, which is where that is decidable.
  → §6.1 `qqq-host` — the execution engine
- [x] **HOST-024** Port the three verification-probe assertions (missing-import failure, instantiation cost, fuel trap) into the permanent test suite and delete the scratch crate.
  → Done: the four probe assertions from `.scratch/witprobe` are ported to `crates/qqq-host/tests/engine.rs` with control cases: an unsatisfied import fails instantiation and names it, a component with no imports runs, fuel exhaustion traps while the host survives, and an epoch deadline interrupts a spinning guest. The scratch crate is deleted.
  → Partial: the assertions are ported; `.scratch/witprobe` still exists and must be deleted.
  → §6.1 `qqq-host` — the execution engine

### CON — Contracts

- [x] **CON-001** Finalize and publish the `qqq.toml` JSON Schema.
  → Done: `schema/qqq-toml.schema.json`, generated from
    `qqq_cap::manifest::Manifest` by `tools/gen_schemas.py` and enforced in CI by
    `python tools/gen_schemas.py --check`, which reports DRIFT when a field is
    added to the Rust type and the document is not regenerated.
  → **The document was published but wrong, and the drift check could not see it**
    (`§O-205`). Three keys were published under names the code does not declare:
    `dev_dependencies` for the declared `dev-dependencies`, and `generated_by` /
    `lockfile_hash` for `generated-by` / `lockfile-hash` in the lockfile's
    `Metadata`. `dev-dependencies` was also listed **required**, so the schema
    rejected a minimal manifest the parser accepts - and `Lockfile.packages`
    carries `#[serde(rename = "package", default)]`, so the lock schema rejected
    a package-less lockfile that `Lockfile::parse` has a test for.
  → `--check` was structurally incapable of catching any of it, because it compares
    the document against the *generator's own output*; both sides carried the same
    misreading, so they agreed and CI was green.
  → The cause was `read_structs` searching its three serde patterns **one line at a
    time** while each pattern anchors on `#[serde(` and continues across newlines,
    so every multi-line attribute was silently ignored. Fixed by gathering the
    attribute block from `#[serde(` to its closing `)]` and searching it once, and
    by adding a `skipped` flag so the `required` rule honours
    `skip_serializing_if` as well as `Option<T>` and `#[serde(default)]` - which
    is what the generator's own comment had always claimed.
  → **The guard is a second, independent check rather than a tighter first one**:
    `tools/check_schema_conformance.py` compares the published document against the
    `#[serde(...)]` attributes in the Rust source - every documented key declared,
    every declared key documented, requiredness matching the source's optionality
    markers - walking `$defs` as well as the root. 14 self-test cases, including an
    empty schema, which is the anti-vacuity case because an empty document
    describes every possible file.
  → `tools/self_test_schemas.py` now carries **8/8** injections, the eighth being
    the multi-line attribute: with the line-oriented reader restored and the
    `dev-dependencies` attribute removed, the output is unchanged, and with the
    fixed reader the removal is honoured - so the case discriminates the two
    readings rather than merely exercising the code.
  → §5.3 The manifest — `qqq.toml`
- [x] **CON-002** Implement manifest parsing with schema-validated diagnostics naming the exact line.
  → Done: `Manifest::parse` produces field-named diagnostics with a line reference.
  → §5.3 The manifest — `qqq.toml`
- [x] **CON-003** Implement `qqq.toml` normalization: host patterns, secret references, path canonicalization.
  → Done: `qqq-cap::normalize` — host patterns, secret references, path canonicalisation.
  → §6.2 `qqq-cap` — the capability engine
- [x] **CON-004** Finalize and publish the `qqq.lock` schema including per-package `caps`.
  → Done: `schema/qqq-lock.schema.json`, generated from
    `qqq_pkg::lock::Lockfile` by `tools/gen_schemas.py` and checked for drift in
    CI. Six `$defs` entries, five resolved `$ref`s, one string enum.
  → **`caps` is present and typed**, verified by reading the generated document
    rather than assuming: `LockPackage`'s properties are `caps`, `digest`,
    `name`, `source`, `version`, `wit`, and `caps` is `{"type": "array", "items":
    {"type": "string"}}`. The per-package capability record §5.4 describes is
    therefore part of the published contract, not only of the Rust type.
  → **Why this landed with `CON-016` rather than as its own piece of work**: the
    item asks for a schema *finalized and published*, and the moment the
    generator exists the schema is derived, published and kept in sync by CI.
    Writing it by hand would have created a second source of truth — which is
    precisely the drift `CON-016` exists to prevent — so the two items are one
    mechanism, and the checklist records that rather than counting the same work
    twice.
  → §5.4 The lockfile — `qqq.lock`
- [x] **CON-005** Implement `lockfile-hash` covering all resolved artifacts and config.
  → Done: `crates/qqq-pkg/src/lock.rs` — `compute_hash`, `stamp`, the
    `lockfile-hash` metadata field, and `BuildConfig`. **44 tests** in the module
    (9 new), all green.
  → **The item's two clauses were satisfied to different degrees, and the audit
    found the gap by reading the wording (`§O-110`).** "All resolved artifacts"
    was covered: the format version and every per-package field — `name`,
    `version`, `source`, `digest`, `wit`, `caps` — with NUL separators so
    `("ab","c")` cannot collide with `("a","bc")`, and a record separator so two
    packages cannot collide either. **"And config" was not covered at all**, so
    two builds from one lockfile with different `[build]` settings produced the
    **same hash while producing different artifacts** — silent exactly where
    §5.4 promises *"a build is either reproducible or it loudly is not."*
  → **Why the existing 38 tests could not see it**: every one of them tests a
    field the hash *does* cover (`the_hash_covers_the_artifact_digest`,
    `the_hash_covers_the_capabilities`, `the_hash_changes_with_every_covered_field`).
    A suite organised as "each covered field has a test" is structurally
    incapable of noticing a field that was never added — the input set excludes
    the target, which is `§O-092`/`§O-103`'s shape for the fourth time, this time
    in a *test suite* rather than a checker.
  → **`BuildConfig` is four fields, not the whole manifest.** Language, target and
    profile are the three inputs that change the bytes `qqqai build` produces, and
    the declared grant set changes the authority the artifact is built against.
    Description, licence and package name change no output byte, and folding them
    in would move the hash for edits that cannot affect reproducibility — which
    trains a reader to ignore it.
  → **An absent config contributes nothing**, so every lockfile written before
    this field existed keeps its exact digest. Folding in an empty block
    unconditionally would change every lockfile in the world on upgrade and
    report every project as dirty — a change a package manager must never make
    silently.
  → **And the defect the new tests found, in code written minutes earlier**: the
    first version wrote the config's group separator *before* testing whether the
    config was empty, so `None` and `Some(BuildConfig::default())` hashed
    differently — while `skip_serializing_if` makes them identical *files*. A
    lockfile would have changed its own digest merely by being read and written.
    Caught by `a_lockfile_without_config_hashes_exactly_as_before`, whose
    assertion was the non-obvious one: the natural test checks only the `None`
    case. **A field whose absence is indistinguishable from its emptiness after a
    round trip must be indistinguishable in any hash over it.**
  → §5.4 The lockfile — `qqq.lock`
- [x] **CON-006** Implement reproducible-build verification that fails when output digests are unstable.
  → §5.4 The lockfile — `qqq.lock`
  → Done, and verified by driving the **command** rather than the helper. `--reproducible`
    records a digest baseline in `target/qqq/<name>.component.wasm.digest` and compares every
    later build against it, failing with `QQQ-1005` when the source produces a different artifact.
  → Three-step proof against a real project:
    (1) `qqqai build --reproducible` records a baseline;
    (2) a rebuild of the same source passes and the digest is stable;
    (3) changing one line of source **fails the build** with
    `error[QQQ-1005]: two builds of the same source produced different artifacts`, carrying
    `previous_digest` and `current_digest` in its context.
  → The check was verified against the artifact rather than against its own stamp: the on-disk
    file hashes to `851351fd...`, exactly the `current_digest` the error reports, so the tool
    computed a real digest rather than narrating one. After the failure the stamp **still holds
    the old baseline**, which is deliberate — a failing build must not poison the thing it is
    compared against, and that is what makes the check usable twice.
  → Covered by three unit tests (`the_first_reproducible_build_records_a_baseline`,
    `a_matching_digest_passes_and_a_differing_one_fails`,
    `a_non_reproducible_build_writes_no_stamp`); the first exists because treating absence as a
    mismatch would fail `--reproducible` on every clean checkout.
  → Measured while proving it, and worth recording because it is a property rather than a bug:
    **the digest is of the artifact, so the promise is toolchain-independent.** The same check
    holds for the other four languages once their build drivers land.
- [x] **CON-007** Define the interface-versioning policy: SemVer per WIT package, `@since` mandatory.
  → Done: the policy is stated in `tools/check_wit_since.py`'s header as four
    rules with the reason for each, and **enforced** rather than described. Every
    WIT package is SemVer'd in its `package` line, and every exported function
    carries `@since(version = 1.0.0)` — **re-derived from the tool rather than
    carried**: `python tools/check_wit_since.py` reports *"16/16 file(s) satisfy the
    versioning policy (82 exported function(s) checked; 1 world(s))"*. The
    annotations were added by `tools/add_wit_since.py`.
  → The policy also states what is deliberately **not** required, which is what
    makes it a policy rather than an aspiration: types and variants inherit their
    introducer's version within a package, so annotating all of them would triple
    the file size for no information a caller needs; and `@unstable` is admitted
    as an alternative but nothing in V1 claims it, so requiring the choice would
    be inventing work.
  → §2.5 NN-5 — Explicit Contracts Over Implicit Behavior
- [x] **CON-008** Implement the CI check that every published WIT function carries `@since`.
  → Done: `tools/check_wit_since.py`, wired into CI beside `check_wit.py`.
  → **A parser is not enough, and that was verified rather than assumed.** A WIT
    file with no `@since` at all is accepted by `wasm-tools` and exits 0 — so
    `check_wit.py` proves each file parses while saying nothing about the
    contract. The two answer different questions and both are required; this is
    the same distinction `check_wit.py` itself documents about structural tests
    versus parsers.
  → The check verifies four things: the package is versioned; every exported
    function has `@since`; the version is not greater than the package's; and the
    version is not below 1.0.0.
  → `tools/fault_inject_wit_since.py` proves it fails for the right reasons with
    three injections, **all of which leave the file parseable** — including the
    one that matters most: a `@since` **moved** onto a `use` line, where the
    annotation silently attaches to the wrong item, so the file is valid WIT with
    a wrong contract. That case is the whole argument for a policy check existing
    alongside a parser.
  → Two findings from writing it, both recorded (`§O-061c`): the "`@since` above
    the package version" case is **deliberately not injected** because
    `wasm-tools` already rejects it (`error: feature gate cannot reference
    unreleased version`), so no parseable file triggers our rule and the harness
    would report BROKEN rather than DETECTED — the rule stays as defence in depth
    and the harness says so rather than implying it is exercised. And the first
    injection of the misplaced case **added** an annotation instead of moving
    one, so no violation existed and the harness reported a checker defect that
    was really a harness defect.
  → §2.5 NN-5 — Explicit Contracts Over Implicit Behavior
- [x] **CON-009** Define and enforce the typed-error rule: every fallible host call returns `result<T, E>`.
  → Done: `tools/check_wit_errors.py`, wired into CI with a fault-injection harness.
    **82 functions checked across 15 interfaces, 19 declared infallible by name.**
    Re-derived from the tool rather than carried: `python tools/check_wit_errors.py`
    prints these three numbers itself, and the entry read 73/13 until 2026-09-23 —
    a count copied at authoring time and never re-run. If this entry and the tool
    disagree again, the tool is right and this line is stale.
  → **The rule is about *fallible* calls, and that distinction is the whole
    difficulty.** It cannot be "every function returns `result`": `clock.timezone`
    returns `"UTC"` and genuinely cannot fail, while `crypto.decrypt` returns
    `result<list<u8>, aead-error>` because a tag may not verify. The check is
    therefore *"every fallible function returns `result<T, E>`, AND every
    infallible one is named in an allowlist with the category that makes it
    infallible"* — which turns "this cannot fail" from an **omission** into a
    **claim someone wrote down**, the property NN-5 asks for. A function added
    without a `result` and without an allowlist entry fails the check, so its
    author must decide which it is.
  → The allowlist is not a dumping ground: each entry carries one of five
    categories (constant, host-fixed measurement, pure computation over a closed
    enum, capability-gated enumeration, pure predicate), and two entries are
    themselves security properties. `secrets.exists` returns `bool` **by design**
    so a guest cannot probe a value, length or type — an error type there would
    be a disclosure channel. `sql.close` is infallible because a closer that can
    fail forces every caller into a cleanup path it cannot act on.
  → **It also enforces the rule's second half.** `result<T, string>` and
    `result<T, u32>` parse fine and defeat *"not a status code buried in a
    payload"*, so the error side must be a **named WIT variant** — which is what
    gives a caller in any of the five languages an exhaustive `match` rather than
    an integer to compare against constants.
  → **Three checker defects found by writing it, every one of which reported a
    *correct* file as broken** (`§O-062`): a line-at-a-time scanner missed
    multi-line signatures and flagged `crypto.encrypt`/`crypto.decrypt` as having
    no `result` (they have one, spanning five lines); a bare-name key could not
    distinguish `wall-clock.now` (fallible) from `monotonic-clock.now`
    (infallible), so the key is now `file.wit:interface[.resource].function`; and
    clearing interface and resource scope together mislabelled
    `database.databases` as `database.statement.databases`. A checker whose
    output is noise gets weakened rather than fixed, so each was corrected at the
    root.
  → `tools/fault_inject_wit_errors.py` proves it fails for the right reasons with
    three injections — a fallible function with no error type, a primitive error
    type, and a stale allowlist entry — every one of which leaves the file
    **parseable**.
  → §2.5 NN-5 — Explicit Contracts Over Implicit Behavior
- [x] **CON-010** Implement the CI check that no host interface reads an environment variable or the working directory implicitly.
  → Done: `tools/check_no_ambient.py` — 73 source files across the six
    guest-reachable crates, wired into CI with a fault-injection harness.
    Also serves `CON-018`, which is the same rule stated as an architecture test.
  → **A source check rather than a runtime test, and the reason is the failure
    mode.** A host interface that reads `QQQ_CONFIG` on a path nobody tests
    behaves identically to a correct one under every test that does not set it —
    and differently on a developer's machine. That divergence appears only in the
    environment where nobody is looking.
  → **The load-bearing part is the allowlist discipline.** A prohibition with no
    exemptions gets worked around by the first person who hits it, so:
    `std::env::consts::{ARCH,OS,FAMILY}` is allowed because those are
    compile-time constants of the **build**, not of the running environment; and
    the two exemptions are scoped to **(file, construct)** rather than to the
    file, so the exempted `var_os` in `cap::normalize::RealEnv` does not
    blanket-cover a bare `var` beside it. That scoping is asserted by an
    injection, not by reading the code.
  → `cap::normalize` is the *remedy* rather than an exemption from the rule:
    environment access there goes through the `HostEnv` **trait**, with `RealEnv`
    as the production implementation and a fake in tests. The rule forbids
    *implicit* reads; an explicit, injected, mockable implementation is what NN-5
    asks for.
  → Injected: an ambient env read, a CWD dependency, an ambient `temp_dir`,
    and **a second construct inside the exempted file** — all four detected, plus
    a negative control proving a `#[cfg(test)]` use is NOT reported (a checker
    that flags test code gets worked around rather than obeyed).
  → §2.5 NN-5 — Explicit Contracts Over Implicit Behavior
- [x] **CON-011** Write the WIT style guide and enforce it in review.
  → §6.3 `qqq-abi` - WIT interfaces as the single source of truth
  → Done as both halves the item names: a guide, and enforcement that is not review.
  → The guide is `docs/wit-style-guide.md`. Proposal §6.3 states six rules and says they are
    *"enforced in review"*; review is prose, and this repository's principle is that prose does
    not fail a build. Four of the six now have a machine check (`check_batch_first.py` rule 1,
    `check_wit_errors.py` rule 3, `check_wit_since.py` rule 6, and the new
    `tools/check_wit_style.py` for rules 2, 4 and 5), and the guide says which is which and why.
  → **Rules 4 and 5 are decided completely; rule 2's decidable half is enforced and the rest is
    named.** Rule 2 (*"streaming for anything that can exceed 64 KiB"*) is a judgement about a
    payload's realistic size, so what the checker enforces is that a declared `stream<T>` is
    consumed by some function - an unconsumed stream type is one no caller can obtain, which
    makes any review of the rule vacuous. The boundary is written in the module doc, following
    `check_batch_first.py`'s precedent of naming what it deliberately does not attempt.
  → Rule 5's scope is likewise explicit rather than blanket: the doc requirement applies to
    **`@since`-published** functions, the set the Proposal calls published. A requirement over
    every one of the 85 existing functions would produce a check nobody can turn green, which is
    the outcome `check_batch_first.py` names as *"paperwork"*.
  → Verified: `python tools/check_wit_style.py` passes on the real corpus - **17 .wit files, 85
    functions, 85 published, zero violations** - and the self-test passes 11/11, firing on each
    rule and staying silent on valid input.
  → **The corpus injection is what proved the rule works, and the first version failed it.** A
    synthetic self-test could not catch that the rule matched nothing: its fixtures were written
    from the same wrong assumption as the pattern, which required a *quoted* version while every
    real `@since` in this corpus is bare (`@since(version = 1.0.0)`). Removing a whole six-line
    doc comment from `wit/qqq-env.wit` now fires `[5/doc-comment]` naming the function, and the
    restore is byte-for-byte. Recorded as `§O-227`.
  → Both the checker and its self-test are wired into `ci.yml` and `docker/entrypoint.sh`.

  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth
- [x] **CON-012** Enforce the batch-first rule: implement a lint that flags list-shaped operations accepting single elements.
  → Done: `tools/check_batch_first.py`, wired into CI with a fault-injection
    harness. **5 declared batch pairs verified complete and consistent.**
  → **The scope is deliberately narrower than the item's wording, and that is the
    finding.** §4.5's rule is *"a host interface that would naturally be called
    in a loop must instead accept a batch"* — the operative phrase is a judgement
    about usage, which **no checker can make**. An earlier version demanded that
    every singular function be classified, and produced 23 demanded
    classifications including `sql.txn.commit`, `trace.span.event` and
    `http.incoming-handler.handle`. Those are *inherently* singular: committing a
    transaction in a loop is not a chatty interface, it is what transactions are.
    A tool demanding a written excuse for each of them is not enforcing a rule,
    it is generating **paperwork** — and paperwork gets `allow`-ed away.
  → What is decidable, and therefore checked: every **declared** batch pair must
    be real, must actually take a collection, and must agree with its singular
    form on the error type. The pair list is declared rather than inferred from
    the `-many` naming convention, because inference breaks the first time a
    batch form is named differently; and a declared entry naming a function that
    no longer exists is itself a failure, so the list cannot rot.
  → **The second rule caught a real weakness in my own first implementation.**
    "Does the signature contain `list<`" passes `digest-many(input: list<u8>)` —
    one buffer, not a batch — so the crude test **certified the exact defect it
    existed to find**. The check now inspects the element type: a scalar element
    means a buffer rather than a collection, while `list<list<_>>`,
    `list<string>`, `list<tuple<_>>` and `stream<_>` all count.
  → Injected: a renamed sibling, a batch form taking no collection, and an
    error-type mismatch between the two halves — all detected, plus a negative
    control proving a new *unpaired* singular function does **not** fail (which is
    the paperwork failure the redesign avoided).
  → §4.5 The ABI boundary — what crosses and at what cost
- [x] **CON-013** Implement the capability-name registry with a published, versioned list.
  → Done: `Capability::all()` — the versioned capability-name registry; `qqqai schema` publishes it.
  → §5.3 The manifest — `qqq.toml`
- [x] **CON-014** Implement `qqqai inspect`'s static capability analysis from the import table.
  → Done: `qqqai inspect <artifact>` compiles the component (without instantiating it) and reads its import table, mapping each imported interface to the capability it requires. **Correction:** this was ticked when the claim was not yet true — the command accepted a path, discarded it, and reported the *manifest's* capabilities, so an artifact's import table was never read. Verified and fixed in `§O-038a`. The precise interface→capability mapping that makes the report correct is `§O-038b`/`§O-038c`.
  → §2.5 NN-5 — Explicit Contracts Over Implicit Behavior
- [ ] **CON-015** Define the deprecation mechanics in WIT: `@deprecated` with a removal version.
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship
- [x] **CON-016** Implement the schema-drift CI check for the manifest, lockfile, CLI output and error catalogue.
  → Done: `tools/gen_schemas.py` + `tools/self_test_schemas.py`, with
    `schema/qqq-toml.schema.json`, `schema/qqq-lock.schema.json` and
    `schema/cli-envelope.schema.json` published and wired into
    `.github/workflows/ci.yml` **and** `docker/entrypoint.sh`. **8/8 fault
    injections detected** (`python tools/self_test_schemas.py`; this line said
    **7/7** and was corrected — see below).
  → **Three things this item did not originally cover, added afterwards.** The
    tick above predated all three, so the count and the scope were both stale.
    • **The schemas were only checked against their own generator, which was the
    wrong comparison.** `gen_schemas.py --check` proves the document matches what
    the generator *read*; it says nothing about whether the generator read the
    source correctly, and it had not: the manifest schema documented
    `dev_dependencies`, `generated_by` and `lockfile_hash` where the source
    declares `dev-dependencies`, `generated-by` and `lockfile-hash`, and listed
    one of them as **required** so the schema rejected a minimal manifest the
    parser accepts. `tools/check_schema_conformance.py` now compares the
    published schema against the Rust source directly — every documented key must
    be declared, every declared key documented, and `required` must match the
    source's optionality markers. It carries **20 self-test cases** and covers
    four surfaces. Recorded as §O-205.
    • **The CLI envelope was hand-written and had drifted from the binary it
    describes.** It listed 5 fields and a fabricated `check_schema_drift.py`;
    the shipped binary emits 8 plus an `error` with `code`, `message`,
    `remediation`, `docs_url`, `retryable`, `cause` and `context`. It is now
    **derived** from `Envelope<T>` and `ErrorPayload` in
    `crates/qqq-run/src/output.rs`, and — because a schema can agree with its
    source while the source disagrees with the running program — the checker
    **runs the shipped binary** and validates three real envelopes against the
    published schema. Recorded as §O-206.
    • **The runtime probe then found a field that was present and false.**
    Adding `Envelope::exit_code` let the probe assert the envelope's number
    equals the process's status, which showed every failure envelope reporting a
    hardcoded `1` — 38 of 48 disagreed with their own `$?`. Recorded as §O-208.
    • **The published envelope is a live contract and the probe is what keeps it
    so**: the checker's own self-test injects a constant `exit_code` and rebuilds,
    because with the field hardcoded every unit test still passes and the binary
    still exits 69.
  → **§8.3's sentence had no implementation**: *"CI fails if it drifts from the
    implementation"* — and no drift check existed anywhere. Measured, the
    surface was worse than unchecked: **three of §8.3's machine-readable
    surfaces had no published schema at all**, so there was nothing for a check
    to check. The deliverable is therefore a generator *and* a checker.
  → **The schemas are derived from the Rust types, not from the binary.**
    `Manifest`, `Lockfile` and the CLI envelope are read from source, so a field
    added and not regenerated is caught by the **same commit** that introduced
    it, and the check runs in CI on a tree that has not been built. Running
    `qqqai schema` would check *the binary*, which is a different claim.
  → **The generator refuses rather than emitting a partial document.** Its first
    run failed with ``unrecognised Rust type: 'Package'`` — correct behaviour,
    because a schema missing a field is worse than no schema: it is believed.
    Named types then resolved to `$ref`s into `$defs`, and `FsMode`/`ChangeKind`
    to string enums read from each enum's own `as_str`. The published lockfile
    schema therefore contains `"modified-in-place"`, the spelling a document
    actually holds, rather than `ModifiedInPlace`, which no document ever holds.
  → **The self-test found a real generator defect within minutes of it being
    written (`§O-112`).** Injection 4 replaced a field's type with `NoSuchType`
    and observed `GENERATION FAILED … exit 0`: `generate()` incremented its
    failure counter and **returned 0 on the write path**, so a CI job would have
    **passed while one of the three schemas was never published**. A partial
    publication is worse than a failed one — the tree holds a mix of current and
    stale contracts with nothing marking which is which. Fixed, and the two
    failure kinds (*could not be generated* vs *drifted*) are now reported
    separately because they need different fixes.
  → **Injection 6 is the anti-vacuity case**: with every source emptied, a
    generator emitting `{"properties": {}}` would "succeed", and that schema
    describes **every possible document** — the schema equivalent of a check
    that finds nothing. It must fail, and it must name which struct was missing.
  → The six injections break the generator's **inputs** (an added field, an
    unknown type, a changed enum spelling, emptied sources) and its **outputs**
    (a deleted schema, a hand-edited schema) separately, and each is applied to a
    **copy** of the tree in a temporary directory so the repository is never
    touched (`§M-007`).
  → **One measurement produced no change, and is recorded so it is not "fixed"
    later**: the schema document uses `schema_version` where §8.3's illustrative
    JSON writes `schemaVersion`. The snake form is used at **all four** call
    sites, so it is a settled choice rather than a slip, and the proposal's block
    is illustration rather than a normative field name. Changing it would break
    the machine contract for no stated reason — **a measurement that produces no
    change is still a measurement.**
  → §8.3 The machine contract layer
- [x] **CON-017** Publish the contract-stability promise for each surface (WIT, manifest, lockfile, CLI JSON).
  → §2.5 NN-5 — Explicit Contracts Over Implicit Behavior
  → Done: **`docs/stability.md`**, which states a separate promise per surface because they are
    not consumed the same way. Each is a table of what is stable, what counts as an *additive*
    change, and what counts as a *breaking* one:
    • **WIT** — interface names and function signatures stable within a major version; adding an
    interface or a function is minor. The dependency direction is why this matters: an already-built
    artifact runs on a host that supports those interfaces, so a break is a break for every guest
    ever compiled against them.
    • **Manifest** — a manifest that parses today parses later with the same meaning. The
    security-relevant row is that **an unknown key is a parse error, not a warning**: a capability
    key that produced a warning would read as granted to a human and as absent to the runtime.
    • **Lockfile** — a lockfile written by one version resolves identically under any later one;
    byte-identical output for identical inputs.
    • **CLI JSON** — `error.code` (`QQQ-nnnn`) is **permanent**, because agents match on it; new
    fields and new variants are minor; codes are retired, never recycled.
  → **Each promise names the mechanism that enforces it**, which is what separates a promise from
    a wish: the tier table by `check_tiers.py`, WIT by `check_wit_style.py` / `check_wit_reference.py`,
    the manifest and lockfile by their published JSON Schemas via `gen_schemas.py --check`, and the
    error codes by the catalogue's round-trip test.
  → **What is not covered, named rather than implied:** `CON-015` (deprecation mechanics in WIT)
    is open, so the `stable` tier's notice period is a convention rather than a mechanism; the
    workspace is `0.0.0`, so every tier describes intent that becomes enforceable at 1.0; and
    `qqq-registry` and `qqq-fabric` have no tier because they are not built in this repository.
- [x] **CON-018** Implement the "no hidden global state" architecture test across all host interfaces.
  → Done: `tools/check_no_ambient.py` enforces §2.5's rule across the runtime
    crates — no environment-variable reads, no CWD dependencies, no process-wide
    mutable statics. `tools/fault_inject_no_ambient.py` proves the checker
    detects what it claims to (four injections), wired into
    `.github/workflows/ci.yml` beside the checker itself.
  → **The pairing is the point**: a checker and its `--self-test` land together,
    so a green result means "checked and clean" rather than "checked nothing"
    (`§M-006`). The four injections are chosen so each targets a distinct way the
    rule could be bypassed, not four spellings of one.
  → Verified live: `python tools/check_no_ambient.py` →
    `NO-HIDDEN-GLOBAL-STATE RULE PASSED`.
  → §2.5 NN-5 — Explicit Contracts Over Implicit Behavior

---

## 5. P2 — Capability engine (M2)

### CAP — Capability resolution

- [x] **CAP-001** Implement the three capability kinds (resource, operation, ambient) as distinct types.
  → Done: `CapabilityKind` in `qqq-cap::capability`, with the three kinds distinguished in resolution.
  → §6.2 `qqq-cap` — the capability engine
- [x] **CAP-002** Implement step 1: PARSE, with schema validation and line-accurate diagnostics.
  → Done: `qqq-cap::manifest` — strict parsing, field-named errors, line references.
  → §6.2 `qqq-cap` — the capability engine
- [x] **CAP-003** Implement step 2: NORMALIZE, including host-pattern expansion and secret-reference resolution.
  → Done: `qqq-cap::normalize` — host-pattern expansion and secret-reference resolution.
  → §6.2 `qqq-cap` — the capability engine
- [x] **CAP-004** Implement step 3: the developer-mode overlay, loudly non-production.
  → Done: `Layer::Developer` with `qqqai run --cap`; narrowing-only, warns when it changes anything.
  → §6.2 `qqq-cap` — the capability engine
- [x] **CAP-005** Implement step 4: the organization policy overlay, narrowing-only.
  → Done: `Layer::Organization`, narrowing-only.
  → §6.2 `qqq-cap` — the capability engine
- [x] **CAP-006** Implement step 5: the platform overlay, narrowing-only.
  → Done: `Layer::Platform`, narrowing-only.
  → §6.2 `qqq-cap` — the capability engine
- [x] **CAP-007** Implement step 6: RESOLVE to a serializable, hashable `Grants` set.
  → Done: `GrantSet` with a stable SHA-256 `digest()` over the granted capabilities.
  → §6.2 `qqq-cap` — the capability engine
- [x] **CAP-008** Implement step 7: BIND, constructing a per-instance linker from grants only.
  → Done: `qqq-host::build_linker` constructs the linker from `grants` alone.
  → §6.2 `qqq-cap` — the capability engine
- [x] **CAP-009** Implement step 8: RECORD, hashing resolved grants into the audit record.
  → Done: `GrantSet::digest()` — the hash that appears in the audit record.
  → §6.2 `qqq-cap` — the capability engine
- [x] **CAP-010** Prove the narrowing invariant with a test: no overlay configuration can widen a declared grant.
  → Done: `no_overlay_can_ever_widen` in `qqq-cap::resolve`: every layer x every mode x every capability.
  → §6.2 `qqq-cap` — the capability engine
- [x] **CAP-011** Implement the restricted policy expression language with static analysability and termination proofs.
  → Done: `crates/qqq-cap/src/policy.rs` — lexer, parser, static analyser,
    executable termination proof, scope/demand evaluator. **68 tests in that
    module**, all green, counted by `cargo test -p qqq-cap --lib policy::`
    (this entry said 72 until 2026-09-23, when the count was re-derived; 68
    is what the runner reports and `policy.rs` carries 68 `#[test]`
    attributes, so the two agree). Bounds: `MAX_EXPR_DEPTH` 16, `MAX_RULES` 4096,
    `MAX_SOURCE_BYTES` 1 MiB.
  → **The three claims §6.2 makes are made true rather than asserted.**
    *Non-Turing-complete*: no loop, no recursion, no user-defined function, no
    variable, no quantifier — every comparison is a field against a literal.
    *Statically analysable*: `Field` is an enum, so an unknown name is a parse
    error rather than a run-time `None`, and `Expr::eval` is **total**, so no
    predicate can be undecided when a request arrives. *Provably terminating*:
    `Policy::prove_terminating` returns a `TerminationProof` holding the
    **measured** facts (max depth, rule count, comparison count,
    `has_repetition`, `has_unbounded_input`), and parsing runs it at
    construction — so a policy that cannot be proven cannot exist as a value.
  → **Widening is unreachable, not merely unwritten.** `Policy::overlay` returns
    an `Overlay`, whose only use in `qqq-cap` is `GrantSet::narrow`, which
    intersects. A policy has no other output, so there is nothing that could
    widen and nothing to check.
    `no_policy_can_widen_a_grant_set` demonstrates it from the empty set with a
    hostile allow-everything policy.
  → **Two of §6.2's own examples did not parse, and both were filed as fixture
    errors first (`§O-106`).** `deny http.client to host "*.onion"` had no `to`
    clause, so the language could not express a **destination constraint** —
    a §7.1 threat row. `require mfa when capability == "sign"` read `mfa` as a
    capability. Fixed by adding `Field::Host` with a real `to` clause, and by
    letting `require` accept a field name as an **ambient requirement**. The
    third example, `subject.department`, is **still refused** and that is
    correct: `host` and `mfa` are values the host has, `department` is not, and
    admitting it would create a field that always evaluates to "unknown" — a
    rule that silently never fires.
  → **The condition of a `require` splits into scope and demand, per
    comparison** (`§O-107`): a comparison on `capability` says "this rule is
    about X"; every other comparison says "and this must hold". Four readings
    were tried; reading the condition as pure demand made one rule about signing
    keys a permanent failure for the whole deployment, and reading it as pure
    scope made the rule inert. An `or` that mixes the two roles has no sound
    reading and is a parse error naming the rewrite.
  → Fault injection throughout: the depth bound is enforced *during* parsing (a
    bound checked afterwards has already paid the stack cost it exists to
    prevent); `deep_not_nesting_is_bounded_by_the_proof_not_the_parser` pins
    that a `not` chain costs two depth levels while the parser recurses one
    frame, so the parser's bound and the proof's bound are different quantities;
    `a_destination_without_a_star_is_an_equality_and_a_dot_is_literal` pins that
    `to host "a.b"` cannot match `axb`; and `glob_match` is a hand-written
    linear matcher tested against an independent reference answer, because a
    regex engine is a compiler whose catastrophic backtracking would be driven
    by a policy file.
  → §6.2 `qqq-cap` — the capability engine
- [x] **CAP-012** Implement `qqqai why <resource>` producing the complete resolution chain.
  → Done: `qqqai why` renders the resolution trace with the deciding layer and the fix stanza.
  → §6.2 `qqq-cap` — the capability engine
- [x] **CAP-013** Implement the ordered-map requirement: no host interface exposes unordered iteration to guests.
  → Done: `BTreeMap`/`BTreeSet` throughout the capability and linker paths; no unordered iteration reaches a guest.
  → §10.5 Determinism — the feature nobody else has
- [x] **CAP-014** Implement per-tenant grant isolation and prove no cross-tenant handle leakage.
  → Done: `crates/qqq-host/src/tenant.rs` — `TenantScope`, `InstanceKey`,
    `GrantDigest`, `ComponentDigest`, `ScopeRefusal` and `TenantLedger`.
    22 unit tests, plus 4 in `crates/qqq-host/src/linker.rs` proving the scope
    travels with the store. `StoreData` gained `with_tenant` / `tenant_scope`.
  → **The item's two halves were true in different ways, and only one of them
    was a property of the types.** Grant isolation was already structural — the
    linker is built per instance from the resolved grants, so an ungranted
    import is *absent*. Handle containment was already structural too — the
    table is a field of `StoreData` and stores are not shared — but that is a
    fact about the call graph, not about tenancy. Two tenants on one artifact
    under one grant set produced two indistinguishable stores, and "no
    cross-tenant handles" held only because *nothing routed between them yet*.
    It would have stopped holding the first time a pool was added (`§O-104`).
  → **The key is `(tenant, component digest, grant digest)`, not `(tenant,
    component digest)`.** A component digest is a content hash of the wasm
    bytes, so two deployments of **the same artifact** under different manifest
    revisions share it and do not share authority. Keying on the digest alone
    hands a pooled instance created under the wider grants to the narrowed
    deployment — the common case for staging/production, or for one tenant
    whose grants were just revoked.
    `one_component_under_two_grant_sets_is_two_keys` is the test that separates
    them; every other test in the module passes without it.
  → **Re-scoping is unreachable rather than merely unwritten.** A `set_tenant`
    would be the entire vulnerability: the pool could be correct and one call in
    one request path would undo it. `TenantScope` fixes the tenant at
    construction; the only mutation available is `for_same_tenant`, which
    refuses to change the tenant, and `StoreData::with_tenant` consumes `self`
    so a store cannot be scoped twice without an explicit rebuild.
  → **`None` means unscoped, never "any tenant".** `StoreData::tenant` is
    `Option<TenantScope>` because `qqqai run` and 280 existing tests are
    single-tenant. The tempting reading of `None` — a wildcard — would make
    every one of those stores a cross-tenant hole the moment one was handed to
    a server request. `an_unscoped_store_reports_no_tenant_rather_than_any_tenant`
    pins the refusal.
  → **`is_isolated` was rewritten after its first version could not fail.**
    `live.keys().all(|k| k.tenant() == k.tenant())` compiles, runs, and returns
    `true` forever: in a `BTreeMap<InstanceKey, _>` the key *is* the filing, so
    the type cannot be asked "is this key filed under its own tenant". The
    invariant the type *can* hold is conservation — every entry has a non-zero
    count. A zero-count slot is the concrete leak: a pool slot not returned to
    the allocator, still carrying its original key, so a later tenant's acquire
    revives it with the previous tenant's claims attached.
    `a_ledger_with_a_zero_count_slot_is_detected_as_not_isolated` injects the
    fault into the private map to prove the check is not blind.
  → Fault injection: `probe`'s refusal branch is driven twice (foreign tenant,
    then stale grants), and the tenant is checked before the grant digest so a
    handle differing in both names the more severe reason. The refusal names
    **both** scopes — "denied" is not actionable, "this store belongs to
    `acme`, the handle to `globex`" is.
  → §7.1 What we are defending, precisely
- [x] **CAP-015** Implement capability-use accounting feeding the audit stream.
  → Done: `crates/qqq-host/src/audit.rs` — `AuditStream`, `AuditRecord`,
    `AuditFields`, `Outcome`, `Ledger`, `Append`, `AppendCounters`. **33 tests in
    that module**, all green, counted by `cargo test -p qqq-host --lib audit::`
    (this entry said 34 until 2026-09-23, when the count was re-derived; 33
    is what the runner reports and `audit.rs` carries 33 `#[test]`
    attributes). `DEFAULT_CAPACITY` 65,536.
  → **§10.1's three emphasised words are each a property a log does not have,
    and each has its own test.** *Append-only*: a full stream **refuses**
    (`Append::Full`) rather than overwriting — under the exact condition an audit
    stream is needed, a ring would evict the *start* of an incident, and the
    oldest records are the interesting ones. *Hash-chained*: every record carries
    its predecessor's digest and its own, so editing one field invalidates every
    later digest; `verify_chain` returns the **index** of the first break, not a
    boolean, because an index is an investigation and a boolean is only an alarm.
    *Evidence*: `AppendCounters` splits `recorded` from `refused`, so a gap is
    **visible as a value** — a caller that cannot tell "nothing happened" from
    "everything was refused" has no way to escalate.
  → **"Granted, denied, and *attempted*" is honoured as three outcomes, not
    two.** `Failed` is a fourth and is deliberately distinct from `Denied`: a
    denial means the guest was not permitted, a failure means it was permitted
    and the operation did not succeed — different remediations. `Attempted` is
    the one that makes the record evidence, because it is the only outcome that
    can show an intent that was **not** realised; without it, *"a component was
    deployed needing authority the manifest does not grant"* — the most common
    real event — leaves no record at all.
  → **The chain is a hash chain rather than a Merkle tree**, because the threat
    is retroactive editing and not third-party inclusion proofs: one comparison
    per record buys "any mutation invalidates every later digest". Fields are
    hashed with a **length prefix**, so the encoding is injective —
    `the_field_encoding_is_injective_across_a_split` pins that `ab`+`c` cannot
    hash as `a`+`bc`, which an un-prefixed concatenation would allow and which a
    guest controlling a function name could use to forge a record.
  → **`Ledger` answers §10.2's Capability row in all three of its dimensions** —
    uses by capability, denials by capability, **by tenant**. The tenant
    dimension is not a convenience: §7.1 names a compromised tenant as an
    adversary, and "which tenant is this?" is the first question a responder
    asks. A total answers nothing about that.
  → Fault injection: editing a field, removing a record and reordering two
    records are each detected, and each names the broken record; every one of the
    eight `AuditFields` is covered by the digest, tested in two halves so a
    failure names which class of field collided; the export **refuses** a
    corrupted stream rather than emitting a valid-looking document; and
    `assertions_on_constants` was fixed with a `const` block rather than
    suppressed, because a runtime assertion of `DEFAULT_CAPACITY > 0` can never
    fail and so carries no information (`§M-006`).
  → §10.1 The three signals, plus one unique to QQQ
- [x] **CAP-016** Implement the `qqq:secrets` interface: use a secret without disclosing it.
  → Done: `crates/qqq-host/src/host_secrets.rs` — `SecretStore`, `SecretMaterial`,
    `PermittedOp`, `RequestedOp` and the `SecretCrypto` delegation trait. 22 unit
    tests.
  → **The inversion §6.3 describes is enforced structurally, not by convention.**
    The guest sends a *name* and an *operation*; the host holds the material and
    returns only the operation's result. `SecretMaterial`'s value is a **private
    field with no accessor at all** — not a `pub` field and not a `value()`
    method, because either would make the guarantee a convention that the first
    caller to want it "just for logging" would break everywhere.
  → **Three properties, each with a test that would fail without it:**
    the material never appears in a result (asserted against the *key bytes*, not
    the result shape — a shape check passes even when the key is returned); the
    value does reach the primitive (the **control**, because proving the key does
    not leak is vacuous if it never reached the crypto); and an out-of-range
    `secret-op` discriminant is rejected, since the WIT variant lowers to a `u32`
    the guest controls entirely. A test pins the discriminants against the WIT
    declaration order, because a mismatch would make a guest's `sign` invoke
    `verify`.
  → **Order is a security decision.** The grant check runs **before** the material
    lookup, so an ungranted guest learns nothing about which secret names the host
    holds. `the_grant_check_precedes_the_material_lookup` uses a store where a
    secret is *resolved but not granted* and asserts `not-granted` — reversing the
    order would report `unavailable` and leak the material's existence.
  → **`Debug` is manual, and `debug_never_prints_the_material` pins it.** A
    derived `Debug` prints the bytes, and a secret in a log line is exactly the
    leak this interface exists to prevent. The manual form prints the name and the
    permitted operations — diagnostic and harmless. The length is withheld too,
    because length is a fact about the secret.
  → **It delegates rather than reimplementing crypto.** Signing, HMAC and AEAD
    already live in `qqq:crypto`; a second implementation would be a second source
    of truth for the algorithm choices (§4.3). `SecretCrypto` is the seam, which
    is also what lets the tests assert **access control** rather than a cipher's
    behaviour — `each_operation_dispatches_to_its_own_primitive` checks that
    `apply` reaches the right primitive, since dispatching to the wrong permitted
    one would pass every permission test.
  → **It reads no ambient state.** Resolution (`SecretRef`, `env:ORDERS_DB_URL`)
    happens once in the deploy layer; resolving per call would read the
    environment on the request path, which §2.5 forbids and
    `tools/check_no_ambient.py` enforces. A store is constructed with material
    already resolved.
  → **The test double had a defect, and the security test caught it** (`§O-065`):
    `FakeCrypto::public_key` returned `PUB` ++ key, modelling a *buggy* primitive
    that leaks the private half through its public key — so
    `the_secret_material_never_appears_in_a_result` failed, correctly. A fake has
    to model a correct implementation, or every test using it tests the fake's
    defect instead.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth
  → §7.1 What we are defending, precisely

### SEC — Security engineering

- [x] **SEC-001** Write the threat model document covering §7.1 assets and §7.2 adversaries.
  → Done: `docs/threat-model.md` — all six §7.1 assets and all seven §7.2 adversaries
    (plus the host administrator, listed rather than omitted). Each adversary names
    the code that defends it, how that is verified, **and its residual risk**.
  → It states first, and checks, that **no external audit has occurred**: §4's
    "validated by an adversary?" column is `No` for every row, because presenting a
    design model as a validated one would be the most dangerous document here.
  → `tools/check_threat_model.py` keeps it true: 9 code references must resolve to
    real crates and modules, every §7.2 adversary must have a section, and claiming
    external validation while `SEC-024`/`SEC-025` are unticked fails the build.
    8/8 self-test cases.
  → It immediately caught a real error in the document — `qqq-host::limits` had been
    renamed to `quota` — which is exactly the decay it exists for.
  → §7.1 What we are defending, precisely
- [x] **SEC-002** Implement the rule that an ungranted import is absent, not merely denied, and prove it by test.
  → Done: the property was already implemented — `build_linker` populates the
    linker **from the grants alone**, so an ungranted import is not present and
    instantiation fails (`QQQ-6003` naming the interface) rather than the call
    being denied. It is now **proven**: `an_ungranted_import_is_absent_rather_than_denied`
    asserts the failure occurs at instantiation and that the error names the
    missing interface, and the hostile-guest table carries **56** ungranted-import
    cases.
  → **The distinction matters and is worth stating.** "Absent" means the component
    cannot be *instantiated*; "denied" would mean it instantiates and fails when
    the import is called. A denied import means the **guest ran** — and a guest
    that runs has consumed resources and may have had side effects before the
    denial, which is why §7.3 places this gate at *instantiate* rather than at
    *call*.
  → **What this test does not prove, stated rather than implied.** There is no
    granted control, and the reason is recorded in the test itself: a control
    needs a component importing an interface the linker *does* provide, and
    hand-written WAT against a real interface failed **four** times with
    *"instance export ... has the wrong type"* — a component declaring the wrong
    export set does not instantiate whether or not the capability is granted, so
    each attempt made the ungranted case pass for the wrong reason. The failure
    half is proven here; the positive half is covered where fixtures are
    generated rather than hand-written (`tests/engine.rs`, `linker.rs`'s own
    tests), and a granted control belongs here once Phase P5's toolchains can
    produce a component from WIT.
  → §7.3 The defence timeline — where we stop an attack
- [x] **SEC-003** Implement manifest capability validation with a deny-by-default posture throughout.
  → Done (verified, not assumed): `Manifest::validate` covers package identity,
    build, limits, dependencies, fs paths and http hosts; all 13 manifest structs
    carry `#[serde(deny_unknown_fields)]`, so a typo'd capability field is a parse
    error rather than a silently ignored grant.
  → Deny-by-default is proven at three layers, each by a passing test:
    `minimal_manifest_parses_and_grants_nothing` (manifest),
    `normalization_of_an_empty_manifest_yields_nothing` (normalize) and
    `empty_grant_set_grants_nothing` (resolve).
  → `declared_capabilities` derives grants only from what is present and non-empty:
    an absent `[capabilities]` entry yields nothing, and an empty `http.client` list
    does not grant `HttpClient`.
  → §7.2 Adversary model
- [x] **SEC-004** Build the hostile-guest test suite (≥200 cases) with a specified expected failure for each.
  → Done: `crates/qqq-host/tests/hostile_guests.rs` — a **table-driven** suite of
    **200 hostile guests**, each naming the exact `ErrorCode` it must produce. Six
    tests, 102 seconds.
  → **"In a specified way" is the load-bearing phrase**, and it is why the suite
    is not a list of `assert!(result.is_err())`. A test that only asserts failure
    cannot distinguish the right failure from the wrong one — a guest rejected for
    the wrong reason would pass, and the reason is exactly what the suite checks.
    Every case names its code, and the runner fails on a *different* one.
  → **The property every case asserts beyond its own code: the host survives.**
    After each guest, a fresh instance on the **same engine** runs a benign
    component to completion — which separates "the guest was stopped" from "the
    guest took the host with it", the claim §7.1 lists first under assets.
  → **Distribution is asserted, not just the total.** `traps >= 140`,
    `instantiation_failures >= 56`, `controls >= 4` — so the suite cannot
    degenerate into 200 copies of one case while still reporting success. The
    count is checked by `the_suite_meets_its_size_requirement`, because a suite
    claiming 200 cases while running 40 is the `§M-006` failure: a check whose
    declared strength is not its real strength.
  → The benign control is in the table *and* has its own test
    (`the_limits_do_not_stop_a_benign_guest`, under all three limit profiles). A
    runtime that trapped everything would satisfy every hostile assertion while
    being useless.
  → **What this suite is not**, stated in the module doc: it drives guests that
    misbehave within Wasm and checks the runtime's response. It is not a fuzzer
    (`SEC-012`/`SEC-013`), it does not attempt sandbox escapes via engine bugs
    (Wasmtime's responsibility, `SEC-014`), and it does not cover HTTP
    (`SEC-016`).
  → §7.2 Adversary model
- [x] **SEC-005** Implement memory-limit enforcement and prove the host survives a guest OOM.
  → Done: **and writing the test found a real security defect.** The memory
    ceiling was installed with Wasmtime's own `StoreLimits`, which makes
    `memory.grow` **return -1** — so the limit was **advisory**: the grow failed,
    the guest kept running, and nothing trapped. Wasmtime documents the
    alternative: returning `Err` from `ResourceLimiter::memory_growing` makes the
    growth behave *"as if a trap has been raised"*.
  → **Measured before and after**, with a temporary probe against a 4 MiB ceiling
    and a 10-billion-fuel budget:
    | Guest behaviour on a refused grow | Before | After |
    |---|---|---|
    | Traps on it | `GuestPanic` in 487 µs | **`MemoryLimitExceeded` in 476 µs** |
    | Ignores it and loops | `FuelExhausted` in **97.68 s** | **`MemoryLimitExceeded` in 144 µs** |
  → Two consequences, both bad and neither visible without measuring. **`QQQ-3001
    MemoryLimitExceeded` was unreachable through this path** — the taxonomy
    documents it as the memory-limit code and nothing could produce it, so a
    memory-limited guest reported a *panic* or *fuel exhaustion* and sent an
    operator to the wrong fix. And **a hostile guest was not stopped promptly**:
    97 seconds at full CPU for one guest against a 4 MiB ceiling is not an
    enforced limit. The fix is **679,000× faster** to stop it.
  → `TrappingLimiter` in `linker.rs` implements `ResourceLimiter` and returns
    `Err` on a breach, delegating every non-memory limit to the `StoreLimits` it
    wraps so the per-instance, per-table and per-memory *counts* still apply.
    `StoreData::resource_limits` now holds the trapping form, and
    `install_trapping_limiter` reads the ceiling from the manifest's limits.
  → The hostile guest that exposes this **ignores the refused grow and loops**,
    which is the hostile shape: a guest that checks the return value and stops is
    behaving correctly. `MEMORY_HOG` is documented with that reasoning, because a
    guest that merely *spins* would trap on fuel and let an absent limiter pass —
    which is exactly what the first version of this fixture did.
  → §7.2 Adversary model
- [x] **SEC-006** Implement fuel-limit enforcement and prove the host survives fuel exhaustion.
  → Done: `store.set_fuel(limits.fuel)`, set **before instantiation** so a
    component whose `start` function runs long cannot escape metering. The proof
    is `fuel_exhaustion_traps_the_guest_and_the_host_survives` (trap classified
    `FuelExhausted`, `QQQ-3002`, not retryable, context carries fuel consumed, and
    a fresh instance on the same engine still runs) plus **40 fuel cases** in the
    hostile-guest suite across twenty budgets.
  → Twenty budgets rather than one, because the property is that **the
    classification does not depend on how much fuel was missing** — a table with a
    single budget would test one number and call it enforcement.
  → §7.2 Adversary model
- [x] **SEC-007** Implement epoch-deadline enforcement and prove the host survives a non-terminating guest.
  → Done: enforcement is `store.set_epoch_deadline(1)` with a host ticker, already
    implemented and proven by `an_epoch_expiry_traps_on_the_synchronous_path` —
    which drives a real ticker thread and asserts the trap is
    `EpochDeadlineExceeded` rather than fuel.
  → **The second half was missing and is what this item adds.** That test asserted
    the *code* but not that the host survived, so "the guest was stopped" was
    proven and "the host still works" was assumed. It now builds a fresh instance
    on the **same engine** and runs a benign component to completion afterwards.
    This is the case where a host is most likely to be left broken, because the
    interruption comes from **outside** the guest's control flow — it did not trap
    itself, it was cut off mid-instruction-sequence.
  → The hostile-guest suite covers non-termination separately with a huge fuel
    budget, and accepts either `FuelExhausted` or `EpochDeadlineExceeded` there
    deliberately: fuel is precise accounting and the epoch is a wall-clock
    backstop, and which fires first depends on the measured burn rate rather than
    on a property under test. Asserting one *there* would make the test depend on
    a timing measurement.
  → §7.2 Adversary model
- [x] **SEC-008** Implement handle-count limits and prove the host survives handle exhaustion attempts.
  → Done: `limits.max_open_handles` was already enforced by `HandleTable`, so the
    risk here was building a **second** counter beside it. Two sources of truth for
    one number drift the first time a remove path forgets to credit one, and drift
    is wrong in *some* direction — permissive is a resource-exhaustion
    vulnerability, strict is a production outage. `quota::HandleQuota` is therefore
    a **view** over the table, and what it adds is what the table lacked:
    `exhaustion_attempts`, which distinguishes "the table reached its ceiling" from
    "a guest **tried** to go past it".
  → The proof is six tests in `handles.rs`, each asserting the **state** after a
    failed attempt rather than merely that it failed — a table that refused but
    corrupted its accounting would pass a bare `is_err()` check:
    | Test | Attack shape |
    |---|---|
    | `an_accumulating_guest_is_refused_without_disturbing_the_table` | open, never close |
    | `a_probing_guest_is_rejected_and_the_probes_are_counted` | guess handle values |
    | `the_limit_holds_across_an_adversarial_interleaving` | 5,000 mixed operations |
    | `a_zero_limit_refuses_indefinitely_rather_than_sporadically` | no handles declared |
    | `churn_is_unbounded_because_the_limit_is_on_concurrency_not_throughput` | **control** |
    | `a_huge_limit_is_representable_and_not_preallocated` | 100,000 declared |
  → **The control is the load-bearing one.** 10,000 open/close cycles through a
    table that holds 4 must never be refused, because the limit is on
    *concurrency* and not *throughput*. A rate limit masquerading as a count limit
    would refuse long-lived honest guests — an outage from a security control.
  → **Fault-injected.** Disabling the limit check (`if false && live >= limit`) in
    `handles.rs` makes **7 tests** fail, the new `SEC-008` ones among them.
    Restored, and the restore re-read rather than assumed.
  → Also proven end-to-end: `subrequest_limits.rs` asserts a real
    `Instance::create` derives its quota from `LimitSet`, and that one instance
    exhausting its budget does **not** affect another — a `static` guard there
    would turn one tenant's misbehaviour into a platform-wide outage.
  → §7.2 Adversary model
- [x] **SEC-009** Implement subrequest limits to prevent guest-driven request amplification.
  → Done, and **the implementation the item implies would itself have been the
    vulnerability.** The obvious design is a counter that returns an error and lets
    the guest continue. That is a **loop amplification attack**: the guest ignores
    the error, calls again, and the host rebuilds a full `Error` — message, context
    `Vec`, remediation `String` — every iteration.
  → **Measured**, `cargo run --release --example refusal_probe -p qqq-host`:
    | Policy | 100,000 charges |
    |---|---|
    | Advisory (refuse, build the `Error`, continue) | **138.3573 ms** for 99,999 refusals |
    | **Poisoned** (shipped) | **48.8 µs** — 1 paid refusal, 99,998 free |
    | Ratio | **2835x** |
    | Cost of one refusal | **1384 ns** |
  → A refusal costs 1.4 µs; a guest's cheapest loop costs nanoseconds. The host was
    paying thousands of times what the guest paid, per iteration, forever.
  → **The fix is structurally the same as the memory defect in §O-066.** There,
    Wasmtime made a refused `memory.grow` *advisory* and the correction was to make
    the growth **trap**; here, returning an error and continuing made the refusal
    advisory in exactly the same way. `SubrequestBudget::charge` returns
    `Charge::Refused` **once**, poisons the budget, and every later charge is
    `Charge::RefusedRepeatedly` — a counter increment with no allocation. **A limit
    whose refusal path can be driven in a loop has not bounded anything.**
  → `limits.max_subrequests` is a new manifest field with a range check
    (`SUBREQUESTS_MAX = 10_000`, deliberately far below `HANDLES_MAX = 100_000`):
    a handle is a locally pooled object, whereas a subrequest is an outbound side
    effect on a **third party**, and 100,000 of them from one request is an outage
    aimed at somebody else.
  → **Why a limit in host-effect units at all.** Fuel bounds what a guest
    *computes*, not what it *causes*: `call http.get` + `br` in a loop costs a few
    fuel units and one outbound request per iteration, so no fuel budget bounds the
    fan-out. Measured, that loop costs the host 1.4 µs per iteration.
  → Nine tests in `subrequest_limits.rs` — the limit reaches a real instance
    through `Instance::create`; the refusal carries `QQQ-3008` and is **not
    retryable** (retrying re-runs the loop); a guest ignoring 10,000 refusals
    drives exactly **one** paid refusal; a zero limit refuses the very first call;
    and the host survives an exhausted budget plus a trapped guest.
  → **Fault-injected twice.** Collapsing `RefusedRepeatedly` into `Refused` — the
    *subtle* regression where the guard exists but rebuilds the error — fails
    `a_poisoned_refusal_does_no_work` and
    `the_amplification_counter_counts_attempts_by_the_guest`. The ratio is asserted
    at `>= 4x` in CI (a property) while the example prints the real figure (a
    measurement), because a test that only says `>= 4x` cannot tell a marginal
    design from a decisive one.
  → **What is not wired, stated rather than implied.** The charge call sites inside
    `qqq:http`, `qqq:dns`, `qqq:sqs` and the rest do not exist because those
    interfaces have no host implementation yet (`QQQ-STUB(CON-009)` in the linker).
    `StoreData::charge_subrequest` documents the contract each must honour — charge
    **before** performing the effect — and the stub marker plus the registry's
    `implemented` flag keep the gap visible. `StoreData::default()` grants **zero**
    budget, because `0 == unlimited` would invert the most restrictive manifest
    into the most permissive one.
  → §7.2 Adversary model. New code `QQQ-3008 SubrequestLimitExceeded`, kept distinct
    from `4005 CapabilityQuotaExhausted`: that one is a per-capability accounting
    question and is retryable, this one is a property of the guest's **control
    flow** and is not. Sharing a code would tell an operator whose problem is a
    looping guest to back off and retry.
- [x] **SEC-010** Implement path-traversal defences at the capability boundary, with a test corpus.
  → Done: **and building the corpus found a real vulnerability.** `path_is_within`
    — the containment check `fs_allows` uses as its defence-in-depth re-check —
    was a pure string-prefix test whose doc said *"Operates on already-canonicalized
    absolute paths"*. Measured, it returned **`true`** for every traversal:
    | Input (root `/var/lib/orders`) | Before |
    |---|---|
    | `/var/lib/orders/../../../etc/passwd` | **`true`** |
    | `/var/lib/orders/../secrets` | **`true`** |
    | `/var/lib/orders/..` | **`true`** |
    | `/var/lib/orders/a/../../b` | **`true`** |
  → It is a string-prefix check, so it sees `/var/lib/orders/…` and stops. Any
    caller that forgot to canonicalize — or canonicalized a path that **does not
    exist yet**, where `std::fs::canonicalize` fails — would have a traversal pass
    a defence-in-depth check. **A defence that passes the attack it exists to stop
    is worse than none**: it looks like protection, so nobody adds the real one.
  → The check is now self-contained: it splits into components, **refuses any path
    containing `..`**, and compares component-by-component with `.` skipped. It
    refuses rather than resolving because resolving `..` lexically is subtly wrong
    — `/a/b/..` is `/a` only if `b` is a directory and not a symlink, and the
    function has no filesystem to ask. A non-canonical input is a caller bug worth
    surfacing, not something to guess at.
  → **What it still does not defend against, stated in the doc rather than
    implied: symlinks.** `/data/link` may point outside `/data`, and a
    non-canonical path gives no way to tell. Symlink safety comes from the
    *preopen handle* — the guest holds a handle to a directory and WASI resolves
    within it — which is the primary enforcement; this remains the re-check for a
    mis-built preopen table.
  → The corpus is a **table**, so adding a case is one line and the count is
    visible: a traversal corpus of two examples is an anecdote. It includes
    `..` escapes, traversals that land *back inside* (still refused, and the test
    says why), and backslash-separated variants on a POSIX path. Plus two controls
    the one-sided version could not have: `legitimate_paths_are_still_admitted_after_the_traversal_fix`,
    without which a check returning `false` for everything would satisfy every
    attack assertion while making every filesystem grant useless; and
    `the_prefix_implementation_would_have_admitted_these`, so reverting to a prefix
    match breaks **two** tests rather than one.
  → §7.2 Adversary model
- [x] **SEC-011** Implement input validation at every guest-to-host boundary crossing.
  → Done: `qqq-host::boundary` is a **table-driven** validation layer, in the same
    shape this project uses for faults and traversals. The load-bearing word in the
    item is *every*, and a check each host function calls when its author remembers
    is not a boundary layer — it is a set of decisions that diverge, and the
    divergence is always in the function nobody considered.
  → **Four classes of check**, each named for the failure it prevents:
    | Class | Question | Failure prevented |
    |---|---|---|
    | Range | Is this integer a host-defined member? | Enum confusion; a discriminant the host indexes with |
    | Size | Is this within the host's budget? | Host allocation on the guest's instruction |
    | Shape | Is this well-formed for its type? | Traversal, injection, a name that is not a name |
    | Consistency | Do two supplied values agree? | The half-updated state a pair creates |
  → `list_size` enforces **two axes because each catches what the other misses**: a
    list of 100 million *empty* strings is zero payload bytes and 100 million
    `String` headers, so a byte ceiling alone lets a guest drive ~2.4 GB of metadata
    from a few kilobytes of input; a count ceiling alone lets three 1 GiB elements
    through. One function, both checks — splitting them would let a caller apply one
    and believe it had applied the other.
  → **The central control:** `every_registered_host_function_is_declared_in_the_boundary_table`
    scans `func_wrap("…")` in the host modules and fails if a boundary is missing
    from the table, so *every* is checked rather than asserted. Its reverse
    (`every_declared_boundary_names_a_real_function`) fails if the table lists one
    that no longer exists. Injecting a rename fails **both**.
  → **And the finding, which took two injections to reach.** The check was written,
    wired into `random.get`, and invisible to the suite:
    1. Neuter the *helper* (`boundary::size(…, 0, …)`) → **all 15 tests still
       passed**, because every boundary test exercised a helper directly, proving
       the helper correct and nothing about whether a host call used it.
    2. Fixed by extracting `random_length_verdict` and testing the pair (ceiling
       from the ambient state, rejection past it). The helper injection now fails.
    3. Neuter the **call site** (`let _check_disabled = …;`) with the helper
       correct → **all 16 tests still passed**. Extracting the helper had closed
       only half the hole.
    4. Fixed by `the_call_site_applies_the_boundary_check`, which asserts in source
       that the registration body calls the helper and propagates with `?`. The
       call-site injection now fails.
  → **The fix is structural, and says so rather than implying otherwise.** Proving
    the call site *behaviourally* needs a guest importing `qqq:crypto/random`, and
    hand-written WAT against that interface has failed to instantiate four times in
    this project (the lowered `result<list<u8>, random-error>` needs a return-area
    pointer and a fully-declared error variant; each attempt failed *whether or not*
    the capability was granted, making the ungranted case pass for the wrong
    reason). Source inspection is **weaker** than execution and **stronger than
    nothing**, which was the previous state.
  → **The general lesson:** *a check that is written is not a check that runs, and a
    check that runs is not a check that is reached.* Found three times now — the
    memory limit was installed but advisory; the refusal path was the
    amplification; this check was wired but unreachable by any test. All three were
    invisible to reasoning and all three were found by injecting a defect and
    watching nothing happen.
  → Two smaller defects it produced: the table's first version used the *qualified*
    name (`wall-clock.now`) while `func_wrap` registers the **bare** name (`now`)
    within an interface instance, so the completeness test reported five undeclared
    clock functions — which is how the mismatch surfaced, and a table that cannot be
    checked against the code is a document rather than a control. And the name
    extractor read **doc comments**, inventing `name` as a boundary because
    `host_crypto.rs` writes `` `func_wrap("name"` `` in its own prose; it now strips
    comments, pinned by `the_detector_ignores_comments_and_doc_examples`.
  → Also added `HASH_ALGORITHM_COUNT` with
    `the_hash_algorithm_count_agrees_with_the_wit`, which *counts* the WIT enum's
    members rather than restating a literal — a member added to the WIT without
    updating it would make the host refuse a valid algorithm, and `algorithm_name`
    would agree with the stale constant, so nothing else would catch it.
  → §2.2 NN-2 — Security and Isolation Are Non-Optional. New file
    `crates/qqq-host/src/boundary.rs` (33 tests); 17 validation calls across 8
    boundaries in 4 interfaces.
- [x] **SEC-012** Establish the fuzzing programme covering the host interfaces, manifest parser and component loader.
  → Done, and the programme is **two mechanisms** because the item and `SEC-013`
    ask for different things. Treating them as one produces a programme that runs
    **when someone remembers**:
    | Mechanism | Cadence | What it finds |
    |---|---|---|
    | Random exploration (`fuzz/`) | nightly, sustained | Unknown shapes; deep bugs |
    | **Regression corpus** (`crates/*/tests/fuzz_corpus.rs`) | every commit, ms | A bug found once, coming back |
  → The corpus is the half that must be in **every** build: a crash found by a
    nightly run is worthless unless the input is re-run on every later commit,
    because the bug is reintroduced by an unrelated change and found again later,
    by luck. The **promotion step** — crash artifact → corpus entry → every future
    build — is stated in the nightly workflow's failure output, where the person
    who needs it will see it rather than in a document they would have to find.
  → **Three targets, each asserting a property rather than "does not panic"**:
    * `manifest_parse` — no panic; **determinism**; grant derivation is a pure
      function of the manifest; renderings are stable. Determinism matters beyond
      tidiness: the manifest is the authority root, so a parser whose output varied
      would make the host's effective authority disagree with `qqqai why`, which is
      the one disagreement the capability model must never have.
    * `component_load` — no panic; every rejection carries a real `QQQ-XXXX` code
      and a non-empty diagnostic; **accept implies usable** (digest present, import
      listing sorted and deduplicated). The highest-value target: it hands
      attacker bytes to Cranelift and the component-model validator, the front door
      to §7.1's first asset.
    * `host_interfaces` — the boundary checks, total and log-safe on hostile input,
      with the traversal corpus re-run every iteration so a regression fails on the
      mutation that causes it.
  → **Building the corpus found a real defect before any fuzzing ran.** `toml`'s
    `Span::start` is documented as a **byte index**, and it was assigned straight to
    a field rendered as `qqq.toml line {n}`:
    | Input | Reported | Actual | Python `tomllib` |
    |---|---|---|---|
    | `[package\nname = "a"\n` | line **8** | line **1** | line 1, col 9 |
    | `not toml at all\n` | line **4** | line **1** | line 1, col 5 |
    The error grows with the file — a 40-line manifest reported line numbers in the
    thousands. **A diagnostic whose whole purpose is to point a developer at a
    location, off by a factor of the average line length, is worse than none
    because it is believed.** Fixed by counting `\n` in the prefix, which is
    correct for `\r\n` files where `str::lines()` would be right on Linux and wrong
    on Windows for every line after the first. Pinned against `tomllib` for the
    specific cases plus a general assertion that every syntax error reports a line
    **inside the file**.
  → Also: one corpus entry was **mislabelled** (`\x00asm\x0d\x00\x01\x00` is a
    valid empty component, not malformed) and the positive-control test named it.
    A corpus entry whose expectation is wrong is worse than a missing one — it
    either fails for the wrong reason or gets "fixed" by loosening the check.
  → New: `fuzz/` (3 targets + corpus harness + 7 tests), `fuzz_corpus.rs` in
    `qqq-cap` and `qqq-host`, `.github/workflows/fuzz.yml`.
  → §2.2 NN-2 — Security and Isolation Are Non-Optional
- [x] **SEC-013** Add `cargo-fuzz` targets to CI with a nightly fuzzing schedule.
  → Done: `.github/workflows/fuzz.yml` runs the three targets **nightly at 03:17
    UTC** (an odd minute on purpose — a round hour is when every other scheduled
    job starts and runner contention is real) and on `workflow_dispatch` with a
    configurable duration. AddressSanitizer is stated explicitly rather than left
    to the default, because a silent fallback to no sanitizer would make every run
    far less useful while still reporting success. `fail-fast: false`, so one
    target's crash does not cancel the others' evidence. Crash artifacts upload
    with `if: always()`, since they are the *interesting* output exactly when the
    run fails.
  → **The targets must also be buildable, so `ci.yml` gained a `fuzz-targets`
    job** that runs `cargo +nightly fuzz build` — not merely `check`. `check`
    proves type-correctness and says nothing about linkability, and the Windows
    linker failure below was invisible to it. `fuzz/` is a separate workspace, so
    nothing at the root touches it, and a signature change in `qqq-cap` or
    `qqq-host` would otherwise break the targets **silently** until 03:17.
  → Two build defects found by actually building, not type-checking:
    * `crate-type = ["cdylib", "lib"]` failed to link on Windows with
      `LNK2001: unresolved external symbol main` — a `#![no_main]` target defines
      no `main`, and the `cdylib` is a Linux-only `cargo-fuzz` convenience. `lib`
      alone is correct, and keeping `cdylib` would have made the fuzzing programme
      unbuildable on the platform half the contributors use.
    * The targets needed `wasmtime` as a **direct** dependency: `qqq-host`
      deliberately does not re-export the engine, and Rust does not let a target
      name a crate it does not depend on directly.
  → **A platform limitation, recorded rather than left silent.** On Windows the
    built target fails to *start* with `0xC0000135 STATUS_DLL_NOT_FOUND` — a
    missing libFuzzer runtime DLL, a known `libfuzzer-sys` limitation, not a QQQ
    defect (confirmed by running the built executable directly and reading the exit
    code). Consequences, both intended: exploration runs on `ubuntu-latest` where
    the sanitizer runtime exists, and the **corpus harness is the part that runs on
    every platform** — another reason the two-mechanism split is the right design
    rather than a convenience.
  → Also proven in this job: the regression corpus runs, so a reviewer reading the
    fuzzing log sees both halves of the programme rather than having to trust that
    another job ran.
  → §2.2 NN-2 — Security and Isolation Are Non-Optional
- [x] **SEC-014** Establish the Wasmtime advisory-tracking process with a 72-hour patch target (`R-04`).
  → Done: the process is `docs/wasmtime-advisory-process.md` (7 sections) plus two
    real mechanisms, because **a process document is worth what its checks are
    worth**.
  → **The 72-hour clock is defined exactly**, because ambiguity is how a target
    becomes unfalsifiable: it starts when a patched upstream release exists (a
    GitHub Security Advisory **or** a changelog entry, whichever is first) and
    stops when a QQQ release tag pins it. Time spent waiting for upstream to
    *write* a patch is **excluded** — not a loophole, but what makes the target
    meaningful, since QQQ cannot ship a patch nobody has written. What the clock
    measures is everything between "the patch exists" and "users have it".
    **Escalation when no patch exists yet:** within 24 h either a mitigation ships
    or an accept-risk decision is recorded publicly. An advisory with no patch is
    not a reason to wait quietly.
  → **Four detection channels, two of them automated**, because a human is asleep a
    third of the time: `cargo deny` on every commit (required CI step, so an
    advisory turns the build red on the next push), a **daily unattended scan**
    (`.github/workflows/advisories.yml`, which opens a labelled issue and reuses it
    rather than filing a daily duplicate that would bury the signal within a week),
    the upstream release/SA watch, and direct reports.
  → **The gap in the automated channel is named rather than implied:** RustSec is a
    third party, an advisory may take days to reach it, and a CVE in Wasmtime's C++
    components may not be a Rust advisory at all. A process claiming the automated
    scan was sufficient would be quietly wrong for exactly the class that matters
    most. CVE tracking for the transitive C dependencies is recorded as a **known
    gap**.
  → **Seven response steps, each with a deadline inside the 72 hours**, so the
    target is composed rather than asserted. Steps 5 and 6 exist as named steps
    because they are the two places a Wasmtime upgrade breaks QQQ **without
    breaking the build**: `ENGINE_VERSION` is pinned alongside the dependency and
    asserted by a test, and the trap taxonomy maps Wasmtime's error kinds to stable
    `QQQ-XXXX` codes — an engine that reclassified a trap would leave every
    downstream dashboard quietly mislabelled, and no compiler notices that.
  → **A verification table, and completing it found a real gap.** The document's
    claim that "the engine version cannot drift silently" was **half true**: the
    existing anti-drift test compares `ENGINE_VERSION` against the workspace
    manifest's requirement (`"48"`), so it caught a major-line change and permitted
    any patch. But the AOT cache key is built from `ENGINE_VERSION` and Cranelift's
    codegen changes between **patch** releases, so a lockfile at `48.0.3` with the
    constant at `48.0.2` would compute a wrong cache key — yielding native code
    that is subtly wrong rather than obviously broken. Added
    `engine_version_matches_the_resolved_lockfile`, which reads the resolved
    version from `Cargo.lock` (exact package-name match, since many crates begin
    with `wasmtime`). **Fault-injected at patch level: the old test still passed
    while the new one failed** — which is the precise measure of the gap it closes.
    The check was completed rather than the claim softened, because a security
    process whose stated verification does not exist is the failure mode `§O-066`
    and `§O-071` both record.
  → `SECURITY.md` now carries the short version and links to the process, so a
    reader of the policy meets the mechanism rather than a promise.
  → §15 — Risk Register
- [x] **SEC-015** Implement the per-dependency capability diff display at install time.
  → Done, **and the diff was structurally never observable through the real
    install path** — found by writing the CLI-level test the item actually calls
    for.
  → The lockfile and diff layers were already correct: `caps` was a first-class
    `LockPackage` field participating in `compute_hash`, `LockDiff::compute`
    produced `caps_added`/`caps_removed`, and `grants_new_authority()` existed as
    the predicate CI branches on. What was missing was the **display**, and
    beneath that, the **input that makes a display possible**.
  → **The defect.** `resolve` carried a satisfied pin forward with
    `pinned.clone()`, so the new lockfile recorded *the same caps the old one did*
    — and `LockDiff::compute(old, &next)` then compared a value **against
    itself**. `caps_added` was therefore structurally always empty, `escalation`
    could never become `true` through `qqqai install`, and a CI gate branching on
    that boolean would have passed **every supply-chain event in silence**. §5.4's
    stated purpose — *"the authority delta is visible in the diff"* — was
    unreachable, and nothing in the existing suite could see it, because every
    test either exercised `LockDiff::compute` directly (correct, and unrelated to
    `resolve`) or asserted merely that install *succeeded*.
  → **The root cause was a missing source of truth.** A real escalation is "the
    authority this dependency needs **now** differs from the authority recorded in
    the lockfile". Comparing requires a "now" that is not the lockfile, and the
    only such source is the manifest — which had **no per-dependency `caps` field
    at all**. §5.4 says *"dependencies declare capabilities too"*, so:
    * `DependencyDetail::caps` added, with `Dependency::caps()` returning an empty
      slice for the bare `name = "1.2"` form. Declaring is **not** granting: the
      effective authority for a runtime is still the root manifest's
      `[capabilities]` plus narrowing overlays, so this is an *audit* input and
      giving it any other meaning would be a capability-widening path.
    * `resolve` now takes `(name, requirement, declared_caps)` and records the
      **declared** set, carrying the version but re-deriving the capabilities. The
      rest of the pin (digest, license, source) is carried as-is, because those
      describe *the bytes that were fetched*.
  → **Two boundary behaviours, each pinned because the naive choice is wrong.**
    * A dependency that declares **nothing** keeps its recorded caps. Clearing
      them would report every recorded capability as *removed* — a false
      de-escalation, wrong in the opposite direction and just as misleading: an
      operator would see authority apparently vanishing on an unrelated manifest
      edit.
    * A **loss** is reported but is **not** an escalation, matching `CLI-015`'s
      rule that a gain exits non-zero and a loss does not; a check that cries wolf
      on the good case is one people learn to bypass.
  → **Convergence is asserted**, not assumed: resolving a second time against the
    lockfile just written must produce *no* further change. A diff that never
    settles is noise, and noise is ignored — which is the same as having none.
  → **Verified end-to-end**, not only in unit tests:
    ```
    $ qqqai install
    qqq.lock: 1 package(s) resolved; AUTHORITY ESCALATION — qqqai/telemetry gains http.client
    ```
    and `--json` reports `"escalation":true` with
    `"capability_changes":[{"added":["http.client"],…}]` on both the dry-run and
    write paths.
  → The new CLI test needed a **fresh sandbox** for the human-readable assertion:
    the `--json` run writes the lockfile, so a second run correctly finds nothing
    to change. The first version re-used one sandbox and failed on its own
    ordering rather than on the code — and the two surfaces must each start from
    the same pre-change state for the human assertion to mean anything.
  → Tests added: 3 in `qqq-run` (escalation observed through `resolve`; a loss is
    not an escalation; declaring nothing preserves the record) and 1 CLI-level
    test proving both the JSON field and the human line.
  → §5.4 The lockfile — `qqq.lock`
- [x] **SEC-016** Implement slow-loris, header-bomb and body-bomb mitigations with tests.
  → Done. All three mitigations were **already implemented and unit-tested** —
    `http1::MAX_HEADERS` (100), `MAX_HEADER_BYTES` (8 KiB) and `MAX_HEAD_BYTES`
    (64 KiB); `body::BodyReader` enforcing `max_request_bytes` **during** streaming;
    and a `connection.header_timeout` with its own tests. Fault injection confirmed
    all three are live at that level (removing them fails 2, 3 and 4 tests
    respectively).
  → **The gap was one layer up, and it is the layer the item is about.** `socket.rs`
    exercises the accept loop over real TCP and had a body-bomb test — but **no
    socket-level header-bomb test and no socket-level slow-loris test**. A parser
    that refuses a bomb after the *server* has buffered it has mitigated nothing,
    so "the mitigation is implemented" is a claim about the server consulting the
    limit, and only a socket can test that. The same two-correct-halves shape as
    `§O-045a`.
  → Added `Server::start_with` (a config seam, because the production 10 s header
    deadline would add ten seconds per test run while the *property* — "the
    deadline closes the connection" — is tested equally well at 200 ms, and the
    *value* is pinned separately without a socket) plus **three** socket-level
    tests: the header-count bomb, a large head that is *not* header-count-large,
    and the slow-loris stall.
  → **Finding 1 — the runtime was the only signal, and it was unasserted.** The
    slow-loris test took **5.73 s** against a 200 ms deadline while passing. The
    discriminator was the response content: a complete correct `200 OK` with a
    `Content-Length`, meaning the server answered *immediately* and the 5 s was
    `read_all` waiting for an EOF a correctly keep-alive server never sends — a
    **test-helper artefact, not a server defect**. Now asserts time-to-*answer*
    (`read_response`), which is what "served promptly" means for keep-alive: the
    test runs in **0.72 s** and bounds the latency a degraded server would show.
  → **Finding 2 — a passing test whose refusal path could not be named**, chased
    down rather than deleted:
    1. `read_head` reaches `parse_head` by **two routes** (terminator present →
       `parse_head(&buf[..end])`; buffer past the ceiling with no terminator →
       `parse_head(buf)`), so disabling either alone leaves the other refusing.
    2. Disabling the parser check **and** the server branch together **did** fail
       the test — so the ceiling is enforced and the test reaches it.
    3. **The first fixture measured the wrong limit**: padding each header to 8 KiB
       trips `MAX_HEADER_BYTES` (*per-header*) before `MAX_HEAD_BYTES` (*total*) is
       consulted. Corrected to 60 headers × 2 KiB — inside the per-header and count
       limits, over the total — with all three preconditions **asserted**, so a
       fixture that stops exercising the intended ceiling fails loudly rather than
       passing quietly.
  → The redundancy is intentional (the source says *"the head ceiling is enforced by
    the parser, not here"*), and the test now documents which injection does and
    does not reach it — because a future reader who injects one check, sees green
    and deletes the test would be drawing a reasonable conclusion from incomplete
    evidence.
  → **The rule this produced:** *a test that passes is not evidence until its
    refusal path is named.* Every other finding this session was a control that
    looked live and was not; this one is the inverse — a control that **is** live,
    where the test proving it did so for a reason nobody had checked.
  → §6.4 `qqq-serve` — the HTTP and application server
- [x] **SEC-017** Implement the cryptographic-posture policy: named algorithms, no silent defaults, no agility without a version bump.
  → Done. Audited **clause by clause** against §7.4's table; every row is either
    implemented or owned by a different item (Ed25519 signing belongs to
    `SUP-001`/`DIST-003`, which are about *publishing* rather than *policy*):
    | §7.4 clause | Mechanism |
    |---|---|
    | Transport named algorithms | `CIPHER_SUITES` — 8 suites, each justified against a §7.4 row |
    | No version agility | `PROTOCOL_VERSIONS` = 1.3, 1.2 only |
    | No silent defaults | `TlsConfig::build` refuses an unspecified field; `ClientAuth::default()` is `None`, with its reasoning written out |
    | Hashing names algorithms | manifest `crypto.hash` allowlist, enforced in `hash_data` |
    Negative properties are tested too: `no_suite_uses_rsa_key_transport`,
    `no_suite_uses_cbc`, `every_tls12_suite_is_forward_secret`,
    `the_version_policy_refuses_tls_11`.
  → **The clause worth testing was the third, and asking how it is enforced found
    something better than expected.** §7.4 says *"no algorithm agility without a
    version bump"* and the module doc claims *"the lists are fixed; changing one is
    a change to a public constant"* — but that second claim is about **code review**,
    not a check. Two widening attacks were attempted:
    | Attempted widening | Result |
    |---|---|
    | add a `TLS_*_CBC_*` suite | `error[E0425]` — rustls 0.23 exports no CBC suite |
    | add TLS 1.1 to `PROTOCOL_VERSIONS` | `error[E0425]` — `rustls::version` exports only `TLS12`, `TLS13` |
    **Neither compiles.** Verified against the installed rustls 0.23.43 source: no
    `CBC_SHA` anywhere, and exactly two public version statics. The agility clause
    is therefore enforced by the **type system** — *stronger* than any test, since
    a test can be deleted or relaxed in review while a suite the dependency does
    not export cannot be named at all.
  → **And that is the finding: the tests could not say so.** `no_suite_uses_cbc`
    **cannot fail** with this rustls version — belt-and-braces rather than a defect,
    but it means the real enforcement lives somewhere the test's name does not
    point, and a reader finding it would reasonably believe it *was* the guarantee.
  → Added `the_agility_guarantee_rests_on_these_dependency_exports`, which pins the
    **dependency-level precondition** the argument rests on. The guarantee is
    borrowed and could be returned: a future rustls reintroducing CBC or TLS 1.1
    restores the ability to widen the policy, and at that moment `no_suite_uses_cbc`
    becomes load-bearing again with nobody noticing. Verified live by simulating
    exactly that — widening `PROTOCOL_VERSIONS` to three entries fails **3 tests**,
    the tripwire among them, naming what just became possible.
  → **The rule this produced:** *a guarantee borrowed from a dependency needs a
    tripwire on that dependency.* The code was right; what was missing was a test
    naming **why** it is right, and failing when the reason stops holding.
  → §7.4 Cryptographic posture
- [x] **SEC-018** Implement the host CSPRNG with no guest-supplied seed outside deterministic test mode.
  → Done; **audit only, no code change was needed**, and the audit is recorded so
    the claim is evidenced rather than asserted.
  → The two halves of the requirement:
    * **Host CSPRNG.** `AmbientState::random_bytes` calls `getrandom::fill` when not
      in deterministic mode — OS entropy, with a failure mapped to
      `RandomFailure::SourceFailed` and then to a **host error** rather than
      fabricated bytes, because predictable "randomness" is worse than a failure.
      splitmix64 is used **only** in deterministic mode, where the doc states
      explicitly that it "is explicitly NOT a CSPRNG, and is never used outside
      deterministic mode".
    * **No guest-supplied seed.** `qqq:crypto/random.get` takes `length: u32` and
      nothing else — the prohibition is in the **WIT signature**, so it holds by
      construction rather than by a check someone could remove. A grep for
      `fn seed` / `with_seed` / `set_seed` across `ambient.rs` and `host_crypto.rs`
      returns nothing, which is the expected result and is why it is written down.
  → The determinism boundary itself is enforced by the grant model as well:
    `crypto.random` defaults to **false** in the manifest, because "an unrequested
    CSPRNG is a covert channel" (§10.5) — so a guest that never asked for
    randomness cannot reach the generator at all.
  → §7.4 Cryptographic posture
- [x] **SEC-019** Implement Linux hardening: dropped privileges, `no_new_privs`, seccomp allowlist.
  → Done, and **the block on this item was on one implementation of it rather than
    on the item.** `qqq-sys` is the crate §4.3 designates for `unsafe` OS
    primitives, and it carries a bare `#![forbid(unsafe_code)]` — so the obvious
    `libc`-in-`unsafe` approach would trigger the exception process: a safety
    argument **plus a second maintainer**, and `SAFETY.md`'s ledger records none
    exists (`GOV-008`, bus factor 1).
  → **It was sidestepped rather than deferred**, because safe wrappers exist:
    `nix` provides `setuid`, `setgid`, `setgroups` and `set_no_new_privs`, and
    `seccompiler` compiles a BPF filter from a typed description. Verified in the
    installed `nix` 0.31.3 source *before* committing to the approach, and both
    licences (MIT; Apache-2.0 OR BSD-3-Clause) are on `deny.toml`'s allowlist.
    **`qqq-sys` still contains no `unsafe`**, the architecture tests pass, and
    nothing waits on an unsatisfiable precondition. The trade is a dependency
    instead of an `unsafe` block, and it is the better side independently: an
    `unsafe` block we write is an obligation we hold forever, while a safe wrapper
    is one the ecosystem holds and we review once.
  → **§7.5's design rule is the specification, not a hedge.** *"None of these are
    required for QQQ's security claim"* shapes the whole module:
    * hardening **never fails the process** — it returns a `HardenReport`, not a
      `Result`, because a `?` on it would turn "this kernel has no seccomp" into a
      startup failure: an availability bug introduced by a defence-in-depth feature;
    * the outcome has **four** variants, because a `bool` would collapse `Skipped`
      and `Failed`, making a deployment that quietly did not harden look identical
      to one that did;
    * `Unsupported` is deliberately **not** a failure — treating it as one would
      make QQQ undeployable off Linux, the opposite of "deployable anywhere".
  → **Two guards that would otherwise be invisible.** `setuid(0)` is refused
    outright, because dropping to root is a no-op that `setuid` reports as
    **success** — a report saying `Applied` would claim a privilege drop that never
    happened. And the seccomp filter is **default-deny with an explicit
    allowlist**, because a filter listing denials permits every syscall newer than
    the list, which is the entire history of seccomp bypasses.
  → **The step order is a security property, asserted rather than assumed:**
    `no_new_privs` before seccomp (installs without `CAP_SYS_ADMIN` only under it),
    groups before uid (dropping the uid removes the authority for `setgroups`),
    seccomp last (the filter refuses `setuid`). Reversing any produces a process
    that keeps running and is merely *less hardened* — a silent-looking failure —
    which is why `STEP_ORDER` is a documented constant with a test.
  → **Deliberately not implemented, named rather than omitted:** `Landlock` needs
    a newer kernel API than `nix` wraps safely, and `capset` is subsumed for the
    common deployment (a process at an unprivileged uid has no capabilities left,
    and dropping capabilities *instead of* the uid would be strictly weaker).
  → **Testing required an unusual approach.** The steps are irreversible and
    process-wide — a filter cannot be removed, and installing one in-process would
    kill every later test with `SIGSYS` — so the tests **re-execute the test
    binary** with an environment variable naming the step and assert on the child's
    report. Calling `harden` directly would pass on Linux CI while making the
    binary un-runnable afterwards: a test that works once, alone.
  → **The general lesson:** *check whether a block is on the item or on one
    implementation of it.* `SEC-019` here and the audit in `SEC-017` both looked
    blockable and both dissolved under a question — and marking either `[!]` would
    have been defensible and wrong.
  → §7.5 Hardening beyond Wasm. New: `crates/qqq-sys/src/harden.rs`,
    `crates/qqq-sys/tests/harden.rs` (18 tests), §8 of `crates/qqq-sys/SAFETY.md`.
- [x] **SEC-020** Audit every `unsafe` block in the three exception crates and record the findings.
  → Done. **The finding is zero, and the work was making that zero mean something.**
    Recorded in `docs/unsafe-audit.md`, reproduced by `python tools/audit_unsafe.py`.
  → **Scope was widened deliberately.** The item says "the three exception crates",
    but an `unsafe` block in a crate that is *supposed* to forbid it is a more
    serious finding than one in a crate allowed to have it — so the audit covers
    every `.rs` file in the workspace.
    | Measure | Count |
    |---|---|
    | `.rs` files scanned | *in `docs/unsafe-audit.md`*, where `audit_unsafe.py --check-doc` fails when it drifts |
    | Code-position `unsafe` (`{}`, `fn`, `impl`, `trait`, `extern`) | **0** |
    | `#[allow(unsafe_code)]` in a code position | **0** |
    | `cfg_attr(..., allow(unsafe_code))` | **0** |
    | Crates with a bare `#![forbid(unsafe_code)]` | **11** (every crate) |
  → **2026-09-22 — the count above was a false claim, and it is deleted rather
    than corrected.** This line read "all 85 `.rs` files" and the table row said
    **85**, while a live scan found **142**: true when written, never tied to the
    tree, and wrong by 57 files in the direction that *understates the sample*. It
    is the same defect `docs/unsafe-audit.md` records about itself — that page once
    said 85 while the tree held 139 — and that page was fixed by adding
    `--check-doc` to CI. **The checklist kept its own copy and was not fixed**,
    because nothing checks a number written in the checklist. The copy is deleted
    here instead of updated, because a second copy of a CI-tied number drifts
    again; the rows that remain are the ones CI enforces (`audit_unsafe.py` exits
    non-zero on any code-position `unsafe`, and the workspace lints carry
    `forbid(unsafe_code)` in all 11 crate roots). Measured in `§O-186`.

### ABI — WIT packages
  → **A zero that appears for the wrong reason is worse than a non-zero, because it
    looks like an achievement.** Two explanations were distinguished rather than
    assumed:
    1. **The audit is not blind** — verified by *injecting* an `unsafe` block and
       confirming it was detected, classified, and caused a non-zero exit. A
       scanner that reports zero because it is broken cannot pass that test.
    2. **The primitives are mostly not built** — no `io_uring` ring, no
       hugepage-backed memory, no signal handler. And `SEC-019`, the one item that
       *did* need OS primitives, avoided `unsafe` entirely via `nix` +
       `seccompiler`. That is the strongest available evidence the zero is
       structural rather than accidental.
  → **The tool has a self-test, and it found a real defect in the tool.**
    `--self-test` injects all seven `unsafe` forms and asserts each is detected,
    **plus three prose controls** — because a scanner whose only tests are
    injections happily over-reports, and an audit that cries wolf is one people
    stop running. It caught exactly that: a string literal containing `unsafe {`
    was flagged as code, because the first classifier only looked for `//` before
    the position. The classifier now walks the line tracking code/string/comment
    state, including the lifetime-vs-char-literal ambiguity that would otherwise
    swallow the rest of a line.
  → **Gaps named rather than implied:** the scanner does not see what a procedural
    macro or `build.rs` *generates*, only what is committed — a real gap, not a
    hypothetical one; and it counts and classifies but does not evaluate soundness
    (with zero blocks there is nothing to evaluate, and `SAFETY.md` §5's reviewer
    checklist applies the moment there is).
  → **What governs the first `unsafe`:** the exception process is enforced by four
    architecture tests plus `tools/fault_inject_architecture.py`, and it is
    **currently blocked** — `SAFETY.md`'s ledger records no second maintainer
    exists (`GOV-008`, bus factor 1). So the honest statement is: the workspace
    contains no `unsafe`, and the process that would govern the first one is
    enforced but cannot currently complete. A governance gap, not a code gap.
  → CI now runs both the audit and its self-test, replacing an inline grep that
    exempted anything matching `#![cfg_attr` — a broader exemption than the thing
    it was guarding against — and that only ever ran in CI (`§O-055`'s failure).
  → §4.3 Crate topology. New: `docs/unsafe-audit.md`, `tools/audit_unsafe.py`.
- [x] **SEC-021** Track post-quantum hybrid TLS (X25519+ML-KEM) as an opt-in, with a standards-watch task.
  → Done: `SERVER_KX_GROUPS` in `qqq-serve::tls` names X25519MLKEM768 **first**, and
    `provider.kx_groups` is set explicitly instead of inheriting a library default.
  → Reading the pinned dependency inverted the item: rustls 0.23.31+ already defaults
    to X25519MLKEM768 and `Cargo.lock` resolves 0.23.45, so the hybrid was ON by
    inheritance. The real risk was it being silently removed, not enabled.
  → 3 tests + a bridge injection (4/4 now caught) prove the policy is load-bearing.
  → §7.4 Cryptographic posture
- [x] **SEC-022** Implement the optional egress proxy with per-tenant policy.
  → Done: `qqq-cap::egress` — `EgressPolicy` authorizes a `Destination` for a
    `TenantId` against a resolved `GrantSet`, with a typed `Denial` per layer.
  → Three layers, in order: capability (the engine's decision is not reviewable),
    tenant (no policy = no egress), then destination shape (literal IP addresses and
    cleartext are refused by default).
  → Literal-address refusal is the SSRF guard: `https://93.184.216.34/` reaches the
    same server as `https://example.com/` while matching no host pattern, so
    permitting it would make the allowlist advisory. Fault-injected: disabling it
    fails 2 tests.
  → 20 tests; `Denial::label` is bounded for §10.2 metric cardinality.
  → §7.5 Hardening beyond Wasm
- [x] **SEC-023** Establish the responsible-disclosure process and a public security-advisory feed.
  → Done: `SECURITY.md` (contact, scope, severities, response targets), plus the
    machine-readable path: `.well-known/security.txt` (RFC 9116) and
    `docs/advisories/` — a public register with `INDEX.md` as its front door.
  → `tools/check_advisories.py` enforces the register in CI: every advisory needs an
    index row and vice versa, identifiers must be unique and `QQQ-YYYY-NNN`,
    required sections must be present and non-empty, severities must agree, and
    "Found" must not postdate "Published".
  → Its 9-case self-test found two real gaps while being written: a dead identifier
    check and an unreachable filename check (the glob only matched well-formed
    names, so a malformed one was invisible).
  → §7.2 Adversary model
- [!] **SEC-024** Commission external security audit #1 before the private alpha (M7).
  → **Blocked**, and this one genuinely is: it requires engaging a third-party firm and
    paying them. `§O-082`'s question — "blocked on the item, or on one way of doing
    it?" — has no third answer here, unlike `SEC-017`, `SEC-019` and `SEC-026`, which
    all dissolved. Recorded in `§O-095` with what *would* unblock it.
  → What is done in the meantime: `docs/threat-model.md` states in its first section
    that no validation has occurred, and `tools/check_threat_model.py` fails the build
    if that claim is made while this item is open.
  → §16 — Definition of Done for V1
- [!] **SEC-025** Commission external security audit #2 before the public beta (M10).
  → **Blocked** on the same condition as `SEC-024`: an external engagement, not a
    technical obstacle. See `§O-095`.
  → §16 — Definition of Done for V1
- [x] **SEC-026** Implement Landlock LSM integration as defence in depth on Linux ≥ 5.13.
  → Done: `STEP_LANDLOCK` in `qqq-sys::harden`, using the `landlock` crate (safe, so
    no `unsafe` exemption is needed). Ordered after the uid drop and before seccomp.
  → `HardRequirement` compatibility, so an older kernel errors instead of silently
    installing a weaker ruleset. `RulesetStatus` decides Applied vs Unsupported, so
    `NotEnforced` can never be reported as success.
  → 3 tests, including a **behavioural** one: a ruleset granting only `/proc/self`
    must refuse `/etc/hostname`. Fault-injected by granting `/` instead — the step
    still reported `Applied`/`FullyEnforced` while the path was `allowed`, which is
    `§O-085` reproduced and caught.
  → Verified live: `HARDEN_PROBE:refused`, Landlock **ABI V7**, `no_new_privs=true`.
  → The earlier "blocked" note was a fact about `nix`, not about the item (`§O-082`).
  → §7.5 Hardening beyond Wasm
- [x] **SEC-027** Implement memory-protection-key support as an optional hardening feature.
  → Done (detection) + `[!]` blocked (enforcement), and the distinction is measured:
    `mpk_support()`, `landlock_available()` and `host_capabilities()` report what the
    host offers, cross-checked in a test against `/proc/cpuinfo` so a probe stuck on
    `false` (the safe-looking answer) cannot pass.
  → Enforcement is blocked on two *specific* things, not on the item: every MPK crate
    is a thin `unsafe` FFI wrapper, and `qqq-sys` may not contain `unsafe` until
    `SAFETY.md`'s ledger gains a second maintainer (`GOV-008`, bus factor 1). This is
    `SEC-019`/`SEC-026`'s shape with the search coming up empty.
  → Verified: this host has no `pku` flag, so enforcement could not be exercised here
    even if unblocked — which is exactly why detection is the deliverable.
  → §7.5 Hardening beyond Wasm
- [x] **SEC-028** Produce and publish the SBOM for every release.
  → Done: CI generates CycloneDX 1.5 per crate with `cargo cyclonedx` (pinned
    `--locked`) and **uploads it as an artifact**, which is what makes "publish"
    true — a file on a runner's ephemeral disk answers nothing.
  → `tools/check_sbom.py` asserts the SBOM is *usable*: parses as JSON, declares
    CycloneDX + specVersion, lists components, names and versions every one, and
    identifies its subject in `metadata.component` matching the filename. 12/12
    self-test cases.
  → The checker's first version asserted the subject appears in `components`;
    running it against real output rejected all 10 files, because CycloneDX puts
    the subject in `metadata.component` and lists its *dependencies* in
    `components`. Corrected against generated output, not against a guess.
  → Verified on real data: 10 files, 677 components, all named and versioned;
    emptying a component list makes the check fail with the reason.
  → `*.cdx.json` is gitignored: a committed SBOM is stale the moment a dependency
    moves, and a stale supply-chain document answers with the wrong tree.
  → §7.3 The defence timeline — where we stop an attack
- [x] **SEC-029** Implement the distroless, read-only, non-root container image.
  → Done: `docker/Dockerfile.prod` — musl-static `qqqai` on
    `gcr.io/distroless/static-debian12:nonroot`. Separate from `docker/Dockerfile`,
    which is the *development* bridge; a shared file risks the runtime stage
    inheriting a build tool.
  → **Verified, with measurements**: no `/bin/sh` (asserted by trying to run one);
    runs under `--read-only`; `USER 65532:65532`; and **33 MB against the dev
    image's 4.33 GB — a 131× reduction**.
  → The build asserts static linking *in the build stage*, so a dynamic link fails
    where `ldd` exists with a message naming libc, rather than in the distroless
    stage as a bare "no such file or directory".
  → CI job `production-image` re-asserts all four properties on every commit: a
    `Dockerfile` that says `FROM distroless` proves nothing on its own.
  → Three real build failures fixed on the way: three crates have no `README.md`
    (so the enumerated COPY was wrong); `qqq-abi` embeds `wit/*.wit` from outside
    `crates/` (13 missing-file errors); and the static-link check grepped for `not
    a dynamic executable` when musl prints `statically linked`.
  → §7.5 Hardening beyond Wasm
- [x] **SEC-030** Publish the explicit out-of-scope section (host admin, side channels, physical, volumetric DoS).
  → Done: `docs/out-of-scope.md` — the published expansion of §7.2's four classes plus
    Wasmtime bugs and unbounded-capability requests. Each entry states a limit **and**
    what to do about it, because a bare "not defended" is accurate and useless.
  → `tools/check_security_scope.py` keeps the four documents from disagreeing, which
    prose alone cannot do: every canonical class must appear in the Proposal §7.2,
    `SECURITY.md` and the published page, the two must link to each other, and a
    section too short to state a consequence is rejected. 7/7 self-test cases.
  → **A removal fails the check**, deliberately: dropping an out-of-scope class is a
    security decision rather than an editorial one, so it must be a loud change.
  → Building it found a real gap: `SECURITY.md` had no link to the new document.
  → §7.2 Adversary model

---

## 6. P3 — HTTP (M3)

### SRV — Server

- [x] **SRV-001** Implement HTTP/1.1 with keep-alive, timeouts and connection limits.
  → §6.4 `qqq-serve` — the HTTP and application server
  → Done. `qqq-serve::server` is the accept loop joining the parts:
    `http1` (head parse + framing validation), `route` (radix trie), `response`
    (writer + error mapping), `conn` (keep-alive, idle/header deadlines,
    request ceiling, graceful drain) and `qqq-io::listener` (socket, shards).
  → Verified in source, not asserted: `Connection::will_keep_alive` (keep-alive),
    `ConnectionConfig::{idle_timeout, header_timeout}` (timeouts),
    `ConnectionConfig::max_requests` (per-connection ceiling),
    `ConnectionLedger::admit` (per-tenant connection limit, checked **before**
    the first byte is read).
  → Evidence: `crates/qqq-serve/tests/socket.rs`, 10 tests against a real
    socket — routing, 404/405/400, keep-alive and `close`, HTTP/1.0 default
    close, body drain across two requests, **pipelining**, graceful shutdown.
  → Defect found and fixed while completing it: `read_head` preserved the bytes
    after the head terminator while `drain_body` refetched the body from the
    socket, desyncing the framing offset when head and body shared a segment
    (`§O-047a`). The test that named this could not fail for it
    (`§O-047b`); its replacement fails on injection and passes without it
    (`§O-047c`).
  → Not covered here: HTTP/2 (`SRV-002`) and streaming bodies (`SRV-004`).
    `drain_body` closes the connection on a `chunked` body rather than
    de-chunking, which is `SRV-004`'s work and is stated in `§O-047a`.
- [x] **SRV-002** Implement HTTP/2 including multiplexing and flow control.
  → §6.4 `qqq-serve` — the HTTP and application server
  → Done in seven layers plus a connection: `h2::frame` (the 9-byte header and
    every frame type), `h2::hpack` (static and dynamic tables, integer, Huffman),
    `h2::flow` (both windows and §6.9.2's retroactive delta), `h2::stream` (the
    §5.1 state table), `h2::settings`, and `h2::conn` — preface, dispatch,
    multiplexing and `CONTINUATION`-reassembly, driven by
    `recv(&[u8]) -> Vec<Event>` over buffers rather than a socket so a header
    block split across three frames is testable by feeding it bytes.
  → Evidence: **239 tests in the `h2` module** (201 + 38 new) and 418 in
    `qqq-serve`; `cargo clippy --workspace --all-targets -- -D warnings` clean.
  → **The module had been excluded from the crate's module tree** by a leftover
    debugging line — 9,370 lines and 201 tests that had never been compiled,
    linted or run. Restoring it cost two compile errors and one warning.
    Recorded as `§O-120`, and now guarded by `tools/check_scope_table.py`, which
    fails when any `.rs` file under `src/` is unreachable from the crate root.
  → **A wrong test was among the ones that had never run**:
    `the_second_end_stream_closes_the_stream` asserted a state §5.1 Figure 2 does
    not have. The implementation was right; the test was corrected.
  → Three defects found by the new connection tests and fixed: stream
    replenishment advertised the whole window instead of the credit owed
    (measured: 65,525 after ten bytes); new streams were never given a
    flow-control window; and a closed stream id skipped the §5.1.1 monotonicity
    check.
  → Not covered: TLS/ALPN negotiation of `h2` on a listener — `crate::server` is
    HTTP/1.1 only. That is the remaining join and is stated in `h2/mod.rs`.
- [x] **SRV-003** Implement the compile-time route table as a radix trie.
  → §6.4 `qqq-serve` — the HTTP and application server
- [x] **SRV-004** Implement streaming bodies end to end with backpressure propagation.
  → §6.4 `qqq-serve` — the HTTP and application server
  → Done as a **pull-based decoder**: `qqq-serve::body::BodyReader::poll_chunk(io, max)`
    yields the next piece of a body and nothing else. `Content-Length` and
    `Transfer-Encoding: chunked` are both decoded incrementally; chunk
    extensions are skipped, a chunk's own CRLF is consumed at its boundary, and
    a trailer section is consumed and **discarded** (a trailer is not
    authenticated in V1, and surfacing it would let a client add headers after
    the head was routed).
  → **Backpressure** is the caller's `max` plus the pull: a handler that asks for
    1 KiB holds 1 KiB, and while it is not asking nothing is read from the
    socket. Asserted by `a_reader_never_reads_more_than_the_caller_asked_for`.
  → The chunked-body connection close that `drain_body` did for want of a decoder
    is gone: a chunked request is answered and the connection reused
    (`a_chunked_body_is_decoded_and_the_connection_is_reused`).
  → Evidence: `crates/qqq-serve/tests/body.rs` (22 tests, including the framing
    offset left exactly at the next request) and `tests/socket.rs` (12).
  → Verified: `tools/fault_inject_body.ps1` breaks six invariants and **all six
    are detected** — chunk CRLF not consumed, trailers not consumed, the
    caller's `max` ignored, and others.
  → Not covered: handing a **`stream<u8>` to the guest** — that is the
    capability path (`qqq-host` + `qqq:http`), and what exists here is the
    server-side framing and enforcement it will sit on.
  → **Response side, added later**: `qqq-serve::stream` — `StreamWriter` (head, then pieces, then a
    version-aware terminator), `StreamOutcome` (`Completed` / `ClientClosed` / `HandlerFailed`, with
    `ClientClosed` at `Info` because a client closing an event stream is the normal end of one), and
    `StreamRecord`. A **second** handler type rather than a change to `Handler`, because `Handler`'s own
    docs state the property worth keeping: it "does not touch the socket", which keeps routing and encoding
    testable without a listener and means a handler cannot hold a connection open by accident. A streaming
    handler violates all of that by necessity — which is the point of an event stream — so the two are
    separate and the difference is visible at the call site.
  → **A real protocol bug found by the tests**: `write` called `write_chunk` unconditionally, gating only
    the *terminator* on the version. An HTTP/1.0 client received `13\r\nraw-body-for-http10\r\n` — the
    chunk length as **body data**. Every HTTP/1.1 test passed, because the framing is correct there; the
    defect lives only in the transition between versions. See `§O-132`.
  → **Measured**: 3 unit + 6 integration tests over a real socket; workspace **1962 passed, 0 failed**.
  → **Wired**: `qqq-serve::server::Dispatch` carries both handler kinds and `serve` takes it; a matched
    route whose handler **name** has a streaming entry is served by it, everything else falls through to the
    flat handler. `Dispatch::flat(handler)` is the constructor for a server with no streaming routes, so no
    existing caller changed meaning. Keyed by name rather than by a flag on `Route`, because `Route`'s
    `handler` is already a name the host resolves at dispatch and the router is not the authority on how a
    guest is invoked.
  → **Measured**: 4 integration tests through the real accept loop, including one that proves an event
    reaches the client **while the handler is still parked** — a buffered path would deadlock rather than
    fail, because the handler awaits a signal the test only sends after reading that event. Workspace
    **1966 passed, 0 failed**. See `§O-133` for the lifetime bug found on the way.

  → **2026-09-22 — the "cap, not a buffer" claim was false for a streaming route, and is
    now true.** `serve_connection` called `drain_body` and *then* `serve_special_route`,
    while `drain_body`'s own documentation stated that a streaming route "is dispatched
    before this function runs". A `StreamingHandler` takes `(head, route_match,
    &mut StreamWriter)` and has **no body parameter**, so the body was read into memory for
    a handler that could not read it. Nothing failed — the response was correct and only the
    cost was wrong — which is why no test noticed. The call order is now the one the
    paragraph describes, and `crates/qqq-serve/tests/streaming_route.rs` drives it:
    `a_streaming_route_does_not_read_the_request_body` declares `Content-Length: 4096` and
    sends none of it, and the first streamed event must still arrive; the control
    `a_flat_route_does_read_the_declared_body` shows a flat route *does* wait, so a server
    that ignored the declaration entirely could not pass both. Fault-injected by swapping
    the calls back: **detected**. See `§O-184`.
- [x] **SRV-005** Implement `max_request_bytes` enforced during streaming, not after buffering.
  → §6.4 `qqq-serve` — the HTTP and application server
  → Done. `BodyReader::account` charges each piece **before it is returned**, so a
    body one byte past the cap is refused without the caller ever holding those
    bytes, and `a_length_delimited_body_past_the_cap_fails_without_reading_it_all`
    asserts the *consumed offset* stayed near the cap rather than reaching the
    100 bytes available — the assertion that distinguishes "enforced during
    streaming" from "checked after buffering".
  → **Found and fixed a real ordering defect while completing this**: the handler
    was dispatched *before* the body was drained, so a 3 MiB chunked body against
    a 2 MiB cap was answered **`200 OK`** — the guest ran, the response was
    written, and only then was the body found too large. The body is now consumed
    before dispatch, and the refusal is `QQQ-6006` (a new code: a *client* fault,
    so a 4xx-class answer rather than a 5xx). `§O-048a`.
  → Verified by injection: restoring the ordering defect makes
    `a_chunked_body_past_the_cap_is_cut_off` fail while every other socket and
    body test stays green.
- [x] **SRV-006** Resolve open question `OQ-007`: decide whether `wasi:http` is the foundation or whether a custom interface is required.
  → §6.4 `qqq-serve` — the HTTP and application server
  → Resolved: `wasi:http` **is** the foundation, and `qqq:http` extends it. Reasoning in Observations §O-027.
- [x] **SRV-007** Implement TLS with rustls and the documented cipher policy.
  → §6.4 `qqq-serve` — the HTTP and application server
  → Done: `qqq-serve::tls`. rustls 0.23 with an **explicit** cipher policy — an
    unspecified algorithm is *refused* rather than defaulted (`SEC-017`'s
    "named algorithms, no silent defaults") — TLS 1.3 preferred with 1.2
    permitted, ALPN negotiating `h2` / `http/1.1`, and certificate sources
    `Files` (PEM; PKCS#8, PKCS#1 and SEC1 keys) and `Platform`. `Acme` is
    refused **by name** with a successor, not silently degraded (`FUT`).
  → Evidence: 35 unit tests; 21 end-to-end tests in `tests/tls.rs` that drive a
    **real handshake** over an in-memory duplex and assert the negotiated
    version, the negotiated cipher, the ALPN outcome, and the refusal cases.
  → Tampered and broken configurations are errors naming the file rather than
    panics; a missing or unusable key, a certificate in the key slot, and a key
    in the certificate slot are each covered.
- [x] **SRV-008** Implement mTLS as a supported `default_auth` mode.
  → §6.4 `qqq-serve` — the HTTP and application server
  → Done: `ClientAuth::{None, Required, Optional}` over
    `WebPkiClientVerifier`, with a configurable trust root, plus `PeerIdentity`
    (subject CN, leaf DER, SHA-256 fingerprint) extracted from the verified
    chain for request attribution. Authorization policy is deliberately **not**
    implemented and says so — this is identity, not a decision about it.
  → Verified end to end: `Required` refuses a client with no certificate *and* a
    client presenting an untrusted one; `Optional` accepts one that declines;
    a presented trusted certificate yields the expected CN.
  → **A real defect was found here and only here**: `common_name_of` returned
    `None` for every certificate, so `subject()` reported
    `"(subject has no common name)"` for every mTLS peer. It searched for tag
    `[3]` among the `Certificate`'s children, where `TBSCertificate` is a plain
    `SEQUENCE` — measured, the children are `0x30, 0x30, 0x03` with no `0xA3`.
    The hand-built unit fixtures encoded the same wrong assumption, so they
    passed; only real bytes found it. A real-certificate test with a control now
    pins it, verified by injection. `§O-053a`.
- [x] **SRV-009** Implement WebSockets over HTTP/1.1 and HTTP/2.
  → §6.4 `qqq-serve` — the HTTP and application server
  → Done in four layers, all reachable: `crates/qqq-serve/src/ws.rs` implements RFC 6455 §4 — `Handshake::parse` (method, `Upgrade`, the `Connection` **token list**, version, and a key that decodes to exactly 16 bytes), `accept()`, `select_protocol`, `write_upgrade` and `write_refusal`.
  → **The specification's own worked example is a test**: RFC 6455 §1.3's key `dGhlIHNhbXBsZSBub25jZQ==` must yield `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`. A control asserts that hashing the key *without* the GUID gives something different — a version that forgot it would still be deterministic and still look plausible.
  → **`Connection` is a token list, not a value.** `keep-alive, Upgrade` is what a browser sends; an equality test against `"upgrade"` rejects correct clients and the failure appears as "WebSockets do not work in Firefox". Five spellings are covered, including the list form and mixed case.
  → **A version refusal must name what is supported** (§4.4), so `write_refusal` sends `426 Upgrade Required` with `Sec-WebSocket-Version: 13`; a malformed request gets `400` without it, because only a 426 means "retry with another version".
  → **Neither response goes through `write_response`.** A `101` must not carry `Content-Length` — after it the connection is not HTTP, and a client reading a length would count frame bytes as content.
  → **SHA-1 is correct here and the reason is recorded at the dependency** (workspace `Cargo.toml`): the accept value is a proof the server read the handshake, not a security control, and the input is a key the client itself chose.
  → **Measured**: 24 handshake tests + 30 frame tests + 19 assembly tests; workspace **2048 passed, 0 failed**.
  → **The frame layer is done** (`crates/qqq-serve/src/ws_frame.rs`, RFC 6455 §5): `Opcode` (the closed set, with `is_control` following §5.5's high bit rather than a hand-rolled list), `Frame`, `decode_server_frame`, `encode`, `text_of`. The nine rules each have a test, and each is a real failure rather than a style preference — most importantly §5.1's **asymmetry**: a client must mask and a server must not, which is why `Frame` and `encode` are separate rather than an inverse pair with a mask parameter.
  → **A real encoder bug the tests caught**: `encode` used `len <= u32::MAX` for the 16-bit length form — four orders of magnitude too wide. A 70,000-byte payload wrote the marker `126` and then `(len as u16)`, silently truncating to **4,464**. The frame was well-formed and the payload was gone. A decode-only fixture cannot see it (the bug is in the encoder) and a short-payload fixture cannot either (every length below 65,536 takes the branch that works); the test encodes and decodes across both boundaries §5.2 defines. See `§O-134`.
  → **Message assembly is done** (`crates/qqq-serve/src/ws_message.rs`, §5.4): `Assembler`, `Message`, `Progress`. It holds the three rules the frame layer **cannot** enforce, because each depends on arrival *order* rather than on one frame: a `Continuation` with no message in progress, a data frame arriving mid-message, and the **running total** — each frame is under its own cap and a thousand of them are not, so the bound is checked before the extend rather than after.
  → **The rule most likely to be got wrong**: a control frame mid-message must **not** reset the accumulation. §5.4 permits interleaving, so a `Ping` between fragments is legal, and a machine that treated any frame as a restart would drop the first half — a failure that appears only under a ping, which is rare in tests and constant in production behind a load balancer. Fault-injected: clearing the state on a control frame fails the test with "the message must survive the ping".
  → **Wired and reachable** (`crates/qqq-serve/src/ws_conn.rs`): `Dispatch` gained a third handler kind — a WebSocket connection is not a request that produces a response, it *becomes a different protocol* and stays open, so neither a flat nor a streaming handler expresses it. `serve_connection` checks the upgrade **first**, before streaming and before the flat path, because answering an upgrade with a body commits the connection to HTTP and makes the upgrade impossible. A WebSocket route reached *without* an upgrade is answered as ordinary HTTP (§4.2.1) — a `101` would put the connection into frame mode for a client still speaking HTTP.
  → **The two rules that belong to the loop, not either codec**: a `Ping` must be answered with a `Pong` carrying **the same payload** (§5.5.3) — a connection that ignores pings is dropped by every intermediary using them as a liveness probe, and the failure reads as "the connection drops after 60 seconds" with nothing in the logs; and a `Close` must be **echoed before teardown** (§5.5.1) — a client that cannot distinguish a clean close from a fault will *reconnect*, turning a deliberate shutdown into a reconnect storm.
  → **Measured**: 24 handshake + 30 frame + 19 assembly + 3 connection unit tests + **10 integration tests over the real accept loop** (the `101` with §1.3's own accept value, text and binary echo, ping/pong payload preservation, close echo carrying the peer's code, a genuine fragmented message arriving whole, a ping between fragments not resetting it, an unmasked frame refused with `1002`, and a non-upgrade getting `400`). Workspace **2061 passed, 0 failed**.
  → The integration client is written **from the specification** — its own masking, close echo and UTF-8 handling per RFC 6455 rather than reusing our encoder. A client built from our `encode` would agree with a wrong server: both would mask, or neither would, and the test would pass.
- [x] **SRV-010** Implement Server-Sent Events.
  → §6.4 `qqq-serve` — the HTTP and application server
  → Done: `crates/qqq-serve/src/sse.rs` — `Event` (event/id/retry/data/comment, each optional and *omitted* when absent, because the parser's `event:` with an empty value sets the type to `""`, so absence and emptiness differ), `Event::encode` (the framing), `headers()` (the three headers a working stream needs), `last_event_id()` (resume). Written to the WHATWG specification's parsing algorithm rather than to the `data: hello\n\n` example, because every rule that matters is invisible in that example.
  → Also added `response::write_stream_head` / `write_chunk` / `write_last_chunk` / `CHUNK_MAX`. SSE cannot be served by `write_response`: an event stream's body ends when the client disconnects, so it has no `Content-Length`. That function's own docs said the streaming form "will be a *different* function, not a flag on this one, because the failure modes are different" — this is it.
  → **Measured**: 24 unit tests + 9 integration tests (`crates/qqq-serve/tests/sse.rs`, including 2 over a real TCP socket with per-event flush and a mid-stream client disconnect). Workspace: **1887 passed, 0 failed**; `clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --check` clean.
  → **Four defects the tests caught in the first draft, all fixed**: (1) a keep-alive emitted a spurious `data:` line, so the client dispatched it as an empty *message* — waking every listener on an idle connection, the opposite of what a keep-alive is for; (2) a payload with a leading space lost it, because the parser strips exactly one space after the colon, so the wire form needs two; (3) a newline-only payload encoded as a bare blank line — an event with no fields at all; (4) `split_lines`' filter closure was vacuous (`|l| !l.is_empty() || s.is_empty()` ignores `l`).
  → **HTTP/1.0 handled explicitly**: it has no chunked encoding, so the body is delimited by EOF and `Connection: close` is forced. Emitting `chunked` there would frame chunk data as body bytes to a client that cannot read it — the request-smuggling shape this project has already had to defend against.
  → **The wiring gap, named not hidden**: `Handler` is `Fn(&RequestHead, &RouteMatch) -> Response` — synchronous, returning a complete `Vec<u8>` body — so a handler today *cannot* stream. SSE is complete at the framing and framing-level integration; reaching it through `serve` requires `Handler` to gain an async streaming variant, which is the same interface change `SRV-004` (streaming bodies with backpressure) needs. The integration tests speak the protocol over a raw socket for exactly this reason, rather than asserting something about `serve` that is not true.
- [x] **SRV-011** Implement graceful shutdown with in-flight request draining.
  → §6.4 `qqq-serve` — the HTTP and application server
  → Done: `qqq-serve::conn::Connection` — in-flight requests finish, idle connections close at once, the drain deadline is enforced and reported.
- [x] **SRV-012** Implement per-tenant connection limits and idle timeouts.
  → §6.4 `qqq-serve` — the HTTP and application server
  → Done: `ConnectionLedger` (per-tenant ceiling) and `ConnectionConfig` (idle and header timeouts). The socket layer that drives them is `SRV-001`.
- [x] **SRV-013** Implement structured access logging with tenant and trace correlation.
  → §10.3 Logging
  → Done: `crates/qqq-serve/src/access_log.rs` — `Level` (5 levels, `Ord`-derived so a filter is a comparison), `TraceId` (32-hex trace / 16-hex span, validated), `Record` (§10.3's fields as a type, not a convention: none is an `Option` except `code`, and no constructor omits one), `Redactor` (longest-first value-substring match, `[redacted:N]` markers), `Format` (Json / Human), `Logger` (level filter, then redact, then render). Wired into `server.rs`: `serve_connection` calls the **public** `access_record(&head, path, &response, &id.tenant, id.trace, span_seq)` and `emit_record` writes it — after the handler (status known) and before the response is written, so a record never describes a response that failed to leave. `TraceCounter` (atomic, process-wide) allocates the trace per accepted connection; `span_seq` stays per-connection so a keep-alive conversation is ordered. `ConnectionId` groups peer + tenant + trace, because they answer one question and the tenant was previously derived twice.
  → **Measured**: 451 lib + 18 `tests/access.rs` + 22 body + 15 socket + 21 tls = **527** tests for `qqq-serve` (counted from the test runner's own totals, not from `grep`); `cargo test --workspace` = **1851 passed, 0 failed**; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo deny check` = advisories/bans/licenses/sources ok; `audit_requirements.py` 32/32.
  → **Two defects found while wiring, both fixed**: (1) `render_human` dropped `manifest_rev` while `render_json` wrote it — §10.3 requires it on *every* line and the human form is what an operator reads, so the module's own "no second source of truth" warning was already violated; `the_two_encodings_carry_the_same_fields` now compares both renderers field-by-field in both directions. (2) the level rule was inline and unnamed, so no test could state it; extracted to the public `server::level_of`.
  → **Five more found by external review (CodeRabbit), all reproduced with a failing test before fixing** — see `§O-125`: raw control characters reaching the human line (a guest could forge a second log line and emit ANSI escapes), `println!` panicking on a closed stdout and taking the connection task down with it, a per-connection trace id that collided across connections, a `dedup` after a length sort that left duplicates (one secret, two marker numbers), and an all-zero first trace id (reserved by W3C Trace Context to mean *no trace*).
  → **Not covered, named rather than papered over**: the test harness captures `println!`, so no test reads back the line the server printed. Everything up to the sink is covered — the record, the filter, both renderings, and the trace allocation — and the sink is one `writeln!` whose failure is discarded.
  → `manifest_rev` is the exported `server::MANIFEST_REV_UNKNOWN` (`"unknown"`) because this layer loads no manifest — a placeholder §10.3 permits, not a stub.
- [ ] **SRV-014** Implement HTTP/3 over QUIC behind a feature flag (beta).
  → §6.4 `qqq-serve` — the HTTP and application server
- [ ] **SRV-015** Implement gRPC over `wasi:http` plus `qqq:grpc` (beta).
  → §6.4 `qqq-serve` — the HTTP and application server
- [ ] **SRV-016** Implement ACME certificate provisioning as an opt-in.
  → §6.4 `qqq-serve` — the HTTP and application server
- [x] **SRV-017** Implement `qqqai openapi` emitting an OpenAPI description of a running app.
  → §5.2 The command surface
  → Done: `crates/qqq-run/src/openapi.rs` — `OPENAPI_VERSION = "3.0.3"`, `Document`, `Info`, `PathItem`, `Operation`, `Response`, `Parameter`, `Schema`, and the pure functions `document(title, version, server)`, `path_template(pattern)`, `parameters_of(pattern)`, `to_json()`. Wired end to end: `OpenapiOutput` in `commands.rs`, `CommandName::Openapi` in `output.rs` (enum, `as_str`, `summary`, `all()`, schema match, `SCHEMA_FOR_OPENAPI`), `dispatch_openapi` in `main.rs`, and the help group.
  → Done: **generated from the manifest, not from a running server.** §5.2 says "of a running app", and the tempting reading is to start the server and introspect it — which would describe whatever that process happened to be serving and go silently wrong the moment the manifest and the process diverged. The manifest is the authority on what the app exposes, so generating from the same route table the server binds makes the document and the serving *the same fact*, and works in CI with no port, no build and no network.
  → Done: **no invented schemas.** A QQQ route declares a path, a method set and a handler name, and no request or response schema — the handler is a guest whose interface is a WIT world. Every operation therefore carries no request body schema and a generic 200, plus `x-qqq-handler` naming its handler. An invented schema would be more useful to a code generator and wrong; the `x-` extension keeps the document valid.
  → Done: `CONNECT` is **refused by name**, not dropped. It is in the manifest's method set and has no OpenAPI operation object; omitting it would understate the exposed surface, which is a false statement about a route that is served.
  → **Measured**: 14 unit tests in `openapi.rs` + 4 CLI tests driving the real binary against a 3-route manifest. End-to-end on `.scratch/oa_probe/qqq.toml`: `3 paths, 3 operations, OpenAPI 3.0.3`; `--out openapi.json` produced `"/orders/{id}"` (the `:id` rewritten, `:id` absent), sorted paths, `x-qqq-handler` present. Fault-injected three behaviours — the placeholder rewrite, the `CONNECT` refusal, and the version constant — and all three drove the corresponding test red; source restored and asserted free of residue. Workspace: 2148 tests pass (was 2130), clippy `-D warnings` clean, fmt clean, topology and EOL checks pass.
  → Gap named: the document describes routes and methods only. It carries **no security scheme**, because the manifest's route-level `auth` policy is enforced by the server and mapping it onto OpenAPI `securitySchemes` would assert a token shape QQQ does not define. It also cannot describe gRPC or HTTP/3, but not because the command omits them: the manifest has **no transport field** (verified — `grep` for `grpc|http3|transport` in `manifest.rs` returns nothing), so there is nothing for `openapi` to report. `SRV-014`/`SRV-015` are unimplemented, and when a transport is added to the manifest this command must learn about it or it will silently describe a subset.
- [x] **SRV-018** Implement the reference application used by all benchmarks (orders API).
  → §9.1 The honest benchmark position
  → Done: `examples/orders-api/` — a **real QQQ guest component**, not a mock. `qqq.toml` declares §5.3's three routes plus the §9.1 workloads; `src/router.rs` holds the route table that dispatches them; `src/orders.rs`, `src/router.rs`, `src/json.rs`, `src/hash.rs` and `src/compute.rs` implement the ten workloads. **Nothing comes from crates.io**: JSON, SHA-256 and the prime sieve are in-tree, because the app is the *measurement instrument* — if the guest's arithmetic came from a dependency, a change in the `crypto` or `cpu` numbers would be a change in that dependency rather than in QQQ.
  → Done: **each §9.1 row is a route, and the set is total.** `hello` (`/healthz`), `json` (`/orders/:id`), `route` (`/r/:slug`), `db` (`/orders/:id/items`), `crypto` (`/crypto/:rounds`, POST), `template` (`/orders`, GET → HTML table), `cpu` (`/compute/:n`), `multi` (`/multi`), `tailp99` (`/orders/:id/status`), `cold` (`/cold`). `/crypto/:rounds` is **bounds-checked** (1..=1_000_000): unbounded, it is a denial-of-service primitive any unauthenticated client can drive.
  → Done: **the app is stateful and validates its input.** `POST /orders` parses a form body, refuses an unknown field by name, caps the id at 64 bytes (it becomes a map key, so an unbounded one is a memory-exhaustion primitive), and returns `201` with a `Location`. `DELETE /orders/:id` returns `404` for an unknown id rather than pretending.
  → **Measured — the guest chain, end to end through the real binary.** `qqqai build --release` → `orders-api.component.wasm`, **167 789 bytes**, staged to `<guest>/target/qqq/`. `qqqai serve --listen 127.0.0.1:18321` then answered **19/19** checks driven over a real socket: every §5.3 route; all ten §9.1 workloads, including `/compute/1000` → `{"mode":"sieve","primes":168}` (π(1000)=168, so the guest's arithmetic is correct through the canonical ABI); `POST /orders` with a body → `201 {"id":"live-1","total_cents":750,"created_seq":1}`; `HEAD /healthz` reporting the **same `Content-Length`** as `GET` (2) with **no body**, per RFC 9110 §9.3.2; `404` on an unknown path; and `405` with a truthful `Allow: GET, HEAD` on an undeclared method. `wasm-tools component wit` confirms `export qqq:http/incoming-handler@1.0.0;`.
  → **Measured — tests.** Guest crate: **57 passed, 0 failed** (`cd examples/orders-api && cargo test`), run **separately** because the crate declares its own empty `[workspace]` and is deliberately not a member (§O-147). Workspace: **2460 passed, 0 failed** — re-measured from the gate's own
    `cargo test --workspace`; the entry read 2249 until 2026-09-23, which was true when
    written and drifted as tests were added. Summing the `test result:` lines is the way
    to re-derive it, and summing them is what the number means.
  → **Defect found and fixed: the reference application was outside every quality gate the repository has.** On `a7c6c53`, `cargo clippy --all-targets -- -D warnings` in `examples/orders-api` reported **11 errors**, `cargo fmt -- --check` reported drift in **4 of 5 source files**, and `grep -rn "examples" .github/workflows/ci.yml` returned **no matches at all** — the crate was built by no CI job, linted by none, and formatted by none. The 11 errors included two `chunks_exact`-with-constant-chunk-size lints, the exact lint class whose 1.98 introduction caused the red runs in §O-121. All 11 were fixed with the remedy clippy asked for — **no `#[allow]` was added** — and the whole crate was formatted. Two are improvements rather than appeasement: `sha256`'s loops copied each chunk into a shared `[u8; 64]` before compressing, and `as_chunks::<64>()` yields `&[u8; 64]` directly, so the copy is gone; the pinned NIST vectors (`"abc"`, the two-block 896-bit vector, and the 55/56/64 padding boundary) all still pass, which is what makes the rewrite byte-for-byte rather than merely compiling.
  → **The durable half of the fix is the new `reference-app` CI job** (`ci.yml`), which gates the crate on fmt, clippy, test, a `wasm32-wasip2` build, and a check that the artifact really is a component exporting `qqq:http/incoming-handler`. It carries an **anti-vacuity guard** so a job that quietly stopped finding the crate cannot report success forever — the failure mode it exists to end.
  → **The guard was fault-injected, and verifying it caught two real bugs in it.** Injection 1 removed the `[workspace]` table; injection 2 moved `wit/app.wit` aside. Each was **proven present before the guard was consulted** (the §O-156 rule), the guard **rejected both** — injection 1 with cargo's own *"current package believes it's in a workspace when it's not"* — and each file was restored **byte-for-byte** with a sha comparison, then touched. **15/15** checks passed, and a final pass confirms the table is back, the hash equals the original, and no backup remains. The bugs the verification caught: (a) the first version piped through `python3`, which on this machine's WSL bash cannot see cargo, so it compared an **empty count** and **passed on a faulted tree** until an anti-vacuity clause was added; (b) the second version counted packages with `grep -o '"name":"[^"]*"'`, measured at **3, not 1**, because `--no-deps` emits a `name` for each target too — shipped as written it would have failed **every healthy run**. It now counts `"manifest_path"` (measured: exactly 1). Both are the same shape as the defect being fixed: a check aimed at a nearby property that is easy to assert instead of the property that matters. Recorded in §O-158.
  → **Gap named, not papered over**: the `db` row measures a **validated write and an in-guest map lookup, not a Postgres round trip**. §5.3's `[[capabilities.sql]]` has no host implementation, so order state lives in a guest `static` — and because §4.2 creates one store per request, that static starts empty each time (measured: three distinct `POST`s each returned `created_seq: 1`). A published `db` number must carry that caveat. It is stated in the module docs and in `qqq.toml` rather than hidden, because a benchmark that measures a *missing* host feature measures nothing.
  → Unblocks: ~25 unchecked `PERF-*` items (the §9.1 ten and the §9.2 budgets), `DOD-002` (the 72-hour soak), `LANG-005` (the Rust reference implementation) and `MKT-010` (third-party benchmark).
- [x] **SRV-019** Implement CORS configuration with safe defaults.
  → §5.3 The manifest — `qqq.toml`
  → Done: `crates/qqq-serve/src/cors.rs` — `Origin` (parsed and canonically serialized: scheme and host lowercased, port kept, path/query/fragment refused because an `Origin` is not a URL), `Cors` (built from the manifest's `[server.cors] allow_origins`), `Decision` (`Granted` / `Denied` with a `Reason`, because "denied" and "no policy" are different facts an access log must be able to tell apart), `Cors::simple` and `Cors::preflight`.
  → **"Safe defaults" is the item, so it is asserted first**: `Cors::none()` is the default and emits **no** `Access-Control-Allow-Origin` for any request. CORS is a *relaxation* of the same-origin policy, and a runtime that relaxes it by default has made every QQQ application cross-origin-readable without its author asking. An **empty** `allow_origins` is also `none`, not a wildcard — the vacuity failure this project refuses everywhere else.
  → **The three dangerous configurations are refused rather than accepted**: a bare `*` (which, combined with credentials, browsers reject outright — so accepting it would produce a policy that silently does nothing), a wildcard host `https://*.example.com` (a substring matcher with extra steps unless written against the URL standard's label rules), and the literal `null` (sent by sandboxed iframes and `file://` pages, so it is the origin an attacker can most easily obtain).
  → **Matching is exact on the canonical form**, and the tests pin the classic CORS bypass by name: `evil-example.com`, `example.com.evil.net`, `notexample.com`, `https://example.com.evil` are all refused for an allow-list of `https://example.com`. The scheme and the port are significant; the host is matched case-insensitively because the URL standard says so — normalized **in the type**, not at the comparison site, so `HTTPS://` cannot bypass a scheme check.
  → **`Vary: Origin` is emitted on a denial too** — a denial is origin-dependent, so a shared cache that stored one would serve a refusal to an origin that should have been granted. The one exception is a request with no `Origin` at all, which is not origin-dependent and is reported as `NotACorsRequest` rather than as a denial.
  → **A preflight is a policy, not an echo**: the requested method and headers are *checked* against the configuration, so the browser learns the refusal before sending the real request. An unconfigured method set advertises nothing rather than guessing, because a guess is how a `GET`-only route comes back advertising `DELETE`.
  → **Measured**: 29 unit tests; workspace **1953 passed, 0 failed**; `clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --check` clean; SPDX, checklist-citation and scope-table checkers green.
  → **Now reachable from the manifest**: `crates/qqq-cap/src/manifest.rs` models `[server]` and `[server.cors]` and validates them at parse time — a wildcard is refused before a server runs, so `qqqai inspect` can report it — and `crates/qqq-run/src/serve_routes.rs` converts the section into a `qqq-serve::route::RouteTable` plus the per-route auth modes. The conversion lives in `qqq-run` because §4.3's ordering forbids an edge between `qqq-cap` and `qqq-serve` in either direction; see `§O-131`.
  → **Wired**: `ServerConfig.cors` carries the policy into `serve_connection`, which applies it to **every** response. Nine integration tests through the real accept loop cover what the policy layer cannot: that a header reaches a client, that a **404 carries the grant** (so a browser reads the error instead of an opaque network failure), that a denial leaves the status and body unchanged and carries only `Vary: Origin`, and that a granted preflight is **204 without ever reaching a handler**.
  → **A preflight is answered before routing**, because it names a path the route table may have no `OPTIONS` handler for — the browser is asking about the path, not calling it. A 404 there would make the browser refuse a request the server would serve. The grant is `204`, the refusal `403`: a preflight has no application semantics, so a status is safe to use, unlike on a simple request where a denial must leave the response intact.
  → **Measured**: 29 policy tests + 9 wiring tests; workspace **1975 passed, 0 failed**.
- [x] **SRV-020** Implement request-body size and count limits enforced per tenant, with metrics.
  → **The last open clause is closed: the per-tenant connection ceiling is configurable.**
    It was a compiled constant — `ServerConfig::connections_per_tenant`, defaulting to
    10 000, reachable from no manifest key and no flag — so "count limits enforced per
    tenant" held only at the default. Now `[server.limits.per_tenant."<ip>"] max_connections`
    is a manifest key and travels the whole chain: `git grep max_connections -- crates/`
    shows the field in `qqq-cap`'s `TenantLimit` and its zero-value refusal, its carriage in
    `qqq-run`'s `build_limits`, `qqq-serve`'s `Limits`, `ConnectionLedger::with_limits`, and
    the served path's read at `server.rs:429` — where the ledger's ceilings come from the
    manifest table with `connections_per_tenant` as the fallback for an unnamed tenant.
    A zero is refused at parse time, because the ledger raises zero to one and a manifest
    claiming zero would state a policy the server does not apply. `ConnectionLedger` became
    per-tenant-keyed with that fallback, so naming one tenant does not change the ceiling
    for every other. Published in `schema/qqq-toml.schema.json`, shaped exactly like its
    three siblings (`anyOf` nullable integer).
  → **Measured, six tests**: `a_per_tenant_connection_ceiling_is_carried` and
    `a_zero_connection_ceiling_is_refused` in `qqq-cap`; `a_named_tenant_gets_its_own_ceiling_and_others_keep_the_fallback`
    and `a_zero_ceiling_in_the_table_is_raised_to_one` in `qqq-serve`'s ledger;
    `a_per_tenant_connection_ceiling_is_enforced` (fills the ceiling, then asserts the
    ledger's bare refusal) and `a_connection_under_the_ceiling_is_served` (the 200 control)
    over a real socket; and `a_manifest_connection_ceiling_is_applied` /
    `raising_the_ceiling_lets_a_second_connection_through` through the `qqqai` binary itself.
    Fault-injected twice, both **DETECTED**: making `admit` ignore the per-tenant table, and
    removing `stop_after_the_bound` from the ledger-refusal path.
  → **A separate, serious defect was found and fixed while proving this** — see §O-215: the
    ledger's refusal closed the socket with the client's request still unread, so the stack
    sent an RST instead of a FIN and the `503` was discarded. Every real client saw a reset
    rather than a refusal; the tests could not see it because their probes read without
    sending. Fixed by draining the pending request, bounded at 8192 bytes / 250 ms.
  → §10.2 Metrics that ship by default
  → Partial: header-count and header-size caps, and a declared-body cap, are enforced
    in `qqq-serve::http1`.
  → **Partial, and the reason is narrower than it was.** The metric set exists
    (`crates/qqq-serve/src/metrics.rs` implements §10.2's HTTP row) and it is now
    **recorded into from the served path** — this clause read *"and nothing records into
    it"* until 2026-09-23, which was true when written and stopped being true when the
    limits were wired. Measured: `server.rs`'s `record_metrics` calls `record_request`
    with the method, status, latency, tenant label and both body-byte counts on the
    completed-request path (`server.rs:1966`), and `record_body_limit` runs on both
    body-refusal paths (`server.rs:1554`, `:1794`), with `config.metrics` and
    `config.limits` shared per connection as `Arc`s (`server.rs:390-394`). Proved through
    `serve` on a real socket by `crates/qqq-serve/tests/metrics_wiring.rs` (9 tests:
    `a_request_is_recorded_through_serve`, `body_bytes_are_recorded`,
    `latency_is_recorded`). The remaining
    gap is the item's own scope, not the recording -- see the tail of this entry. What
    follows is §10.2's HTTP row as implemented: per-(method, status-class) request counters, **per-tenant** body bytes in and out, per-tenant body-limit refusals, connection count by outcome, and a fixed-bucket latency histogram. 25 tests.
  → **§10.2's cardinality discipline is enforced by the type system, not by a convention.** Every label is an enum — `Method`, `StatusClass`, `Outcome` — so the compiler is the lint `OBS-006` asks for. Measured, not argued: **1,000 invented methods produce exactly 1 series**, and 500 distinct status codes produce **5**. A registry with `&str` labels works in development and destroys the monitoring system in production, because every distinct value is a new time series.
  → **The tenant ceiling is bounded and the trade is stated**: past 64 distinct tenants, further ones collapse to `Tenant::Other`, so the series count stays finite however many tenants exist and the overflow is **visible in one series**. A name seen before the ceiling keeps its own label afterwards, or a deployment's history would change retroactively as it grew. Per-tenant facts survive in the audit log (§10.1), which is not aggregated.
  → **`Latency` compares with `<=`** because `le` means "less than or equal"; an exclusive comparison shifts a whole bucket and makes every quantile *plausibly* wrong. `mean_micros` returns `None` with no observations rather than `0`, because `0` reads as "instant" rather than "unmeasured".
  → **Two real defects the tests caught in this module**, both fault-injected: an exclusive bucket comparison (fails `1000 <= 1000`) and a removed tenant ceiling (fails `tenant 64 must collapse`).
  → **Measured**: 25 unit tests; workspace **2089 passed, 0 failed**.
  → **Declared and built**: a manifest's `[server.limits]` reaches the runtime. `qqq_cap::manifest::RequestLimits` (named that, not `Limits`, because `Limits` already means the **sandbox** bounds — memory, fuel, epoch — and the compiler refused the duplicate), validated inside `Manifest::parse` so a zero window is refused before a server can bind, and converted by `qqq_run::serve_routes::build_limits` — which lives there because `qqq-cap` may not depend on `qqq-serve` in either direction and `qqq-run` is the only crate that sees both.
  → **The default is "no limits", not a built-in number.** A cap invented here would be a guess this crate has no basis for and would silently apply to deployments that never asked for one, changing behaviour on upgrade. The *connection* ceiling is different and already defaults to 10 000: it bounds a resource this crate owns, while a body cap bounds a resource the application's design decides. `default` is an explicit field rather than an implicit property of the table, and `window_seconds` defaults to 60 when a cap is set, because a cap with no window has no meaning.
  → **`gen_schemas.py` refused to publish a schema rather than omit a field**: my `std::collections::BTreeMap<String, TenantLimit>` was the only fully qualified map path in the codebase, and the generator declined with "unrecognised Rust type" instead of writing a schema that silently dropped `per_tenant`. Fixed by matching the existing bare-`BTreeMap` convention; the generator's self-test is 7/7 again.
  → **Measured**: 18 limit tests + 6 conversion tests + 2 fault injections, both reproducing; the round-trip test now carries a populated `limits` because the point of a round-trip is that every field survives.
  → **Enforced, and `SRV-020` is done**: `serve_connection` consults the limiter **before the body is read and before a handler runs**, at both points — the body cap against the **declared** length first (a client understating it is caught by the streaming count; one stating it honestly pays nothing to find out), and the rate through `check_and_record`, which consumes the allowance as a side effect rather than exposing a `check` a caller could skip.
  → **Two statuses, because they are two facts**: `413 Content Too Large` and `429 Too Many Requests` have different remedies, and a client given one for both would retry a body it can never send or shrink a payload when it should have waited. `Served::Refused` joins the enum for the rate case, distinct from `BodyRejected` — *how many* the tenant sent versus *how much* one request carried.
  → **The `Arc` is load-bearing**: the rate windows are shared **mutable** state, so a per-connection copy would give every connection its own allowance and a tenant with a limit of 100 could make 100 per connection. `the_allowance_spans_connections` opens a **new socket per request**, which is what makes the distinction visible.
  → **Measured**: 20 limit tests + 6 conversion tests + **6 integration tests over the real accept loop**, plus 2 fault injections that both reproduce (disabling the rate check fails three tests, disabling the body check fails two). Workspace **2130 passed, 0 failed**.
  → **`None` means unlimited; zero means the smallest limit, and the two fields differ**: a zero **body** cap accepts an empty body and rejects any non-empty one, while a zero **request** cap rejects every request. They are deliberately different values from `None` because a limit of zero is almost never what an operator meant, and making them distinguishable turns that mistake into a visible violation rather than silent non-enforcement (`§O-128`).
  → **The window is a caller-supplied monotonic instant, not a timer** — a background task resetting counters would be a second authority on time, and the connection state machine is already the first. It also makes the limiter a pure function of `(tenant, now)`, testable without sleeping. `check_and_record` consumes the allowance as a side effect, because a separate `check` and `record` would let a caller check without recording — a limiter that never limits (`§O-130`).
  → **Measured**: 15 limit tests + 2 fault injections, both reproducing (an off-by-one using `>` for `>=` fails five tests; one shared window instead of per-tenant fails exactly the isolation tests and would present in production as one busy client throttling everybody). Workspace **2113 passed, 0 failed**, run **three times consecutively**.
  → **Still not wired** (at the time of writing; **superseded on 2026-09-22** by the
    update below, which is why this line is kept rather than deleted): `TenantLimits`
    is not constructed from a manifest, and `serve_connection` does not consult it. The
    limits are correct and **unapplied**, and `SRV-020` stays open until they are. The
    per-tenant *connection* ceiling was already enforced by `ConnectionLedger`.



  → **2026-09-22 — the limits are wired, and the per-tenant key was wrong.** Two fixes, both
    fault-injected.
  → **Wired.** `prepare()` now sets `config.limits` from the manifest's `[server.limits]`, so
    `serve_connection` consults it. The earlier entry's *"`TenantLimits` is not constructed
    from a manifest, and `serve_connection` does not consult it"* is no longer true; the
    limits are applied and the body cap is answered with `413` on a real socket
    (`crates/qqq-serve/tests/limits_wiring.rs`, 8 tests).
  → **The key was a name nothing produces.** `RequestLimits::per_tenant` was documented as
    *"keyed by tenant name"* while `tenant_of` returns `peer.ip().to_string()` and
    `limits_for` looks the tenant up by that string — so every entry was dead configuration:
    it parsed, it validated, `qqqai inspect` listed it, and it was never applied. The
    reality was already recorded in `§O-136` (*"**The tenant is the peer IP address.**"*),
    written when a *metric* test failed on the same mismatch, and it was not applied to the
    manifest field three files away.
  → `RequestLimits::validate` now refuses a key that is not a **canonical** IP address,
    naming the key, the reason, a working example and the `default` alternative;
    `Ipv6Addr::to_string` compresses, so a non-canonical spelling that parses and still
    cannot match is refused too. Tests: `a_per_tenant_key_that_is_a_name_is_refused`,
    `a_non_canonical_ipv6_key_is_refused_and_the_canonical_one_named`,
    `a_canonical_address_key_is_accepted` (the control) in `qqq-cap`; and on a real socket,
    `a_per_tenant_entry_keyed_by_the_peer_address_is_applied` with the control
    `a_per_tenant_entry_for_another_address_is_not_applied` in `qqq-serve`. Fault-injected
    by removing the key check: **detected** in both `qqq-cap` and `qqq-run`. See `§O-185`.
- [ ] **SRV-021** Model the `[server.tls]` manifest section and wire a TLS-terminating accept path into `qqqai serve`.
  → §6.4 `qqq-serve` — the HTTP and application server
  → **This row exists because its absence was found by reading a remediation string** (`§O-283`).
    `SRV-007` delivered the TLS **library** — `qqq-serve::tls`, rustls 0.23, the explicit cipher
    policy, TLS 1.3 preferred with 1.2 permitted, ALPN, and 21 end-to-end tests that drive a real
    handshake — and it is ticked on that basis, correctly. What has never existed is the
    **manifest section that would configure it** and the **accept path in `serve.rs` that would
    read that section**, so `qqqai serve --tls` is refused at parse time rather than honoured.
  → **Nothing owned the remainder, and that was the defect.** The refusal's remediation used to
    read *"until `SRV-007`'s configuration and accept path land"* — pointing an operator at a
    **ticked item** as outstanding work. A reader who followed it found a done row and no work
    item, so the gap looked accounted for rather than unowned. The remediation now names the two
    missing pieces, and this row is their owner.
  → Unblocks: `crates/qqq-run/src/serve.rs` refuses `--tls` with `error[QQQ-7001]`; the refusal is
    deleted — with nothing else moving — once both halves land, and `crates/qqq-serve/tests/tls.rs`
    already proves the library it would call.
- [x] **ABI-001** Author `qqq:http@1.0` with routing, streaming and client.
  → Done: `wit/qqq-http.wit` — 103 lines, 2 interface(s), 3 function(s).
    Validated by `tools/check_wit.py`, `tools/check_wit_errors.py` and
    `tools/check_wit_since.py`, and rendered into `docs/wit-reference.md`.
  → §6.7 `qqqai test` — test runner
- [x] **ABI-002** Author `qqq:fs@1.0` with opened directories, handles, metadata and write modes.
  → Done: `wit/qqq-fs.wit` — 120 lines, 1 interface(s), 7 function(s).
    Validated by `tools/check_wit.py`, `tools/check_wit_errors.py` and
    `tools/check_wit_since.py`, and rendered into `docs/wit-reference.md`.
  → §6.4 `qqq-cap` — the capability engine
- [x] **ABI-003** Author `qqq:sql@1.0` with pooled connections, prepared statements and transactions.
  → Done: `wit/qqq-sql.wit` — 149 lines, 2 interface(s), 12 function(s).
    Validated by `tools/check_wit.py`, `tools/check_wit_errors.py` and
    `tools/check_wit_since.py`, and rendered into `docs/wit-reference.md`.
  → §6.3 The standard library
- [x] **ABI-004** Author `qqq:kv@1.0` with namespacing, TTL and scan.
  → Done: `wit/qqq-kv.wit` — 72 lines, 1 interface(s), 7 function(s).
    Validated by `tools/check_wit.py`, `tools/check_wit_errors.py` and
    `tools/check_wit_since.py`, and rendered into `docs/wit-reference.md`.
  → §6.3 The standard library
- [x] **ABI-005** Author `qqq:queue@1.0` with publish, subscribe via `stream`, and acknowledgement.
  → Done: `wit/qqq-queue.wit` — 99 lines, 1 interface(s), 6 function(s).
    Validated by `tools/check_wit.py`, `tools/check_wit_errors.py` and
    `tools/check_wit_since.py`, and rendered into `docs/wit-reference.md`.
  → §6.3 The standard library
- [x] **ABI-006** Author `qqq:crypto@1.0` with random, hash, hmac, aead and sign/verify.
  → Done: `wit/qqq-crypto.wit` — 205 lines, 5 interface(s), 12 function(s).
    Validated by `tools/check_wit.py`, `tools/check_wit_errors.py` and
    `tools/check_wit_since.py`, and rendered into `docs/wit-reference.md`.
  → §7.4 Cryptographic posture
- [x] **ABI-007** Author `qqq:clock@1.0` with wall, monotonic, timers and controllable time.
  → Done: `wit/qqq-clock.wit` — 78 lines, 2 interface(s), 5 function(s).
    Validated by `tools/check_wit.py`, `tools/check_wit_errors.py` and
    `tools/check_wit_since.py`, and rendered into `docs/wit-reference.md`.
  → §10.5 Determinism
- [x] **ABI-008** Author `qqq:log@1.0` with structured, levelled logging with tenant attribution.
  → Done: `wit/qqq-log.wit` — 69 lines, 1 interface(s), 3 function(s).
    Validated by `tools/check_wit.py`, `tools/check_wit_errors.py` and
    `tools/check_wit_since.py`, and rendered into `docs/wit-reference.md`.
  → §10.3 Logging
- [x] **ABI-009** Author `qqq:trace@1.0` with spans, events and W3C context propagation.
  → Done: `wit/qqq-trace.wit` — 99 lines, 1 interface(s), 6 function(s).
    Validated by `tools/check_wit.py`, `tools/check_wit_errors.py` and
    `tools/check_wit_since.py`, and rendered into `docs/wit-reference.md`.
  → §10.4 Tracing
- [x] **ABI-010** Author `qqq:secrets@1.0` with use-without-disclosure.
  → Done: `wit/qqq-secrets.wit` — 124 lines, 1 interface(s), 3 function(s).
    Validated by `tools/check_wit.py`, `tools/check_wit_errors.py` and
    `tools/check_wit_since.py`, and rendered into `docs/wit-reference.md`.
  → §7.4 Cryptographic posture
- [x] **ABI-011** Author `qqq:test@1.0` with assertions and capability assertions.
  → Done: `wit/qqq-test.wit` — 145 lines, 1 interface(s), 6 function(s).
    Validated by `tools/check_wit.py`, `tools/check_wit_errors.py` and
    `tools/check_wit_since.py`, and rendered into `docs/wit-reference.md`.
  → **Authored in this round.** The other eleven existed; this one was missing.
  → §6.7
- [x] **ABI-012** Author `qqq:agent@1.0` for self-description and structured progress.
  → Done: `wit/qqq-agent.wit` — 178 lines, 1 interface(s), 3 function(s).
    Validated by `tools/check_wit.py`, `tools/check_wit_errors.py` and
    `tools/check_wit_since.py`, and rendered into `docs/wit-reference.md`.
  → **Authored in this round.** The description format version is separate from the
    package version on purpose: a caller written against format 1 must keep working
    when the guest is rebuilt, so a package bump cannot break its parser.
  → Progress events carry a monotonic `sequence` rather than relying on arrival order,
    because a display that goes backwards is the visible symptom of conflating a late
    event with a new one.
  → §8.3 The machine contract layer
  → §8.3 The machine contract layer
- [x] **ABI-013** Author `qqq:ai@1.0` with the inference interface (implementation deferred to `FUT-*`).
  → Done: `wit/qqq-ai.wit` — 100 lines, 1 interface(s), 3 function(s).
    Validated by `tools/check_wit.py`, `tools/check_wit_errors.py` and
    `tools/check_wit_since.py`, and rendered into `docs/wit-reference.md`.
  → §7.4 Cryptographic posture
- [ ] **ABI-014** Implement `qqqai bindings` generating every language's types from `wit/`.
  → §2.4 NN-4 — Multi-Language by Design
- [x] **ABI-015** Implement the CI drift check between `wit/` and all generated bindings.
  → Done: `tools/check_wit_bindings.py` — asserts that every `wit/*.wit` file is embedded
    in `crates/qqq-abi/src/wit.rs`, that every `include_str!` names a file that exists,
    that `ALL_WIT` registers the package each file declares, and that the registry is
    sorted so an *absent* entry is visible in a diff.
  → **The audit found the repository already drifted by two files.** `wit/` held 15 and
    the crate embedded 13: `qqq-test.wit` and `qqq-agent.wit` had been authored,
    validated and rendered into the reference documentation while remaining **invisible
    to the runtime** — no host could serve them and no binding could be generated from
    them. Nothing was broken, which is what made it dangerous: every existing check
    looked at `wit/` and found it fine, and nothing looked at the *relationship* between
    the directory and the crate.
  → Fixed by embedding both, and a stray insertion inside the `ALL_WIT` doc comment was
    caught by the workspace's own missing-documentation lint.
  → 7/7 self-test cases, covering drift in both directions plus an unsorted registry.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **ABI-016** Resolve open question `OQ-005`: ratify the shared-memory policy at the interface level.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth

---

## 7. P4 — DX v0 (M4)

### DX — Developer experience

- [x] **DX-001** Implement `qqqai new` scaffolding for all five languages and five templates.
  → §5.2 The command surface
- [x] **DX-002** Implement generated-manifest minimality: a new project grants nothing it does not need.
  → §2.7 NN-7 — Progressive Power, Safe Defaults
- [x] **DX-003** Implement the "your app has 0 capabilities" guidance shown at dev-server start.
  → §12.1 The first ten minutes (a spec, not a wish)
- [x] **DX-004** Implement the error-message standard: what, code, why, fix, machine block.
  → §12.2 Error message design standard
  → **The standard was already met; nothing checked that it was.** Measured on six real errors
    driven through the built binary, all five parts are present in every one — the sentence,
    the stable code, the docs URL, a cause, a remediation, and a machine block carrying
    `code`, `message`, `remediation`, `docs_url` (the field's name in the published schema;
    §12.2 names the concept). So this is §O-219's shape, an implemented-and-unticked item,
    and the gap was enforcement rather than behaviour.
  → The two existing checks cover the standard's **edges**, not its subject:
    `gen_error_catalogue.py --check` verifies every `ErrorCode` variant has a cause and a
    remediation line, and `check_schema_conformance.py` verifies `error.docs_url` exists in
    the envelope schema. Neither reads a message a user receives, so a complete catalogue
    entry could still be dropped by the renderer — §O-225's shape exactly.
  → Done: `tools/check_error_standard.py` drives five error cases through the **real binary**,
    each run in human **and** `--json` mode, and asserts all five parts in both. Two decisions
    worth recording: **vacuity is refused per case** (a case that stopped failing fails the
    check rather than passing it, which is what a command gaining a flag would otherwise do
    silently), and **a `remediation` equal to `message` is a violation**, because §12.2 part 4
    asks for a runnable command and a field that restates the message reads complete in a
    schema while telling a reader nothing.
  → Verified: self-test 9/9, firing on each missing part and staying silent on a complete
    error; the real corpus passes 5/5; and a **corpus injection** confirms the check works
    against the real renderer — renaming the docs URL host in `ErrorCode::docs_url` makes all
    five cases report `no docs URL in the human output`, restored byte-for-byte from SHA-256
    and green afterward. The injection failed **twice** before it worked, both times because
    it did not reproduce the defect, and the diagnostic that separated the two was reading
    the binary's own output under the fault. Recorded as §O-231.
  → Wired into `ci.yml`'s Rust job (where a binary exists) and `docker/entrypoint.sh`, which
    skips with a stated reason when no binary is built — a check that silently passes on a
    missing subject certifies nothing.
  → §12.2 Error message design standard
- [x] **DX-005** Implement the `QQQ-XXXX` error-code registry with generated docs pages.
  → Done: `tools/gen_error_catalogue.py` generates `docs/errors.md` from the
    `ErrorCode` enum, and `tools/check_error_catalogue.py` verifies it with an
    **8-case self-test**. Measured: **42 codes, every one with a cause and a
    remediation.**
  → **Every code has a stable docs URL**, which §8.3 names as part of the
    contract: `format!("https://qqq.codes/errors/{}", self.id())` in
    `crates/qqq-core/src/error.rs`. The URL shape is documented as one that *"must
    never change"*, so a code arriving in a log line resolves to a page.
  → **The catalogue cannot be missing a code, and that guarantee is itself
    checked.** The generator's only source is the enum, so a code added to the
    enum and not regenerated is caught by `--check` — and the checker's self-test
    drives the *parse* on synthetic enum sources, because a guarantee derived from
    a parser is only as strong as the parser. The checker's own documentation names
    the four cases that must be reported: a missing remediation, two variants
    sharing a code, a code outside every documented range, and a hand-edit to the
    generated file.
  → **Found by audit rather than assumed.** The item says "generated docs pages"
    and "a CI check"; both exist and pass. This is the twentieth item this session
    found already implemented by reading the item and measuring the code.
  → §8.3 The machine contract layer
- [ ] **DX-006** Implement the TIER-1 hot reload: component swap preserving the host process.
  → §6.6 `qqq-run` — CLI and dev server
- [ ] **DX-007** Implement TIER-2 state-preserving swap with declared guest state.
  → §6.6 `qqq-run` — CLI and dev server
- [ ] **DX-008** Implement TIER-3 full restart triggered only by manifest capability or limit changes.
  → §6.6 `qqq-run` — CLI and dev server
- [x] **DX-009** Implement the file watcher with debounce and ignore rules.
  → §6.6 `qqq-run` — CLI and dev server
- [ ] **DX-010** Implement HTTPS in dev with locally-trusted certificates.
  → §6.6 `qqq-run` — CLI and dev server
- [ ] **DX-011** Implement the TTFA measurement job on a clean container for all three OSes.
  → §12.3 The DX commitments (measurable, in CI)
- [ ] **DX-012** Implement the scripted DX test suite: deliberate mistakes must produce the intended guidance within the target time.
  → §12.3 The DX commitments (measurable, in CI)
- [x] **DX-013** Implement the `--help` brevity standard (≤40 lines, actionable) and a CI check.
  → Done: `HELP_MAX_LINES`, `HELP_GROUPS` and `render_help(verbose)` in
    `crates/qqq-run/src/main.rs` (**5 help tests**, of 22 in the file), plus a CI step in
    `.github/workflows/ci.yml`. Re-derived by listing the binary's own tests: the five are
    `no_arguments_shows_help`, `help_lists_every_command`, `help_fits_the_brevity_standard`,
    `the_full_help_is_a_superset_of_the_brief_one` and `help_mentions_the_json_contract`.
    This entry said 6 until 2026-09-23; the file's total is 22, so neither number was the
    file count, and 5 is the count of the surface the sentence names.
  → **Measured before: 53 lines. Measured after: 40** — which satisfies the item's own
    `≤ 40` and is one off the 39 this entry claimed until 2026-09-23. `qqqai --help`
    is the measurement; re-run it rather than trusting either number. §12.3's table is titled
    *"The DX commitments (measurable, in CI)"* and its row is
    `qqqai --help` for any command **≤ 40 lines, actionable** — so the commitment
    had a number on it and nothing counted. That is `§O-066`'s shape (a control
    believed live that is not) applied to a **documented promise** rather than a
    code path.
  → **The design is progressive disclosure, not truncation.** Cutting 13 lines
    would have fit the number and lost real information — the `--json` contract
    line is the single most useful thing a script author reads here. So:
    `qqqai --help` is **39 lines** with every command listed, and
    `qqqai --help --all` is 43 with the long option descriptions and the schemas
    hint. That fits the budget *and* makes the default better, because a reader
    scanning for a command is not wading through option prose they will read
    later, if ever.
  → **`HELP_MAX_LINES` is a constant so the standard is machine-checked.**
    `help_fits_the_brevity_standard` asserts a **ceiling and a floor** — a budget
    satisfied by printing nothing is the vacuity failure `§M-006` records — and
    `the_full_help_is_a_superset_of_the_brief_one` proves progressive disclosure
    **relocated** information rather than deleting it, by requiring every line the
    brief help prints to also appear in the full form.
  → **An ordering bug caught by its own test**: the first `--all` guard was
    `if action == Some(Action::Help)`, which made `--all --help` fail while
    `--help --all` worked — an order-dependence introduced by a guard written to
    prevent a *different* problem, contradicting this file's own documented
    principle that flag precedence is order-independent. `--all` is now an
    unconditional modifier, like `--verbose`.
  → **And one test was the thing that was wrong.** It asserted *"`--all` alone
    must not set the flag"*; the parser accepts it and treats it as inert, which
    is what `--verbose` alone does. The test was corrected with the reasoning
    recorded rather than the code bent to match it.
  → **The CI check would have passed vacuously, and that is the finding worth the
    most (`§O-116`).** The step captured the help into a shell variable and
    counted lines in it; measured, a **1890-byte** output containing a UTF-8
    em-dash yields **`len=0`** under some bash builds, and `LANG`/`LC_ALL=C.UTF-8`
    did **not** change it. `LINES` would be empty, `[ "" -gt 40 ]` is not true, and
    the budget assertion would **pass while measuring nothing** — the seventh
    occurrence of this class in the project. The step now counts lines in a
    **pipe** and greps a **pipe**, so there is no value that can be silently lost;
    verified by counting a wrapper's output (39) on the same machine where
    capturing the file into a variable returned length 0. Two further guards: the
    count must **be a number**, and the command loop **counts its own iterations**
    and fails unless all 16 ran — because a skipped loop would look exactly like
    every command being present.
  → §12.3 The DX commitments (measurable, in CI)
- [x] **DX-014** Implement the CI check that every error code has a docs page.
  → Done: the same pair as `DX-005` — `tools/check_error_catalogue.py` run in
    `.github/workflows/ci.yml` **and** `docker/entrypoint.sh`, beside its
    generator. §12.3's row is *"Every error code documented | 100% | CI check"*.
  → **The check is paired with its self-test in the same job**, so a green result
    means *"checked and clean"* rather than *"checked nothing"* — the distinction
    `§M-006` records seven times in this project, most recently inside the CI step
    written to enforce a *different* commitment (`§O-116`).
  → **What "100%" means here, measured**: 42 codes in the enum, 42 in
    `docs/errors.md`, 42 remediations, and a resolvable docs URL per code. A code
    with no page fails `--check` rather than being counted as documented.
  → **Found by audit rather than assumed done.** This item and `DX-013` sit in the
    same table, and `DX-013`'s number was **unmet** (53 lines against a budget of
    40) while `DX-014`'s was met. That is the argument for measuring each row
    rather than trusting a table as a block: one row in the same table was a real
    gap, and assuming the table was uniformly satisfied would have missed it.
  → §12.3 The DX commitments (measurable, in CI)
- [ ] **DX-015** Implement the CI check that every public API has a compiling example.
  → §12.3 The DX commitments (measurable, in CI)
  → **The check is built and wired; the standard is far from met, and the item stays open.**
    Measured on 2026-09-25: **2,116 public declarations across the 11 crates, and 9 doctests
    running** — 0.4% against §12.3's 100% target. Recording that plainly is the point:
    `§O-219`'s shape is an item that looks done, and this one would look done if the check
    existed and nobody read its number.
  → `tools/check_api_examples.py` measures the surface and enforces a **ratchet**. `ci.yml` runs
    it with `--allow 2107`, which is the visible distance to the target: a *regression* — an
    example lost — fails immediately, and the allowance is lowered as examples land. A check
    demanding 2,107 new examples in one commit would be red forever, and a permanently red gate is
    one people learn to skip.
  → The nine: `qqq-core` carries four (`PackageName` construction, a positioned rejection, why a
    trailing separator is its own error rather than a generic one, and `Version`'s one-directional
    compatibility relation plus a parse failure that names the offending component) with a fifth
    marked `ignore`; `qqq-bench` one; `qqq-cap` one — `GrantSet::narrow`, which shows both modes
    removing authority from an empty set and proves the manifest is the only layer that can grant;
    `qqq-host` two — `PreparedComponent::compile`, driving a real Wasmtime engine through both a
    successful compile and the `QQQ-1002` refusal of a core module, and `Instance::create`, which
    instantiates a component that imports the clock under empty grants and gets `QQQ-6003`, then
    shows the same bytes refused again after an overlay narrows the clock away. That second one
    states "absent, not denied" on the real path rather than in prose.
    Each new one is **fault-injected**: disabling the character guard, deleting the directional
    comparison, replacing `narrow`'s intersection with a union, replacing `compile`'s artifact
    rejection with an accept-anything fallback, and asserting the wrong error id in the `create`
    example each made the corresponding example fail, with byte-for-byte restore from SHA-256
    verified.
  → **A `no_run` fence counts and asserts nothing** (`§O-236`). The `qqq-host` example was first
    written with `no_run` on the reasoning that Wasmtime compilation is expensive, and the fault
    injection above left it **green** — rustdoc had compiled it and never run a line. The fence now
    executes (the test takes ~1.9s instead of ~0.15s, which is the evidence), and the checker
    reports `no_run` fences in their own column, so coverage cannot be misread as behaviour. Today
    the column reads 0.
  → A counting discrepancy was run down rather than assumed: the checker's "doctests cargo runs"
    figure read 7 while this entry said 4, and `cargo test --doc --workspace` settled it — 7 run
    (and an eighth block is marked `ignore`). The older figure was simply stale, and the entry now
    carries the measured one.
  → Two counting bugs were found by the checker's own self-test and fixed, both of which had
    made the measurement wrong: `pub const NAME` was missed because `const` sat in the modifier
    group rather than as a keyword, and a **closing** fence counted as an opening one, doubling
    every block. The first reported 1,937 items where the truth is 2,116.
  → **What remains, stated so the next reader does not have to rediscover it.** 2,109 of 2,116
    declarations have no example. `qqq-serve` alone has 676; `qqq-host` 461. The highest-value
    next targets are the public entry points a Rust embedder calls first — `qqq-host`'s
    `PreparedComponent` / `Instance` / `Linker` construction and `qqq-cap`'s `GrantSet` — rather
    than working down each crate in file order, because an example on an internal helper teaches
    nobody. `python tools/check_api_examples.py --list` names every file with items and no example.

- [x] **DX-016** Implement `qqqai doctor` with environment diagnosis and remediation.
  → §5.2 The command surface

  Implemented in `crates/qqq-run/src/main.rs`: `run_doctor` (three checks --
  `binary-name`, `manifest`, `wasm-target`), `wasm_target_present` (a real probe:
  an explicit override, then the target directory under `$RUSTUP_HOME`/`~/.rustup`,
  then `rustup target list --installed`), `FixPlan`/`fix_for`/`apply_fixes`
  (`--fix`), and `reject_unknown_flags`.
  Flags per Proposal line 723: `--json` (global) and `--fix`.

  **Four defects were found and fixed here, three by running the shipped binary
  and one by the check written to verify the others -- see O-207 and O-208 of
  `QQQ-Observations-and-Memories.md`.** (1) `wasm-target` was `ok: true`
  hardcoded, so it printed a pass while measuring nothing. (2) The probe's doc
  comment described `QQQ_TEST_WASM_TARGET_PRESENT` as a product setting; nothing
  outside its own tests sets it. (3) `--fix` was documented, absent, and silently
  ignored -- and so was every mistyped flag on every command, which produced
  `CliFlagUnknown = QQQ-7004` and the rejection wired into this arm. (4) The
  success envelope reported `"ok":true` beside exit `69`, which produced
  `Envelope::exit_code` and revealed that **38 of 48** failure envelopes named a
  status their process did not return.

  Tests: `doctor_finds_no_problems_in_a_sane_environment`,
  `doctor_checks_are_wellformed`, `fix_is_a_global_flag`,
  `wasm_target_check_follows_the_probe`, `fix_plan_is_inert_without_the_flag`,
  `fix_accounts_for_every_failing_check`, `target_install_is_planned_but_not_run`,
  `doctor_refuses_flags_it_does_not_accept`, `doctor_json_carries_the_fix_outcome`.

  Evidence, each a real command: `qqqai doctor` in a project -> `all 3 checks
  passed`, exit `0`, and outside one -> `1 of 3 checks need attention`, exit `69`;
  `qqqai doctor --json` -> `"exit_code":69` matching `$?`; `qqqai doctor --jsonn` ->
  `error[QQQ-7004]`, exit `2`; `qqqai doctor --fix` and `qqqai --fix doctor` ->
  identical, both exit `69`, a network-touching repair is printed and listed as
  left to the user. Fault-injected: restoring `ok: true` fails
  `wasm_target_check_follows_the_probe`; restoring `exit_code: 0` fails the live
  probe in `tools/check_schema_conformance.py` (and passes all 29 unit tests,
  which is why the assertion lives there).

  `--fix` performs no repair automatically when the repair would download a
  toolchain component; it is planned, printed with its exact command, and left to
  the user. That is a deliberate limit rather than an unfinished path, and it is
  recorded as such.
- [ ] **DX-017** Implement the DevTools-protocol inspector adapter over DWARF source maps.
  → §6.6 `qqq-run` — CLI and dev server
- [ ] **DX-018** Implement the progressive-disclosure documentation tiers (Solo, Team, Fleet).
  → §2.7 NN-7 — Progressive Power, Safe Defaults
- [ ] **DX-019** Implement `qqqai add-cap` writing the correct manifest stanza.
  → §5.3 The manifest — `qqq.toml`
- [ ] **DX-020** Implement the ten-minute script as an automated, CI-run acceptance test.
  → §12.1 The first ten minutes (a spec, not a wish)

### CLI — Command surface

- [x] **CLI-001** Implement the shared output layer with `--json` supported by every command.
  → Done: `qqq-run::output` — `CommandOutput` with `--json` on every command.
  → §5.2 The command surface
- [x] **CLI-002** Implement compile-time exhaustiveness so a new command cannot ship without a JSON shape.
  → Done: `CommandName::all()` drives both the dispatch and the schema list; a new command cannot omit a JSON shape.
  → §2.1 NN-1 — AI Agents Are First-Class Users
- [x] **CLI-003** Implement `qqqai new`.
  → §5.2 The command surface
- [x] **CLI-004** Implement `qqqai init`.
  → §5.2 The command surface
- [x] **CLI-005** Implement `qqqai add` and `qqqai remove`.
  → Done: `qqq-run::deps::add`/`remove`, dispatched from `main.rs`. Edits `qqq.toml` as **text**, preserving every comment and byte outside the changed line; writes atomically via temp-file + rename so a crash cannot truncate the manifest; re-parses the result before publishing it. `--dev`, `--exact`, `--feature`, `--registry`, `name@version`, and `--json` all work. Requirement is validated with the real `qqq_pkg::Requirement` parser before writing.
  → Fixed on the way: `[dependencies]` was not modelled at all and was silently dropped (`§O-033`), and the requirement parser rejected `"1.2"` — the form Proposal §5.3 itself writes (`§O-034a`).
  → §5.2 command surface; §5.3 `qqq.toml`
  → §5.2 The command surface
- [x] **CLI-006** Implement `qqqai install` with `--locked`, `--frozen`, `--offline`.
  → Done: `qqq-run::install`, dispatched from `main.rs`. `LockMode` is an **enum ordered by strictness** rather than three booleans, so `frozen` without `locked` is unrepresentable; combining flags takes the strictest. Reads and verifies `qqq.lock`, resolves the manifest against its pins (a pin the manifest no longer accepts is dropped rather than carried), reports the §5.4 **capability diff** with `escalation` as a first-class field, and writes the lockfile atomically via the shared atomic write.
  → Honest about the registry gap: with no registry (`PKG-006`) anything not already pinned fails with `QQQ-5001` naming the package, rather than writing a lockfile that promises bytes nobody fetched. `--locked` on a missing or stale lockfile fails with `QQQ-5003` and the exact next command.
  → §5.2 command surface; §5.4 the lockfile and the capability diff
  → §6.5 `qqq-pkg` — package manager and registry
- [x] **CLI-007** Implement `qqqai update` with `--latest` and `--dry-run`.
  → Done: `qqq-run::update`, dispatched from `main.rs`. The default strategy honours the manifest's requirement; `--latest` crosses it, and crossing requires a word because defaulting to it would resolve `^1.2.3` to `2.0.0` while the user believes they asked for a routine refresh. `--latest` combined with `exact = true` is **refused rather than resolved by precedence** — the two state opposite intents.
  → `VersionSource` is the seam the registry plugs into (`NoRegistry` today, `FixedVersions` for tests), so the decision logic is fully exercised now rather than first tested when `PKG-006` lands. `decide` is a pure function; the best version is chosen by **semver, not list position**, because a registry is not required to sort. A keep always carries a reason, so `--dry-run` answers "why is this not updating?".
  → §5.2 The command surface
- [x] **CLI-008** Implement `qqqai build` with `--release`, `--target`, `--aot`, `--reproducible`.
  → §5.2 The command surface
- [x] **CLI-009** Implement `qqqai run` with explicit capability and limit flags.
  → §5.2 The command surface
- [x] **CLI-010** Implement `qqqai dev`.
  → §6.6 `qqq-run` — CLI and dev server
- [x] **CLI-011** Implement `qqqai serve` with `--workers`, `--tls`, `--config`.
  → §6.4 `qqq-serve` — the HTTP and application server

  → **State on 2026-09-22, after the serve wiring was repaired.** The manifest is now
    attached to the server rather than computed and dropped: `prepare()` sets
    `config.auth`, `config.limits`, `config.cors`, `config.metrics` and
    `config.accept_limit`, and `--config` is read (it was parsed and then ignored, because
    the handler read the *global* `--manifest` flag that `serve::options` rejects). The
    guest chain is loaded and served: `build_dispatch` compiles the artifact through
    `GuestApp` and registers `dispatch()` / `dispatch_with_body()` per declared route name.
    Verified end to end on 2026-09-22 against the reference application: `qqqai build`
    produced `target/qqq/orders-api.component.wasm` (167,828 bytes), `qqqai serve` answered
    `GET /healthz` three times with an identical body `ok`, `POST /orders` with a
    form-encoded body answered `201` with the guest's own JSON
    (`{"id":"A1","total_cents":1000,"created_seq":1}`), a malformed body was refused by the
    **guest** with its own `400` message, and an undeclared path was a `404`. Transcript
    captured outside the repository.
  → **2026-09-24: `--workers` now sizes something.** It was parsed, capped at 128 and
    **reported with no effect** — `--workers 4` was accepted and the process ran one — with a
    refusal standing in its place, which said what would end it: *"when a pool lands, the
    check is deleted and the number acquires its meaning"*. The pool is
    `qqq_host::pool::Pool`; `GuestApp::with_capacity` builds it, `handle_request` acquires
    **before** instantiating and releases on every exit path, and `build_dispatch` returns
    the capacity so `ServeOutput::workers` carries what the pool **installed** rather than
    what the operator typed. Verified by fault injection: making `with_capacity` ignore its
    argument and always build `Pool::new(1)` fails the integration test with *"the report
    must carry the capacity the pool installed"*, so the report genuinely reads from the
    pool. `--workers 4` against the reference application answers `200 OK` and reports
    `4 concurrent instance(s)`.
  → **What the capacity bounds, measured rather than assumed.** Concurrent *guest instances*,
    not connections: a connection holding a partial body does not hold a slot, because
    `serve_connection` reads the body before dispatching, so the pool is acquired only for
    the guest call. The report says `concurrent instance(s)` for that reason.
  → **It is not `[limits] max_instances`**, and the old refusal conflated them. That limit is
    the per-store ceiling on how many Wasmtime instances one *instantiation* may create
    (`§O-154`); this pool bounds how many *requests* hold a guest across the process.
  → **`--tls` still refuses**, and that is the honest state rather than the finished one: there
    is no `[server.tls]` section and no TLS-terminating accept path, so accepting the flag
    would serve cleartext while reporting `TLS: on`. The refusal names that and points at
    `SRV-007`. `--config` is read and `--listen`, `--accept-limit` work.
  → Verified: `cargo test -p qqq-run` 627 passed / 0 failed; the `worker_pool` integration
    test drives the **real binary** against the **real 167,380-byte reference component**,
    placed where `find_artifact` looks (`target/wasm32-wasip2/release/orders_api.wasm`), and
    ran green six consecutive times; `clippy -D warnings` and `fmt --check` clean. The
    first version of that test was flaky — it asserted a digit appeared in a line that
    carries an ephemeral port — and the fix parses the capacity field instead.
    Recorded as `§O-230`.
- [x] **CLI-012** Implement `qqqai test`.
  → Done: `qqq-run::test_runner` (the module is named `test_runner` because `test` is a Rust keyword, so the file uses `#[path]` like `scaffold`), dispatched from `main.rs`. Discovery asks cargo for its test targets and runs **each binary directly**, which makes a test's source file exact rather than inferred. `--filter`, `--fail-fast`, `--trials N`, `--dry-run` and `--json` work; a failing test **exits 1** so CI can gate on it. 51 CLI integration tests.
  → `--trials N` is the first architecture-enabled feature from §6.7 and the one that needs no unbuilt dependency: it runs each test N times and flags output that differs. A determinism failure counts as a failure for the exit code, because a test passing 4 of 5 trials is not a passing test.
  → §6.7 `qqqai test` — test runner
- [x] **CLI-013** Implement `qqqai bench`.
  → Done: `crates/qqq-run/src/bench.rs` + `bench_output.rs`, dispatched from
    `main.rs`. Every `§9.2` row is selectable, `--json` emits the document, and
    `--fail-on-miss` is opt-in because `§9.2` calls these "numeric targets
    engineering is held to" rather than a pass/fail gate — turning a measurement
    tool into a gate by default would be the wrong default.
  → The document is the unit of output: a result cannot be rendered without its
    methodology, because `PERF-001` made the methodology a required field.
  → Two bugs found and fixed by its own tests: `parse_response` returned
    `(status, len)` and a caller misread it as a head length, reporting 38 bytes
    for a 2-byte body (now a named `ResponseHead` struct); and `read_to_end`
    waited for a close that `qqq-serve` never sends (now frames on
    `Content-Length`). A failing target also used to cost 200 warmup requests ×
    10 s, now bounded by a separate `connect_timeout` and `EARLY_EXIT_AFTER`.
  → **Verified**: gate clean at `d3915f3`; CI run
    [35803815743](https://github.com/RatioArtificiosa/QQQ/actions/runs/35803815743)
    green — 11 success, 0 failures.
  → §9.1 The honest benchmark position
- [x] **CLI-014** Implement `qqqai fmt` and `qqqai lint` with a unified interface over language toolchains.
  → §5.2 The command surface
  → Done as a unified interface, which is the item's own wording: one module
    (`qqq_run::style`) holds the language resolution, the driver's arguments and the
    declared-but-unbuilt diagnosis, because splitting the two verbs would have duplicated
    exactly the parts that must not drift.
  → The language comes from the manifest's `[build] language` rather than a flag, so `lint`
    cannot check a different toolchain than `build` compiles. `fmt` runs `cargo fmt --all`;
    `lint` runs `cargo clippy --all-targets -- -D warnings`, which is the gate this repository
    runs on itself — without `-D warnings` clippy prints and exits zero, making the command
    decorative in a CI job. The tool runs in the manifest's directory, so
    `--manifest path/to/qqq.toml` lints that project rather than the caller's cwd.
  → Verified against the real reference application, not a fixture: `qqqai fmt` in
    `examples/orders-api` reports "already formatted, no changes needed" and exits 0, and
    `qqqai lint` runs clippy and reports "no problems found".
  → Of the five languages in the manifest grammar, Rust has a driver; `ts`, `go`, `python` and
    `cpp` are refused with `QQQ-1003` naming the language and the `LANG-*` item that owns each.
    The refusal is the point: a `lint` answering "0 problems" for a language it never checked is
    a green light over nothing, and is indistinguishable in a log from a real clean run.
  → Verified: nine unit tests over the pure planner (which driver, which arguments, which
    directory, and both refusal kinds) and five CLI tests driving the built binary through argv
    (`fmt_refuses_a_language_with_no_driver_and_names_the_owner` and four others in
    `crates/qqq-run/tests/cli.rs`). Three faults injected, all caught and restored byte-for-byte
    from SHA-256. The first injection run reported all three MISSED and the cause was the
    harness, not the tests — recorded as `§O-223`, whose fix (assert a non-zero executed-test
    count) is now in place. `cargo clippy -D warnings` clean; 733 tests green across `qqq-pkg`
    and `qqq-run`.
  → §5.2 The command surface
- [x] **CLI-015** Implement `qqqai inspect` with static capability reporting and `--diff`.
  → Done: `qqqai inspect` with no argument reports the manifest's grants; `qqqai inspect <artifact>` compiles the component without instantiating it and reports the capabilities its **import table** requires, with the digest and `component`/`core-module` kind so a report is tied to the bytes that produced it. Unmapped interfaces are listed rather than dropped, and a file that is not a component is an error rather than a fallback to the manifest.
  → `--diff <other>` reports the **authority** delta between two artifacts, which is §5.4's central supply-chain question: which capabilities did this build add? A gain **exits non-zero** so the flag is usable as a CI gate without parsing output; a loss reports but succeeds, because failing on a reduction would train people to bypass the check. A gain of a *covert channel* (`clock.wall`, `crypto.random`) escalates even though it cannot move the posture band — the §10.5 distinction.
  → **The per-tenant request limits are reported** (2026-09-24). `LimitsReport` carried
    the three sandbox limits (memory, fuel, epoch deadline) and nothing from
    `[server.limits]`, so the per-tenant body cap, request rate and connection ceiling were
    enforced by the server while appearing nowhere in the command whose purpose is to answer
    "what will this project do?". Enforced-and-invisible is the shape §O-130 records
    repeatedly. The report is built from the manifest's own `RequestLimits`, so it cannot
    disagree with what the server applies; an entry declaring no limit is dropped rather than
    shown as a limited tenant, and a manifest with no table reports no section rather than an
    empty one. Three tests, one fault injection (dropping the ceiling from the report)
    **DETECTED**, and verified on the shipped binary in both renderings. See §O-216.
  → §5.2 The command surface
- [x] **CLI-016** Implement `qqqai audit` with SARIF output and `--fail-on`.
  → §5.2 The command surface
  → Done. Found implemented-and-unticked, the `§O-219` shape, and ticked only after driving both
    named features against a real project (`examples/orders-api`'s manifest, its two findings).
  → `--sarif` emits SARIF 2.1.0, not a shape that resembles it: `$schema`, `version`, and a
    `runs[].tool.driver` carrying `name`, `informationUri` and all five `rules` with
    `shortDescription` and `helpUri`, with each `results[]` entry naming its `ruleId`, `level`
    and `fixes[].description.text`. Verified by parsing the output as JSON.
  → `--fail-on` separates the thresholds rather than always failing: on the same project,
    `--fail-on warning` exits `1` (a warning-level finding exists) and `--fail-on error` exits
    `0` (none does). That pair is the test - a threshold that always fired would pass a single
    check and is what the flag exists to avoid.
  → The human rendering and the `--sarif` document are separate, so `qqqai --json audit | jq`
    is not buried behind prose (that ordering bug is recorded in `dispatch_audit`'s own comment
    and was found by CodeRabbit reviewing this command).
  → §5.2 The command surface
- [x] **CLI-017** Implement `qqqai verify` for signature and attestation checking.
  → §5.2 The command surface
  → Done, with one half of §5.2's "signature + attestation" stated as absent rather than implied.
    The signature half is real: `qqq_pkg::signature` verifies a detached Ed25519 signature over
    the artifact's bytes, with the signing key's 8-byte id inside the 72-byte `.sig` so a refusal
    can name which key signed; `qqq_run::verify::verify` turns that into a report;
    `dispatch_verify` in `main.rs` gives it `--key <hex>` (repeatable) and `--policy require`.
    The exit status is the gate: valid `0`, unsigned-under-opportunistic `0` saying `unsigned`,
    unsigned-under-`require` non-zero, invalid non-zero — so a CI step needs no prose parsing.
  → The attestation half reports `attestation: not_checked` and names `SUP-004`: §7.4 fixes
    artifact signing, while provenance attestation has no format in this repository to verify
    against, and a green check over nothing would be worse than an absent one.
  → Verified: six CLI tests drive the built binary through argv
    (`verify_accepts_a_real_signature_and_names_the_key` and five others in
    `crates/qqq-run/tests/cli.rs`), plus unit tests over key parsing and policy construction in
    `verify.rs`. Fixtures are signed through `qqq_pkg::signature` rather than embedding a stored
    `.sig`, so no test can pass against a drifted copy of the format. Three faults were injected
    and each was caught by exactly the test that should catch it, then restored byte-for-byte
    with SHA-256 checked: a tampered comparison message, an inverted `require_signature`, and a
    removed dispatch arm. `cargo clippy -D warnings` clean; 719 tests green across `qqq-pkg` and
    `qqq-run`.
- [x] **CLI-018** Implement `qqqai caps` with `--explain`.
  → §5.2 The command surface
  → Done: `caps(loaded, explain)` in `qqq-run::commands`, dispatched by `dispatch_caps` in
    `main.rs`. `--explain` adds the resolution reasoning under each capability — the layer
    that decided and the rule that fired, from the same `Resolution::trace` that `why` reads,
    filtered to `changed()` nodes so only the steps that moved that capability appear:
    `qqqai caps --explain` prints
    `      manifest     grants: declared in qqq.toml` under `clock.wall`, and the JSON gains
    `"explained":[{"capability":...,"decisions":[{"granted":true,"layer":"manifest",
    "rule":"declared in qqq.toml"}]}]`.

  → **The flag was accepted and silently ignored.** Measured on the shipped binary before the
    fix: `qqqai caps --explain` produced **byte-identical output** to `qqqai caps`. The string
    `explain` appeared nowhere in the argument handling, so the flag was parsed as unknown and
    dropped — and `--explan` behaved the same way, which is worse: a typo that succeeds is
    undetectable. This mattered because two separate texts send the reader to the flag:
    Proposal §5.2 documents it, and `crates/qqq-run/src/audit.rs:378` tells them to *"run
    `qqqai caps --explain` to see which layer granted it"*. Unknown flags are now a QQQ-7001
    usage error naming the flag and listing what `caps` accepts, which is what `build` and
    `run` already do.

  → Why one function and not two: the two renderings share the resolution, the grouping and
    the digest, and differ only in whether each capability carries its reasoning. A second
    function would duplicate the resolution and the copies would eventually disagree about
    what is granted — the one thing this command must not get wrong. The reasoning is built
    only when asked, and the JSON field is `skip_serializing_if` so a consumer can tell "not
    asked for" from "no decisions".

  → Also fixed here: `Resolution::warnings` had **no consumer** in this file. A developer
    overlay — the one warning a reader most needs — was computed and discarded. It now renders
    through `CapsOutput::warning_suffix`, used by both `summary` returns, because the deny-all
    path is exactly where an overlay is most likely to have landed.

  → Verified by a live probe against the freshly built binary over a real project: plain
    `caps` and `caps --explain` differ; `--explain --json` carries `"explained"` and
    `"layer":"manifest"`; plain `--json` does not carry the field; `--explan` exits 2 with
    `unknown flag`. Three tests in `crates/qqq-run/tests/cli.rs`
    (`caps_explain_adds_the_reasoning`, `caps_json_grows_explained_only_when_asked`,
    `caps_refuses_an_unknown_flag`), each **fault-injected**: forcing `explain = false` in
    `caps`, forcing the JSON field unconditional, and removing the unknown-flag arm each made
    exactly the corresponding test fail; every file restored byte-for-byte (sha256 compared)
    and no `INJECTED FAULT` marker remains.

  → Caught while measuring: the new remediation string carried a run of **twenty-two spaces**,
    because a line-continuation backslash was missing. It is invisible in the human renderer
    and visible in the JSON one. Reading the source lines with `repr()` showed the literal, so
    the cause was the literal rather than a renderer — the same construct in `run`'s
    remediation renders correctly. The test asserts no run of spaces survives, because only one
    of the two renderers makes the mistake obvious. Recorded as §O-218b.
- [x] **CLI-019** Implement `qqqai why`.
  → §6.2 `qqq-cap` - the capability engine
  → Done. Found implemented-and-unticked (`§O-219`'s shape again) and verified against a real
    project before ticking.
  → A granted capability names the deciding layer (`crypto.hash GRANTED by manifest`) and exits
    `0`; a denied one says why nothing granted it (`sql.query DENIED (default: not granted by
    any layer)`) and exits `1`, so the exit status carries the answer for a script.
  → The denial prints a copy-pasteable manifest stanza rather than prose about writing one,
    which is §6.2's point: the command's job is to tell the author the exact lines that would
    change the decision. Verified in `qql-run::commands::fix_stanza_for` and in the output above.
  → Six CLI tests in `crates/qqq-run/tests/cli.rs` drive it through argv, including
    `why_suggests_a_correction_for_a_typo`, `why_names_the_deciding_layer_for_a_grant` and
    `why_exit_status_separates_a_grant_from_a_denial`.
  → §6.2 `qqq-cap` — the capability engine
- [ ] **CLI-020** Implement `qqqai trace`.
  → §10.4 Distributed tracing
- [x] **CLI-021** Implement `qqqai doctor`.
  → §5.2 The command surface
  → **Delivered by `DX-016`**, which describes the same command and carries the
    evidence, the four defects found in it and the fault injections. This item is
    the §5.2 command-surface entry for `doctor`; the two were written as one
    deliverable in two areas of the checklist, and the evidence is recorded once
    rather than restated in a second place that would drift. Same pattern as
    `CON-004` pointing at `CON-016`.
- [ ] **CLI-022** Implement `qqqai mcp`.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [x] **CLI-023** Implement `qqqai schema --all` and the per-command schema output.
  → §8.3 The machine contract layer
  → Done: `dispatch_schema` in `main.rs` plus `SchemaDocument` in `qqq-run`, emitting §8.3's
    document with all eight fields — `qqqai`, `schemaVersion`, `commands`, `errors`,
    `manifest`, `capabilities`, `wit`, `mcp`. `--all` is accepted and is the bare command's
    behaviour; `--command <name>` narrows `commands` to one entry and adds a top-level
    `command` field so a caller does not have to search a one-element array to confirm what
    it got. Verified against the built binary: `schema --all --json` has exactly those eight
    top-level keys, 27 commands, 40 error codes, 13 WIT interfaces, 12 MCP tool names.

  → **Both flags were accepted and silently ignored.** Measured before the work:
    `qqqai schema --all` and `qqqai schema --command caps` produced the **same one-line
    summary** (`27 commands, 40 error codes, 24 capabilities`) and dropped the flag, so the
    document §8.3 specifies could not be obtained at all. Four of the eight fields existed
    and were emitted in **snake_case** (`schema_version`), which a consumer generated from
    the Proposal's own example would not have found. §2.1 NN-1's promise — *"an agent can be
    given `qqqai schema --all` and write correct code against this platform from a cold
    start"* — referred to a document the command did not emit.

  → `wit` and `mcp` carry `"complete": false` and a `note` naming where the definitions live
    (`wit/` for the interfaces; `qqqai mcp --list` for the tool schemas, `CLI-022` being
    open). A section that silently omitted them would be a lie of omission; one claiming a
    shape it does not have would be worse. The `wit` list is read from `qqq_abi::interfaces()`
    rather than hand-written, because a second copy of a fact the repository already states is
    how the two drift apart.

  → An unknown command name is **refused**, not answered with an empty `commands` map: empty
    reads as "this command has no schema", when the truth is "that command does not exist",
    and the two need different fixes. The refusal is QQQ-7001 listing every valid name, and it
    exits 2 with the envelope agreeing.

  → Three tests in `crates/qqq-run/tests/cli.rs` (`schema_all_emits_the_section_8_3_document`,
    `schema_command_narrows_and_names_the_command`, `schema_refuses_an_unknown_command_name`),
    each **fault-injected**. Two injections initially reported MISSED and both were
    investigated before anything was concluded, per invariant TWO:
    * the first was a **harness bug** — the null was appended *after* the real
      `"manifest": manifest_schema()`, and `serde_json::json!` keeps the last duplicate, so
      the fault never reached the binary;
    * the second was a **genuinely blind test** — `stdout.contains("\"command\":\"caps\"")`
      could not see the top-level field go missing, because the nested `commands` entry
      serializes to the same substring.
    Both assertions now parse the envelope and check the structure, and both injections are
    DETECTED. Recorded as §O-220, with the general rule: **if the subject is a JSON document,
    the assertion parses it.**

  → One assertion was also **wrong rather than the code**: the first version required that
    `schema_version` appear nowhere in stdout, and it failed because the *envelope's* own
    top-level `schema_version` is a different key on a different object from the document's
    §8.3 `schemaVersion`. Scoped to `data`, where the contract lives.
- [ ] **CLI-024** Implement `qqqai migrate`.
  → §6.8 `qqqai migrate` — the adoption ramp

### DIST — Distribution

- [ ] **DIST-001** Implement the POSIX `install.sh` installer with checksum and signature verification.
  → §11.1 Install channels, in priority order
- [ ] **DIST-002** Implement the Windows `install.ps1` installer with the same verification.
  → §11.1 Install channels, in priority order
- [ ] **DIST-003** Publish GitHub Releases with binaries, checksums and Ed25519 signatures for all five targets.
  → §11.1 Install channels, in priority order
- [ ] **DIST-004** Publish the `qqqai` crate to crates.io and verify `cargo install qqqai` on all targets.
  → §11.1 Install channels, in priority order
- [ ] **DIST-005** Publish the `qqqai` npm wrapper package and verify `npm install -g qqqai`.
  → §11.1 Install channels, in priority order
- [ ] **DIST-006** Submit the Homebrew formula.
  → §11.1 Install channels, in priority order
- [ ] **DIST-007** Submit Scoop and winget manifests.
  → §11.1 Install channels, in priority order
- [ ] **DIST-008** Publish the OCI image to `ghcr.io/qqqai/qqqai`.
  → §11.1 Install channels, in priority order
- [ ] **DIST-009** Implement `qqqai doctor`'s self-verification of its own binary.
  → §11.1 Install channels, in priority order
- [ ] **DIST-010** Meet the download-size SLO (≤25 MB compressed).
  → §5.1 What a user actually installs
- [ ] **DIST-011** Meet the `--version` startup SLO (≤15 ms).
  → §5.1 What a user actually installs
- [ ] **DIST-012** Meet the cold-start SLO (≤40 ms cached).
  → §5.1 What a user actually installs
- [ ] **DIST-013** Publish apt/dnf/apk repositories once the release cadence is stable.
  → §11.1 Install channels, in priority order
- [ ] **DIST-014** Publish AUR, Nix, asdf and mise specifications.
  → §11.1 Install channels, in priority order
- [ ] **DIST-015** Implement binary reproducibility verification across independent build hosts.
  → §11.1 Install channels, in priority order
- [ ] **DIST-016** Implement macOS notarization and Windows code signing.
  → §11.1 Install channels, in priority order
- [ ] **DIST-017** Implement offline installation from a local bundle.
  → §11.1 Install channels, in priority order
- [ ] **DIST-018** Publish the install-verification instructions users can follow without trusting us.
  → §11.1 Install channels, in priority order
- [ ] **DIST-019** Implement version-manager support (asdf/mise plugins) with tests.
  → §11.1 Install channels, in priority order
- [ ] **DIST-020** Resolve open question `OQ-004`: Windows first-class or best-effort, and reflect this in the CI budget.
  → §11.1 Install channels, in priority order

---

## 8. P5 — Languages (M5, M8)

### LANG — Toolchains

Each language has eight required items. The parity matrix makes any gap visible.

**Rust (Tier A)**

- [ ] **LANG-001** Rust toolchain integration: `wasm32-wasip2` build path, verified end to end.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-002** Rust bindings generated from `wit/` via `wit-bindgen`.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-003** Rust project template with tests and CI.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-004** Rust conformance-suite pass.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **LANG-005** Rust reference application implementation.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **LANG-006** Rust documentation, recipes and examples.
  → §11.3 Documentation as a product surface
- [ ] **LANG-007** Rust build-time and binary-size budget met.
  → §5.1 What a user actually installs
- [ ] **LANG-008** Rust language-guide page published with honest limitations (there are few).
  → §6.10 Language toolchains — one per target language

**TypeScript / AssemblyScript (Tier A / C)**

- [ ] **LANG-009** AssemblyScript toolchain integration and build path.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-010** AssemblyScript bindings generated from `wit/`.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-011** TypeScript-shaped project template using AssemblyScript.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-012** AssemblyScript conformance-suite pass.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **LANG-013** AssemblyScript reference application implementation.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **LANG-014** Documentation that states clearly what AssemblyScript is not (full TypeScript).
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-015** Evaluate and document the full-TypeScript-via-engine-in-Wasm path, with measurements.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-016** Resolve open question `OQ-002`: how we name and market this path.
  → §6.10 Language toolchains — one per target language

**Go (Tier B)**

- [ ] **LANG-017** TinyGo toolchain integration and build path.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-018** Go bindings generated from `wit/`.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-019** Go project template.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-020** Go conformance-suite pass.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **LANG-021** Go reference application implementation.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **LANG-022** Document TinyGo's runtime differences, reduced stdlib, and in-guest GC.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-023** Contribute upstream fixes to TinyGo where the component path is weak.
  → §15 — Risk Register
- [ ] **LANG-024** Track standard-Go component support and re-evaluate quarterly.
  → §6.10 Language toolchains — one per target language

**Python (Tier B)**

- [ ] **LANG-025** Spike: CPython compiled to WASI, measured for size, cold start and correctness.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-026** Python bindings generated from `wit/` via `componentize-py` or equivalent.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-027** Python project template.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-028** Python conformance-suite pass.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **LANG-029** Python reference application implementation.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **LANG-030** Implement precompiled-`.pyc` bundling and interpreter-instance pooling to cut startup cost.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-031** Resolve open question `OQ-003`: first-class or experimental, based on the M5 measurement.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-032** Document Python's honest limits (component size, startup, stdlib coverage).
  → §6.10 Language toolchains — one per target language

**C / C++ (Tier A)**

- [ ] **LANG-033** Clang `--target=wasm32-wasip2` integration and build path.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-034** C and C++ bindings generated from `wit/`.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-035** C and C++ project templates.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-036** C and C++ conformance-suite pass.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **LANG-037** C and C++ reference application implementation.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **LANG-038** Document the C/C++ path and the `wasm-ld`/`wit-bindgen` toolchain requirements.
  → §6.10 Language toolchains — one per target language
- [ ] **LANG-039** Publish the language parity matrix, generated from CI, with every gap owned and dated.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **LANG-040** Implement the CI job that fails when the parity matrix gains an unexplained gap.
  → §2.4 NN-4 — Multi-Language by Design

---

## 9. P6 — Packages (M6)

### PKG — Package manager and registry

- [ ] **PKG-001** Implement the content-addressed global store with hard-link/reflink materialization.
  → Partial: `qqq-pkg::store::{Digest, StoreLayout}` is done — sha256-only digest parsing that refuses other algorithms, a two-level fan-out layout, verified reads, and a case-insensitive sidecar skip. **Materialization is not done**: there is no hard-link or reflink of a stored artifact into a project, which is the second half of this item and the half that makes the store worth having.
  → §6.5 `qqq-pkg` — package manager and registry
- [ ] **PKG-002** Implement parallel, resumable fetching with HTTP/3 where available.
  → §6.5 `qqq-pkg` — package manager and registry
- [ ] **PKG-003** Implement the version solver with lockfile-first resolution.
  → §6.5 `qqq-pkg` — package manager and registry
- [x] **PKG-004** Implement lockfile read/write with `caps` per package and a covering hash.
  → Done: `qqq-pkg::lock::{Lockfile, LockPackage}`. `caps` is a first-class field participating in equality and in the covering hash, so a version bump that adds authority changes the lockfile even if the artifact digest somehow does not. The hash is computed over the package list with NUL separators (no field may contain a NUL, so distinct field sets cannot collide) and is **verified on read**, which makes a hand-edited lockfile detectable rather than silently trusted. `caps` is sorted and deduplicated on read, so two lockfiles describing the same authority compare equal regardless of how they were written. An unstamped lockfile parses, so `install` can bootstrap. 21 tests.
  → §5.4 The lockfile — `qqq.lock`
- [ ] **PKG-005** Resolve open question `OQ-006`: build the registry from day one, or bootstrap on OCI and migrate.
  → §6.5 `qqq-pkg` — package manager and registry
- [ ] **PKG-006** Implement `registry.qqq.codes` as a QQQ application (dogfooding).
  → §6.5 `qqq-pkg` — package manager and registry
- [ ] **PKG-007** Implement immutable versions with yank support.
  → §11.2 The registry and ecosystem
- [ ] **PKG-008** Implement provenance attestation (SLSA-style) for every published artifact.
  → §11.2 The registry and ecosystem
- [ ] **PKG-009** Implement capability metadata on package pages and in the registry API.
  → §11.2 The registry and ecosystem
- [ ] **PKG-010** Implement capability-aware search ("find a JSON parser needing no capabilities").
  → §11.2 The registry and ecosystem
- [ ] **PKG-011** Implement the registry API with a published schema and fair rate limits.
  → §11.2 The registry and ecosystem
- [ ] **PKG-012** Implement self-hostable registry mirrors; Fabric adds air-gapped mode.
  → §11.2 The registry and ecosystem
- [ ] **PKG-013** Implement the scoped-namespace and ownership-verification system.
  → §6.5 `qqq-pkg` — package manager and registry
- [ ] **PKG-014** Implement `--offline` fully from the local store.
  → §6.5 `qqq-pkg` — package manager and registry
- [ ] **PKG-015** Implement the trust policy for signature verification, configurable per project and per org.
  → §6.5 `qqq-pkg` — package manager and registry
- [ ] **PKG-016** Ship the 30 essential first-party packages (JSON, HTTP client, validation, logging, testing, crypto, date/time, collections).
  → §11.2 The registry and ecosystem
- [ ] **PKG-017** Port the curated top-200 high-value libraries with correct attribution and licence checks.
  → §11.2 The registry and ecosystem
- [ ] **PKG-018** Publish the "port a library in an afternoon" guide.
  → §11.2 The registry and ecosystem
- [ ] **PKG-019** Launch the public porting bounty programme.
  → §11.2 The registry and ecosystem
- [ ] **PKG-020** Implement dependency-confusion and typosquatting defences.
  → §7.2 Adversary model
- [ ] **PKG-021** Implement `qqqai audit` for a project's full dependency tree with SARIF output.
  → §5.2 The command surface
- [ ] **PKG-022** Implement the registry's abuse-reporting and takedown process.
  → §6.5 `qqq-pkg` — package manager and registry
- [ ] **PKG-023** Implement registry analytics that respect privacy (aggregate only, no per-user tracking).
  → §11.2 The registry and ecosystem
- [ ] **PKG-024** Implement the registry's own SLA monitoring and status page.
  → §6.5 `qqq-pkg` — package manager and registry

### SUP — Supply chain

- [ ] **SUP-001** Implement artifact signing with Ed25519 at publish time.
  → §7.4 Cryptographic posture
- [ ] **SUP-002** Implement signature verification at install time with a configurable trust policy.
  → §5.4 The lockfile — `qqq.lock`
- [ ] **SUP-003** Implement the SBOM generator per artifact.
  → §7.3 The defence timeline — where we stop an attack
- [ ] **SUP-004** Implement provenance attestation capture in the build pipeline.
  → §11.2 The registry and ecosystem
- [ ] **SUP-005** Implement hash pinning in the lockfile with verification on every install.
  → §5.4 The lockfile — `qqq.lock`
- [ ] **SUP-006** Implement the air-gapped mirror workflow for Fabric.
  → §11.2 The registry and ecosystem
- [ ] **SUP-007** Implement the dependency-vulnerability feed and `qqqai audit` integration.
  → §5.2 The command surface
- [ ] **SUP-008** Establish the incident process for a compromised first-party package.
  → §7.2 Adversary model
- [ ] **SUP-009** Implement build-environment attestation (what ran the build).
  → §11.2 The registry and ecosystem
- [ ] **SUP-010** Implement the reproducible-build check across independent build hosts.
  → §11.1 Install channels, in priority order
- [ ] **SUP-011** Publish the trust-chain document explaining every verification a user can perform.
  → §11.1 Install channels, in priority order
- [ ] **SUP-012** Implement key-rotation and revocation for the project's signing keys.
  → §7.4 Cryptographic posture

---

## 10. P7 — Agent face (M9)

### AGENT — Machine contracts

- [ ] **AGENT-025** Prove all four agent relationships (author, operator, host, adversary) are genuinely served: run a structured exercise for each and publish the findings, including any relationship that turns out to be unserved.
  → §8.1 The four agent relationships
- [ ] **AGENT-001** Implement `qqqai schema --all` producing the complete machine contract document.
  → §8.3 The machine contract layer
- [ ] **AGENT-002** Implement the versioning policy for the schema document.
  → §8.3 The machine contract layer
- [ ] **AGENT-003** Implement the CI drift check that fails when schema output diverges from the implementation.
  → §8.3 The machine contract layer
- [ ] **AGENT-004** Implement `qqqai mcp` as a stdio MCP server.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-005** Implement `qqqai mcp` as an HTTP MCP server.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-006** Implement `qqq_new` tool with dry-run.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-007** Implement `qqq_build` tool returning structured diagnostics.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-008** Implement `qqq_run` tool with explicit capabilities.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-009** Implement `qqq_test` tool returning structured results.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-010** Implement `qqq_inspect` tool returning a static capability report.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-011** Implement `qqq_audit` tool returning SARIF.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-012** Implement `qqq_caps_explain` tool.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-013** Implement `qqq_dev_status` tool.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-014** Implement `qqq_schema` tool.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-015** Implement `qqq_logs`, `qqq_metrics` and `qqq_trace` tools.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-016** Implement `qqq_doctor` tool.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-017** Implement `qqq_migrate_plan` tool (read-only analysis).
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-018** Write MCP tool descriptions for models, then review them with a human.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-019** Ensure every tool returns structured content, never prose-only.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-020** Ensure every mutating tool supports `dry_run` and says so in its description.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **AGENT-021** Implement the error-code class table and publish it.
  → §8.3 The machine contract layer
- [ ] **AGENT-022** Implement the docs URL pattern for every error code.
  → §8.3 The machine contract layer
- [ ] **AGENT-023** Build the agent benchmark suite and track success rate.
  → §2.1 NN-1 — AI Agents Are First-Class Users
- [ ] **AGENT-024** Publish the agent cookbook: a minimal reproducer for every error code.
  → §8.5 Making the codebase legible to machines

### TEST — Test runner

- [ ] **TEST-001** Implement test discovery for all five languages.
  → §6.7 `qqqai test` — test runner
- [ ] **TEST-002** Implement filtering, parallel execution and watch mode.
  → §6.7 `qqqai test` — test runner
- [ ] **TEST-003** Implement JUnit, TAP and JSON output.
  → §6.7 `qqqai test` — test runner
- [ ] **TEST-004** Implement coverage via Wasm instrumentation plus DWARF source mapping.
  → §6.7 `qqqai test` — test runner
- [ ] **TEST-005** Implement `--trials N` determinism checking.
  → §6.7 `qqqai test` — test runner
- [ ] **TEST-006** Implement deterministic replay logs and `--replay`.
  → §10.5 Determinism — the feature nobody else has
- [ ] **TEST-007** Implement capability assertions (`assert_caps!`).
  → §6.7 `qqqai test` — test runner
- [ ] **TEST-008** Implement fuel assertions (`assert_fuel_below!`).
  → §6.7 `qqqai test` — test runner
- [ ] **TEST-009** Implement property tests with shrinking and replayable failures.
  → §6.7 `qqqai test` — test runner
- [ ] **TEST-010** Implement the cross-language conformance suite and wire it into CI.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **TEST-011** Implement snapshot testing with a reviewable diff format.
  → §6.7 `qqqai test` — test runner
- [ ] **TEST-012** Implement test isolation guarantees: no test can observe another test's state.
  → §6.7 `qqqai test` — test runner
- [ ] **TEST-013** Implement benchmark-as-test: fail a build when a performance budget regresses.
  → §9.2 The performance budget
- [ ] **TEST-014** Implement the flaky-test detector.
  → §6.7 `qqqai test` — test runner
- [ ] **TEST-015** Implement the dead-code and unused-capability detector ("this app declares a capability it never uses").
  → §7.1 What we are defending, precisely
- [ ] **TEST-016** Implement the conformance-suite runner as an independently usable tool.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **TEST-017** Publish the test-runner documentation with per-language examples.
  → §11.3 Documentation as a product surface
- [ ] **TEST-018** Implement CI integration examples for GitHub Actions, GitLab CI and others.
  → §11.3 Documentation as a product surface

### MIG — Migration

- [ ] **MIG-001** Implement Node/Express route-table extraction.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **MIG-002** Implement middleware-ordering analysis.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **MIG-003** Implement env-var access inventory.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **MIG-004** Implement package inventory with alternative suggestions.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **MIG-005** Implement capability inference from source analysis.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **MIG-006** Implement the Bun-specific API flagging.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **MIG-007** Implement the Deno permission-to-capability mapping.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **MIG-008** Implement core-Wasm-to-component wrapping with a generated manifest.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **MIG-009** Implement `migration-report.md` generation.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **MIG-010** Implement `migration-report.json` with per-file confidence scores.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **MIG-011** Ensure the report is consumable by an agent so it can finish the migration autonomously.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **MIG-012** Publish worked migration case studies from real projects.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **MIG-013** Implement `qqq_migrate_plan` MCP tool (shared with `AGENT-017`).
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **MIG-014** Publish the migration guide with honest "this cannot be migrated" sections.
  → §6.8 `qqqai migrate` — the adoption ramp

---

## 11. P8 — Performance, determinism, observability

### PERF — Performance engineering

- [ ] **PERF-027** Establish and enforce the tail-latency and cold-start budgets as *contractual* objectives: publish them, alert on regression, and treat a breach as a release blocker rather than a metric.
  → §2.3 NN-3 — Performance and Predictability Over Micro-Benchmarks
  → **Measured and not met.** The three parts are separately checkable and none is
    done: the budgets are **published as data** (`Budget::ALL`, and §9.2) but not as
    *contractual objectives* — nothing in the repository commits to a breach blocking
    a release; there is **no alerting** on regression (no monitor, no threshold
    watcher, no CI step); and no release path checks them.
  → **The one piece that exists is the mechanism a gate would use**:
    `qqqai bench --fail-on-miss` exits **non-zero** when a budget is missed, which is
    the enforcement primitive. It is a flag on a measurement command, not a release
    blocker — nothing invokes it as one.
  → **Why it cannot honestly be tightened yet, and the reason is the same as
    `PERF-020`'s.** A contractual objective requires a measurement stable enough that
    a breach means something. `§O-248` measures the tail p99 at **52.66 ms** against
    a 2 ms contractual target on loopback — 26× over. Making that a release blocker
    today would block every release for a reason that is environmental, which is how
    a gate gets disabled and stays disabled. The prerequisite is the reference
    profile, then the contract.
- [x] **PERF-001** Build the benchmark harness with the full published methodology.
  → §9.1 The honest benchmark position
  → Done: **`crates/qqq-bench`** — a new workspace crate, second in the topology order because it has **no workspace dependency at all**. It defines what a *measurement* is and nothing that runs, so it can measure any crate above it; a harness that depended on the server could not be used to time the server's own startup. (Its first manifest declared a `qqq-core` dependency that was never used; `cargo-machete` rejected the unused edge in CI and it was removed — an unused declaration is a false statement about the dependency graph.)
  → Done: **the methodology is a type, not a paragraph.** §9.1's nine required elements are fields on `Methodology`, and three words in §9.1 decide the design: *"published with every result"* (so they are fields of the **result**, not of a document — the fifth report can omit its warmup and a page still exists), *"percentiles, not averages"* (so `Distribution` has `p50`/`p90`/`p99`/`p999`/`max` and **no `mean`** — a prohibition is honoured by the forbidden thing not existing), and *"we should not publish it"* (so the type is **unconstructible** without them; a warning or a `validate()` would be advice where §9.1 states a refusal).
  → Done: **§9.2's budget table is data.** `Budget::ALL` holds the rows, each with an `Item` (a checklist id that cannot be invented — §O-126), a target, a `Direction`, a `Unit`, and the `method` under `bench/` that §9.2 says each row has. The direction is a property of the **row**, not of the call site, because half of §9.2 is ceilings (`≤ 100 µs`) and half is floors (`≥ 60k RPS`) and a comparison written the wrong way round makes a failing benchmark report success while looking identical in review. `Budget::meets` **refuses a unit mismatch** rather than comparing microseconds against milliseconds — a factor-of-1000 error that produces a plausible verdict.
  → Done: **the `db` caveat is structural, not a sentence.** `NonClaims` is a **required** field, and `NonClaims::qualified` refuses an empty list. §9.1's ninth requirement *is* "what this does not measure", so it is the honest home for the `db` caveat recorded in `§O-155` and `SRV-018`: a `db` result that omits "this did not touch a database" **does not compile**. A caveat that survives as a compile error cannot be lost by a reader who never opened an observation. That is the answer to the question this round was asked to settle, and it is better than both alternatives — dropping the row (it is one of §9.1's ten) or building `qqq:sql` to rescue it (a `CAP-*`/`HOST-*` item with its own credential handling and pooling, whose gates would have been skipped to serve one benchmark row).
  → **Measured — the crate.** `cargo test -p qqq-bench`: **55 unit tests + 1 doctest, all passing**. `cargo clippy -p qqq-bench --all-targets --all-features -- -D warnings`: **clean** (it found 10 pedantic violations on first run — lossy casts, a derivable `Default`, identical match arms, strict float comparisons — and every one was **fixed rather than suppressed**; only one `#[allow]` exists, on a documented `u64`→`f64` conversion with its reason stated once at the point of conversion). `cargo fmt --check`: clean.
  → **Measured — the workspace.** **2460 passed, 0 failed** when re-summed from the
    gate's `cargo test --workspace` on 2026-09-23 (this entry said 2305, and `SRV-018`
    independently said 2249: two entries disagreeing about one number is how a stale
    count survives). The workspace total is the sum of the `test result:` lines. Guest crate run separately as always: **57 passed**. `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean. Topology OK with **11 crates**. SPDX OK across 199 files. Every `tools/*.py` checker green except the two that cannot run locally by design (`audit_requirements.py` needs a clean tree; `check_sbom.py sbom` needs a CI artifact).
  → Done: **`tools/check_bench_contract.py`** — a new checker wired into CI **and** into `docker/entrypoint.sh`'s counterpart list, comparing §9.2, `Budget::ALL` and the checklist against each other. It refuses to pass when it finds nothing to compare (the `§M-006` vacuity failure), and it ships with a `--self-test` that injects the four defects it exists to catch.
  → **The checker found a real omission in the crate it guards, and three bugs in itself.** Real omission: `§9.2`'s *"Routed request overhead (empty handler) | ≤ 60 µs p99 | Host-side, excluding guest work"* had **no `Budget` row and no exclusion** — it was in neither list, which is precisely what the "every §9.2 row has a decision" rule detects. It is now `Item::Perf002`, the one §9.2 row that is *purely* the host's since the measurement excludes all guest work. Its `--self-test` found three bugs in the checker itself on first run (`§O-161`): **(a)** it read "which rows exist" from `Item::metric()`, which is a name lookup rather than evidence a row exists; **(b)** it compared targets against the Proposal but never against the Rust table — the numbers that actually execute — so a drifted target reported PASS; **(c)** its first `parse_target` read `≥ 60k RPS` as **60.0**, ignoring the `k`, which would have compared a real system against sixty requests per second instead of sixty thousand and reported a 1000× pass. All three fixed, and the rule now lives in one function the checker and its self-test both call.
  → **A fourth defect was found by a pre-existing checker, not by me.** `check_checklist_citations.py` rejected the new source because a doc comment quoted a non-existent identifier in the form `AREA-NNN`. It was a quotation of a historical defect, not a live citation — but a bare token is indistinguishable from one, which is exactly what that checker exists to catch (`§O-126`). Rewritten to describe the identifier rather than reproduce it.
  → **Gap named, not papered over**: this harness **runs no workload and meets no budget**. `PERF-002` implements the ten §9.1 benchmarks; `PERF-003`–`PERF-013` are the numeric targets. A budget item is met by a harness that **produces** the number plus a recorded comparison against the target — never by asserting the target is achievable. Writing those numbers before something produced them would be the first fabricated measurement in a document whose entire value is that its numbers came from commands.
  → Also unblocks: `PERF-005` (real ABI costs replacing §9.3's estimates), `PERF-020` (regression detection in CI, which needs the contract), `PERF-022` ("what this does not measure", now a required field rather than a section someone must remember to write).
- [x] **PERF-002** Implement the ten benchmarks listed in §9.1.
  → Done: the ten §9.1 workloads are `qqq-bench::Workload::ALL` (exactly 10, a
    `static` table rather than a hand-maintained list), with `Methodology`,
    `Distribution` (nearest-rank percentiles; **no `mean`**, so an average cannot
    be published even by mistake), `Budget::ALL` (the §9.2 rows as data) and
    `loadgen` (async, `Connection: close`, frames on `Content-Length`).
  → Reachable via `qqqai bench` (`CLI-013`), which is what stops the harness being
    a library nothing calls.
  → `tools/check_bench_contract.py` compares §9.2, `Budget::ALL` and this
    checklist against each other; `--self-test` fault-injects 5 cases, including
    the `≥ 60k RPS` parse that was silently reading as **60.0**.
  → **Verified**: gate clean at `d3915f3` (2409 workspace + 57 guest tests, fmt
    and clippy at `-D warnings`), and GitHub Actions run
    [35803815743](https://github.com/RatioArtificiosa/QQQ/actions/runs/35803815743)
    green on that commit — 11 jobs success, 0 failures.
  → **Not claimed**: no workload has been *run against real hardware here*, so
    `PERF-003`–`PERF-013` remain unticked. This item is the harness, not a number.
  → **Measured 2026-09-24 — the harness was run on the real path.** `qqqai serve
    --listen 127.0.0.1:3000 --config qqq.toml` in `examples/orders-api`, then
    `qqqai bench --listen 127.0.0.1:3000 --json`. `GET /healthz` returned HTTP 200
    `ok`; `qqqai openapi` confirms the app declares 10 paths / 10 operations; the
    run produced **10 workloads** and the summary `10 benchmark(s) run, 0/4 §9.2
    budget(s) met`. Two runs agreed on every verdict. Full table in `§O-248`.
  → §9.1 The honest benchmark position
- [ ] **PERF-003** Meet the warm-instance-acquire budget (≤100 µs p99).
  → §9.2 The performance budget
  → **Measured and not met — the measurement does not exist.** `Budget::ALL` declares
    this row against `bench/warm_acquire.rs::warm_instance_acquire`, and that file
    **does not exist**: `crates/qqq-bench/src/` holds `budget.rs`, `lib.rs`,
    `loadgen.rs`, `methodology.rs`, `stats.rs` and `workload.rs`, with no `bench/`
    directory and no such function anywhere in the repository (`§O-249`).
  → The row's citation now reads `NOT_IMPLEMENTED::warm_instance_acquire`, which
    `tools/check_bench_contract.py` accepts as an honest declaration and which fails
    the gate if a fabricated path replaces it.
  → **The socket harness cannot produce this number**: it is an in-process timer
    around pool acquisition, and `qqqai bench` reaches the system through a listening
    socket by design (`crates/qqq-run/src/bench.rs`). `§O-248` records what that run
    did reach — 10 workloads, 4 budget verdicts.
  → **§9.2 also records a measured baseline and it is favourable**, from an
    independent probe: instantiating a compiled component into a fresh `Store` per
    sample, **with no pooling allocator at all**, measured min 700 ns / p50 800 ns /
    p99 2.1 µs over 500 samples against a 100 µs budget. That is a different
    measurement from this item's (unpooled, probe crate, not the harness) and is
    cited as context rather than claimed as this row's verdict.
  → Note `ARCH-011` step 6: no instance is actually reused in V1, so the "warm"
    acquire path this budget names does not exist yet — `Acquired::pooled` means the
    idle count was non-zero, not that a guest instance was reused.
- [ ] **PERF-004** Meet the cold-instantiate budgets (≤5 ms cached, ≤150 ms from `.wasm`).
  → §9.2 The performance budget
  → **Measured and not met — the harness produces no verdict for this row.**
    `Budget::ALL` cites `bench/cold.rs::cold_instantiate_cached`, a file that does
    not exist (`§O-249`); the citation now reads
    `NOT_IMPLEMENTED::cold_instantiate_cached`.
  → **The engine-level fact is recorded in §9.2** and is the one that matters for the
    design: `Component::deserialize` on a precompiled artifact **304.8 µs for a
    1.2 MB component**, after up-front `/d` builds on 6.8 ms — two orders inside the
    5 ms budget, which is why the caching design is viable. `Module::new` from
    `.wasm` is 3.8 ms, inside the 150 ms path.
  → Those are single-machine engine figures from a probe, not the harness's verdict
    on the reference application, so this item stays open. Reading them as this
    item's measurement would be the substitution of a nearby number for the named
    one.
- [x] **PERF-005** Measure and publish the real ABI-crossing costs, replacing the estimates in §9.3.
  → §9.3 The ABI cost, quantified honestly
  → Done: **the estimate is replaced by a measurement of a real component boundary.** All six §9.3 rows plus one control row were measured across compiled, instantiated, *called* Wasmtime 48.0.2 components — not a synthetic stand-in. The harness is `crates/qqq-bench/tests/abi_cost.rs`; the published numbers and environment are `docs/abi-cost-measured.md`; §9.3's table now shows estimate and measurement side by side.
  → **Measured (p50 / p99, nanoseconds, 20 000 samples, nearest-rank percentiles, 1 000-iteration warmup, concurrency `Sequential`)** — run 1, with a second run published in the document: `u64` argument + return **900 / 1 800**; string copy in 64 B **900 / 1 900**; `list<u32>` 1 000 elements **1 600 / 2 000**; `list<u32>` 1 element **800 / 1 700**; resource handle create + drop **1 200 / 2 500**; async `future` rendezvous **2 100 / 3 800**; `stream<u8>` 64 KiB chunk **24 800 / 51 400**. Environment: Intel Xeon E5-1650 v4, Windows 10 Pro 19045, rustc 1.98.1, `--release`. No `mean` is reported anywhere — `Distribution` has none.
  → **One of six estimates survived.** `list<u32>` of 1 000 elements (~1–3 µs) was **confirmed** at 1.60 µs p50. The other five were **above** their ranges: `u64` ~180×, resource create ~30×, string ~13×, async ~5×, `stream` ~3–6×.
  → **The finding, not just the numbers.** The `u64` row is the smallest possible crossing and costs ~900 ns p50. The **fixed** cost of entering and leaving a component is therefore of order **900 ns**, which §9.3 did not price at all — the estimate called a scalar crossing "effectively free", and it is three orders of magnitude from free. §9.3's conclusion is **strengthened rather than overturned**: at ~900 ns a crossing, §4.5's batch-first rule is the difference between a request costing one crossing and one costing a hundred, and against §9.2's ≤60 µs p99 routed-request budget a hundred crossings would consume most of it.
  → **A claim made and then withdrawn, because a second run contradicted it.** The first version of the document inferred a marginal cost of **~0.8 ns per `u32`** from run 1's p50s (1-element list 800 ns, 1 000-element list 1 600 ns — *"the copy itself, exactly as §9.3 describes it"*). A **second run** measured the same two rows at **1 400 ns and 900 ns**: the opposite order, and physically implausible, since a 1 000-element list must copy 4 000 bytes a 1-element list does not. At this scale fixed crossing cost and marginal copy cost are both ~800 ns, so one 20 000-sample run cannot separate them. **The per-element figure is not established and is not published as one.** Both runs are printed in the document (§2), and the withdrawal is recorded in §3 rather than the sentence being quietly edited. What the second run *did* establish: **p99 reproduces across runs to within ~3 %; p50 does not**.
  → **Two §9.3 rows were un-measurable today and that is stated, not hidden.** (a) **The async row is not reachable:** `qqq-host`'s engine config enables neither `wasm_component_model_async` nor `-stackful`, and no `qqq:*` WIT interface uses `future`/`stream` — so the 2.1 µs figure describes what async *will* cost when §9.4's row lands, not what QQQ costs today. (b) The harness drives Wasmtime **directly with the minimal component-model configuration**, so these are canonical-ABI numbers and not deployed-engine numbers; `qqq-host` adds the pooling allocator, guard pages and epoch interruption, none of which is in the timed path here.
  → **Not claimed — and this is the largest gap.** §9.1 requires "three repetitions **with variance**". **Two runs** of 20 000 samples were taken (both published) and **no `Repetitions` spread is published** — `Repetitions::new` requires three and refuses fewer, correctly, which is why none appears. Two is still not three. Also unmeasured: any host-capability crossing (`qqq:crypto`/`http`/`kv`/`sql`), other string/list sizes, per-byte stream rates, non-Windows platforms, and the §9.2 budget rows owned by PERF-003/004/008–013.
  → **Verified:** `cargo test -p qqq-bench --test abi_cost --release -- --ignored --nocapture --test-threads=1` → **2 passed** with all seven `ABICOST` rows emitted; default (non-ignored) run → **3 passed, 2 ignored**; the ignores carry a stated reason (benchmarks in a test harness). To keep those from being *unverified* ignores, three tests run in CI and guard the harness itself: `every_probe_component_compiles_and_instantiates` (a Wasmtime upgrade cannot silently invalidate the WAT), `the_summary_reports_the_percentiles_it_names` (pins the percentile accessors against a known distribution), and `the_async_probe_is_gated_on_the_stackful_feature` (fails if Wasmtime removes the gate, so the published caveat cannot go stale).
  → **A manifest change, and why it is legal.** `wasmtime` was added to `crates/qqq-bench`'s **`[dev-dependencies]`** — two files, the manifest and `Cargo.lock`. It creates **no §4.3 edge**: both `tools/check_topology.py` and `crates/qqq-core/tests/architecture.rs`'s `declared_qqq_deps` filter on the `qqq-` prefix, so an external crate is invisible to the ordering rule. A `qqq-host` edge would have been rejected — `qqq-bench` is position 1 and `qqq-host` position 5. The published library's dependency graph is unchanged (still `serde` + Tokio), which preserves the property the manifest records: `qqq-bench` can measure anything without dragging in this project's internals. Verified: `python tools/check_topology.py` → `TOPOLOGY OK`; `cargo test -p qqq-core --test architecture` → pass.
  → **Three findings recorded rather than rediscovered.** (a) A **guest-owned** resource cannot be lifted as a component export — `(canon resource.new $t)` lifted as `(result (own $t))` fails with `func not valid to be used as export`; the working shape is host-owned with the guest importing the constructor, which is also what §4.5 describes and what `qqq-host`'s `HandleTable` implements. (b) Async lifting requires **both** the `Config` knob **and** the `WASMTIME_COMPONENT_MODEL_ASYNC_STACKFUL` environment gate. (c) A single core module cannot serve as both the un-arg'd memory provider and the arg-taking import consumer — two modules are needed.
  → **Measured — the workspace after this change.** `cargo test --workspace --all-features`: **passing, 0 failed**; `cargo clippy --workspace --all-targets --all-features -- -D warnings`: clean; `cargo fmt --all`: no diff. `python tools/check_checklist_citations.py` OK. `docs/abi-cost-measured.md` registered in `tools/gen_llms_txt.py`'s `CURATED` table, which is what keeps the "WIT interface validation" CI job from failing on an unindexed `docs/*.md`.
  → Also unblocks: **`PERF-006`** (validating §4.5's batch-first rule *with measurements showing its effect*) now has the per-crossing cost to measure against — the "one crossing versus N crossings" comparison it needs is priced by the ~900 ns fixed cost established here.
- [ ] **PERF-006** Validate the batch-first design rule with measurements showing its effect.
  → §4.5 The ABI boundary — what crosses and at what cost
  → **Measured and not met as stated — the measurements exist, and they do not yet show
    the effect this item asks for.** The rule (cross the boundary once with a batch,
    not once per item) has supporting numbers from `PERF-005`'s work: crossing at all
    costs **900 ns p50 / 1 800 ns p99** for a `u64` argument and return, while a
    `list<u32>` of **1 000 elements crosses at 1 600 ns p50 / 2 000 ns p99** — so 1,000
    values cost **~1.8× a single value**, which is the batch-first argument in one line.
  → **What is missing is the comparison the item names**: a measurement of the *same*
    workload crossing once-per-item versus batched. The published figures contrast two
    *different* shapes (scalar vs list), which supports the rule but does not isolate
    it — a 1,000× per-item loop was never run to produce the counterfactual.
  → Recorded as not met rather than ticked because "the numbers are consistent with the
    rule" and "the rule is validated by measurement of its effect" are different claims,
    and `PERF-005`'s `docs/abi-cost-measured.md` is careful to state which it is.
- [ ] **PERF-007** Meet the AOT cache performance target.
  → §9.4 Specific optimizations planned
  → **Measured and not met — no harness row and no verdict.** `Budget::ALL` cites
    `bench/cold.rs::aot_cache_roundtrip`, which does not exist (`§O-249`); the
    citation now reads `NOT_IMPLEMENTED::aot_cache_roundtrip`. No `qqqai bench`
    workload measures an AOT round trip, and no published document states one.
  → **What does exist is the deserialize path, measured**: `Component::deserialize`
    on a precompiled 1.2 MB component is **304.8 µs**, against 6.8 ms for an
    up-front `/d` build. That is the mechanism the AOT target depends on, recorded
    here as context.
  → The item stays open because "the mechanism is measured" and "the target is met"
    are different claims, and this project's `§M-006` shape is exactly a control
    believed live that is not.
- [ ] **PERF-008** Meet the idle RSS budget (≤25 MB).
  → §9.2 The performance budget
  → **Measured and not met.** A freshly started `qqqai serve --listen
    127.0.0.1:3111 --config qqq.toml` on the reference application, after 12 s
    settling and with **one** `GET /healthz` proving it was serving (HTTP 200),
    reports **RSS 27.6 MB** against a ≤ 25 MB budget — **2.6 MB over**. Measured
    with `Get-Process -Id <pid> | WorkingSet64`.
  → **The liveness check is part of the measurement, not decoration.** A dead
    process also has a resident set, and reading RSS without confirming the server
    answers would measure a corpse. RSS read again after the request: 27.63 MB, so
    the figure is stable rather than a startup transient.
  → **`WorkSet64` is the resident set, which is the quantity §9.2 names** ("`rss`
    after 60 s idle"). Two honest qualifications: this is a **12-second** settle, not
    60, and the platform is `windows x86_64` on a 12-core machine rather than the
    reference profile (`§O-248`).
  → **The harness still has no row for this**, and `Budget::ALL`'s citation says so:
    `NOT_IMPLEMENTED::idle_host_rss` (`§O-249`). The number above comes from a direct
    process read, which is what the item asks for; instrumenting it as a harness row
    is what the citation marks as outstanding.
- [ ] **PERF-009** Meet the 1000-idle-instance RSS budget (≤350 MB).
  → §9.2 The performance budget
  → **Measured and not met — not measured at all.** `Budget::ALL` cites
    `bench/memory.rs::thousand_idle_instances_rss`, which does not exist (`§O-249`);
    the citation now reads `NOT_IMPLEMENTED::thousand_idle_instances_rss`. Nothing in
    the repository instantiates 1,000 idle instances and reads the resident set.
  → **The item cannot be honesty-claimed from a nearby number.** `PERF-008`'s 27.6 MB
    is one idle host with **one** loaded component, and `ARCH-011` step 6 records that
    V1 does not actually reuse instances — so `Acquired::pooled` counts idle
    *slots*, not 1,000 live guests. Producing this number needs the pooling path
    built first, which is the dependency the citation states.
- [ ] **PERF-010** Meet the throughput budget (≥60k RPS).
  → §9.2 The performance budget
  → **Measured and not met.** `qqqai bench --listen 127.0.0.1:3000 --json` against
    `qqqai serve` hosting `examples/orders-api` reports the `json` workload at
    **1,118.4 RPS** (p50 758.8 µs, p99 1,098.6 µs) and `multi` at **1,679.1 RPS**
    (p50 4,433.2 µs, p99 18,024.2 µs); the harness's own verdict is
    **`met=false`**, target `≥ 60,000 RPS`.
  → **Why it is not met here, stated rather than restated as met.** §9.2 states this
    against *"the reference application, 8 cores"* over real network I/O. This run
    is **loopback** on a machine the harness read as **12 physical cores**, using
    `Connection: close` — the harness's own `does_not_measure` field names this:
    *"every request opens a connection, so this does not measure keep-alive or
    HTTP/2 reuse"*. The best measured value is **2.8% of the target**, and it is a
    different measurement from the one §9.2 specifies. No keep-alive path, no
    multi-core sharding (`PERF-016`) and no pooled-instance reuse (`ARCH-011` steps
    6/14) exist in V1, so the gap is architectural as well as environmental.
  → Machine as read, not as asserted: `windows x86_64`, 12 physical cores,
    `Intel64 Family 6 Model 79 Stepping 1, GenuineIntel`. Full table in `§O-248`.
- [ ] **PERF-011** Meet the p99 latency budget (≤2 ms at 10k RPS).
  → §9.2 The performance budget
  → **Measured and not met.** The `tailp99` workload reports **p99 = 52,661.5 µs
    (52.66 ms)**, p50 38,459.9 µs, at 1,719.4 RPS — the harness's own verdict is
    **`met=false`** against a 2 ms target. That is **26.3× over**.
  → **Why it is not met here.** Two independent reasons, both stated: (a) the run is
    **not at 10k RPS** — it reached 1,719 RPS, so the percentile is not the
    percentile §9.2 names; and (b) it is **loopback on a 12-core machine** rather
    than the reference profile over real network I/O, so the p99 carries the
    client's own syscall and scheduling cost, which the harness's `does_not_measure`
    field names explicitly. A p99 from a different load point on a different
    profile is a different claim.
  → Reported honestly rather than restated: this is a **tail-latency** miss of the
    same kind `PERF-023` (the soak test) exists to characterise, and `PERF-027`
    (contractual objectives with alerting) exists to track.
  → Full table in `§O-248`.
- [ ] **PERF-012** Meet the per-instance memory budget (≤256 KB).
  → §9.2 The performance budget
  → **Measured and not met — no verdict.** `Budget::ALL` cites
    `bench/memory.rs::per_instance_pooled`, which does not exist (`§O-249`); the
    citation now reads `NOT_IMPLEMENTED::per_instance_pooled`.
  → **A measured figure exists and is reported here with its true meaning**, because
    the item asks for one: at 27.6 MB RSS for one idle host with one loaded
    component, a single component's **marginal** cost is a fraction of that — but it
    is not the quantity §9.2 names. That budget is *"Pooled slot accounting"*, and
    `ARCH-011` step 6 records that **V1 does not pool**: no instance is reused, so
    there is no pooled slot to account for and no per-instance figure to publish.
  → The honest disposition is therefore not-met-for-a-named-reason: the number this
    row wants cannot exist until `Pool` actually reuses an instance, which is the
    same gap `PERF-003` records from the acquire side.
- [ ] **PERF-013** Meet the build-time budget (≤20 s for 10k LOC).
  → §9.2 The performance budget
  → **Measured and not met.** A cold release build of the reference application —
    `CARGO_TARGET_DIR` outside the repository so nothing is incremental,
    `cargo build --release` in `examples/orders-api` — took **25.34 s** wall clock
    (`Finished \`release\` profile ... in 25.26s`), against the ≤ 20 s budget.
  → **The comparison is worth stating exactly, because it is unfavourable to the
    budget's premise.** The reference application is **2,513 lines across 6 files**,
    not 10,000, so it is **four times smaller** than the subject this budget names
    and still **27% over** the limit. If the budget scales with LOC, the measured
    figure implies well over 100 s at 10k LOC.
  → **What the 25.34 s actually measures, stated rather than left implicit:** the
    reference app plus its full dependency graph (`wit-component`, `wit-bindgen`,
    wasm tooling) compiled from an empty target directory. That is a genuine
    developer experience — "clone and build the example" — and it is what the
    command produces; it is not a per-LOC rate.
  → `Budget::ALL`'s citation remains `NOT_IMPLEMENTED::reference_app_clean_build`
    (`§O-249`): the number above comes from a timed command, and instrumenting it as
    a harness row is what the citation marks as outstanding.
- [ ] **PERF-014** Evaluate the io_uring backend and publish whether it earns its complexity.
  → §4.2 Process and thread model
- [ ] **PERF-015** Validate the async-single-threaded guest default against a shared-memory alternative.
  → §4.7 Concurrency model for guests
- [ ] **PERF-016** Implement and measure the listener-per-shard optimization.
  → §9.4 Specific optimizations planned
  → Partial: userspace round-robin assignment is implemented and tested (`qqq-io`). The
    kernel-level listener-per-shard form (`SO_REUSEPORT`) is deliberately deferred, because it
    distributes differently on macOS and Windows — a platform divergence that would make the
    sharding behave one way in Linux CI and another on a developer's machine. Measurement is
    outstanding.
- [ ] **PERF-017** Implement and measure the zero-copy streaming response path.
  → §9.4 Specific optimizations planned
- [ ] **PERF-018** Implement and measure SIMD acceleration in `qqqai/json`.
  → §9.4 Specific optimizations planned
- [ ] **PERF-019** Implement and measure huge-page allocation for guest memory.
  → §9.4 Specific optimizations planned
- [ ] **PERF-020** Implement continuous performance regression detection in CI.
  → §9.2 The performance budget
  → **Measured and not met.** `grep` of `.github/workflows/ci.yml` finds **no step
    that runs a benchmark, stores a number, or compares one run against another**.
    What CI has is `check_bench_contract.py`, which verifies the *budget table* is
    internally consistent — a static check on data, not a measurement of the system.
  → **Why the gate cannot exist yet, stated as the reason rather than the excuse.**
    Regression detection needs a stable measurement to compare against, and `§O-248`
    records that this machine's numbers are neither on the reference profile nor
    stable enough to be a baseline: the best throughput measured is **1,679 RPS**
    against a 60,000 RPS target, on loopback with `Connection: close`. A threshold
    set from that would ratify a number the budget says is wrong by 36×. The
    prerequisite is a reference-class runner with pinned hardware (`§9.1`'s
    requirement), not a CI step.
  → The harness itself is ready for it (`qqqai bench --fail-on-miss` exits non-zero
    on a miss, which is the mechanism a gate would call) — what is missing is the
    baseline to compare against.
- [ ] **PERF-021** Publish the benchmarks dashboard with hardware disclosure.
  → §11.3 Documentation as a product surface
  → **Measured and not met.** No dashboard exists: no file matching `*dashboard*`
    under `docs/`, and no published page renders the benchmark results. What exists
    is the *input* to one — `qqqai bench --json` emits a stable document carrying
    `data.environment` (CPU model, kernel, OS, physical cores, memory, toolchains),
    `data.results` (p50/p99/RPS per workload with its budget verdict) and
    `data.does_not_measure`.
  → **The hardware disclosure half is already satisfied and verified**: the run
    reported `windows x86_64`, **12 physical cores**, `Intel64 Family 6 Model 79
    Stepping 1, GenuineIntel`, read from the machine rather than asserted by the
    caller — `read_environment` refuses a blank field, so a returned `Environment`
    is evidence nine facts were read.
  → The remaining work is publication, not measurement, which is why it is recorded
    as a miss with the reason rather than claimed from the JSON shape.
- [x] **PERF-022** Publish the "what this does not measure" section for every benchmark.
  → §9.1 The honest benchmark position
  → Done: the caveat is **a required field on the result type**, not a prose section
    that a renderer may omit. `qqq_bench::methodology::Methodology::non_claims` is a
    `NonClaims` — not an `Option`, with no `serde(default)` — and both constructors
    refuse vacant input: `NonClaims::qualified` rejects an empty or all-blank list and
    `NonClaims::unqualified` rejects a blank reason, so "nothing to disclaim" must be
    stated as a claim with its reason rather than left silent.
  → **Verified structurally, by the compiler.** A probe constructing `Methodology`
    without the field fails with **`error[E0063]: missing field `non_claims` in
    initializer of `methodology::Methodology``**. A result that does not carry the
    disclaimer does not build. The probe was removed after capture.
  → **Verified populated on the real path.** `qqqai bench --listen 127.0.0.1:3000
    --json` against the served reference app populates `data.does_not_measure` with
    three claims, including the one this item exists for:
    *"the reference application's `db` row reads an in-guest store, not a Postgres
    round trip: the host has no `qqq:sql` implementation (O-155)"*. The others name
    the hardware the run actually used and the `Connection: close` shape.
  → The `db` caveat is required **because** the host has no `qqq:sql` implementation
    (`§O-155`), so the row name overstates its coverage without it. Recorded in the
    type's own documentation as the reason the type is not optional.
  → Measured and captured in `§O-248`.
- [ ] **PERF-023** Implement a tail-latency soak test (30+ minutes at sustained load).
  → §9.1 The honest benchmark position
  → **Measured and not met.** The soak has not been run: `§O-248`'s runs are the
    default interactive shape (**10 seconds**, per `Workload::TailP99`'s `Shape::
    Sustained { seconds: 10 }`), not 30 minutes.
  → **The capacity to run it exists and is deliberate.** `qqqai bench --seconds <n>`
    raises the duration, and `crates/qqq-bench/src/workload.rs:243` records the
    arrangement in its own comment: *"`§9.1` states a 30-minute run. Ten seconds is
    the default so the command is usable interactively; `PERF-023` owns the 30-minute
    soak and `--seconds` raises this deliberately rather than by accident."* So the
    item is a run to be performed, not a feature to be built.
  → **Why the run is not performed here and now:** a 30-minute soak produces a tail
    number about a load point and a machine, and this machine is loopback with
    `Connection: close` at ~1,700 RPS rather than the 10k RPS `PERF-011` names — so
    the result would characterise the development host rather than the runtime. The
    measurement is worth doing on the reference profile (`PERF-010`/`-011`'s stated
    hardware), and this record states the run and the reason together.
- [ ] **PERF-024** Establish the profiling workflow (perf, samply, VTune) and document it.
  → §9.4 Specific optimizations planned
  → **Measured and not met.** No profiling workflow is established and no document
    describes one: no file matching `*profil*` under `docs/`, and no CI step or tool
    wrapper invokes `perf`, `samply` or `VTune`. `tools/` contains 62 checkers, none
    of which profiles.
  → **The reason is capability, not decision:** `perf` and `VTune` are Linux and
    Intel-profiler tooling — this machine reports `windows x86_64`
    (`§O-248`) — and `samply` is not installed. Naming a workflow the project cannot
    run would be the "documentation describes something that does not exist" failure
    `DOC-018` exists to catch, so the item stays open rather than being ticked with a
    procedure nobody executed.
- [ ] **PERF-025** Implement the CPU-cost-per-request metric derived from fuel.
  → §10.2 Metrics that ship by default
  → **Measured and not met — and the gap is specific rather than total.** Fuel *is*
    tracked: `qqq_host::Metrics::fuel` reads a per-instance fuel counter, and
    `Metrics::write_counters` emits it. What does **not** exist is a **per-request**
    CPU-cost figure derived from it on the HTTP path.
  → The obstruction is the one `ARCH-011` already records for step 13: the two
    registries do not meet. `HttpMetrics::record_request` records latency, bytes and
    connections in `qqq-serve`; `qqq_host::Metrics::note_execution` records fuel,
    traps and peak memory in `qqq-host`; **nothing joins them and there is no common
    key**, so a request's fuel cost cannot be attributed to the request that spent
    it. The per-connection trace id in `qqq-serve::conn` is the correlation handle
    that would close it, and wiring it across the two registries is the work.
  → Recorded as not met rather than partially claimed, because "fuel is measured" and
    "CPU cost per request is published" are different facts and conflating them is
    how a wired-but-unreached feature reads as shipped.
- [x] **PERF-026** Re-examine every performance claim at each milestone and correct it publicly when wrong.
  → §3.3 Where we win, where we lose, and where we might be lying to ourselves
  → Done: **this round is an execution of the item, and it corrected claims that were
    wrong.** The `PERF` block was walked against measurements taken on the real path
    (`§O-248`) and **every §9.2 budget in range was found unmet** — 0 of 4 budgeted
    rows met, with `PERF-010` at 2.8% of target and `PERF-011` 26.3× over.
  → **Corrections made publicly, in this repository's records, rather than privately
    noted.** `PERF-010`, `PERF-011` and the five other budget items now carry
    *measured and not met* with the measured value and the profile mismatch, where
    before they carried the bare target with no measurement. The `db` row's coverage
    claim is corrected by the required caveat stating it reads an in-guest store
    because the host has no `qqq:sql` implementation.
  → The standing instruction this item states is honoured by the *structure* of the
    record: each budget item names the command that produced its number, the
    environment, and the reason where it does not meet the target, so a later reader
    can re-run and contradict it.
  → The mechanism is durable: `tools/check_bench_contract.py` compares §9.2, this
    checklist and `Budget::ALL` against each other on every CI run, so a claim that
    drifts from its source is a gate failure rather than a slow discovery.

### DET — Determinism

- [ ] **DET-001** Implement deterministic mode as an engine configuration profile.
  → §10.5 Determinism — the feature nobody else has
- [ ] **DET-002** Implement virtualized wall and monotonic clocks.
  → §10.5 Determinism — the feature nobody else has
- [ ] **DET-003** Implement the seeded CSPRNG for deterministic randomness.
  → §10.5 Determinism — the feature nobody else has
- [ ] **DET-004** Implement the deterministic single-threaded scheduler for deterministic mode.
  → §10.5 Determinism — the feature nobody else has
- [ ] **DET-005** Enable NaN canonicalization and disable float fusion in deterministic mode.
  → §10.5 Determinism — the feature nobody else has
- [ ] **DET-006** Enforce ordered maps in all guest-visible interfaces.
  → §10.5 Determinism — the feature nobody else has
- [ ] **DET-007** Implement the replay log format.
  → §10.5 Determinism — the feature nobody else has
- [ ] **DET-008** Implement `--replay` reproducing a recorded execution exactly.
  → §10.5 Determinism — the feature nobody else has
- [ ] **DET-009** Implement the 10,000-trial bit-identical verification required by the Definition of Done.
  → §16 — Definition of Done for V1
- [ ] **DET-010** Document determinism's honest limits (engine version, target triple, external I/O).
  → §10.5 Determinism — the feature nobody else has
- [ ] **DET-011** Implement network-timing recording for replay.
  → §10.5 Determinism — the feature nobody else has
- [ ] **DET-012** Implement deterministic-mode rejection of shared memory.
  → §10.5 Determinism — the feature nobody else has
- [ ] **DET-013** Implement deterministic compilation pinning by artifact digest and compiler version.
  → §10.5 Determinism — the feature nobody else has
- [ ] **DET-014** Publish the determinism documentation with use cases and non-use-cases.
  → §10.5 Determinism — the feature nobody else has
- [ ] **DET-015** Implement deterministic replay for the agent-sandbox reference architecture.
  → §8.4 The "agent sandbox" reference architecture
- [ ] **DET-016** Implement the deterministic-mode performance-cost report so users know what they pay.
  → §10.5 Determinism — the feature nobody else has

### OBS — Observability

- [ ] **OBS-001** Implement the capability-audit stream: granted, denied and attempted.
  → §10.1 The three signals, plus one unique to QQQ
- [x] **OBS-002** Implement the append-only, hash-chained audit record.
  → **Done, and the last piece was persistence.** `crates/qqq-run/src/guest_handler.rs` —
    `GuestApp` holds `Mutex<AuditStream>` and appends on every served request, and
    `attach_audit_file` persists it. `crates/qqq-host/src/audit_sink.rs` is the file: JSON Lines,
    loaded and **verified before the first request is served**. `qqqai serve --audit-log <path>`.
  → **Measured**: 7 sink tests + 7 `guest_handler` tests, and **three fault injections fired** —
    a removed broken-chain refusal, a resumed head reset to genesis, and a removed write-through
    (“one served request must write exactly one line; got: `""`”). Workspace 2612 passed.
  → **The record outlives the process that made it**: a second `GuestApp` attaching the same file
    resumes the history, and its next record chains from the one the previous process wrote.
  → `§O-299` records the design: a truncated FINAL line is dropped and *reported*, a malformed
    INTERIOR line is refused, and the parser refuses an unknown capability rather than reading the
    record as capability-less.
  → §10.1 The three signals, plus one unique to QQQ
- [x] **OBS-003** Implement SARIF export of the audit record.
  → **Done.** `crates/qqq-host/src/audit_export.rs` — `to_sarif` renders SARIF 2.1.0, and
    `qqqai audit-log <path> --sarif` reaches it. **Only refusals and failures become `results`**:
    a `granted` row is counted in the run's `properties` and omitted, because SARIF's `results`
    array is *findings* and a document where every normal operation is a finding has no signal.
  → **Measured**: 7 export tests + 5 CLI tests over the real binary. **Fault-injected twice** —
    removing one closing brace left every substring assertion passing and only the parse test
    firing (*“EOF while parsing an object”*), and wrapping the document in a preamble left every
    fragment intact and only *“SARIF must be the whole document”* firing.
  → Both exports **verify the chain and refuse rather than render**: a SARIF consumer does not
    re-check a hash chain, so a corrupted stream rendered as valid SARIF becomes a plausible-
    looking artefact. `§O-296`.
  → §10.1 The three signals, plus one unique to QQQ
- [x] **OBS-004** Implement the compliance-report export.
  → **Done.** `to_compliance_report` in the same module, reached by `qqqai audit-log <path>`.
    It carries the **chain head** (a digest a reader cross-checks), the counts per capability and
    outcome, every refusal individually, and **its own bound**: `Appends refused` is printed even
    at zero, next to the capacity, so a bounded history is visible rather than implied.
  → **An empty refusal list says what it does *not* prove**: *“a runtime with a grant set nobody
    exercises also produces no refusals.”* An absence of refusals is not evidence of safety.
  → **Measured**: `the_compliance_report_carries_the_chain_head`, `the_report_states_its_own_bound`,
    `an_empty_refusal_list_says_what_it_does_not_prove`, and `the_report_is_rendered_from_a_real_record`
    over the real binary.
  → §10.1 The three signals, plus one unique to QQQ
- [ ] **OBS-005** Implement the default metric set.
  → §10.2 Metrics that ship by default
  → **Wired**: `serve_connection` records into the registry, and the wiring found a real defect. `ConnectionContext` carries `metrics` and an `Arc<TenantLabels>`; `record_metrics` and `serve_special_route` are the extracted sites.
  → **The cardinality violation the wiring exposed**: `tenant_of` returns the **peer IP address**, so recording the tenant directly gives one time series per client — §10.2's violation in its worst form, because an attacker chooses the value. `TenantLabels` existed and bounds the space at 64 names; the wiring did not use it. Found by a test asserting the wrong key: tracing the value showed the count was correct (`5`) all the way to the registry, so the *key* differed. See `§O-136`.
  → **A test that agrees with the implementation cannot find a design error in it** — the failing assertion was my error, and fixing it is what surfaced the real defect. A test that read the key back from the code would have passed and shipped the unbounded label.
  → **`drain_body` now returns `Option<u64>`** rather than discarding the count `discard` already produces, so `body_bytes` is the bytes that **crossed the socket** rather than the head's declaration. They agree for a well-formed request and disagree for a truncated one.
  → **Measured**: 25 registry tests + **9 integration tests over the real accept loop** (recorded at all; the server's *chosen* status is what gets counted, so a router 404 and a handler 201 land in different series; three requests on one keep-alive connection are three; bytes; latency; one open and one close; a disconnect classified as such; the peer IP is a bounded label; a server with no registry still serves). Workspace **2098 passed, 0 failed**.
  → **Still open, and named**: only the **HTTP row** of §10.2's table is implemented — the instance, execution, memory, capability, supply-chain and cost rows are not. Per-tenant *enforcement* (as opposed to accounting) is not done, and the registry is not exposed on any endpoint. `OBS-005` stays unticked until the set is complete.
- [ ] **OBS-006** Implement the cardinality lint on metric definitions.
  → §10.2 Metrics that ship by default
- [ ] **OBS-007** Implement structured JSON logging with trace and tenant correlation.
  → §10.3 Logging
- [ ] **OBS-008** Implement host-side redaction using manifest-declared secret names.
  → §10.3 Logging
- [ ] **OBS-009** Implement automatic spans for the fifteen lifecycle steps.
  → §10.4 Distributed tracing
- [ ] **OBS-010** Implement W3C Trace Context propagation through `wasi:http`.
  → §10.4 Distributed tracing
- [ ] **OBS-011** Implement host-controlled sampling with a tail-sampling option.
  → §10.4 Distributed tracing
- [ ] **OBS-012** Implement the OTLP exporter for traces, metrics and logs.
  → §10.1 The three signals, plus one unique to QQQ
- [ ] **OBS-013** Implement the Prometheus scrape endpoint.
  → §10.2 Metrics that ship by default
- [ ] **OBS-014** Prove that a guest cannot influence sampling decisions.
  → §10.4 Distributed tracing
- [ ] **OBS-015** Implement per-tenant audit isolation and retention controls.
  → §10.1 The three signals, plus one unique to QQQ
- [x] **OBS-016** Implement the "prove what this code did" report generator.
  → **Done — this is the compliance report.** §10.1 calls *“prove what this code did”* QQQ's
    fourth signal and says no other runtime answers it structurally. `to_compliance_report` is that
    answer: per-record evidence with the chain head, so a reader can recompute rather than trust.
  → **What it still does not answer, named rather than implied**: the capability column is a
    **stated placeholder** (`FsRead`), because the served seam sees one guest call and not the host
    calls inside it. The per-capability rows are `OBS-001`, which needs the `ambient::require` seam.
    A report that aggregated by capability today would be aggregating a constant.
  → §10.1 The three signals, plus one unique to QQQ
- [ ] **OBS-017** Decide whether to contribute capability-audit semantic conventions to OpenTelemetry (open question `OQ-010`).
  → §10.4 Distributed tracing
- [ ] **OBS-018** Implement the local development observability experience (readable traces in the terminal).
  → §6.6 `qqq-run` — CLI and dev server

---

## 12. P9 — V1 release

### DOD — Definition-of-done verification

- [ ] **DOD-001** Verify all five languages pass the identical conformance suite, or document gaps with owners and dates.
  → §16 — Definition of Done for V1
- [ ] **DOD-002** Run the reference application under sustained load for 72 hours with zero crashes.
  → §16 — Definition of Done for V1
- [ ] **DOD-003** Verify bit-identical results across 10,000 deterministic trials.
  → §16 — Definition of Done for V1
- [ ] **DOD-004** Confirm both external audits are complete and all critical and high findings are fixed.
  → §16 — Definition of Done for V1
- [ ] **DOD-005** Confirm the ≥200-case hostile-guest suite passes with zero host memory-safety incidents.
  → §16 — Definition of Done for V1
- [ ] **DOD-006** Confirm `qqqai audit --fail-on high` is clean on all first-party packages.
  → §16 — Definition of Done for V1
- [ ] **DOD-007** Publish the threat model including explicit non-goals.
  → §16 — Definition of Done for V1
- [ ] **DOD-008** Verify every numeric target in the performance budget on reference hardware.
  → §16 — Definition of Done for V1
- [ ] **DOD-009** Publish the benchmark suite with methodology and honest losses.
  → §16 — Definition of Done for V1
- [ ] **DOD-010** Verify TTFA ≤3 minutes on a clean machine across all three OSes.
  → §16 — Definition of Done for V1
- [ ] **DOD-011** Verify 100% of error codes are documented with remediation.
  → §16 — Definition of Done for V1
- [ ] **DOD-012** Verify 100% of public APIs have a compiling example.
  → §16 — Definition of Done for V1
- [ ] **DOD-013** Verify `qqqai schema --all` is complete and drift-checked in CI.
  → §16 — Definition of Done for V1
- [ ] **DOD-014** Verify the MCP server exposes all V1 tools with structured output.
  → §16 — Definition of Done for V1
- [ ] **DOD-015** Verify the agent benchmark meets its success target.
  → §16 — Definition of Done for V1
- [ ] **DOD-016** Publish licence, governance, contribution guide and code of conduct.
  → §16 — Definition of Done for V1
- [ ] **DOD-017** Verify the deprecation policy is written and in force.
  → §16 — Definition of Done for V1
- [ ] **DOD-018** Verify at least two maintainers have commit rights and a succession plan exists.
  → §16 — Definition of Done for V1
- [ ] **DOD-019** Publish the support and security-response policies.
  → §16 — Definition of Done for V1
- [ ] **DOD-020** Run the independent third-party acceptance test: an external team builds and ships a real app from the docs alone.
  → §16 — Definition of Done for V1
- [ ] **DOD-021** Verify the install path on a genuinely clean machine for each supported OS and each install channel.
  → §11.1 Install channels, in priority order
- [ ] **DOD-022** Verify the migration tool on at least three real Node projects with published results.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **DOD-023** Verify the registry has enough packages for the reference application to be built without vendoring.
  → §11.2 The registry and ecosystem
- [ ] **DOD-024** Hold the go/no-go review with the cut-order list on the table.
  → §14.4 What we would cut first, in order

### GTM — Go-to-market

- [ ] **GTM-001** Build the qqq.codes website as a QQQ application (dogfooding).
  → §3.1 Who this is for
- [ ] **GTM-002** Publish the competitive-comparison page with cited evidence and no disparagement.
  → §3.2 The competitive set, honestly
- [ ] **GTM-003** Launch the migration-programme landing page and the agent-assisted migration offer.
  → §6.8 `qqqai migrate` — the adoption ramp
- [ ] **GTM-004** Execute Phase 0 (credibility): publish benchmarks and the security model; seek public criticism.
  → §13.4 Go-to-market sequence
- [ ] **GTM-005** Execute Phase 1 (agents): MCP integration, agent-sandbox reference architecture, framework partnerships.
  → §13.4 Go-to-market sequence
- [ ] **GTM-006** Execute Phase 2 (edge/serverless): publish density and cold-start case studies with real numbers.
  → §13.4 Go-to-market sequence
- [ ] **GTM-007** Execute Phase 3 (polyglot teams): migration tooling, parity, ported registry.
  → §13.4 Go-to-market sequence
- [ ] **GTM-008** Execute Phase 4 (enterprise): Fabric, compliance evidence, support.
  → §13.4 Go-to-market sequence
- [ ] **GTM-009** Secure the first three design partners before M3.
  → §3.1 Who this is for
- [ ] **GTM-010** Publish the agent-sandbox reference implementation as open source.
  → §8.4 The "agent sandbox" reference architecture
- [ ] **GTM-011** Build the pricing page and the licence FAQ together, so they never contradict each other.
  → §13.3 Pricing sketch (for planning, not commitment)
- [ ] **GTM-012** Establish the enterprise-sales motion: what we sell, to whom, and what we refuse to sell.
  → §13.1 The commercial problem, stated plainly
- [ ] **GTM-013** Publish the OEM/platform-embedding programme.
  → §13.3 Pricing sketch (for planning, not commitment)
- [ ] **GTM-014** Establish the developer-relations content programme (talks, essays, live coding).
  → §13.4 Go-to-market sequence

### RISK — Risk management

- [ ] **RISK-001** Track `R-01` ecosystem emptiness; alert below 50 useful packages at M6.
  → §15 — Risk Register
- [ ] **RISK-002** Track `R-02` language toolchain immaturity; run spikes from M1 and drop a language after two failures.
  → §15 — Risk Register
- [ ] **RISK-003** Track `R-03` Wasmtime API instability; quarterly upgrade sprint.
  → §15 — Risk Register
- [ ] **RISK-004** Track `R-04` sandbox escape; 72-hour patch target and public advisories.
  → §15 — Risk Register
- [ ] **RISK-005** Track `R-05` competitive performance; measure at M3 and pivot messaging if missed by >2×.
  → §15 — Risk Register
- [ ] **RISK-006** Track `R-06` competitor capability copying.
  → §15 — Risk Register
- [ ] **RISK-007** Track `R-07` licence-driven enterprise friction.
  → §15 — Risk Register
- [ ] **RISK-008** Track `R-08` late structural audit findings; audit at M7.
  → §15 — Risk Register
- [ ] **RISK-009** Track `R-09` runway exhaustion; alert at six months before M7.
  → §15 — Risk Register
- [ ] **RISK-010** Track `R-10` positioning confusion; verify with user research at 3 months.
  → §15 — Risk Register
- [ ] **RISK-011** Track `R-11` CPython-to-Wasm viability; measure at M5.
  → §15 — Risk Register
- [ ] **RISK-012** Track `R-12` trademark friction; legal review before launch.
  → §15 — Risk Register
- [ ] **RISK-013** Track `R-13` documentation and agent-contract drift.
  → §15 — Risk Register
- [ ] **RISK-014** Track `R-14` standards churn in Wasm/WASI.
  → §15 — Risk Register
- [ ] **RISK-015** Track `R-15` maintainer concentration; require a second maintainer by M5.
  → §15 — Risk Register

---

## 13. P10 — Beyond V1

### FUT — Deferred work (stubs, explicitly marked)

- [ ] **FUT-001** QQQ Fabric GA: multi-host control plane, fleet policy, attestation.
  → §17 — Beyond V1
- [ ] **FUT-002** Browser target: the QQQ host compiled to Wasm, running components in-browser.
  → §17 — Beyond V1
- [ ] **FUT-003** Native codegen escape hatch with MPK-based isolation replacing the Wasm sandbox.
  → §17 — Beyond V1
- [ ] **FUT-004** Component Model cooperative-threads support, contingent on Wasmtime's stack-switching.
  → §4.7 Concurrency model for guests
- [ ] **FUT-005** Distributed composition: components calling components over the network transparently.
  → §17 — Beyond V1
- [ ] **FUT-006** Formal verification of the capability engine.
  → §17 — Beyond V1
- [ ] **FUT-007** Implement `qqq:ai` local inference as a metered capability (interface already authored in `ABI-013`).
  → §6.9 `qqq:ai` — local inference as a capability
- [ ] **FUT-008** GPU capability with metered access.
  → §17 — Beyond V1
- [ ] **FUT-009** Time-travel debugging with reverse stepping, built on determinism.
  → §17 — Beyond V1
- [ ] **FUT-010** QQQ Cloud hosted platform.
  → §17 — Beyond V1
- [ ] **FUT-011** Hardware-backed attestation (TPM / Secure Enclave).
  → §17 — Beyond V1
- [ ] **FUT-012** Registry federation for private registries that mirror and extend the public one.
  → §17 — Beyond V1

### OQ — Open questions requiring a decision

- [ ] **OQ-001** Define and close the free-tier eligibility boundary and revenue-attestation mechanism.
  → §13.2 The licence model, and why NN-8 still holds
- [ ] **OQ-002** Decide how the AssemblyScript path is named and marketed.
  → §6.10 Language toolchains — one per target language
- [ ] **OQ-003** Decide whether Python is first-class or experimental, based on the M5 spike.
  → §6.10 Language toolchains — one per target language
- [ ] **OQ-004** Decide whether Windows is first-class or best-effort.
  → §6.10 Language toolchains — one per target language
- [ ] **OQ-005** Ratify the Wasm shared-memory and threads policy.
  → §4.7 Concurrency model for guests
- [ ] **OQ-006** Decide whether to build the registry now or bootstrap on OCI.
  → §6.5 `qqq-pkg` — package manager and registry
- [x] **OQ-007** Decide whether `wasi:http` is sufficient or a custom HTTP interface is required.
  → Resolved: `wasi:http` is the foundation and `qqq:http` extends it — routing, per-route
    capability scoping and stream-shaped bodies are QQQ's contribution, carried as an
    extension rather than a fork. Reasoning in Observations §O-027.
  → §6.4 `qqq-serve` — the HTTP and application server
- [ ] **OQ-008** Choose the exact Fabric licence.
  → §13.2 The licence model, and why NN-8 still holds
- [ ] **OQ-009** Decide on Bytecode Alliance engagement.
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship
- [ ] **OQ-010** Decide on contributing capability-audit semantic conventions to OpenTelemetry.
  → §10.1 The three signals, plus one unique to QQQ
- [ ] **OQ-011** Decide whether `qqq:ai` ships inside the V1 line or moves to V2.
  → §6.9 `qqq:ai` — local inference as a capability
- [ ] **OQ-012** Decide the deprecation window: two minor versions, or a fixed time period.
  → §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship

### AI — Inference capability (staged behind `OQ-011`)

- [ ] **AI-001** Ratify the `qqq:ai@1.0` interface (authored in `ABI-013`, implementation deferred).
  → §6.9 `qqq:ai` — local inference as a capability
- [ ] **AI-002** Implement host-owned model loading and memory management.
  → §6.9 `qqq:ai` — local inference as a capability
- [ ] **AI-003** Implement token metering as a first-class resource, like fuel.
  → §6.9 `qqq:ai` — local inference as a capability
- [ ] **AI-004** Implement `max_tokens_per_request` enforcement by the host.
  → §6.9 `qqq:ai` — local inference as a capability
- [ ] **AI-005** Implement the local GGML-family provider as the default.
  → §6.9 `qqq:ai` — local inference as a capability
- [ ] **AI-006** Implement cloud providers as a separately granted capability with named endpoints.
  → §6.9 `qqq:ai` — local inference as a capability
- [ ] **AI-007** Implement the size-constrained model allowlist (`*:<=4B`).
  → §5.3 The manifest — `qqq.toml`
- [ ] **AI-008** Ensure the interface is async-only and documented as never being on the request hot path.
  → §6.9 `qqq:ai` — local inference as a capability
- [ ] **AI-009** Implement per-tenant model isolation and accounting.
  → §6.9 `qqq:ai` — local inference as a capability
- [ ] **AI-010** Publish the `qqq:ai` documentation with honest latency expectations.
  → §6.9 `qqq:ai` — local inference as a capability

---

## 14. Summary counters

| Phase | Milestone | Items |
|---|---|---|
| P0 Foundation | M0 | 79 |
| P1 Heartbeat | M1 | 58 |
| P2 Capability engine | M2 | 46 |
| P3 HTTP | M3 | 37 |
| P4 DX v0 | M4 | 64 |
| P5 Languages | M5, M8 | 40 |
| P6 Packages | M6 | 36 |
| P7 Agent face | M9 | 57 |
| P8 Perf/determinism/obs | continuous | 61 |
| P9 V1 release | M10, M11 | 75 |
| P10 Beyond V1 | post-1.0 | 34 |
| **Total** | | **587** |

**Coverage rule:** every section of `QQQ-Proposal-V1.md` carrying implementation work has at least one item above. The only Proposal sections with no items are §0.1–§0.2, §1.3, §3.3, §13.1 and the appendices, which are narrative, justification or registers rather than buildable work.

*End of `QQQ-Checklist-V1.md`.*
