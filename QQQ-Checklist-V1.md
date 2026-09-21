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
| `DOC` | Documentation, docs-as-code, cross-reference machinery | 20 | Tech writer |
| `MKT` | Market research, positioning, competitive analysis | 16 | Founder |
| `POS` | Product positioning and messaging | 6 | Founder |
| `ARCH` | Architecture decisions and crate topology | 16 | Systems lead |
| `HOST` | `qqq-host` execution engine | 24 | Systems engineer |
| `CAP` | Capability resolution pipeline | 16 | Security engineer |
| `SEC` | Security engineering, audits, hardening | 30 | Security engineer |
| `CON` | Contracts: WIT interfaces, manifest schema, versioning | 20 | Architect |
| `ABI` | WIT package authoring and binding generation | 16 | Runtime engineer |
| `SRV` | HTTP/application server | 20 | Systems engineer |
| `PKG` | Package manager and registry | 24 | Platform engineer |
| `SUP` | Supply chain: signing, provenance, SBOM | 14 | Security engineer |
| `DX` | Developer experience, CLI ergonomics, errors | 20 | DX engineer |
| `CLI` | CLI commands | 24 | DX engineer |
| `TEST` | Test runner and test infrastructure | 18 | Runtime engineer |
| `MIG` | Migration tooling | 14 | DX engineer |
| `AI` | `qqq:ai` inference capability | 10 | Runtime engineer |
| `LANG` | Language toolchains (5 languages) | 40 | Runtime engineer |
| `AGENT` | Agent face: MCP, schemas, machine contracts | 24 | Architect |
| `PERF` | Performance: benchmarks, budgets, optimizations | 26 | Performance engineer |
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

**Total: 578 items.**

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
- [ ] **FND-010** Establish the release-engineering pipeline: versioning, changelog generation, artifact signing hooks.
  → Partial: no release-engineering pipeline yet: versioning, changelog generation and artifact signing hooks are unbuilt.
  → §11.1 Install channels, in priority order
- [x] **FND-011** Delete the scratch verification crate at `.scratch/witprobe` once its findings are folded into the test suite; port its three assertions into `crates/qqq-host/tests/`.
  → Done: `.scratch/witprobe` deleted; its four assertions ported to `crates/qqq-host/tests/engine.rs` with control cases (4 tests pass).
  → §0.4 How to read the cross-references
- [ ] **FND-012** Install `wasm-tools` and the `wasmtime` CLI into the developer bootstrap script (both were found missing on the reference machine).
  → Partial: `wasm-tools` is used by the test fixtures, but no bootstrap script installs it.
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
    nine checks the self-test actually exercises (listed from the harness, not from
    the validator's shorter docstring), and the change recipes.
  → The first draft listed twelve checks from the validator's module docstring; the
    self-test drives nine. Counting coverage from the thing that *exercises* it is the
    correction.
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
- [ ] **DOC-015** Add the "framework vs runtime" usage rule to the contributing guide.
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
  → Done: `docs/wit-reference.md` — 13 packages, 20 interfaces, **71 functions** and
    47 types, generated from `wit/` by `tools/gen_wit_reference.py` and verified by
    `tools/check_wit_reference.py` in CI and in the bridge.
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
- [ ] **DOC-018** Build the documentation freshness test: compile a sample project against the published docs and fail on drift.
  → §2.6 NN-6 — Human + Machine Documentation Parity
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
- [ ] **DOC-020** Publish `llms.txt` and `llms-full.txt` at the repository root and on the docs site.
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
  → Done: **145 files** now carry `SPDX-License-Identifier: Apache-2.0` — every `.rs`
    under `crates/` and `fuzz/fuzz_targets/`, every `wit/*.wit`, and every `tools/*.py`.
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
- [ ] **ARCH-003** Implement the compile-time rule that a host function without a WIT definition cannot enter a release build.
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
- [ ] **ARCH-010** Publish the crate stability tiers and the API-stability contract per tier.
  → §4.3 Crate topology
- [ ] **ARCH-011** Implement the fifteen-step request lifecycle as an instrumented pipeline.
  → §4.4 Request lifecycle — the detailed path
- [ ] **ARCH-012** Implement the defence-in-depth re-check of grants at host-call time.
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
- [ ] **HOST-009** Implement structured trap reporting with guest backtrace and DWARF source mapping when available.
  → Partial: the **join is done**. `Instance::run` and `run_measured` build a `Trap` from the real `wasmtime::Error` (`trap_from` takes the error, not a formatted string), so a real trap now carries **frames** — Wasmtime's `WasmBacktrace`, which resolves each frame through the module's DWARF when `debug_info` is on. `qqqai run` sets `debug_info = true` on its engine, so a CLI trap names a file and line. Three tests trap a guest through the real path and assert on the structured frames; all three were **fault-injected** by dropping the frames and confirmed to fail.
  → `qqq-debug` extracts a standalone `SourceMap` from a built component (24 unit tests, 4 end-to-end), for reports read where no engine exists.
  → **Remaining:** `qqqai build` does not yet extract the map beside the artifact, so a *detached* trap report cannot be resolved without re-reading the DWARF; and `WasmFrame.offset` is populated but nothing consumes it against a `SourceMap` yet. Both are the detached-report path, not the live one.
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
- [ ] **HOST-020** Write the Wasmtime upgrade runbook and the compatibility-test suite.
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

- [ ] **CON-001** Finalize and publish the `qqq.toml` JSON Schema.
  → Partial: the manifest parses and validates, but no JSON Schema document is published.
  → Partial: the manifest parses and validates, but no JSON Schema document is published.
  → §5.3 The manifest — `qqq.toml`
- [x] **CON-002** Implement manifest parsing with schema-validated diagnostics naming the exact line.
  → Done: `Manifest::parse` produces field-named diagnostics with a line reference.
  → §5.3 The manifest — `qqq.toml`
- [x] **CON-003** Implement `qqq.toml` normalization: host patterns, secret references, path canonicalization.
  → Done: `qqq-cap::normalize` — host patterns, secret references, path canonicalisation.
  → §6.2 `qqq-cap` — the capability engine
- [ ] **CON-004** Finalize and publish the `qqq.lock` schema including per-package `caps`.
  → §5.4 The lockfile — `qqq.lock`
- [ ] **CON-005** Implement `lockfile-hash` covering all resolved artifacts and config.
  → §5.4 The lockfile — `qqq.lock`
- [ ] **CON-006** Implement reproducible-build verification that fails when output digests are unstable.
  → §5.4 The lockfile — `qqq.lock`
- [x] **CON-007** Define the interface-versioning policy: SemVer per WIT package, `@since` mandatory.
  → Done: the policy is stated in `tools/check_wit_since.py`'s header as four
    rules with the reason for each, and **enforced** rather than described. Every
    WIT package is SemVer'd in its `package` line, and every exported function
    carries `@since(version = 1.0.0)` — 73 annotations across 13 interfaces,
    added by `tools/add_wit_since.py`.
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
    **73 functions checked across 13 interfaces, 19 declared infallible by name.**
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
  → Done: `tools/check_no_ambient.py` — 40 source files across the six
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
- [ ] **CON-011** Write the WIT style guide and enforce it in review.
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
- [ ] **CON-016** Implement the schema-drift CI check for the manifest, lockfile, CLI output and error catalogue.
  → §8.3 The machine contract layer
- [ ] **CON-017** Publish the contract-stability promise for each surface (WIT, manifest, lockfile, CLI JSON).
  → §2.5 NN-5 — Explicit Contracts Over Implicit Behavior
- [ ] **CON-018** Implement the "no hidden global state" architecture test across all host interfaces.
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
- [ ] **CAP-011** Implement the restricted policy expression language with static analysability and termination proofs.
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
- [ ] **CAP-015** Implement capability-use accounting feeding the audit stream.
  → Partial: fuel and duration per execution are reported; capability-use accounting into an audit stream is not built.
  → Partial: fuel and duration per execution are reported; capability-use accounting into an audit stream is not built.
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
    all 85 `.rs` files in the workspace.
    | Measure | Count |
    |---|---|
    | `.rs` files scanned | **85** |
    | Code-position `unsafe` (`{}`, `fn`, `impl`, `trait`, `extern`) | **0** |
    | `#[allow(unsafe_code)]` in a code position | **0** |
    | `cfg_attr(..., allow(unsafe_code))` | **0** |
    | Crates with a bare `#![forbid(unsafe_code)]` | **11** (every crate) |
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
- [ ] **SRV-002** Implement HTTP/2 including multiplexing and flow control.
  → §6.4 `qqq-serve` — the HTTP and application server
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
- [ ] **SRV-009** Implement WebSockets over HTTP/1.1 and HTTP/2.
  → §6.4 `qqq-serve` — the HTTP and application server
- [ ] **SRV-010** Implement Server-Sent Events.
  → §6.4 `qqq-serve` — the HTTP and application server
- [x] **SRV-011** Implement graceful shutdown with in-flight request draining.
  → §6.4 `qqq-serve` — the HTTP and application server
  → Done: `qqq-serve::conn::Connection` — in-flight requests finish, idle connections close at once, the drain deadline is enforced and reported.
- [x] **SRV-012** Implement per-tenant connection limits and idle timeouts.
  → §6.4 `qqq-serve` — the HTTP and application server
  → Done: `ConnectionLedger` (per-tenant ceiling) and `ConnectionConfig` (idle and header timeouts). The socket layer that drives them is `SRV-001`.
- [ ] **SRV-013** Implement structured access logging with tenant and trace correlation.
  → §10.3 Logging
- [ ] **SRV-014** Implement HTTP/3 over QUIC behind a feature flag (beta).
  → §6.4 `qqq-serve` — the HTTP and application server
- [ ] **SRV-015** Implement gRPC over `wasi:http` plus `qqq:grpc` (beta).
  → §6.4 `qqq-serve` — the HTTP and application server
- [ ] **SRV-016** Implement ACME certificate provisioning as an opt-in.
  → §6.4 `qqq-serve` — the HTTP and application server
- [ ] **SRV-017** Implement `qqqai openapi` emitting an OpenAPI description of a running app.
  → §5.2 The command surface
- [ ] **SRV-018** Implement the reference application used by all benchmarks (orders API).
  → §9.1 The honest benchmark position
- [ ] **SRV-019** Implement CORS configuration with safe defaults.
  → §5.3 The manifest — `qqq.toml`
- [ ] **SRV-020** Implement request-body size and count limits enforced per tenant, with metrics.
  → §10.2 Metrics that ship by default
  → Partial: header-count and header-size caps, and a declared-body cap, are enforced
    in `qqq-serve::http1`. Per-tenant accounting and metrics remain.

### ABI — WIT packages

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
- [ ] **DX-004** Implement the error-message standard: what, code, why, fix, machine block.
  → §12.2 Error message design standard
- [ ] **DX-005** Implement the `QQQ-XXXX` error-code registry with generated docs pages.
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
- [ ] **DX-013** Implement the `--help` brevity standard (≤40 lines, actionable) and a CI check.
  → §12.3 The DX commitments (measurable, in CI)
- [ ] **DX-014** Implement the CI check that every error code has a docs page.
  → §12.3 The DX commitments (measurable, in CI)
- [ ] **DX-015** Implement the CI check that every public API has a compiling example.
  → §12.3 The DX commitments (measurable, in CI)
- [ ] **DX-016** Implement `qqqai doctor` with environment diagnosis and remediation.
  → §5.2 The command surface
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
- [ ] **CLI-011** Implement `qqqai serve` with `--workers`, `--tls`, `--config`.
  → §6.4 `qqq-serve` — the HTTP and application server
- [x] **CLI-012** Implement `qqqai test`.
  → Done: `qqq-run::test_runner` (the module is named `test_runner` because `test` is a Rust keyword, so the file uses `#[path]` like `scaffold`), dispatched from `main.rs`. Discovery asks cargo for its test targets and runs **each binary directly**, which makes a test's source file exact rather than inferred. `--filter`, `--fail-fast`, `--trials N`, `--dry-run` and `--json` work; a failing test **exits 1** so CI can gate on it. 51 CLI integration tests.
  → `--trials N` is the first architecture-enabled feature from §6.7 and the one that needs no unbuilt dependency: it runs each test N times and flags output that differs. A determinism failure counts as a failure for the exit code, because a test passing 4 of 5 trials is not a passing test.
  → §6.7 `qqqai test` — test runner
- [ ] **CLI-013** Implement `qqqai bench`.
  → §9.1 The honest benchmark position
- [ ] **CLI-014** Implement `qqqai fmt` and `qqqai lint` with a unified interface over language toolchains.
  → §5.2 The command surface
- [x] **CLI-015** Implement `qqqai inspect` with static capability reporting and `--diff`.
  → Done: `qqqai inspect` with no argument reports the manifest's grants; `qqqai inspect <artifact>` compiles the component without instantiating it and reports the capabilities its **import table** requires, with the digest and `component`/`core-module` kind so a report is tied to the bytes that produced it. Unmapped interfaces are listed rather than dropped, and a file that is not a component is an error rather than a fallback to the manifest.
  → `--diff <other>` reports the **authority** delta between two artifacts, which is §5.4's central supply-chain question: which capabilities did this build add? A gain **exits non-zero** so the flag is usable as a CI gate without parsing output; a loss reports but succeeds, because failing on a reduction would train people to bypass the check. A gain of a *covert channel* (`clock.wall`, `crypto.random`) escalates even though it cannot move the posture band — the §10.5 distinction.
  → §5.2 The command surface
- [ ] **CLI-016** Implement `qqqai audit` with SARIF output and `--fail-on`.
  → §5.2 The command surface
- [ ] **CLI-017** Implement `qqqai verify` for signature and attestation checking.
  → §5.2 The command surface
- [ ] **CLI-018** Implement `qqqai caps` with `--explain`.
  → §5.2 The command surface
- [ ] **CLI-019** Implement `qqqai why`.
  → §6.2 `qqq-cap` — the capability engine
- [ ] **CLI-020** Implement `qqqai trace`.
  → §10.4 Distributed tracing
- [ ] **CLI-021** Implement `qqqai doctor`.
  → §5.2 The command surface
- [ ] **CLI-022** Implement `qqqai mcp`.
  → §8.2 `qqqai mcp` — the Model Context Protocol server
- [ ] **CLI-023** Implement `qqqai schema --all` and the per-command schema output.
  → §8.3 The machine contract layer
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
- [ ] **PERF-001** Build the benchmark harness with the full published methodology.
  → §9.1 The honest benchmark position
- [ ] **PERF-002** Implement the ten benchmarks listed in §9.1.
  → §9.1 The honest benchmark position
- [ ] **PERF-003** Meet the warm-instance-acquire budget (≤100 µs p99).
  → §9.2 The performance budget
- [ ] **PERF-004** Meet the cold-instantiate budgets (≤5 ms cached, ≤150 ms from `.wasm`).
  → §9.2 The performance budget
- [ ] **PERF-005** Measure and publish the real ABI-crossing costs, replacing the estimates in §9.3.
  → §9.3 The ABI cost, quantified honestly
- [ ] **PERF-006** Validate the batch-first design rule with measurements showing its effect.
  → §4.5 The ABI boundary — what crosses and at what cost
- [ ] **PERF-007** Meet the AOT cache performance target.
  → §9.4 Specific optimizations planned
- [ ] **PERF-008** Meet the idle RSS budget (≤25 MB).
  → §9.2 The performance budget
- [ ] **PERF-009** Meet the 1000-idle-instance RSS budget (≤350 MB).
  → §9.2 The performance budget
- [ ] **PERF-010** Meet the throughput budget (≥60k RPS).
  → §9.2 The performance budget
- [ ] **PERF-011** Meet the p99 latency budget (≤2 ms at 10k RPS).
  → §9.2 The performance budget
- [ ] **PERF-012** Meet the per-instance memory budget (≤256 KB).
  → §9.2 The performance budget
- [ ] **PERF-013** Meet the build-time budget (≤20 s for 10k LOC).
  → §9.2 The performance budget
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
- [ ] **PERF-021** Publish the benchmarks dashboard with hardware disclosure.
  → §11.3 Documentation as a product surface
- [ ] **PERF-022** Publish the "what this does not measure" section for every benchmark.
  → §9.1 The honest benchmark position
- [ ] **PERF-023** Implement a tail-latency soak test (30+ minutes at sustained load).
  → §9.1 The honest benchmark position
- [ ] **PERF-024** Establish the profiling workflow (perf, samply, VTune) and document it.
  → §9.4 Specific optimizations planned
- [ ] **PERF-025** Implement the CPU-cost-per-request metric derived from fuel.
  → §10.2 Metrics that ship by default
- [ ] **PERF-026** Re-examine every performance claim at each milestone and correct it publicly when wrong.
  → §3.3 Where we win, where we lose, and where we might be lying to ourselves

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
- [ ] **OBS-002** Implement the append-only, hash-chained audit record.
  → §10.1 The three signals, plus one unique to QQQ
- [ ] **OBS-003** Implement SARIF export of the audit record.
  → §10.1 The three signals, plus one unique to QQQ
- [ ] **OBS-004** Implement the compliance-report export.
  → §10.1 The three signals, plus one unique to QQQ
- [ ] **OBS-005** Implement the default metric set.
  → §10.2 Metrics that ship by default
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
- [ ] **OBS-016** Implement the "prove what this code did" report generator.
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
| P0 Foundation | M0 | 74 |
| P1 Heartbeat | M1 | 64 |
| P2 Capability engine | M2 | 46 |
| P3 HTTP | M3 | 36 |
| P4 DX v0 | M4 | 44 |
| P5 Languages | M5, M8 | 40 |
| P6 Packages | M6 | 38 |
| P7 Agent face | M9 | 56 |
| P8 Perf/determinism/obs | continuous | 60 |
| P9 V1 release | M10, M11 | 76 |
| P10 Beyond V1 | post-1.0 | 34 |
| **Total** | | **586** |

**Coverage rule:** every section of `QQQ-Proposal-V1.md` carrying implementation work has at least one item above. The only Proposal sections with no items are §0.1–§0.2, §1.3, §3.3, §13.1 and the appendices, which are narrative, justification or registers rather than buildable work.

*End of `QQQ-Checklist-V1.md`.*
