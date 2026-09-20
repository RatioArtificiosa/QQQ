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
- [ ] **DOC-005** Add a `docs/README.md` index that explains the three-document system and how to keep them in sync.
  → §0.4 How to read the cross-references
- [x] **DOC-006** Build `tools/check-xrefs/` — the cross-reference validator described in the proposal.
  → Done: `tools/check_xrefs.py` — checks over the Proposal/Checklist/Observations graph.
  → §0.4 How to read the cross-references
- [x] **DOC-007** Wire `check-xrefs` into CI as a required check.
  → Done: `check_xrefs.py` and `self_test_xrefs.py` are both required steps in the `xrefs` CI job.
  → §0.4 How to read the cross-references
- [ ] **DOC-008** Document the anchor derivation and stability rules in `docs/contributing/anchors.md`.
  → §0.5 Identifier and anchor discipline
- [x] **DOC-009** Implement the stub-marker convention (`// QQQ-STUB(<ID>): …`) and a CI check that every stub marker has a matching Observations entry.
  → Done: `QQQ-STUB(<ID>)` markers are validated against checklist items by `check_xrefs.py` checks [7] and [11], including the bidirectional case, as a required CI step.
  → §0.5 Identifier and anchor discipline
- [ ] **DOC-010** Implement the tombstone convention for retired anchors and add a CI check that no anchor is silently deleted.
  → §0.5 Identifier and anchor discipline
- [ ] **DOC-011** Publish `docs/glossary.md` generated from the Proposal glossary, with anchors.
  → §0.6 Glossary
- [ ] **DOC-012** Add a CI check that every glossary term used in WIT doc comments exists in the glossary.
  → §0.6 Glossary
- [ ] **DOC-013** Maintain `docs/reconciliation.md` tracking every correction made to the source corpus, kept in sync with Appendix A.
  → §0.4 How to read the cross-references
- [ ] **DOC-014** Publish the vocabulary and claims rules as `docs/contributing/claims-policy.md`, and add a CI check that no unqualified performance claim appears without a benchmark reference.
  → §3.4 Positioning statement and the language we use
- [ ] **DOC-015** Add the "framework vs runtime" usage rule to the contributing guide.
  → §3.4 Positioning statement and the language we use
- [ ] **DOC-016** Publish `docs/verified-facts.md` as the live, dated register of external facts the project depends on, with a re-verification cadence.
  → §0.4 How to read the cross-references
- [ ] **DOC-017** Generate the WIT reference documentation from `wit/` into Markdown, with per-language examples.
  → §11.3 Documentation as a product surface
- [ ] **DOC-018** Build the documentation freshness test: compile a sample project against the published docs and fail on drift.
  → §2.6 NN-6 — Human + Machine Documentation Parity
- [ ] **DOC-019** Publish the error catalogue generator: every `QQQ-XXXX` code becomes a docs page with cause, fix and example.
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
- [ ] **LIC-006** Add SPDX headers to every source file and a CI check that they are present and correct.
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
- [ ] **LIC-012** Add a CI check that the runtime crates never depend on Fabric-licensed code in either direction.
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

- [ ] **ARCH-001** Write the layered-architecture ADR fixing the nine layers and the authority-flow invariant.
  → §4.1 The layer cake
- [ ] **ARCH-002** Implement and test the invariant that authority only narrows downward.
  → §4.1 The layer cake
- [ ] **ARCH-003** Implement the compile-time rule that a host function without a WIT definition cannot enter a release build.
  → §4.1 The layer cake
- [ ] **ARCH-004** Add an architecture test that no crate depends on a crate above it in the topology.
  → §4.3 Crate topology
- [ ] **ARCH-005** Write the process-and-thread-model ADR including the explicit rejection of a Tokio replacement.
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
- [ ] **ARCH-008** Enforce `#![forbid(unsafe_code)]` on every crate except the three named exceptions.
  → §4.3 Crate topology
- [ ] **ARCH-009** Write the safety argument document for each `unsafe`-permitting crate.
  → §4.3 Crate topology
- [ ] **ARCH-010** Publish the crate stability tiers and the API-stability contract per tier.
  → §4.3 Crate topology
- [ ] **ARCH-011** Implement the fifteen-step request lifecycle as an instrumented pipeline.
  → §4.4 Request lifecycle — the detailed path
- [ ] **ARCH-012** Implement the defence-in-depth re-check of grants at host-call time.
  → §4.4 Request lifecycle — the detailed path
- [ ] **ARCH-013** Write the guest-concurrency ADR fixing the async-single-threaded default.
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
- [ ] **HOST-011** Implement the panic hook converting host-function panics into traps, with severity-1 alerting.
  → Partial: the panic hook exists in the trap taxonomy; severity-1 alerting is not built.
  → Partial: the panic hook exists in the trap taxonomy; severity-1 alerting is not built.
  → §6.1 `qqq-host` — the execution engine
- [ ] **HOST-012** Implement pool-exhaustion backpressure with 503 and `Retry-After`, plus a saturation metric.
  → §6.1 `qqq-host` — the execution engine
- [x] **HOST-013** Implement the AOT `.cwasm` cache with digest+config keying and safe invalidation.
  → Done: `aot_cache_key` keys by component digest, target triple and engine config.
  → §9.4 Specific optimizations planned
- [x] **HOST-014** Implement cross-tenant compiled-module deduplication keyed by artifact digest.
  → Done: `digest_of` content-addresses an artifact, so one module backs many tenants.
  → §9.4 Specific optimizations planned
- [ ] **HOST-015** Use `*_async` Wasmtime APIs throughout, with the compile-time guard that prevents mixing sync and async.
  → §6.1 `qqq-host` — the execution engine
- [x] **HOST-016** Implement `epoch_deadline_async_yield_and_update` so a guest yield does not stall the reactor.
  → Done: Host functions registered per interface in `host_clock` and `host_crypto`.
  → §6.1 `qqq-host` — the execution engine
- [ ] **HOST-017** Implement the invariant that guest-visible blocking host functions bypass host cooperative budgets.
  → §4.2 Process and thread model
- [x] **HOST-018** Implement deterministic-mode engine configuration (NaN canonicalization, seeded RNG, fixed clock).
  → Done: `EngineConfig::deterministic` — fixed clock, seeded RNG, canonical NaN.
  → §10.5 Determinism — the feature nobody else has
- [ ] **HOST-019** Implement instance metrics: acquire latency histogram, pool occupancy, trap counts by code.
  → Partial: fuel and duration per execution; the acquire-latency histogram and pool occupancy gauge are not built.
  → Partial: fuel and duration per execution; the acquire-latency histogram and pool occupancy gauge are not built.
  → §10.2 Metrics that ship by default
- [ ] **HOST-020** Write the Wasmtime upgrade runbook and the compatibility-test suite.
  → §15 — Risk Register
- [ ] **HOST-021** Implement the module-preloading strategy for scale-out (compile on deploy, not on first request).
  → §9.4 Specific optimizations planned
- [ ] **HOST-022** Implement resource-handle table pooling and lifetime diagnostics.
  → §4.5 The ABI boundary — what crosses and at what cost
- [ ] **HOST-023** Implement `ResourcesRequired`-based admission control: refuse to load a component whose declared minimums exceed the host's capacity.
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
- [ ] **CON-007** Define the interface-versioning policy: SemVer per WIT package, `@since` mandatory.
  → Partial: WIT packages are semver'd `@1.0.0`; the `@since` policy is not enforced.
  → Partial: WIT packages are semver'd `@1.0.0`; the `@since` policy is not enforced.
  → §2.5 NN-5 — Explicit Contracts Over Implicit Behavior
- [ ] **CON-008** Implement the CI check that every published WIT function carries `@since`.
  → §2.5 NN-5 — Explicit Contracts Over Implicit Behavior
- [ ] **CON-009** Define and enforce the typed-error rule: every fallible host call returns `result<T, E>`.
  → §2.5 NN-5 — Explicit Contracts Over Implicit Behavior
- [ ] **CON-010** Implement the CI check that no host interface reads an environment variable or the working directory implicitly.
  → §2.5 NN-5 — Explicit Contracts Over Implicit Behavior
- [ ] **CON-011** Write the WIT style guide and enforce it in review.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth
- [ ] **CON-012** Enforce the batch-first rule: implement a lint that flags list-shaped operations accepting single elements.
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
- [ ] **CAP-014** Implement per-tenant grant isolation and prove no cross-tenant handle leakage.
  → Partial: per-tenant `TenantId` exists and grants are per-instance, but cross-tenant handle leakage is not yet proven by test.
  → Partial: per-tenant `TenantId` exists and grants are per-instance, but cross-tenant handle leakage is not yet proven by test.
  → §7.1 What we are defending, precisely
- [ ] **CAP-015** Implement capability-use accounting feeding the audit stream.
  → Partial: fuel and duration per execution are reported; capability-use accounting into an audit stream is not built.
  → Partial: fuel and duration per execution are reported; capability-use accounting into an audit stream is not built.
  → §10.1 The three signals, plus one unique to QQQ
- [ ] **CAP-016** Implement the `qqq:secrets` interface: use a secret without disclosing it.
  → Partial: `qqq:secrets` WIT exists and the manifest parses `secrets`; the host interface is not registered.
  → Partial: `qqq:secrets` WIT exists and the manifest parses `secrets`; the host interface is not registered.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth

### SEC — Security engineering

- [ ] **SEC-001** Write the threat model document covering §7.1 assets and §7.2 adversaries.
  → §7.1 What we are defending, precisely
- [ ] **SEC-002** Implement the rule that an ungranted import is absent, not merely denied, and prove it by test.
  → §7.3 The defence timeline — where we stop an attack
- [ ] **SEC-003** Implement manifest capability validation with a deny-by-default posture throughout.
  → §7.2 Adversary model
- [ ] **SEC-004** Build the hostile-guest test suite (≥200 cases) with a specified expected failure for each.
  → §7.2 Adversary model
- [ ] **SEC-005** Implement memory-limit enforcement and prove the host survives a guest OOM.
  → §7.2 Adversary model
- [ ] **SEC-006** Implement fuel-limit enforcement and prove the host survives fuel exhaustion.
  → §7.2 Adversary model
- [ ] **SEC-007** Implement epoch-deadline enforcement and prove the host survives a non-terminating guest.
  → §7.2 Adversary model
- [ ] **SEC-008** Implement handle-count limits and prove the host survives handle exhaustion attempts.
  → §7.2 Adversary model
- [ ] **SEC-009** Implement subrequest limits to prevent guest-driven request amplification.
  → §7.2 Adversary model
- [ ] **SEC-010** Implement path-traversal defences at the capability boundary, with a test corpus.
  → §7.2 Adversary model
- [ ] **SEC-011** Implement input validation at every guest-to-host boundary crossing.
  → §2.2 NN-2 — Security and Isolation Are Non-Optional
- [ ] **SEC-012** Establish the fuzzing programme covering the host interfaces, manifest parser and component loader.
  → §2.2 NN-2 — Security and Isolation Are Non-Optional
- [ ] **SEC-013** Add `cargo-fuzz` targets to CI with a nightly fuzzing schedule.
  → §2.2 NN-2 — Security and Isolation Are Non-Optional
- [ ] **SEC-014** Establish the Wasmtime advisory-tracking process with a 72-hour patch target (`R-04`).
  → §15 — Risk Register
- [ ] **SEC-015** Implement the per-dependency capability diff display at install time.
  → §5.4 The lockfile — `qqq.lock`
- [ ] **SEC-016** Implement slow-loris, header-bomb and body-bomb mitigations with tests.
  → §6.4 `qqq-serve` — the HTTP and application server
- [ ] **SEC-017** Implement the cryptographic-posture policy: named algorithms, no silent defaults, no agility without a version bump.
  → §7.4 Cryptographic posture
- [ ] **SEC-018** Implement the host CSPRNG with no guest-supplied seed outside deterministic test mode.
  → §7.4 Cryptographic posture
- [ ] **SEC-019** Implement Linux hardening: dropped privileges, `no_new_privs`, seccomp allowlist.
  → §7.5 Hardening beyond Wasm
- [ ] **SEC-020** Audit every `unsafe` block in the three exception crates and record the findings.
  → §4.3 Crate topology
- [ ] **SEC-021** Track post-quantum hybrid TLS (X25519+ML-KEM) as an opt-in, with a standards-watch task.
  → §7.4 Cryptographic posture
- [ ] **SEC-022** Implement the optional egress proxy with per-tenant policy.
  → §7.5 Hardening beyond Wasm
- [ ] **SEC-023** Establish the responsible-disclosure process and a public security-advisory feed.
  → §7.2 Adversary model
- [ ] **SEC-024** Commission external security audit #1 before the private alpha (M7).
  → §16 — Definition of Done for V1
- [ ] **SEC-025** Commission external security audit #2 before the public beta (M10).
  → §16 — Definition of Done for V1
- [ ] **SEC-026** Implement Landlock LSM integration as defence in depth on Linux ≥ 5.13.
  → §7.5 Hardening beyond Wasm
- [ ] **SEC-027** Implement memory-protection-key support as an optional hardening feature.
  → §7.5 Hardening beyond Wasm
- [ ] **SEC-028** Produce and publish the SBOM for every release.
  → §7.3 The defence timeline — where we stop an attack
- [ ] **SEC-029** Implement the distroless, read-only, non-root container image.
  → §7.5 Hardening beyond Wasm
- [ ] **SEC-030** Publish the explicit out-of-scope section (host admin, side channels, physical, volumetric DoS).
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
- [ ] **SRV-007** Implement TLS with rustls and the documented cipher policy.
  → §6.4 `qqq-serve` — the HTTP and application server
- [ ] **SRV-008** Implement mTLS as a supported `default_auth` mode.
  → §6.4 `qqq-serve` — the HTTP and application server
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

- [ ] **ABI-001** Author `qqq:http@1.0` including routing, streaming and client.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth
- [ ] **ABI-002** Author `qqq:fs@1.0` with opened directories, handles, metadata and watch.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth
- [ ] **ABI-003** Author `qqq:sql@1.0` with pooled connections, prepared statements and transactions.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth
- [ ] **ABI-004** Author `qqq:kv@1.0` with namespacing, TTL and scan.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth
- [ ] **ABI-005** Author `qqq:queue@1.0` with publish, subscribe via `stream`, and ack.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth
- [ ] **ABI-006** Author `qqq:crypto@1.0` with random, hash, hmac, aead, sign/verify and key derivation.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth
- [ ] **ABI-007** Author `qqq:clock@1.0` with wall, monotonic, timers and controllable sleep.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth
- [ ] **ABI-008** Author `qqq:log@1.0` with structured, levelled logging and tenant attribution.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth
- [ ] **ABI-009** Author `qqq:trace@1.0` with spans, events and W3C context propagation.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth
- [ ] **ABI-010** Author `qqq:secrets@1.0` implementing use-without-disclosure.
  → §6.3 `qqq-abi` — WIT interfaces as the single source of truth
- [ ] **ABI-011** Author `qqq:test@1.0` with assertions and capability assertions.
  → §6.7 `qqqai test` — test runner
- [ ] **ABI-012** Author `qqq:agent@1.0` for self-description and structured progress.
  → §8.3 The machine contract layer
- [ ] **ABI-013** Author `qqq:ai@1.0` (interface only; implementation deferred to `FUT-007`).
  → §6.9 `qqq:ai` — local inference as a capability
- [ ] **ABI-014** Implement `qqqai bindings` generating every language's types from `wit/`.
  → §2.4 NN-4 — Multi-Language by Design
- [ ] **ABI-015** Implement the CI drift check between `wit/` and all generated bindings.
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
