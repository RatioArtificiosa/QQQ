# QQQ — Observations & Memories

> **Institutional memory for the QQQ project.** Decisions and their reasons, mistakes and their fixes, verified facts, corrections, open threads, and things that must not be forgotten.
>
> **Rule:** if it would cost someone an hour to rediscover, it belongs in this file.

| Field | Value |
|---|---|
| **Document** | QQQ-Observations-and-Memories.md |
| **Version** | 1.0.0 |
| **Status** | Living document — append-only for the decision log; sections 1–4 may be edited |
| **Date opened** | 2026-09-19 |
| **Companion** | [`QQQ-Proposal-V1.md`](./QQQ-Proposal-V1.md) · [`QQQ-Checklist-V1.md`](./QQQ-Checklist-V1.md) |

**Conventions used here**

| Prefix | Meaning |
|---|---|
| `§D-nnn` | **Decision** — made, with rationale. Changing one requires an ADR. |
| `§O-nnn` | **Observation** — a fact learned, often the hard way. |
| `§M-nnn` | **Mistake** — something that went wrong, and the fix. |
| `§C-nnn` | **Correction** — a claim in the source corpus that is wrong or unverifiable. |
| `§S-nnn` | **Stub / pending** — deliberately unfinished, with the reason and the successor item. |
| `§Q-nnn` | **Open question** — awaiting a human decision. Mirrors Proposal Appendix C. |

---

## 1. NEEDS YOUR ATTENTION

Items that require the founder specifically. Reviewed and pruned at every milestone.

| # | Item | Why it needs you | Blocking |
|---|---|---|---|
| 1 | **Ratify the licence model** (Proposal §13.2, `§D-004`) | It is a business decision with legal consequences. The conflict between NN-8 and the tiered-pricing instruction is real and only you can resolve it. | `LIC-001` … `LIC-011` |
| 2 | **Trademark clearance on "QQQ"** (`§Q-008`, `MKT-014`) | "QQQ" is strongly associated with the Invesco QQQ ETF in finance and tech circles. This needs a lawyer, not an engineer. | `LIC-008`, launch |
| 3 | **Approve the budget envelope** (Proposal §14.3) | ~$2.3M–$4.5M to V1.0 over ~23 months. This is the honest number and it must be accepted or the scope must be cut. | `PLAN-005`, `PLAN-006` |
| 4 | **Approve the cut order** (Proposal §14.4) | Pre-agreeing the cut list is what makes scope cuts mechanical rather than emotional. | `PLAN-007`, `DOD-024` |
| 5 | **Recruit a second maintainer** (`R-15`) | Bus factor is currently 1. This is the risk most likely to kill the project, and it is not technical. | `GOV-008` |
| 6 | **Decide the four "loud" open questions** (`§Q-002` TypeScript naming, `§Q-003` Python tier, `§Q-004` Windows, `§Q-008` Fabric licence) | Each changes public promises. They are cheap now and expensive later. | M4/M5 |

---

## 2. DECISIONS

### §D-001 — Product name is **QQQ**; technical surfaces are `qqqai`

**Decision.** Product/brand: **QQQ**. CLI binary, crates.io package, npm package: **`qqqai`**. Domain: **qqq.codes**.

**Why.** Empirically verified availability (Proposal Appendix B, B-15 … B-19):

| Name | crates.io | npm | GitHub | Verdict |
|---|---|---|---|---|
| `qqq` | **TAKEN** (v0.2.0, 131 downloads) | **TAKEN** (v0.0.6) | **TAKEN** (personal user `qqq`) | Unusable as an install name |
| `qqqai` | **FREE** | **FREE** | **FREE** | Chosen |
| `qqq-codes` | free | free | — | Fallback only |
| `qx3` | free | free | **TAKEN** (organization) | Rejected |

**Consequence.** `cargo install qqqai` and `npm install -g qqqai` both work and both are claimable today. The trade-off is five characters typed instead of three; the alternative was a name collision with an existing crate and an unreachable npm namespace.

**Binding detail.** The *binary* inside the `qqqai` crate is named `qqqai`, not `qqq`. Do not "fix" this later — `qqq` on PATH is not ours to take.

**Founder clarification (2026-09-19, recorded verbatim in substance).** The founder confirmed: the crate/package name published to crates.io **is `qqqai`**, precisely because `qqq` is taken there. This is a *deliberate, permanent* decision, not a workaround awaiting a better option.

Two distinct identifiers must never be conflated:

| Identifier | Value | Where it appears | Changeable? |
|---|---|---|---|
| **Brand / product name** | **QQQ** | README, website, docs, marketing, conversation | No |
| **Crate / package name** | **`qqqai`** | `Cargo.toml` `[package] name`, crates.io, npm | **No — this is settled** |
| **Binary / command name** | **`qqqai`** | `[[bin]] name`, every command in every doc (`qqqai new`, `qqqai dev`, …) | **No — this is settled** |
| **Rust crate identifiers** | `qqq_core`, `qqq_cap`, `qqq_host`, … | `use` statements, workspace members | No |
| **Domain** | `qqq.codes` | Install URLs, docs site, registry | No |

**Implementation rule for every future contributor and agent.** When writing code, manifests, tests, scripts, CI, install commands or documentation:

- Use **`qqqai`** for anything that is *executed* or *installed*.
- Use **`QQQ`** only for prose and branding.
- Use **`qqqai/`** for the package namespace in WIT interfaces and registry paths (e.g. `qqqai/json`), never `qqq/`.
- Never write `cargo install qqq`, `npm i -g qqq`, `brew install qqq`, or a binary named `qqq`. **A build that produces a `qqq` binary is a defect**, not a convenience.

**Why this is recorded so emphatically.** The single most likely future regression in this project is an agent or contributor "helpfully" shortening `qqqai` to `qqq` for aesthetics — which would collide with an existing crates.io package and an existing npm package, making the release unpublishable. There is now a checklist item (`DIST-004`) and this note so the mistake is caught before it ships.

**Cross-refs:** Proposal §0.1, §5.1, §5.2, Appendix B; Checklist `DIST-004`, `DIST-005`, `CON-013`.

---

### §D-002 — V1 supports five languages: Rust, TypeScript/AssemblyScript, Go, Python, C/C++

**Decision.** All five are "first-class" in the sense that all five must pass the identical conformance suite, with gaps published in a generated parity matrix rather than hidden.

**Why these five.** Each covers a distinct buying centre: Rust (performance/systems), TypeScript (the largest developer population and the Node/Bun audience), Go (cloud-native and infrastructure), Python (AI/data — and the single strongest differentiator against Node/Bun, neither of which can run Python), C/C++ (systems, legacy, codecs).

**Honest tiering** (Proposal §6.10): Rust and C/C++ are Tier A; AssemblyScript is Tier A *as AssemblyScript* but is not full TypeScript; Go is Tier B (TinyGo); Python is Tier B with real risk of being Tier C.

**Rejected alternative:** Rust + TS + Go only. Rejected because dropping Python removes the most compelling "Node and Bun cannot do this at all" argument.

**Cross-refs:** Proposal §2.4, §6.10; Checklist `LANG-001` … `LANG-040`.

---

### §D-003 — Execution engine is Wasmtime, pinned to the 48.x line

**Decision.** Host on **Wasmtime 48.x** (verified latest stable at time of writing: **48.0.2**, published 2026-09-10). `49.0.0-rc.1` exists but is a release candidate and is not adopted.

**Why Wasmtime over Wasmer or a bespoke engine.** It is the Bytecode Alliance reference implementation, Apache-2.0 WITH LLVM-exception, 18.6k stars, actively pushed (last push verified 2026-09-18), the only engine with Tier 1 `component-model` support and full WASI Preview 2/3 coverage, and it passes the official WebAssembly test suite. Writing our own engine would consume the entire budget and produce a worse result.

**Consequence accepted.** We inherit Wasmtime's release cadence and its CVE exposure. Mitigations: a recurring quarterly upgrade sprint (`PLAN-012`), a 72-hour patch target on advisories (`SEC-014`), and all churn isolated behind `qqq-abi` (`R-03`, `R-14`).

**Cross-refs:** Proposal §6.1, §15, Appendix B (B-1 … B-4, B-12, B-13); Checklist `HOST-001` … `HOST-024`, `ARCH-005`.

---

### §D-004 — Licence model is open core with a **governance** boundary, not a user-count boundary

> ⚠️ **This decision resolves a genuine conflict in the instructions. It is the most consequential non-technical decision in this corpus.**

**The conflict.** `docs/Notes.txt` Non-Negotiable #8 says: *"Open source with a clear, permissive license (MIT or Apache-2.0 recommended)."* The founder's later instruction says: *"free for individuals and sole entrepreneurs, but has a fee for small businesses to enterprises."* These cannot both be satisfied by a single licence: no OSI-approved licence can charge by company size.

**Decision (Option C).**

| Layer | Licence | Free for | Paid for |
|---|---|---|---|
| `qqqai` runtime, CLI, SDKs, package manager, all runtime crates | **Apache-2.0** | Everyone, forever, including commercial use | — |
| **QQQ Fabric** (separate repository): org policy, fleet attestation, SSO/RBAC, compliance evidence, air-gapped mirror | **Commercial / Business Source** | Individuals, solo developers, non-profits, companies under $2M revenue | Companies above that threshold |
| Commercial support & indemnification | Contract | — | Everyone who wants it |

**Why not pure MIT/Apache (Option A).** It gives away the only monetisable layer. The precedents are unambiguous: Redis, Elastic, MongoDB and HashiCorp all relicensed away from permissive licences because a hyperscaler could resell their work. Committing to pure permissive for the *whole* stack would mean choosing to have no business.

**Why not a user-count licence on the runtime (Option B).** It kills bottom-up adoption, which is the only adoption a runtime gets. Node and Bun won because an engineer could `npm install` without asking legal. A licence that requires procurement review *before the binary runs* means nobody ever runs it. This would satisfy the pricing instruction and destroy the product.

**Why C works.** The boundary sits exactly where enterprises actually pay — **governance, evidence, liability, support** — and never at "may I execute code". The runtime stays genuinely open source (satisfying NN-8); the commercial layer is additive (satisfying the business instruction). Crucially, an individual gets *everything* including Fabric, which is what the instruction asked for.

**Honest caveat, recorded deliberately.** Fabric is **not** OSI open source, and the project must say so plainly rather than using weasel language. The docs will not call Fabric "open source".

**Pre-committed fallback.** If community pressure or market reality demands it, the fallback is a fair-source licence with a change date. This is written down *now*, while there is no pressure, so the decision is never made in a hurry. (`LIC-011`)

**Not legal advice.** All licence texts require review by counsel before publication.

**Cross-refs:** Proposal §2.8, §13.2; Checklist `LIC-001` … `LIC-012`; Observations `§Q-008`.

---

### §D-005 — Keep Tokio; do not rewrite the async reactor

**Decision.** Portable default is Tokio's multi-threaded runtime with a **sharded acceptor**. io_uring is an opt-in Linux backend behind a flag, adopted only if it earns its complexity with measured results.

**Why.** The source conversation explicitly asked whether Tokio or a thread-per-core runtime (monoio/glommio) is better. The answer is that monoio/glommio are **Linux-only** — io_uring does not exist on macOS or Windows — so adopting them as the only backend would make QQQ unable to run on two of its five target platforms. The sharded acceptor recovers most of the thread-per-core benefit (a connection is accepted and served on the same core, so there is no cross-core handoff on the common path) while remaining portable.

**Explicitly rejected:** rewriting the reactor. It is a multi-year detour with no differentiation. *The differentiation is the capability layer, not the event loop.*

**Cross-refs:** Proposal §4.2; Checklist `ARCH-005`, `ARCH-006`, `PERF-014`.

---

### §D-006 — Default guest concurrency is async-single-threaded

**Decision.** The recommended and default guest model is one logical task per request using Component Model `async`/`future`/`stream`. Shared-memory Wasm threads are permitted only behind an explicit manifest opt-in. Cooperative threads are not enabled in V1.

**Why.** One memory per task preserves the strongest isolation guarantee, keeps fuel accounting exact, and matches how request-scoped work actually looks. Density — many instances — replaces threads. Shared linear memory undermines per-instance accounting, which is a core security property.

**Cross-refs:** Proposal §4.7; Checklist `ARCH-013`, `ARCH-014`, `DET-012`, `OQ-005`.

---

### §D-007 — Determinism is a headline feature, not a testing convenience

**Decision.** Deterministic mode (fixed clock, seeded RNG, deterministic scheduler, NaN canonicalization, ordered maps, replay log) is a **product feature** that ships in V1 and is marketed as such.

**Why.** No competing runtime can offer it, because Node and Bun cannot control the nondeterminism their own engines and GC introduce. It enables replay debugging, reliable property testing, and — commercially — **auditable AI-agent actions**, where you can replay exactly what an autonomous system did. It is also the direct enabler of `qqqai test --trials N` and `--replay`.

**Cross-refs:** Proposal §10.5; Checklist `DET-001` … `DET-016`.

---

### §D-008 — Every host capability is a WIT interface first, a language binding second

**Decision.** If a feature cannot be expressed in WIT, it does not ship. This is recorded as an architectural invariant with a CI check.

**Why.** This single rule is what makes the multi-language claim *structural* rather than aspirational. It also means an agent can read one interface definition and generate correct code in any of the five languages.

**Cross-refs:** Proposal §1.3, §4.1, §6.3; Checklist `ARCH-003`, `ABI-001` … `ABI-016`, `LANG-039`.

---

### §D-009 — README is a sales surface, written to the "premium tech" standard

**Decision.** The GitHub README is treated as the product's front page: benefit-led, not feature-led; visually striking in a terminal-aesthetic register; and psychologically structured to create urgency without lying.

**Brief used:**
- **Hook** in the first screen: the one-sentence positioning plus three hard numbers.
- **The problem** stated as a felt pain (GC pauses, memory bills, agent code you cannot trust), not as a spec.
- **The proof** — benchmarks with methodology, and an explicit "where we lose" section. Counter-intuitively, publishing losses is the strongest credibility signal available.
- **The five-minute path** — copy-pasteable, no prerequisites.
- **The differentiators** framed as *what this unlocks for you*, never as a feature list.
- **Trust** — the eight principles, the threat model, the licence in plain language.
- **An explicit urgency mechanism** — the agent-sandbox capability gap is closing and the cost of the current approach is measurable today.
- **Honest status** — a pre-1.0 banner. Overclaiming at this stage would permanently damage the credibility the project's whole strategy depends on.

**Constraint:** the README must pass the same claims policy as every other surface (`DOC-014`) — no unqualified performance claim without a benchmark reference.

**Cross-refs:** Checklist `DOC-001`, `POS-001`, `POS-004`, `MKT-013`.

---

## 3. OBSERVATIONS

### §O-001 — The target repository is completely empty

**Observed.** `RatioArtificiosa/QQQ` is public, created 2026-09-18T01:26:52Z, `isEmpty: true`, no branches, no commits, no licence, no topics.

**Implication.** There is no history to preserve and no prior structure to respect. The first commit establishes every convention, so it must be correct. `FND-001` … `FND-010` all land in that first commit.

---

### §O-002 — The workspace contains only three documents

**Observed.** `E:\QQQ` contained only `docs/` with `Notes.txt` (55 lines), `QQQAI-Conversation-Full.md` (213 lines) and `QQQAI-Full-Conversation-Complete.md` (1,032 lines).

**Implication.** The instruction to read *"the text file"* was ambiguous — there is no other text file. Resolved by treating `docs/Notes.txt` as the intended artifact, since it contains the eight non-negotiables that the entire brief references repeatedly and that `QQQAI-Full-Conversation-Complete.md` explicitly cites as the project's foundation. **Recorded here in case that reading was wrong.**

---

### §O-003 — Local toolchain inventory (verified, not assumed)

| Tool | Present | Version / note |
|---|---|---|
| `rustc` / `cargo` | ✅ | 1.97.1 |
| `rust-analyzer` | ✅ | 1.97.1 (also a VS Code extension, 3 versions installed) |
| `cargo-clippy` | ✅ | present |
| `cargo-deny` | ✅ | present, useful for the licence allowlist (`LIC-007`) |
| `cargo-machete` | ✅ | present, useful for unused-dependency CI (`FND-005`) |
| `wasm-tools` | ❌ | **not installed** — needed for artifact inspection (`FND-012`) |
| `wasmtime` CLI | ❌ | **not installed** |
| Installed Rust targets | ⚠️ | only `x86_64-pc-windows-msvc`; `wasm32-wasip2` must be added |
| Node | ✅ | v22.22.0 |
| Bun | ✅ | 1.3.14 — useful for competitor benchmarking (`MKT-010`) |
| Python | ✅ | 3.13.2 |
| `gh` CLI | ✅ | 2.96.0, authenticated as `RatioArtificiosa` with `repo`, `workflow`, `gist`, `read:org` |
| `git` | ✅ | 2.49.0.windows.1 |

**Action recorded:** `FND-012` adds the missing tools to the developer bootstrap script, and the `wasm32-wasip2` target to the documented setup.

---

### §O-004 — The DSH session and the QQQ project are on different working directories

**Observed.** The agent's working directory is `E:\QQQ`; the DSH web GUI being used is served at port 3090 and the browser bridge's session belongs to a *different* project (`RobinHorde`, session `91d0a2b7…`).

**Implication.** Browser tools attached to that session address the wrong project's page. Do not use the browser bridge for QQQ verification unless a QQQ session is explicitly attached. Use shell and file tools instead.

---

### §O-005 — A pre-existing autonomous timer job belongs to a different project
**Observed.** `~/.dsh/timer-agent/jobs.json` contains one job, `keep-working`, scheduled `*/5 * * * *`, targeting `G:\RobinHorde` and session `91d0a2b7-1904-4d43-8c5e-8fd5fec13b73`.

**Two implications, both important:**

1. **It is not ours.** It must not be modified, paused, or repurposed for QQQ. It belongs to another project's workflow.
2. **It contains a warning worth heeding.** Its recent execution history shows five consecutive failures with `pi-ai stream idle timeout after 300000ms`. The job's own prompt explains the cause: *"if a command will run longer than ~2 minutes, start it as a background job and poll it in short steps instead of blocking on it. A long silent foreground command gets this turn killed by the idle timeout."*

**Applied here.** All long-running builds in this session (`cargo check`, `cargo run`) were started as background jobs and polled, rather than blocking a foreground turn. This is the reason the `cargo` probe runs did not kill the session.

**Cross-refs:** `§M-002`.

---

### §O-006 — ⭐ All four architectural load-bearing claims were verified against the real toolchain

**What was done.** Rather than asserting that the proposal's core mechanics work, a throwaway probe crate (`.scratch/witprobe`, marked `QQQ-STUB(FND-011)`) was built against **Wasmtime 48.0.2** on **rustc 1.97.1** and run. It tests the four claims the entire architecture rests on.

**Results — all four verified:**

| # | Claim | Proposal ref | Result |
|---|---|---|---|
| 1 | An ungranted import must fail **instantiation**, and name the missing import | §4.4, §7.3, §6.1 | ✅ Rejected with: *"component imports instance `host:probe/greeter`, but a matching implementation was not found in the linker: instance export `greet` has the wrong type: function implementation is missing"* |
| 1b | **Control case:** the same shape with a satisfied import instantiates and runs | (guards claim 1) | ✅ Instantiated, returned `42` — proving claim 1 fails for the right reason, not because the harness is broken |
| 2 | Instantiation cost is in the microsecond range | §9.2 | ✅ **min 700 ns, p50 800 ns, p99 2.1 µs** (n=500) |
| 3 | Fuel exhaustion traps the **guest**, and the host survives | §6.1 | ✅ Trapped on fuel; the host then successfully ran a different guest on the same engine |
| 4 | Epoch preemption interrupts a non-terminating guest | §6.1 | ✅ Infinite guest interrupted after **50.3 ms** (epoch bumped from another thread after a 50 ms sleep) |

**Why claim 1b matters more than it looks.** Without the control, claim 1 could have been passing because the harness itself was broken. The control proves the negative result is caused by the missing import specifically. **This pattern — always pair a negative assertion with a positive control — should be mandatory for every security test in the project, and is recorded as a standard for `SEC-004`.**

**The headline number.** Claim 2 measured a **fresh `Store` per sample with no pooling allocator** — the worst realistic case. The proposal budgeted ≤100 µs p99 for the *pooled* path. The measurement is roughly **50× better than budget**, and the pooling allocator (`HOST-004`) only improves it.

**Consequence for the product argument.** The commercial thesis in §3.3 and §8.4 rests on per-request isolation being cheap enough to be the default. That is no longer an assumption. At sub-microsecond instantiation, "one isolated instance per request" is not a performance compromise; it is free. **This is the single strongest piece of evidence the project currently has**, and it should be the first thing shown to a sceptical platform engineer.

**Caveats, stated honestly.** This measured **instantiation only**, on one machine (Windows x86_64), with a trivial component. It says nothing about request throughput, guest execution speed, or the ABI crossing costs in §9.3. Those remain unmeasured, and `PERF-003` … `PERF-013` must not be treated as met.

---

### §O-007 — The Component Model's low-level WAT is genuinely hard, which validates the `qqq-abi` design

**Observed.** Writing a *correct* component by hand in WAT took four iterations, each rejected with a precise but non-obvious error. The four traps, in order:

1. **A core instance cannot import a component function.** Core instances import *core* functions. The correct shape is that the core module imports a core-level func, and a `canon lower` of the component-level import satisfies it.
2. **`canon lower` of a function using `string` requires explicit canonical options.** Omitting them produced: *"canonical option `memory` is required"*. Strings are lowered through linear memory, so a memory must be named.
3. **Component-model index syntax is now strict.** Instance export references must be nested and core-typed: `(memory (core memory $i "mem"))` and `(core func $i "realloc")`, not the legacy `(memory $i "name")` / `(func $i "realloc")`. The error names the escape hatch (`WAST_STRICT_COMPONENT_INDICES=0`) for accepting old syntax.
4. **A memory/realloc used by `canon lower` must come from an already-instantiated instance.** This makes the single-module shape circular and unsolvable; the fix is **two core modules** — one providing memory and realloc, one importing the lowered function.

**Why this is important, not just trivia.** These four details are exactly what a user of QQQ should never see. They are the strongest possible argument for the `qqq-abi` design rule (`§D-008`): **WIT is the source of truth and every binding is generated.** If a human must know that `canon lower` needs a `realloc` from a *different* instance than the one it feeds, then an AI agent will get it wrong most of the time. Generated bindings are not a convenience; they are the load-bearing wall of both the multi-language and the agent-native claims.

**Action.** These four findings belong in `qqq-abi`'s internal design notes for `ABI-014` (binding generation), so the generator emits the correct shapes from day one. Recorded here so nobody rediscovers them.

---

### §O-008 — Two Wasmtime 48 API differences from commonly-cited examples

**Observed during the probe build.**

1. **`Engine::is_async()` does not exist in Wasmtime 48.** The first probe used it to assert host liveness and failed to compile. Async-ness is a property of the *Store* and call site, not of the `Engine`. The probe now proves host liveness by running another guest on the same engine after a trap — which is a **better test anyway**, because it exercises real behaviour instead of introspection.
2. **`Context`/`context()` comes from `wasmtime::error::Context`, not `anyhow`.** Wasmtime ships its own error types (`wasmtime::Error`, `wasmtime::Result`), and the idiomatic `.context(...)` extension trait is re-exported from there.

**Consequence for `qqq-host`.** Standardise on `wasmtime::Result`/`wasmtime::Error` at the host boundary rather than introducing a second error type. The probe now depends on `wasmtime` alone.

---

### §O-009 — Implementation began: `qqq-core` is real, tested, and lint-clean

**What was built.** The first functional crate. `crates/qqq-core` is no longer a
stub: it implements the error model (37 stable codes across the seven classes,
with docs URLs, cause chains, remediation and retryability), the identifier
newtypes (`TenantId`, `ComponentId`, `PackageName`) and the version type.

**Verification — actual commands, actual output:**

| Command | Result |
|---|---|
| `cargo test -p qqq-core` | **35 tests pass**, 1 doc-test passes |
| `cargo clippy -p qqq-core --all-targets -- -D warnings` | **clean**, with `clippy::pedantic` enabled workspace-wide |

**Design decisions taken during implementation, recorded so they are not
re-litigated:**

1. **Errors are data structures, not messages.** `Error` carries `code`,
   `message`, `cause[]`, `remediation` and ordered `context[]`. The doc comment
   on `message` states explicitly that it is **unstable** and must not be
   parsed — because wording will improve and an agent that parses prose is
   making a mistake we should not encourage. Match on `code`.
2. **`is_retryable()` is derived from the error class, not per-code.** Only
   `Package` and `Host` retry. A guest trap is deliberately *not* retryable:
   the same input traps identically, and a caller retrying with different input
   is making a product decision, not a retry.
3. **Identifiers are newtypes with validation.** This is a security control: a
   package name reaches filesystem paths, so `../etc/passwd`, `a/b` and `a\0b`
   are rejected at construction. Tested directly.
4. **The naming decision is now executable.** `BINARY_NAME = "qqqai"` and
   `BRAND_NAME = "QQQ"` are constants, and `naming_constants_match_the_recorded_decision`
   asserts them — including an explicit `assert_ne!(BINARY_NAME, "qqq")` with the
   reason in the message. A future contributor who shortens the name must
   delete a documented constant and break a named test.

**Codes are enforced, not merely documented.** Seven tests police the table:
codes are unique, sorted, class-consistent, round-trip from both number and id,
and the seven examples printed in Proposal §8.3 actually resolve. Adding a code
incorrectly now fails the build rather than shipping a broken contract.

**Cross-refs:** Checklist `ARCH-007`, `ARCH-008`, `CON-009`, `CON-016`,
`AGENT-021`, `AGENT-022`; Proposal §4.3, §8.3, §12.2.

---

## 4. MISTAKES AND FIXES

### §M-001 — Proposal was written as a stub part-file and then extended

**What happened.** The first `write` of `QQQ-Proposal-V1.md` covered only §0–§3 and ended with *"End of Part 1"*, intending to append later. That would have left a deliverable in an incomplete state if the session had ended.

**Fix.** The file was completed in the same session by replacing the Part 1 footer with the full §4–§17 body and the three appendices. **Lesson:** never leave a named deliverable in a partial state; a document that says "continued later" is a broken promise, not a work in progress.

---

### §M-002 — Background jobs were used for long compiles; foreground would have been killed

**What happened.** Type-checking Wasmtime pulls a large dependency tree and takes minutes. Run in the foreground, a long silent command gets the turn killed by the 300-second stream idle timeout (observed repeatedly in `§O-005`).

**Fix.** `cargo check` and `cargo run` were launched with `run_in_background: true` and polled with `job_output`. **Lesson:** on this machine, any build expected to exceed ~2 minutes must be a background job. Recorded here so the next engineer does not rediscover it by losing a turn.

---

### §M-003 — The first probe manifest was written to the wrong filename

**What happened.** The scratch crate's manifest was written to `.scratch/witprobe/probe.toml` instead of `Cargo.toml`. `cargo check --manifest-path .scratch/witprobe/Cargo.toml` then failed with:

```
error: manifest path `E:\QQQ\.scratch\witprobe\Cargo.toml` does not exist
```

**Fix.** Renamed to `Cargo.toml` and re-run. **Lesson:** the failure was reported as a missing file rather than as a bad name, which is easy to misread as "the directory does not exist". When Cargo reports a missing manifest immediately after a write, check the filename before checking the path.

---

### §M-004 — Four consecutive WAT errors while building the verification probe

**What happened.** The probe's claim-1 component was written in hand-authored WAT and rejected four times in a row. Each error was correct and each took a build-and-run cycle to surface. The full technical explanation is in `§O-007`; recorded here as a process lesson.

| Attempt | Error | Root cause |
|---|---|---|
| 1 | *"unknown core func: failed to find name `$greet`"* | A core instance was wired to a lifted **component** function. Core instances import core functions. |
| 2 | *"canonical option `memory` is required"* | `canon lower` of a `string`-using function needs an explicit memory. |
| 3 | *"an export name must be written inside a nested reference"*, then *"the `core` keyword is required in this reference"* | Component-model index syntax was tightened; both the nesting **and** the `core` keyword are now mandatory. The compiler supplied the exact escape hatch (`WAST_STRICT_COMPONENT_INDICES=0`). |
| 4 | *"unknown core function 1: function index out of bounds"* | The memory/realloc used by `canon lower` must come from an **already-instantiated** instance, which makes the original single-module shape circular. Correct shape: **two core modules**. |

**Fix.** Restructured into two core modules: `$mem` provides the linear memory and `realloc`; the component-level import is lowered using `$mem`'s memory and realloc; a second module `$m` imports the lowered function and calls it. All four claims then passed.

**Lessons, all three of which are now project standards:**

1. **Hand-writing component WAT is a trap.** Budget two to four iterations for anything non-trivial. This is now the primary argument for `ABI-014` (generated bindings) — recorded in `§O-007`.
2. **Read the compiler's suggested fix literally.** In attempt 3 the error message named the exact syntax *and* the escape hatch. Copying the prescribed form resolved it in one pass; guessing would have cost another cycle.
3. **When a shape is circular, the answer is usually a split, not a reorder.** Attempt 4 was not a syntax problem at all — no ordering of a single module could work. Recognising "this is structurally impossible" rather than "this is written wrong" is what ended the loop.

---

### §M-005 — An `edit` failed because the file had changed since it was read

**What happened.** After running `tools/fix_corpus.py` and `tools/fix_corpus2.py`, both of which rewrite `QQQ-Proposal-V1.md` and `QQQ-Checklist-V1.md`, a subsequent `edit` on the proposal was rejected: *"file changed since it was read — re-read the file, then retry"*.

**Fix.** Re-read the region and retried. **Lesson:** any script that rewrites a document invalidates prior reads of it. After running a corpus-mutation tool, always re-read before editing. This will recur every time `fix_corpus*.py` is used, so those scripts should be considered read-invalidating.

---

### §M-006 — The cross-reference validator had never been proven to detect anything

**What happened.** On review, `tools/check_xrefs.py` reported `validation PASSED` — but nothing had ever demonstrated that it *fails* when the corpus is actually broken. A validator that cannot fail is worse than no validator, because it manufactures false confidence. This is the same failure mode as a security test with no positive control (`§O-006`).

**Fix.** Built `tools/self_test_xrefs.py`, a fault-injection harness that deliberately breaks the corpus in seven distinct ways, asserts the validator rejects each one, and restores the files afterwards. Result: **7/7 detected**, baseline restored clean.

| # | Injected fault | Check that caught it |
|---|---|---|
| 1 | Proposal cites `HOST-999` | `[2]` dangling checklist ID |
| 2 | Checklist cites `§99.9` | `[1]` dangling Proposal section |
| 3 | `CAP-001` loses its citation line | `[4]` uncited item |
| 4 | Observations `§C-006` removed | `[8]` Appendix A parity |
| 5 | Checklist `OQ-012` renamed | `[2]` proposal cites undefined item |
| 6 | Proposal cites `§D-099` | `[10]` undefined decision |
| 7 | `CAP-001` duplicated | `[6]` duplicate ID |

**Two real defects the self-test exposed, which a passing validator had been hiding:**

1. **`check [8]` found genuine drift.** The Proposal's Appendix A had **6** correction rows but the Observations document defined only **5** — row **A-3** (Wasmtime version never pinned) had no counterpart. The missing entry was written as **`§C-006`**, and the pre-existing near-native-Wasm correction was renumbered from `§C-005` to `§C-006` so the two registers align one-to-one. Appendix A and Observations now match exactly.
2. **`check [10]` had nothing to catch, because the Proposal cited only one of nine decisions.** Decision IDs were effectively *write-only* — `§D-002`, `§D-005`, `§D-006`, `§D-007`, `§D-008`, `§D-009` existed in Observations but were never referenced from the Proposal, so a reader of the Proposal alone would never learn they existed. The document-control table and the relevant sections now cite them.

**Lessons:**
- **A validator must be tested by breaking things, not by observing that it passes.** The self-test is wired into CI (`DOC-007`).
- **"Write-only" identifiers are a silent form of drift.** If an ID is defined but never cited, the cross-reference graph is decorative. Checks `[9]` and `[10]` exist specifically to catch this class.
- **Your own fault injections can be wrong.** Two manual injections initially did not fire; investigation showed the *injections* were faulty (a mismatched literal, and a replace that left one instance of the target string intact), not the checks. Always inspect a non-firing injection before concluding a check is dead.

---

## 5. CORRECTIONS TO THE SOURCE CORPUS

The brief said: *"If you are fixing something or just working and see something wrong or missing, fix it, even if it is out of scope."* These are the corrections. Each is mirrored in Proposal Appendix A.

### §C-001 — The Bun "11-day Zig→Rust rewrite with 13,000 unsafe blocks" narrative is unverifiable

**Source.** `docs/QQQAI-Full-Conversation-Complete.md`, Message 1 attachment (an AI-generated text), repeated in the assistant's summary.

**Problem.** It originated entirely within a model-generated attachment. No primary source is cited, and it is the kind of claim that is both flattering to a competitor's critics and impossible to check. **Basing a competitive strategy on it would be building on sand.**

**Correction.** The proposal does not rely on it. Bun is treated as a serious engineering effort, and QQQ competes on architecture — capability isolation, multi-language, determinism — not on the premise that a competitor executed badly.

**Proposal ref:** Appendix A, item A-1.

---

### §C-002 — "Bun is 42,000+ requests per second" is unverifiable and perishable

**Source.** Same attachment.

**Problem.** No hardware, no workload, no version, no date. Numbers of this kind rot within months and are trivially gamed.

**Correction.** QQQ cites only its own measurements, with hardware, toolchain versions, concurrency levels and percentiles disclosed (`PERF-001`, `MKT-010`). Any competitor number used publicly must come from an independent third-party benchmark, cited with its methodology.

**Proposal ref:** Appendix A, item A-2; §9.1.

---

### §C-003 — WASI version was never specified

**Source.** The entire corpus says "WASI" or refers implicitly to Preview 1/2.

**Problem.** The WASI landscape moved substantially. As of the verified current state, **WASI 0.3 (Preview 3) is the current preview**, and it *replaces* the earlier explicit streams and polling interfaces with the Component Model's native, composable `async` functionality via `future` and `stream`. Designing against Preview 2 would have been designing against the previous generation.

**Correction.** QQQ targets **WASI 0.3**. Preview 2 remains supported for compatibility. Verified against the WASI repository README.

**Proposal ref:** Appendix A, item A-4; Appendix B, items B-5, B-6.

---

### §C-004 — `qqq` as the crate and CLI name is unavailable

**Source.** `docs/QQQAI-Conversation-Full.md` §5.3 already noted the crates.io collision; the later messages proposed fallbacks without resolving them.

**Verified current state.** `qqq` is taken on crates.io (v0.2.0), taken on npm (v0.0.6), and `github.com/qqq` is an existing personal account. `qqqai` is free on all three.

**Correction.** Resolved as `§D-001`.

**Proposal ref:** Appendix A, item A-5; Appendix B, items B-15 … B-19.

---

### §C-005 — "Wasmtime" was recommended without a version, which is not a decision

**Source.** `docs/Notes.txt` and both conversation logs name Wasmtime as the recommended engine but never pin a version, and never acknowledge that it changes.

**Problem.** "Use Wasmtime" is not an engineering decision; it is the absence of one. A systems project that does not pin its execution engine cannot reason about security advisories, cannot schedule compatibility work, and cannot answer "what exactly are we shipping?". It also invites silent behavioural drift when a dependency resolves to a new minor.

**Correction.** Pinned to the **48.x line** — verified latest stable `48.0.2`, published 2026-09-10 (`49.0.0-rc.1` exists and is deliberately **not** adopted, being a release candidate). Engine upgrades are a scheduled, budgeted activity (`PLAN-012`, `HOST-020`) with a 72-hour patch target on advisories (`SEC-014`), and all churn is isolated behind `qqq-abi`.

**Proposal ref:** Appendix A, item A-3; Appendix B, items B-1, B-2, B-3, B-4; §6.1, §15 (`R-03`, `R-14`).

---

### §C-006 — The "Wasm is near-native" claim is true for compute and false for boundary crossings

**Source.** The corpus repeatedly asserts near-native Wasm performance without qualification.

**Problem.** It is true for compute-bound code compiled with a good toolchain, and **false** for code that crosses the host boundary constantly. The Component Model's canonical ABI has real per-crossing cost, and a chatty interface can erase the advantage entirely. Shipping the unqualified claim would set the project up for a very public correction — and would be exactly the kind of overclaim that `§D-009` forbids.

**Correction.** Proposal §9.3 quantifies the crossing costs, §4.5 derives the **batch-first design rule** as a consequence and makes it a WIT style-guide requirement (`CON-011`, `CON-012`), and §3.3 states the limitation publicly. This is also why "we may lose the `hello world` benchmark" is written into the proposal rather than discovered later.

**Proposal ref:** Appendix A, item A-6; §4.5, §9.3.

---

## 6. CODE STUBS AND PENDING ITEMS

**Policy.** A stub is only permitted when there is genuinely nothing to connect it to yet. Every stub must carry **both** an inline `// QQQ-STUB(<CHECKLIST-ID>):` marker in the code **and** an entry here. `DOC-009` implements the CI check that enforces this pairing.

### §S-001 — `.scratch/witprobe/` is a temporary verification crate

**Marker in code:** `// QQQ-STUB(FND-011): scratch verification crate. NOT part of the QQQ workspace.`

**What it is.** A throwaway crate that makes the proposal's Wasmtime claims falsifiable. It has now **served its purpose**: all four claims verified, plus a control case (`§O-006`).

**Why it is still a stub.** It is not part of the QQQ workspace and must not be committed to the repository in its current throwaway form.

**How to close it.** `HOST-024` / `FND-011`: port its five assertions (including the 1b control) into `crates/qqq-host/tests/` as permanent tests with CI thresholds — specifically, fail the build if p99 instantiation regresses past the §9.2 budget — then delete `.scratch/`.

**Status: verified and ready to port.** The port is mechanical. What must **not** be lost in the port:
- the **1b positive control** (a negative assertion without a positive control is not evidence),
- the **measured p50/p99 numbers** as a regression baseline (`PERF-003`),
- the four WAT/ABI findings in `§O-007`, which belong in `qqq-abi`'s internals.

---

### §S-002 — `qqq:ai@1.0` interface is authored; implementation is deferred

**What it is.** The WIT interface for local model inference is specified in V1 (`ABI-013`) so that the capability model is coherent from the start, but the implementation is deliberately deferred to `FUT-007`.

**Why deferred.** §6.9's honest assessment: it is a differentiator, not a foundation. A model call is a 10–2000 ms operation and QQQ does not pretend otherwise. Building it before the core is solid would be a distraction with a large support surface.

**Decision gate.** `OQ-011` — whether it enters the V1 line at all, decided at M7.

---

### §S-003 — Cooperative threads (`FUT-004`) are blocked on upstream

**What it is.** Component Model cooperative threads (the 🧵 gated feature) would allow true parallelism inside one instance while keeping one linear memory.

**Why it is a stub, not a task.** Wasmtime lists `stack-switching` as work-in-progress for Cranelift on x86_64 and **unsupported on aarch64**. There is no implementation to build against.

**How to close it.** Re-evaluate quarterly; `PLAN-012` is the existing cadence for engine-upgrade review.

---

### §S-004 — Browser target (`FUT-002`) is designed for but not built

**What it is.** Compiling the QQQ host itself to Wasm so components run identically in a browser. Wasmtime's `cranelift` and `winch` features can compile to WebAssembly, but the `runtime` feature cannot — so the host cannot currently be built for the browser.

**Why it is a stub.** The upstream capability does not exist yet. The architecture is compatible; the platform is not.

---

### §S-005 — No open `TODO`/`FIXME` markers were left in the deliverables

**Verified.** The three documents contain no unresolved `TODO`, `FIXME` or `XXX` markers. The only deliberately-flagged incomplete work is the five stubs above, each with a checklist successor ID, and the twelve open questions in `§Q`, each with a decision gate.

**Policy going forward.** A `TODO` without a checklist ID is not permitted; it becomes a checklist item or it does not exist.

---

## 7. OPEN QUESTIONS

Mirrors Proposal Appendix C. Each needs a **human** decision; none can be resolved by more analysis.

| # | Question | Owner | Needed by | Mirrors |
|---|---|---|---|---|
| `§Q-001` | Free-tier eligibility boundary and revenue attestation | Founder + counsel | M0 | `OQ-001` |
| `§Q-002` | Is the AssemblyScript path named "TypeScript" (with caveat) or "AssemblyScript"? | Founder | M5 | `OQ-002` |
| `§Q-003` | Is Python first-class or "experimental"? | Founder + runtime lead | M5 spike | `OQ-003` |
| `§Q-004` | Is Windows first-class or best-effort? | Founder | M4 | `OQ-004` |
| `§Q-005` | Do we accept Wasm shared memory at all? | Architect + security | M2 | `OQ-005` |
| `§Q-006` | Build the registry now, or bootstrap on OCI? | Founder | M6 | `OQ-006` |
| `§Q-007` | Is `wasi:http` sufficient, or do we need a custom HTTP interface? | Systems lead | M3 | `OQ-007` |
| `§Q-008` | Which exact Fabric licence? | Founder + counsel | M0 | `OQ-008` |
| `§Q-009` | Bytecode Alliance engagement? | Founder | M1 | `OQ-009` |
| `§Q-010` | Contribute capability-audit semantic conventions to OpenTelemetry? | Platform lead | M7 | `OQ-010` |
| `§Q-011` | Does `qqq:ai` ship in the V1 line? | Founder | M7 | `OQ-011` |
| `§Q-012` | Deprecation window: two minor versions, or fixed time? | Architect | M0 | `OQ-012` |

---

## 8. THINGS TO REMEMBER (THE SHORT LIST)

If someone reads nothing else in this file, these are the items that cost the most to learn.

1. **The runtime is Apache-2.0; the governance layer is commercial.** Do not let that boundary drift, in either direction. (`§D-004`)
2. **`qqqai` is the name on all technical surfaces. `qqq` is not available and never will be.** (`§D-001`)
3. **Nothing in this project rests on an unverified competitor claim.** If a number has no methodology, it does not go in a document. (`§C-001`, `§C-002`)
4. **"Wasm is near-native" is only true for compute-heavy, few-crossings code.** Say so, or be corrected publicly. (`§C-005`)
5. **Capabilities are denied by default and no overlay can ever widen them.** If that invariant breaks, the product has no reason to exist. (`§D-008`, `CAP-010`)
6. **Long builds on this machine must be background jobs.** A foreground command silent for 300 seconds gets the turn killed. (`§M-002`, `§O-005`)
7. **The `keep-working` timer job belongs to RobinHorde.** Do not touch it. (`§O-005`)
8. **Every stub needs both an inline marker and an entry here.** The CI check that enforces this is `DOC-009`.
9. **Every checklist item cites a Proposal section; every Proposal section cites its items.** `DOC-006` enforces it; breaking it silently is how this corpus rots.
10. **The honest timeline is ~23 months and $2.3M–$4.5M.** A plan that says twelve months is lying, and it will be discovered.
11. **The biggest risks are organizational, not technical** — runway (`R-09`) and bus factor (`R-15`).
12. **Publishing where we lose is the strongest credibility asset this project has.** Do not let marketing remove it. (`§D-009`, `MKT-011`)

---

## 9. CHANGE LOG

| Date | Change | Author |
|---|---|---|
| 2026-09-19 | Document opened. Initial decisions `§D-001` … `§D-009`, observations `§O-001` … `§O-008`, mistakes `§M-001` … `§M-006`, corrections `§C-001` … `§C-006`, stubs `§S-001` … `§S-005`, questions `§Q-001` … `§Q-012`. | Architect |
| 2026-09-19 | Verification round. All four load-bearing architecture claims verified against Wasmtime 48.0.2 (`§O-006`); four WAT/ABI findings recorded (`§O-007`); two Wasmtime API differences recorded (`§O-008`); validator self-test built and **7/7 fault injections detected** (`§M-006`), which exposed and fixed two real defects: Appendix A/Observations correction drift, and Proposal decision citations that were write-only. `check [8]`, `[9]`, `[10]`, `[11]` added to the validator; self-test wired into CI. | Architect |

*End of `QQQ-Observations-and-Memories.md`.*
