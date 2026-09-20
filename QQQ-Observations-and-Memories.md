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

### §O-010 — `qqq-cap` part 1: manifest parsing is strict by design

**What was built.** The capability vocabulary (24 capabilities, three kinds) and
`qqq.toml` parsing/validation, which is pipeline steps 1 (PARSE) and the static
half of 2 (NORMALIZE) from Proposal §6.2.

**Verification:** `cargo test -p qqq-cap` → **43 pass**; `cargo clippy -p qqq-cap
--all-targets -- -D warnings` → clean.

**Decisions taken, recorded so they are not re-litigated:**

1. **Unknown manifest fields are an error, not a warning.** A user who writes
   `[capabilities.crypto] hassh = [...]` has made a mistake that, if silently
   ignored, produces a service failing at runtime with a capability denial far
   from the typo. Rejecting at parse time with the field named is the entire
   point. `deny_unknown_fields` on every capability struct.
2. **`crypto.random` and `clock.wall` default to `false`.** Both are classic
   covert channels and neither is ever granted implicitly. Tested explicitly:
   a crypto stanza asking only for `hash` must not grant `random`.
3. **Wildcards are impossible in a manifest.** `CapabilitySelector` supports
   `sql.*` for *policy*, but manifests name each capability. A wildcard in a
   manifest is a blank cheque, and "the manifest is the truth" is a property
   this design depends on.
4. **`env.allow = ["*"]` is rejected** with an explanatory message, because a
   blanket inherit is ambient authority wearing a different hat.
5. **Byte sizes are binary throughout** — `128M` and `128MiB` mean the same
   thing. Offering decimal multipliers only for the unsuffixed spelling would
   make those differ, which is a trap in a *limit* field.
6. **Limit bounds live in one `limit_bounds` module** so the check and the
   error message cannot disagree about what the permitted range is.

**Tests that encode the contract rather than the implementation:**

| Test | What it guarantees |
|---|---|
| `proposal_full_manifest_example_parses` | The manifest printed in Proposal §5.3 actually parses — if it breaks, the docs are lying |
| `minimal_manifest_parses_and_grants_nothing` | Deny-by-default holds for the simplest possible project |
| `crypto_random_and_wall_clock_default_to_denied` | The covert-channel defaults cannot regress |
| `read_only_fs_does_not_grant_write` | A mode mix-up cannot silently escalate authority |
| `nul_byte_in_path_is_rejected` | Path handling is a security surface, not a string field |
| `url_in_http_client_allowlist_is_rejected_with_guidance` | Errors teach; `https://x` is a common mistake with a specific fix |

**Cross-refs:** Checklist `CAP-001`, `CAP-002`, `CON-001`, `CON-002`,
`SEC-003`; Proposal §5.3, §6.2, §12.2.

---

### §O-011 — `qqq-cap` part 2: the narrowing-only invariant is provable

**What was built.** The resolution pipeline (Proposal §6.2 steps 3–6): `Layer`,
`Overlay`, `GrantSet`, `Resolution` and the `why` chain.

**Verification:** `cargo test -p qqq-cap` → **68 pass**; clippy → clean.

**The invariant is structural, not checked.** A rule enforced by a check can be
bypassed by a bug in the check; a rule enforced by the type system cannot. So
`GrantSet` has **no public method that adds a capability**. Its only
constructors are `empty()` and `from_manifest()`, and the only combinator is
`narrow()`, which intersects or subtracts. `Layer::may_grant()` returns `true`
for `Manifest` alone, and `narrow()` refuses an overlay from any other layer
that claims granting authority — with a `debug_assert` for the programming
error plus a test that proves it.

`no_overlay_can_ever_widen` starts from an *empty* set and applies every
non-granting layer × every mode, each carrying **every capability that exists**,
and asserts the result is still empty.

---

#### §O-011a — A real design flaw the commutativity test caught

**What happened.** `narrowing_is_commutative_across_layers` failed. The
capability sets were correctly identical, but the `applied_layers` vectors
differed by insertion order — and `GrantSet` derived `PartialEq`, so it was
comparing **provenance** rather than **authority**.

**Why this mattered more than a failed test.** Narrowing is commutative: A then
B grants the same authority as B then A. If equality compared history, then
(a) the commutativity guarantee would be *untestable*, and (b) any caller
comparing two resolutions would see a phantom difference where the authority is
identical. That is precisely the kind of subtle wrongness that ships and then
confuses someone two years later.

**Fix.** `GrantSet` now implements `PartialEq`, `Eq` and `Hash` **by hand**,
over `capabilities` only, with the semantics documented on the type: *"two
grant sets are equal if and only if they grant the same authority; provenance
is not authority."* Ordering history remains available through
`applied_layers()` and the full `Resolution::trace`, which is where a human or
agent looks to understand *how* a result was reached.

Two tests now pin this:
- `equality_ignores_provenance_and_compares_authority` — asserts the histories
  genuinely differ *and* the sets still compare equal (so the test cannot pass
  vacuously), plus the audit digests match.
- `overlay_from_a_non_granting_layer_that_claims_to_grant_is_ignored` — asserts
  authority and digest are unchanged while provenance *is* recorded.

---

#### §O-011b — The trace records transitions, not membership

**What happened.** A second failure: `resolution_records_which_layer_removed_what`
expected one trace node and got two. Investigation showed the **code** was
right and my **expectation** was wrong.

**Resolution.** A capability declared by the manifest and later removed by
policy legitimately has *two* transitions: `false → true` (manifest grants) and
`true → false` (policy removes). Recording both is strictly better — it lets
`qqqai why` tell the complete story rather than showing an orphaned removal with
no explanation of where the capability came from. The trace now filters to
**genuine transitions only** (`granted_before != granted_after`), which keeps it
readable, and the test asserts both transitions plus that the *last* one names
the deciding layer.

**Lesson recorded:** when a test fails, establish whether the *code* or the
*expectation* is wrong before changing either. Here, changing the code to match
my expectation would have silently degraded the `why` output.

**Cross-refs:** Checklist `CAP-003` … `CAP-012`, `SEC-001`, `SEC-003`;
Proposal §6.2.

---

### §O-012 — `qqq-cap` part 3: normalization, and three real bugs the tests caught

**What was built.** Pipeline step 2, NORMALIZE (Checklist `CAP-003`):
`HostPattern`, `SecretRef`, `Normalized`, `FsGrant`, and the `HostEnv` trait.

**Verification:** `cargo test -p qqq-cap` → **93 pass**; clippy → clean.

**The design decision worth recording: `HostEnv` is a trait, not direct
syscalls.** Normalization touches the filesystem and the process environment,
which makes it untestable and also wrong for cross-compilation — `qqqai build`
on CI must be able to validate a manifest for a *different* target host. So
normalization runs against a `HostEnv` implementation, with `RealEnv` for
production and a `FakeEnv` for tests. This is what let me write 20 tests for
path canonicalization and secret checking without creating a single real file.

**Secrets are checked but never read.** `HostEnv` exposes only
`has_env(&str) -> bool` — there is deliberately **no value getter anywhere in
the trait**. A bug in `normalize_secrets` therefore *cannot* leak a secret into
configuration, a log line or a serialized struct. The value is fetched by the
host at the moment of use inside `qqq:secrets` (Proposal §6.3).

---

#### §O-012a — Three real bugs found by the tests, all fixed at the root

**Bug 1 — IPv6 literals were rejected as invalid hosts.** My character
validator only accepted `[a-z0-9._-]`, so `[::1]:8080` failed with *"host `::1`
contains invalid characters"*. An IPv6 literal is a legitimate allowlist entry
for an internal service. **Fix:** detect a literal by the presence of a colon
and validate it against its own alphabet (hex digits and colons), comparing by
exact equality since wildcards are meaningless for an address.

**Bug 2 — the fix for bug 1 was itself over-strict.** My first correction
rejected any literal beginning or ending with a colon — but `::1` and `::`
**legitimately** begin with one; that is IPv6 shorthand for a run of zero
groups. **Lesson:** a validation rule written from a plausible-sounding
principle, rather than from the actual grammar, produces a rule that rejects
valid input. Only three-or-more consecutive colons (and a lone `:`) are
genuinely invalid.

**Bug 3 — `fs_allows` compared the wrong thing.** The original expression was
`g.mode.can_write() == mode.can_write() && (mode.can_read() <= g.mode.can_read())`.
The first clause is an **equality** where a *coverage* relation was needed, so a
`read-write` grant failed to satisfy a `read-only` request. **Fix:** replaced
with an explicit `FsMode::covers()` expressed as a **rights check** — does the
grant permit reading if the request needs it, and writing if the request needs
it — plus a test asserting the **full 3×3 matrix** rather than sampling two
cases. Expressing it as rights rather than a match over pairs also means a
future mode must be taught to the function explicitly instead of silently
inheriting permissive behaviour from its position in the enum ordering.

**Pattern across all three:** the bug was in my *mental model* of a rule, not
in the code that implemented the model. That is precisely why the matrix test
exists — sample-based tests would have passed all three.

**Cross-refs:** Checklist `CAP-003`, `SEC-010`; Proposal §5.3, §6.2, §6.3.

---

### §O-013 — `qqq-host` part 1: the trap taxonomy and engine configuration

**What was built.** `trap` (classification, structured traps, the `QQQ-3xxx`
taxonomy) and `config` (engine configuration, pooling sizing, store limits,
AOT cache keying). Checklist `HOST-001`, `HOST-007`, `HOST-008`, `HOST-009`,
`HOST-010`, `HOST-013`.

**Verification:** `cargo test -p qqq-host` → **29 pass**; clippy → clean.
Full workspace: **158 tests pass**.

---

#### §O-013a — A wrong abstraction the tests caught: two different memory failures

**What happened.** `wasmtime_memory_message_classifies_as_memory` failed on the
input `"wasm trap: out of bounds memory access"`. My classifier bucketed it as
`MemoryLimitExceeded`.

**Why that was wrong, and worth a new error code.** These are **two different
failures with opposite fixes**:

| Detail | Meaning | The fix |
|---|---|---|
| `memory limit exceeded` | the guest asked for more than it was allowed | **raise `limits.memory`** |
| `out of bounds memory access` | the guest has a **buffer overrun bug** | **change the code** |

Conflating them sends a developer hunting for a limit to raise when the actual
defect is in their indexing. So `QQQ-3007 GuestOutOfBounds` was added with a
remediation that explicitly says *"this is a guest bug, not a limit to raise"* —
and a test asserts that wording, so the distinction cannot silently collapse
back.

**This is the second time the same pattern has appeared** (see `§O-012a`): the
bug was in the *mental model* of the domain, not in the code implementing it.
Sample-based tests would have passed. The value of asserting specific real
Wasmtime strings — rather than plausible ones — is that it forced the model to
be corrected.

---

#### §O-013b — Wasmtime emits `"wasm trap: interrupt"` for epoch preemption

**Observed.** The epoch-preemption path does not contain the word "epoch". The
actual message Wasmtime emits when an epoch deadline fires is
`wasm trap: interrupt`.

**Consequence.** A classifier keyed on "epoch" would have silently misclassified
*every* preemption as a generic trap — meaning `QQQ-3003` would never fire in
production and timeouts would look like crashes. There is now a dedicated arm for
the bare `interrupt` signature, with a comment naming it as the real message.

---

#### §O-013c — Three Wasmtime 48 API differences from the documented surface

**Observed while compiling.**

1. **`wasmtime::VERSION` does not exist.** The engine does not re-export its
   version, which matters because the **AOT cache key must include the engine
   version** — Cranelift codegen changes between releases, and a `.cwasm`
   compiled by one release is not guaranteed valid for another. A stale key
   would let native code compiled for a different engine be loaded, producing
   code that is *subtly* wrong rather than obviously broken. Resolution: a
   pinned `ENGINE_VERSION` constant plus a test that reads the **workspace
   `Cargo.toml` at compile time** and fails if the constant and the dependency
   drift apart. The constant cannot silently rot.
2. **`PoolingAllocationConfig::total_stacks` takes `u32`**, not `usize`.
3. **`Config::wasm_relaxed_simd` and `cranelift_nan_canonicalization` behave as
   expected** — confirmed by building a real engine from both the default and
   deterministic configurations in a test, which is what proves our flag
   combination is *valid* rather than merely plausible.

**Cross-refs:** Checklist `HOST-001`, `HOST-007`, `HOST-008`, `HOST-009`,
`HOST-010`, `HOST-013`; Proposal §6.1, §9.4, §10.5.

---

### §O-014 — `qqq-host` part 2: the grant-built linker is real, and the security claim is a test

**What was built.** `linker.rs`: `interface_for`, `required_interfaces`,
`build_linker`, `BoundInterfaces`, `StoreData`, `recheck`, `describe_gap`.
Checklist `CAP-008`, `SEC-002`, `HOST-012`.

**Verification:** `cargo test -p qqq-host` → **44 pass**; full workspace →
**173 pass**; `cargo clippy --workspace --all-targets -- -D warnings` → clean.

---

#### §O-014a — The claim from `§O-006` is now a permanent regression test

Observation `§O-006` recorded a claim verified by a throwaway probe: *a guest
importing an ungranted capability fails at instantiation, and the error names
the missing import.* That probe has now been replaced by two permanent tests
in `qqq-host`:

| Test | What it proves |
|---|---|
| `an_ungranted_import_fails_instantiation_and_names_itself` | The negative case: real Wasmtime component, real empty linker, instantiation fails and the error names `greet`/`host:probe` |
| `a_satisfied_import_instantiates_and_runs` | **The positive control:** the same harness shape with a satisfiable component instantiates and returns 42 |

**The control is not decoration.** Without it, the first test could be passing
because the harness is broken rather than because the capability model works.
This pairing was recorded as a standard in `§O-006` and is now enforced in the
permanent suite.

---

#### §O-014b — Why the linker is per-instance, stated for the record

A per-process linker would give every tenant the **union** of every tenant's
grants — a catastrophic cross-tenant authority leak, and precisely the failure
the architecture exists to prevent. Building per instance costs microseconds
(the instantiation measurement in `§O-006` was p50 800 ns) and is the
difference between *"the server has permissions"* and *"this request has
permissions"*.

`recheck` consults the **store's** grant set, never a re-derivation from the
linker. Re-deriving would make the second check vacuous: a mis-built linker
would produce the same wrong answer twice. The asymmetry justifies the cost —
a mis-built linker is a *security hole*, while a spurious re-check denial is an
*annoying error*.

---

#### §O-014c — Two design decisions forced by the type system, both improvements

**1. `Capability` is `#[non_exhaustive]`, so `interface_for` needed a `_` arm.**
The compiler refused to let me ignore it. The resolution is the **safe**
direction: an unknown capability unlocks **no** interface, and the gap is
surfaced through `describe_gap` as `QQQ-6004` rather than silently ignored. A
newer `qqq-cap` variant reaching an older `qqq-host` therefore fails loudly
instead of guessing.

**2. `BoundInterfaces` could not hold `Vec<&'static str>`, because it must
deserialize.** `Deserialize` cannot produce a `&'static str`, and this type is
part of `qqqai inspect --json` and the audit record. It now owns `String`s —
one small allocation per interface at *bind* time, on a path that runs once per
component rather than once per request. The cheaper type was the wrong trade.

---

#### §O-014d — WIT interface versions are `major.minor`, not `major.minor.patch`

**Observed.** My interface-name test failed: `interface version 1.0 is not a
valid semver`, because it was validated against `qqq_core::Version`, which
requires three components.

**Resolution — a deliberate distinction, now documented in the test.** WIT
interface versions follow the **WIT convention of `major.minor`**. The patch
level of an *interface* carries no meaning, because an interface is a type
signature: it either changed compatibly or it did not. Accepting `@1.0.3` would
imply a distinction no consumer can act on.

This is deliberately **different** from `qqq_core::Version`, which models
*package* versions where the patch level is meaningful. Two version types with
two rules, each matching its domain — rather than one loose type that is wrong
for both. The test now asserts the WIT shape explicitly so the distinction
cannot erode.

**Cross-refs:** Checklist `CAP-008`, `SEC-002`, `HOST-012`; Proposal §4.4,
§6.2, §7.3.

---

### §O-015 — `qqq-host` part 3: the instance lifecycle, limits proven by execution

**What was built.** `instance.rs`: `PreparedComponent`, `Instance`, `run`,
`run_measured`, `ExecutionOutcome`, `digest_of`, `epoch_tick_interval`,
`DeterministicClock`. Implements `HOST-005` … `HOST-012`, `HOST-014`,
`HOST-015`, `HOST-018`, `HOST-019`.

**Verification:** `cargo test -p qqq-host` → **59 pass**; workspace → **189
pass**; clippy across the workspace → clean.

---

#### §O-015a — The limits are proven by *running* a real guest, not by inspection

The central claims of `HOST-005`/`006`/`010` are now executable tests against
the real engine:

| Test | What it actually does |
|---|---|
| `fuel_exhaustion_traps_the_guest_and_the_host_survives` | Compiles a component containing a **genuine infinite loop**, gives it 10,000 fuel, runs it, asserts the trap classifies as `QQQ-3002`, asserts fuel-consumed reaches the error context, **then runs a different component on the same engine to prove the host survived** |
| `execution_reports_fuel_consumed` | Runs a real call and asserts fuel is observable and bounded |
| `a_poisoned_instance_refuses_to_run` | Poisons an instance and proves it refuses rather than executing with unknown state |
| `instance_creation_fails_when_an_import_is_ungranted` | The capability rule end to end through `Instance::create`, not only at the linker level |

The host-survival assertion is the one that matters. *"A guest trap does not
kill the host"* is the claim in Proposal §6.1's failure table, and it is now
checked by actually trapping a guest and then using the engine again.

---

#### §O-015b — `HOST-010` is enforced by the ownership model, not a flag

`Instance::run` **consumes `self`**. A trapped instance therefore cannot be
returned to a pool, because after `run` returns there is nothing left to return.
The alternative — a `must_discard` boolean every caller must remember to check —
is exactly the kind of convention that gets skipped under deadline pressure, in
the one place where skipping it means a cross-request state leak.

`poison()` exists as a *second* mechanism, for a host function that detects a
condition only it can see. Belt and braces, with the compiler holding the belt.

---

#### §O-015c — `StoreData` gained the resource limiter, and why it lives there

`Store::limiter` takes a closure returning `&mut StoreLimits`, and the returned
reference must outlive the store. Storing the limiter **inside the store's own
data** is the only arrangement satisfying that without self-reference — and it
keeps the limits travelling with the instance they constrain, so they cannot be
swapped by mistake.

Two layers of memory bound, deliberately:
* the **pooling config** reserves for the worst case at startup, so
  over-provisioning fails at boot rather than under load;
* **`StoreLimits`** is what actually traps a runaway guest at runtime.

An unset `StoreData` uses `StoreLimits::default()` — the safe direction twice
over: no grants, and Wasmtime's own defaults.

---

#### §O-015d — `PreparedComponent` deliberately does not hold the engine

**What happened.** My first draft had `imported_interfaces()` reach for an
engine through an `unreachable!()` placeholder — a genuine design smell caught
on review before it ever compiled.

**Why it was wrong.** Holding a second engine reference inside the component
risks it disagreeing with the engine the component was *compiled against* —
exactly the kind of aliasing bug that produces unreproducible behaviour.

**Fix.** The engine is an explicit parameter, so the caller must prove it is
using the right one. NN-5's "discoverable without running it" still holds,
because the import table is derived from the compiled artifact rather than from
execution.

---

#### §O-015e — A 32-bit correctness bug found by clippy, not by a test

**Observed.** `tick.as_millis() as u64` in a bound assertion. `as_millis`
returns `u128`, and the cast truncates on overflow.

**Why it mattered.** The value is at most 100 ms by construction, so the cast
was *safe in practice* — but "safe in practice because of an invariant asserted
three lines away" is precisely the reasoning that rots when someone later
changes the clamp. Replaced with `u64::try_from(...).expect(...)`, making the
invariant explicit and failing loudly if it ever stops holding.

**Broader note.** This is the **second 32-bit truncation clippy caught in this
crate** (the first was the `u64 → usize` pool-memory cast in `§O-013`). Both
were latent, both invisible on this 64-bit development machine, and both are now
explicit conversions with a stated direction of failure. Worth watching for
systematically in the remaining crates.

**Cross-refs:** Checklist `HOST-005` … `HOST-012`, `HOST-014`, `HOST-015`,
`HOST-018`, `HOST-019`; Proposal §6.1, §9.4, §10.5.

---

### §O-016 — `qqqai` exists and runs: the machine contract is live

**What was built.** The `qqq-run` crate and the `qqqai` binary: the shared
output layer (`CLI-001`, `CLI-002`), argument parsing, help generation, the
`schema` and `doctor` commands, and honest `UNAVAILABLE` reporting for the rest.

**Verification — by *running the binary*, not by reading the tests:**

```console
$ qqqai --version
qqqai 0.0.0

$ qqqai --version --json
{"producer":"qqqai","schema_version":"1.0.0","version":"0.0.0",
 "wasi_target":"0.3","wasmtime_line":"48"}

$ qqqai schema --json
  commands: 26   errors: 38   capabilities: 24

$ qqqai frobnicate
error[QQQ-7001]: unknown command `frobnicate`

  → run `qqqai --help` to see the available commands

  Docs: https://qqq.codes/errors/QQQ-7001
exit=2
```

**Every claim in Proposal §12.2 is now observable.** The error block has the
mandated shape — what happened, then the fix, then the docs URL — and exits `2`
(usage) rather than `1` (failure), because an agent needs to distinguish "you
called it wrong" from "it broke".

**The naming invariant is enforced three ways**, because this is the decision
most likely to be "helpfully" undone: a constant (`BINARY_NAME = "qqqai"`), a
test asserting `assert_ne!(BINARY_NAME, "qqq")` with the reason in the message,
and a third test that reads `crates/qqq-run/Cargo.toml` at compile time and
fails if the `[[bin]]` name is ever changed to `qqq`.

---

#### §O-016a — `CLI-002` is enforced by the compiler, not by review

Non-Negotiable #1 requires every command to support `--json`. The mechanism is
not a checklist item a reviewer might skip:

* `CommandOutput` requires a `to_json` method, so a command's return type cannot
  be printed without having a machine form.
* `Output::emit` is the **only** way to produce user-visible output.
* `command_schemas()` matches over `CommandName` with no wildcard arm for the
  commands that have a real schema, so adding a command **fails to compile**
  until a schema is provided.

The `--help` text is likewise generated from `CommandName::all()`, so a new
command cannot be missing from it either. A test asserts every command and its
summary appear.

---

#### §O-016b — A real bug found by *running* the binary, not by testing it

**What happened.** `qqqai --version --json` printed the plain text version. The
parser set `Action::Version` and then `break`-ed out of the loop, so `--json` —
which appeared **after** the short-circuiting flag — was never recorded. All 30
unit tests passed, because none of them exercised a flag *after* a
short-circuiting flag.

**Fix.** `--help` and `--version` now `continue` rather than `break`: they fix
the *action* but let the parser finish recording flags.

**The test that would have caught it** was added, and it asserts the general
property rather than the single case:
`short_circuit_flags_do_not_swallow_later_flags` checks `--version --json`,
`--help --jsonl`, and that `--version --help` yields `Version` (the first
short-circuit wins).

**Lesson, and it is the third instance of the same pattern in this project:**
unit tests written from the same mental model as the code cannot catch a flaw in
that mental model. Running the actual binary — the way a user or an agent would
— found in one command what 30 passing tests missed.

---

#### §O-016c — "More than 3 bools in a struct" was a design signal, not noise

**Observed.** Clippy flagged `GlobalFlags`'s five boolean fields. The obvious
response is an `#[allow]`. The better one is to notice that a struct of five
bools is a struct where every combination is representable — including
meaningless ones like `json && json_lines` — and that the shape does not survive
a sixth flag.

**Fix.** `GlobalFlags` is now a newtype over `u8` with named bit constants and
`set`/`has`/`json`/`json_lines` accessors. Call sites read the same, the
representation is explicit, adding a sixth flag costs nothing, and two tests
pin that the bits are independent — a bug a bool struct cannot even express.

**Cross-refs:** Checklist `CLI-001`, `CLI-002`, `CLI-021`, `CLI-023`,
`DOC-014`; Proposal §5.2, §8.3, §12.2.

---

### §O-017 — `qqq-abi`: thirteen interfaces, and a wrong conclusion corrected

**What was built.** `qqq-abi`: thirteen WIT interface definitions under `wit/`,
embedded via `include_str!` so the runtime and the published files cannot
diverge; and `registry.rs`, the **single** capability-to-interface mapping shared
by the runtime and the static capability report.

**Verification:** `cargo test --workspace` → **238 pass**; clippy → clean;
`wasm-tools component wit` → **13/13 interfaces parse**.

---

#### §O-017a — ⚠️ **I was wrong about the WIT version format, and the whole corpus encoded the error**

**What I claimed in round 2** (`§O-014d`): *"WIT interface versions are
`major.minor`, not `major.minor.patch`. The patch level of an interface carries
no meaning, because an interface is a type signature."*

**That reasoning is plausible and completely wrong.** WIT requires full semver.
Verified by parsing with the real toolchain:

```text
package qqq:x@1.0;    ->  error: expected '.', found ';'
package qqq:x@1.0.0;  ->  parses
```

**How far the error had spread.** The wrong conclusion was recorded in
Observations, written into all **thirteen** `.wit` files, encoded in the
registry's interface names, in `qqq-host`'s static-name projection, and asserted
by **three tests** — in `qqq-abi` (twice) and `qqq-host` (once). Ninety-eight
occurrences were corrected.

**Why the tests did not catch it.** They asserted the convention I had invented,
so they *confirmed* my mistake rather than challenging it. A test can only check
a property you state correctly; it cannot tell you the property is wrong.

**What caught it.** Parsing the files with `wasm-tools`. Not reasoning — running.

**Lesson, and it generalises past this instance:** *a plausible-sounding
principle about a format is not evidence about that format.* I had a tidy
rationale ("patch level carries no meaning for an interface") and it felt like
understanding. It was rationalisation. **When a claim is about an external
grammar, parse it; do not reason about it.**

---

#### §O-017b — The structural tests passed while every file was invalid WIT

**What happened.** `qqq-abi` had fifteen passing tests — every capability maps to
exactly one interface, every interface has source, names are versioned and
unique, names are sorted. **All thirteen `.wit` files were simultaneously
rejected by `wasm-tools`.**

The tests checked the *shape of my model*. The parser checks *the language*.
Those are different properties, and only one of them was verified.

**Fix.** `tools/check_wit.py` runs `wasm-tools` over every interface, and CI
gained a dedicated `wit` job. The script **fails rather than warns** when
`wasm-tools` is absent, because skipping validation would mean shipping unparsed
interface definitions.

---

#### §O-017c — Six real WIT grammar errors, each a genuine mistake

Once the files were actually parsed, six further errors surfaced. Each is
recorded because each is a trap a future interface would hit again:

| Error | Cause | Fix |
|---|---|---|
| `expected '.', found ';'` | `@1.0` — needs full semver | `@1.0.0` |
| `expected constructor or identifier, found keyword 'list'` | `list` is a WIT keyword and cannot name a function | renamed to `entries` |
| `name 'request' is defined more than once` | a function and a record cannot share a name in one interface | function became `send` |
| `expected an identifier or string, found keyword 'string'` | variant case named `string` with a `string` payload | case renamed to `text` |
| `expected ')', found ':'` | variant case payloads are **types**, not `name: type` fields | `sign(list<u8>)` |
| `expected ')', found ','` | a variant case carries **exactly one** payload | `verify(list<u8>, list<u8>)` → a named `verify-request` record |
| `expected identifier or string, found ':'` | `use` is a WIT keyword | renamed to `apply` |

**The most interesting one is `verify`.** A variant case takes exactly one
payload type, so two adjacent `list<u8>` parameters are impossible. The fix — a
named record — is *better* than what I originally wrote: two adjacent `list<u8>`
arguments are trivially swappable at a call site, and swapping them would
produce a confusing failure rather than a compile error. The grammar pushed the
design toward something clearer.

---

#### §O-017d — A real WIT limitation invalidated a design assumption

**What I designed.** `qqq:trace`'s `span.child` returned `borrow<span>`, so the
type system would enforce that a child span cannot outlive its parent.

**What the parser said.**

```text
error: function `[method]span.child` returns a type which contains a
       `borrow<T>` which is not supported
```

A borrow's lifetime is bound to the dynamic call, and an owning resource can
outlive the call that produced it — so the Component Model forbids returning one.

**Resolution.** `child` now returns an owned `span`, and **the host enforces
nesting at runtime**: a child records its parent when created, and the host
rejects an out-of-order close with a clear error. The guarantee moves from
compile time to runtime.

That is a real downgrade in strength and it is documented in the interface's own
doc comment rather than glossed over. It is also a candidate for revisiting if
the Component Model gains a mechanism for it — tracked by the existing
`FUT-*` process.

---

#### §O-017e — One mapping, two consumers: the drift test

`qqq-host::linker::interface_for` now **delegates** to `qqq_abi`. It previously
held a second table, which is exactly how a security report ends up claiming a
component cannot reach the network while the runtime quietly lets it.

Delegation alone is not enough, because `qqq-host` projects the registry's owned
`String` names into `&'static str` literals for the hot path. Two tests make the
drift impossible:

* `static_names_cover_the_registry` — fails if an interface is added to
  `qqq-abi` without being added to the static projection.
* `host_and_abi_agree_on_every_mapping` — compares both crates' answers for
  every capability.

**Cross-refs:** Checklist `ABI-001` … `ABI-016`, `CON-011`, `CON-014`;
Proposal §6.3.

---

### §O-018 — The first host implementations: `qqq:clock` and `qqq:crypto`

**What was built.** `qqq-host::ambient`: `AmbientState` (the deterministic clock
and seeded RNG), `HashAlgorithm`, `hash_data`, `require`, and `HostCallError`.
Partially closes the stub recorded in `§S-006`, and honestly.

**Verification:** `cargo test --workspace` → **244 pass**; clippy → clean;
`wasm-tools` → 13/13.

**Scope, stated precisely.** `random` and `hash` are implemented and tested.
`hmac`, `aead` and `sign` are **not**. So `qqq:crypto` reports
`implemented: false` in the registry, and a test
(`partial_implementations_do_not_claim_completeness`) pins that. Claiming
`true` for a partially-served interface would let a component needing AEAD pass
admission and then fail at first call — the opaque failure the flag exists to
prevent.

---

#### §O-018a — Known-answer tests, not round-trip tests

The hash tests assert **published test vectors**:

```text
SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
BLAKE3("abc")  = 6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85
```

A round-trip test (`hash(x) == hash(x)`) passes for any deterministic function,
including a wrong one. A known-answer test fails unless the implementation is
*correct*, which matters because these digests are compared against values
produced by other systems.

---

#### §O-018b — An allowlist that is enforced, not advisory

`hash_data` checks three things in order: the `crypto.hash` **grant**, that the
algorithm is **known**, and that it is in the **manifest's list**. The third
check is the one that is easy to omit: the host can compute SHA-512 whether or
not the manifest mentioned it, so without the check the manifest's allowlist
would be advisory and a guest could use any primitive the host happens to link.

**Unknown and known-but-ungranted algorithms return the same error code**, so a
guest cannot enumerate the host's supported set by probing. That is the same
reasoning as `qqq:env`'s single `not-allowed` error.

---

#### §O-018c — Determinism is a property of the *instance*, not the host

`AmbientState` is created per store, not shared. Two instances running
concurrently must each see a reproducible sequence; a host-global counter would
make one instance's output depend on how much the other had run — exactly the
nondeterminism the feature removes.

A test proves two independently constructed states produce **identical**
sequences, which is what makes bit-identical replay achievable.

**The generator's output is pinned.** `deterministic_randomness_is_pinned_to_known_bytes`
asserts the first eight bytes are `9639138b2c6e4176`. I originally guessed a
different value and the test failed — which is the point: the output is a
*compatibility surface* for replay, so an accidental change to the mixing
function would silently invalidate every recorded run. Pinning it makes such a
change a build failure requiring a deliberate decision.

It is a splitmix64 counter rather than a `HashMap`-seeded or address-derived
source, because those vary between runs and machines — precisely the property
that must not exist here. It is **not** a CSPRNG and is never used outside
deterministic mode.

---

#### §O-018d — A bug in my own test setup, found by the tests

`hashing_produces_known_digests` failed with `AlgorithmNotAllowed("sha256")`.
The cause was in the *test helper*: `store_with` used `StoreData::new(grants)`,
which leaves `allowed_hashes` empty, instead of `StoreData::from_manifest`,
which populates it.

**Why this is a useful failure.** It shows the allowlist check is genuinely
load-bearing — a store built from grants alone cannot hash anything, which is
the correct behaviour and was briefly mistaken for a bug in the hash
implementation. The helper now uses `from_manifest` and says why in a comment.

**Cross-refs:** Checklist `HOST-016`, `CAP-016`, `DET-002`, `DET-003`;
Proposal §6.1, §6.3, §7.4, §10.5.

---

### §O-019 — The capability engine is now reachable: `why`, `caps` and `inspect`

**What was built.** `qqq-run::commands` and `qqq-run::manifest_loader`, and the
CLI wiring for three commands. Implements `CLI-015`, `CLI-018`, `CLI-019`,
`CLI-002`.

**Verification — by running the commands against a real project:**

```console
$ qqqai caps
orders-api: 3 capabilities across 2 namespaces

$ qqqai why http.client
http.client GRANTED

$ qqqai why sql.query --json
ok: true   granted: false
fix:
    add to qqq.toml:

        [[capabilities.sql]]
        name = "orders"
        driver = "postgres"
        host = "db.internal:5432"
        secret = "env:ORDERS_DB_URL"

$ qqqai inspect --json
project: orders-api   posture: exposed
caps: ['http.server', 'http.client', 'crypto.hash']
interfaces: qqq:crypto@1.0.0 (implemented=False), qqq:http@1.0.0 (implemented=False)
limits: {epoch_deadline_ms: 5000, fuel: 10000000, memory: '64MiB'}
```

**Why this mattered more than it looks.** Before this round the capability
engine was proven correct and **completely unreachable** — five CLI commands
returned `QQQ-6004 not implemented`. Proposal §6.2 calls `qqqai why` "the killer
DX affordance" and §5.2 lists `inspect` among "the surfaces that make QQQ
different". Neither claim was worth anything until the commands existed. A
correct engine behind an unreachable surface delivers no value.

---

#### §O-019a — The fix stanza is generated, not documented

`why sql.query` prints the **exact** `qqq.toml` stanza that would grant it,
rendered from the capability's namespace. A developer who hits a denial needs
that text, not a link to a capabilities reference — and generating it means the
suggestion cannot drift from what the parser accepts.

A test (`every_capability_has_a_useful_fix_stanza`) walks all 24 capabilities
and asserts each produces a stanza naming both `qqq.toml` and its own namespace.
A new capability cannot ship without a fix suggestion.

---

#### §O-019b — `inspect` reports interfaces, not just capabilities

The value of `inspect` over reading `qqq.toml` is that it answers a **different
question**: not "what did I declare?" but "what will this component be able to
import?". It resolves capabilities through the `qqq-abi` registry — the same
table `qqq-host` builds its linker from — so the static report and the runtime
enforcement cannot disagree.

It also reports `implemented` per interface, honestly. A reviewer sees that
`qqq:http@1.0.0` is granted but not yet servable, which is exactly the
information a pre-deployment check needs.

---

#### §O-019c — `Posture` is an enum, not a sentence

`classify_posture` returns `Minimal` / `Contained` / `Exposed`. `qqqai audit
--fail-on` needs to compare against a severity, and an agent needs to branch on
it — both impossible against free text. The classification rule is stated in one
function rather than inferred, and tested across every capability: anything that
writes or reaches the network is `Exposed`.

---

#### §O-019d — Manifest discovery does not walk upward, deliberately

`qqqai` looks for `qqq.toml` in the current directory only. Upward search is
convenient and ambiguous: in a directory nested under two projects, which
manifest applies? NN-5 says nothing important is inferred, so the rule is one
directory plus an explicit `--manifest` flag.

A test (`discovery_does_not_walk_upward`) creates a nested directory under a
project and asserts the parent manifest is **not** found. If upward search is
ever wanted, that test has to be deliberately changed.

---

#### §O-019e — Three test failures, all my expectations being wrong

Every one of the three initial failures was a **test** defect, not a code
defect. Recorded because the pattern keeps recurring:

| Failure | What was wrong |
|---|---|
| `caps` summary did not contain `"crypto"` | The summary reports counts; namespace *names* live in the structured field an agent reads. My assertion tested the human string for data that belongs to the machine contract. |
| The developer-overlay warning did not fire | The warning fires only when an overlay **changes something** — correct behaviour, since warning about a no-op trains users to ignore warnings. My test applied it to a deny-all manifest where it is a no-op. |
| The unknown-capability error did not mention `qqqai caps` | The *message* offers a name suggestion when one is close; the *remediation* explains the naming convention. I asserted on the wrong field. |

**Each fix improved the test.** The overlay case in particular gained a second
assertion worth having: `a_developer_overlay_cannot_widen_a_deny_all_manifest`
proves through the command surface that `--cap` cannot grant authority the
manifest did not declare — a security property now tested end to end, not only
in `qqq-cap`.

**Cross-refs:** Checklist `CLI-015`, `CLI-018`, `CLI-019`, `CAP-012`, `SEC-002`;
Proposal §5.2, §6.2.

---

### §O-020 — `build` and `run`: the loop closes, and two real bugs fall out

**What was built.** `qqq-run::build` (toolchain probing, plan, execution, artifact
classification, staging, reproducibility) and `qqq-run::run` (artifact location,
pre-flight import checking, grant resolution, instantiation, trap reporting), the
`[build]` section in the manifest, and the CLI wiring for `build` and `run`.
Implements `CLI-008`, `CLI-009`.

**Verification — by running the loop against a real project:**

```console
$ qqqai build
e2eapp: target/qqq/e2eapp.component.wasm (14372 bytes) for wasm32-wasip2

$ qqqai run
e2eapp: ran in 86 µs
```

`cargo test --workspace` → **363 pass**; `clippy --workspace --all-targets -D
warnings` → clean; `check_xrefs.py` → PASSED; `check_wit.py` → 13/13 PASSED.

---

#### §O-020a — The artifact classifier was wrong, twice, and tests passed both times

**First bug.** The classifier walked the Wasm section framing and reported "core
module" on seeing a type or code section. Running it against a real
`wasm32-wasip2` artifact produced:

```console
$ qqqai build
error[QQQ-1002]: the build produced a core module, not a WebAssembly component
```

The artifact was a component. `wasm-tools print` showed `(component (core module
$main …))` — and that is the whole explanation: **a component *contains* core
modules.** Its payload begins with `\0asm` and holds type and code sections, so
any rule that looks for core sections *inside the file* misclassifies every
genuine component. The check had to move to the header.

**Second bug.** Having moved to the header, the discriminator was written as
`bytes[4] == 1` for a component. But `bytes[4]` is the *version*'s low byte, and
a **core module's version is `01 00 00 00`** — so every core module was reported
as a component. The real layout is:

```text
core module: \0asm  01 00  00 00
                   version layer
component:   \0asm  0d 00  01 00
                   version layer
```

The **layer** (bytes 6..8, little-endian) is the discriminator; the version
(bytes 4..6) differs for historical reasons and must not be consulted.

**Why this is the most instructive failure in the round.** The first version had
five passing unit tests, written by me, asserting the behaviour I had just
implemented — including one that constructed a fake artifact with a type section
and asserted it was a core module. **The tests encoded the same wrong model as
the code**, so they confirmed the mistake rather than catching it. One command
against one real artifact found it immediately.

The regression test now uses the **literal first eight bytes captured from a real
`wasm32-wasip2` build on this machine** (`\0asm\x0d\0\x01\0`), and a companion
test asserts classification ignores the body entirely — the exact property the
first implementation violated.

**Lesson, restated because it keeps recurring (§O-016b, §O-017a):** a test
written from the same mental model as the code cannot refute that model. For
anything defined by an external format, capture real bytes and assert on those.

---

#### §O-020b — An interface is not a package, and the false alarm was on the most load-bearing diagnostic

**What happened.** `run` compares a component's imports against the grants. The
component imports **interfaces** — `qqq:clock/wall-clock@1.0.0`. QQQ's registry
grants **packages** — `qqq:clock@1.0.0`. Normalising both by stripping `@version`
left `qqq:clock/wall-clock` versus `qqq:clock`, which never match.

The effect: a component whose capability *was* granted was told its import was
missing. The positive control caught it — granting `clock.wall` did not satisfy
the import, which is not a state that should exist.

**Fix.** `package_of` reduces both forms to `namespace:name`, dropping the
version *and* the interface path:

```text
qqq:clock@1.0.0      -> qqq:clock
qqq:clock/now@1.0.0  -> qqq:clock
wasi:cli/stdout@0.2  -> wasi:cli
```

A name without a colon is returned unchanged rather than mangled, so an unknown
foreign import cannot be reduced into a spurious match against another unknown.

**Why it matters more than a matching bug.** The import check is the diagnostic a
user meets when their capability model is wrong — the single moment the whole
design has to be *clear*. A false "missing import" for a granted capability
teaches users to distrust the tool and to grant capabilities they do not need,
which is the failure the capability system exists to prevent.

**And the second half.** The tests passed while this was broken, because they
used the same string form the code did. The fix was found by building a real WAT
component that imports the real interface, against a real manifest.

---

#### §O-020c — `GrantSet::empty().narrow(...)` grants nothing, and a test helper built that way proves nothing

`narrow` **intersects**. Intersecting with the empty set is empty. So the
`qqq-host` test helper

```rust
GrantSet::empty().narrow(&Overlay::allow_only(Layer::Manifest, caps, "test"))
```

grants **nothing regardless of `caps`**. Two consequences, both observed:

* The deny-by-default assertion passed trivially — it would have passed against
  any implementation.
* The positive assertion failed, for a reason unrelated to the code under test.

**Fix.** The helper now builds a real `qqq.toml` and calls `GrantSet::from_manifest`
— documented as *the only layer that may grant authority* — and then **asserts
its own precondition**, failing loudly if it did not grant what it was asked for.

**The generalisable part.** A test fixture that cannot construct the state it
means to test is worse than no test, because it produces green with no coverage.
Helpers deserve the same scrutiny as production code, and the strongest form is
for the helper to assert what it produced before the test asserts on it.

---

#### §O-020d — The stub gap was real: host logic existed but was never bound

`ambient.rs` had a complete, tested `AmbientState` — deterministic clock, seeded
RNG, hashing. `StoreData` carried it. But `build_linker` never registered **any**
host function: the function body was a `let _ = &linker;` and a comment saying
the implementations "land next". So every granted capability was reported
unimplemented at instantiation, and no component could import anything.

**And the comment cited the wrong checklist item, twice.** It said
`QQQ-STUB(HOST-016)`. `HOST-016` is `epoch_deadline_async_yield_and_update` — a
scheduling concern with no relation to interface implementation. The correction
first landed on `CON-011`, which is the WIT style guide: also wrong. Only on
checking every `CON-*` item did the real situation become clear: **there is no
checklist item that says "implement the host functions of interface X".** The
closest governing item is `CON-009` (every fallible host call returns
`result<T, E>`).

**Why a wrong cross-reference is worse than none.** A stub marker is a promise
that a reader can follow it to the work that closes it. Pointing at an unrelated
item means the next person reads a scheduling task, concludes the host
implementations are already tracked, and moves on. The project's whole
cross-referencing discipline exists to prevent exactly this, and it was violated
in a comment that *looked* rigorous because it carried an identifier.

**Lesson:** an identifier is not a citation. Before writing `§x` or `ITEM-nnn`,
open the target and confirm it says what you are claiming it says. Two of the
three stubs in this repository cited the right item; the one that did not was
the one whose reference was never opened.

This session wired `qqq:clock`: `host_clock.rs` registers `wall-clock` and
`monotonic-clock` under their own grants, with `now`, `resolution` and `timezone`
on the wall clock. `AmbientState` gained `elapsed_nanos` and
`tick_interval_nanos`, backed by a lazily-captured `Instant` origin — `Instant`
rather than `SystemTime` because a monotonic reading must never go backwards when
the system clock is adjusted.

**Registration is per-function, not per-interface.** `clock.wall` and
`clock.monotonic` are separate capabilities, so a manifest granting only
`monotonic` must not expose `now`. A test (`registration_follows_the_grants`)
pins this in both directions.

**The probe, and its positive control.** `Linker` exposes no lookup API in
Wasmtime 48 — the public surface is `new`, `engine`, `allow_shadowing`, `root`,
`instance`, `instantiate*`, `func_wrap*`, `func_new*`, `module`, `resource*`,
`define_unknown_imports_as_traps`. There is no `get` and no `iter`. The
observable signal is **shadowing**: with shadowing disallowed, redefining a name
fails while defining a free one succeeds. So a probe was written that redefines
the name and reports presence on failure.

An earlier draft of that probe **returned a hardcoded `false`**, which would have
made the deny-by-default test pass vacuously. `the_registration_probe_can_detect_a_bound_function`
exists specifically to catch that: it asserts the probe reports a function that
is certainly registered. A probe needs a positive control or it is decoration.

**The empirical check, not the reasoned one.** The shadowing behaviour was
confirmed with a throwaway example that printed actual results —
redefining with a different signature errors (`true`), redefining with the same
signature errors (`true`), defining a new name succeeds (`false`). Three lines of
output replaced a paragraph of reasoning about `NameMap` internals.

---

#### §O-020e — Hand-written bindings are pinned to the WIT by tests

`qqq:clock`'s host functions are written by hand against `wit/qqq-clock.wit`,
because `wasmtime::component::bindgen!` needs the `wit/` directory wired into the
crate build — the right change for the *whole* interface set at once, not for one
interface. Until then three tests keep the hand-written binding honest:

| Test | Property |
|---|---|
| `every_wit_function_is_registered` | Every function declared in the WIT appears in the host file. `now` and `resolution` appear in **both** interfaces, so the test **counts** occurrences rather than checking presence — a presence check would pass with only one registered. |
| `the_package_name_matches_the_wit` | The interface constant equals the WIT `package` declaration. A typo binds a name no component imports, and every call fails while the file looks correct. |
| `the_error_variant_order_matches_the_wit` | `ClockError`'s indices follow the WIT `variant` declaration order. A swapped case makes a guest read a denial as an out-of-range error — silent, and security-relevant. |

---

#### §O-020f — The security property, verified end to end for the first time

A WAT component importing `qqq:clock/wall-clock@1.0.0` was built with
`wasm-tools parse` and run against two manifests:

| Manifest | Result | Exit |
|---|---|---|
| deny-all | `error[QQQ-6003]: the component imports 'qqq:clock/wall-clock@1.0.0' that no grant provides` + the generated `qqq.toml` stanza | **1** |
| `[capabilities.clock] wall = true` | `deniedapp: ran in 28 µs` | **0** |

This is the first time a QQQ component has actually called into a host
capability. The refusal happens **before any instruction runs**, and names the
exact interface and the exact stanza that would resolve it.

**Cross-refs:** Checklist `CLI-008`, `CLI-009`, `PKG-001`, `SEC-002`, `DET-002`,
`CON-009`; Proposal §4.6, §5.2, §5.3, §6.1, §10.5.

---

### §O-021 — `qqq:crypto` becomes real: two interfaces, and the tests that expired

**What was built.** `qqq-host::host_crypto` registers the `random` and `hashing`
interfaces of `qqq:crypto@1.0.0`, following the pattern `host_clock` established:
per-capability registration, a call-time re-check, and hand-written bindings
pinned to the WIT by tests.

**Scope, stated precisely — unchanged from `§O-018`'s honesty.** `hmac`, `aead`
and `signing` remain **unimplemented and deliberately unregistered**. The
registry still reports `qqq:crypto@1.0.0` as `implemented: false`, and
`qqq-abi`'s test still pins that. Partial service must not claim completeness: a
component needing AEAD would otherwise pass admission and fail at first call.

**Verification — three real components, by running them:**

| Component imports | Manifest grant | Result | Exit |
|---|---|---|---|
| `qqq:crypto/hashing` (digest + digest-many) | `hash = ["sha256"]` | instantiated, 13 µs | **0** |
| `qqq:crypto/hashing` | `random = true` only | `QQQ-6003`, hashing not exposed | **1** |
| `qqq:crypto/hashing` | deny-all | `QQQ-6003`, refused at import check | **1** |
| `qqq:clock/wall-clock` | `wall = true` | instantiated, 28 µs | **0** |

`cargo test --workspace` → **378 pass**; `clippy -D warnings` → clean.

---

#### §O-021a — Two tests expired the moment the feature landed, and that is correct behaviour

Wiring `qqq:crypto` broke two tests that had been green:

* `linker::a_granted_capability_binds_its_interface_and_reports_the_gap`
* `instance::a_granted_but_unimplemented_capability_is_reported_clearly`

Both used `crypto.hash` as their example of a capability with **no host
implementation**. Once `host_crypto` landed, that example stopped being true and
the assertions failed.

**They were right to fail.** The tests were correct and the code changed under
them. The instructive part is what a careless fix looks like: deleting the
assertions, or relaxing them, would have silently removed the only coverage of
"an unimplemented capability is reported clearly" — a property that still
matters, because eight capabilities remain unimplemented.

**The fix.** Both tests were **repointed** at `fs.read`, which has no registered
interface, and each gained a converse test proving an *implemented* capability
is **not** reported as a gap. That second test catches a regression in the other
direction: marking everything unimplemented would otherwise leave the original
assertions passing while breaking every real component.

**The generalisation, worth stating because it will recur many times as this
runtime fills in:** *a test that names a specific unfinished feature has an
expiry date.* When such a test fails, the failure is information — the feature
landed — not noise. Repoint it at something still unfinished, and add the
converse.

---

#### §O-021b — `ComponentNamedList` is implemented for tuples, not for bare types

A host function's parameters and return must satisfy `ComponentNamedList`. That
trait is implemented for **tuples**, so a function returning one value must
return `(T,)`:

```rust
// does not compile — Vec<u8> is not a ComponentNamedList
|store, (length,): (u32,)| -> Result<Vec<u8>>

// compiles — the one-element tuple is the named list
|store, (length,): (u32,)| -> Result<(Vec<u8>,)>
```

`Vec<T>` *is* the Rust type for WIT `list<T>`, which is what made the error
confusing: the element type was right and the container was wrong. The
distinction is between a **component type** (`ComponentType`, satisfied by
`Vec<u8>`) and a **named list of component types** (`ComponentNamedList`,
satisfied by tuples of them). The Component Model's flat parameter
representation is what forces this, not a stylistic choice.

Found by compiling, in one attempt. No amount of reading the WIT would have
surfaced it — the WIT was correct and the Rust was wrong.

---

#### §O-021c — A test that greps prose tests the prose

One of the new tests asserted that the names of unimplemented interface
functions (`compute`, `encrypt`, `sign`, …) do not appear in `host_crypto.rs`.
It failed — because the word `compute` appears in that file's own documentation
explaining which interfaces are unimplemented.

**The property was right; the detection was wrong.** The assertion should be "no
host function is *registered* under this name", and registrations are written
`func_wrap("name"`. Matching the registration form rather than the bare word
tests the property. A positive control
(`the_unregistered_check_can_find_a_registered_name`) asserts the same detection
*finds* `digest`, which is registered — without it, a matcher that never matched
anything would look like proof.

**Cross-refs:** Checklist `CON-009`, `CON-012`, `CAP-001`, `SEC-002`, `DET-003`;
Proposal §4.5, §6.3, §7.4, §10.5.

---

### §O-022 — CI was red from the first commit, and nobody noticed

**The discovery.** The GitHub commit list showed a red ✗ on every commit since
the repository was created. Not one commit had ever passed. The cause was the
**first step of the Rust job**: `cargo fmt --all -- --check` failed, which
short-circuits every later step on all three platforms. So `clippy`, `build`,
`test` and the unsafe check had **never once run in CI**.

**What this means for every prior claim in this document.** Each round reported
"clippy clean, tests pass" — and every one of those reports was **local only**.
The numbers were real, but they were verified on one machine, in one
configuration, by the same person who wrote the code. That is exactly the
evidence the three-platform matrix exists to replace, and the guarantee I
thought I had was not in force.

**Three separate defects, all fixed:**

| # | Defect | Fix |
|---|---|---|
| 1 | Formatting drift in every crate, from the first commit | `cargo fmt --all` |
| 2 | The unsafe check grepped `\bunsafe\b`, so it failed on a comment reading *"which is the unsafe direction"* | Match the `unsafe` **keyword** in code positions: `unsafe {`, `unsafe fn`, `unsafe impl`, `unsafe extern`, `unsafe trait`. Added a second check that every crate except `qqq-sys` carries `#![forbid(unsafe_code)]` |
| 3 | Three `build` tests asserted *arguments* through `plan`, which also probes for `wasm-tools` — absent on a bare runner | Split into `plan_pure` (no host access) and `plan` (probes). See §O-023 |

**A fourth, found only because the matrix now ran**: `the_unregistered_check_can_find_a_registered_name`
passed on macOS and Ubuntu and failed on Windows, because it matched the literal
string `func_wrap(\n        "digest"` — one newline and eight spaces. `rustfmt`
lays the call out differently on that runner. **A test whose result depends on
where a line breaks is not testing the property it names.** The detection now
strips whitespace first, and a dedicated test feeds the same call in three
layouts to pin it. See §O-024.

**The lesson, and it is the sharpest one in this document.** The cross-reference
validator, `check_wit.py`, `self_test_xrefs.py` and `audit_requirements.py` all
ran *locally* and all passed, and their passing was reported as evidence. But the
audit's "working tree clean" check and the xref validator prove things about the
**corpus**; neither of them ever looked at what CI does. A green local run and a
green pipeline are different claims, and only one of them is about the code
anyone else will get.

**What made the difference.** Not more tests — the tests were already right. It
was **looking at the actual commit list** rather than trusting the summary. The
red ✗ marks had been visible in the repository UI the whole time.

**Now verified:** run `35479329970` — `"conclusion":"success"`, all six jobs
green across `ubuntu-latest`, `macos-latest` and `windows-latest`.

---

#### §O-022a — The 415 → 418 test count is a different measurement

Worth stating because the number changed while the code barely did. Local totals
were reported as 363, then 378, then 415. The 415 figure comes from
`--all-features` on Windows; the earlier ones did not pass that flag. The counts
are not directly comparable, and the increase is not 52 new tests — it is partly
a different measurement of the same suite.

The lesson is smaller but the same shape as §O-022: **a number is only meaningful
with the command that produced it.** Every count in this document now names its
invocation.

**Cross-refs:** Checklist `FND-004`, `FND-005`, `CON-016`, `DOC-007`, `ARCH-008`;
Proposal §11.1, §2.2 NN-2.

---

### §O-023 — A test can be right about what it checks and wrong about how it reaches it

Three tests in `qqq-run::build` asserted that a manifest with a given profile
produces the right `cargo` arguments. They called `plan` to get those arguments.
`plan` also probes the host for the toolchain — including `wasm-tools`, which is
installed here and is not on a GitHub runner. So on CI the probe failed before
the assertion could run:

```text
thread 'build::tests::a_rust_project_plans_a_cargo_build' panicked:
must plan: Error { code: MissingTarget,
  cause: ["missing:\n  wasm-tools (...)"] }
```

**The tests were not wrong.** The behaviour they named is real and they asserted
it correctly. They were checking it *through a door that is locked on that
machine*.

**The fix separates two questions that were sharing a function:**

```text
plan_pure(manifest, options) -> BuildPlan   pure; no host access
plan(manifest, options)      -> BuildPlan   plan_pure, then probe the toolchain
```

Argument construction is a function of committed inputs, so it is now testable
anywhere. Toolchain availability is a property of the machine, tested where it
can be controlled. A further test asserts the two agree on the arguments when
the toolchain *is* present — the probe must add a check, not a second
interpretation of the manifest.

**Verified by reproducing the CI condition exactly:** a PATH shim containing
`cargo`, `rustc` and `rustup` but deliberately not `wasm-tools`.

```text
with wasm-tools absent:  cargo test -p qqq-run --lib  -> 137 pass, 0 fail
with wasm-tools absent:  qqqai build --dry-run        -> QQQ-1003 naming
                                                          wasm-tools and
                                                          `cargo install wasm-tools`
```

So the missing-tool diagnosis survives — only the test's route to the assertion
changed. **Building the CI environment by hand was what turned a guess into a
verification.**

**Cross-refs:** Checklist `CLI-008`, `FND-004`; Proposal §5.2, §4.6.

---

### §O-024 — Two scaffold bugs that only running the generated project could find

`qqqai new` was implemented with 22 tests, all passing, covering name validation,
template dispatch, generated manifest contents and zero-capability guarantees.
Then the generated project was actually built, and it did not compile. Twice.

**Bug one.** The scaffold wrote `src/<crate>.rs` and declared
`crate-type = ["cdylib"]` without a `path`. Cargo refuses to parse the manifest:

```text
error: failed to parse manifest
  can't find library `orders_api`, rename file to `src/lib.rs` or specify lib.path
```

Every string assertion in the suite passed throughout, because they asserted on
*text in generated files* rather than on whether Cargo would accept that text.

**Bug two.** With that fixed, the build still failed:

```text
error: failed searching for potential workspace
invalid potential workspace manifest: /home/user/Cargo.toml
```

Cargo walks **up** the directory tree looking for a workspace. A project created
in a directory containing a stray `Cargo.toml` — which is a normal thing to have
in a home directory — fails to build. The generated `Cargo.toml` now declares an
empty `[workspace]`, making it its own root and independent of everything above.

**Bug three, in `build` itself.** Artifact discovery looked for
`<package>.wasm`. Cargo emits the **crate** name, which is the package name with
hyphens replaced by underscores, so `orders-api` produces `orders_api.wasm`.
Every hyphenated project — including every scaffolded one — compiled
successfully and was then reported as *"the build succeeded but no component was
produced"*. Discovery now tries the underscored name, then the literal name, then
any single `.wasm`, and reports every candidate it saw when all three fail.
Ambiguity resolves to an error rather than a guess, because picking the wrong
artifact silently would ship the wrong code.

**The pattern, and it is the same one as §O-016b, §O-017a and §O-020a:** the tests
encoded my model of the tooling, not the tooling. Twenty-two assertions about
strings could not tell me that Cargo would reject the file those strings were
written into. **Running the generator's output found three defects in one
command.**

**The regression tests added for each** are anchored on the real constraint
rather than on my description of it: `the_declared_lib_path_is_a_file_that_is_written`
parses the generated `Cargo.toml` and checks the path exists among the files the
scaffold wrote; `a_generated_crate_is_its_own_workspace_root` asserts the
`[workspace]` table is present; and artifact discovery has eight tests including
the hyphenated case taken from the real failure.

**The loop, verified end to end:**

```console
$ qqqai new orders-api --lang rust --template http
created orders-api (http, 6 files, 0 capabilities granted)

$ qqqai caps
orders-api: no capabilities granted

$ qqqai build
orders-api: target/qqq/orders-api.component.wasm (14231 bytes) for wasm32-wasip2

$ qqqai run
orders-api: ran in 145 µs
```

**Cross-refs:** Checklist `CLI-003`, `CLI-008`, `CLI-009`, `DX-001`, `DX-002`;
Proposal §5.2, §5.3, §12.1.

---

### §O-025 — `qqqai init`, and the two defects that only a real project revealed

**What was built.** `qqqai init` (CLI-004): adopt an existing directory, detect
its language and crate name, write a manifest that grants nothing, and **never
overwrite a file the user owns**. Detection is reported with its *source* —
`existing-manifest`, `inferred-from-files`, `default` or `explicit` — so a guess
is visibly a guess.

**The command's central decision.** `init` runs on a directory that already
contains someone's work, which makes it the one command in the CLI that can
destroy value. Its rule is absolute: `USER_OWNED` files are never replaced, **and
`--force` does not override that**. A `--force` that clobbered a hand-written
`qqq.toml` would silently discard the capability decisions that are the entire
point of the manifest, in the one command a user runs on a directory they already
care about.

**Verified against a real project, not a fixture:**

```console
$ cd legacy-app && qqqai init
initialised legacy-app (rust, 3 files written, 2 existing preserved, 0 capabilities granted)

$ qqqai build
legacy-app: target/qqq/legacy-app.component.wasm (14340 bytes) for wasm32-wasip2

$ qqqai run
legacy-app: ran in 88 µs
```

`src/lib.rs`, `README.md` and `Cargo.toml` all survived byte-for-byte.

---

#### §O-025a — The manifest was named after the directory, and `build` could not find the artifact

**What happened.** `init` took the project name from the directory. In
`/tmp/qqq-init-test/` containing package `legacy-app`, it wrote
`name = "qqq-init-test"`. Since `Cargo.toml` is user-owned and therefore not
rewritten, the manifest and the crate disagreed — and `build` looks for the
artifact under the manifest's name, so an initialised project could not be built.

**Fix.** Detection now reads `[package] name` from an existing `Cargo.toml`
before falling back to the directory name, and `name_source` reports
`existing-manifest` so the user can see where the name came from. The scan is a
deliberately small line reader rather than a TOML parse: `init` needs one string
from a file it will not modify, and making it depend on a full parser would mean
a malformed `Cargo.toml` could stop `init` from adopting the directory at all.
It reads only the `[package]` table, so a `name` under `[dependencies]` cannot be
mistaken for the crate.

---

#### §O-025b — `init` wrote an orphan source file into an existing crate

**What happened.** The Rust template writes `src/<crate>.rs` and points
`[lib].path` at it. In a crate that already existed, `Cargo.toml` was correctly
left alone — so the generated `src/qqq_init_test.rs` was referenced by nothing
and compiled by nothing. Not destructive, but misleading: a file appeared in the
user's `src/` with no explanation and no effect.

**Fix.** `has_existing_rust_library` detects an existing `src/lib.rs` or
`src/main.rs`, and the source files are then **skipped** — reported in a
`skipped` field and in a note, because a user who expects a file and does not get
one needs to know it was a decision rather than a bug.

---

#### §O-025c — A test caught a protection list that protected nothing

`USER_OWNED` listed `package.json`, which the scaffold never generates. The entry
protected no file while making it look as though that case were handled, and
`every_user_owned_name_is_a_file_the_scaffold_writes` failed on exactly that.

**The fix was to split one list into two, because they answer different
questions:**

| List | Question | Constraint |
|---|---|---|
| `USER_OWNED` | Which generated files must never be replaced? | Must be exactly the files the scaffold writes |
| `PRESERVED_INTERESTING` | Which pre-existing files should the report acknowledge? | A superset, including files the scaffold does not touch |

Three tests now pin the relationship in both directions, including that a file
which is both generated *and* reported must be protected — otherwise the report
would be a lie.

**Why this is worth recording.** The instinct on seeing that failure is to delete
`package.json` from the list. That would have removed the *reporting* behaviour,
which is genuinely useful, to fix a *classification* mistake. The test was right;
the data structure was wrong.

---

#### §O-025d — The decision order is the safety argument, so it is now reviewable as a unit

`write_scaffold_files` was extracted from `init` (which had grown past the line
limit, and the extraction was the right fix rather than an allow attribute). The
order is now one screen:

1. user-owned and present → leave it, unconditionally
2. source in a crate that already has a library → skip it
3. present without `--force` → leave it
4. present with `--force` → replace, and record that we did
5. absent → write it

Three tests pin the precedence directly: rule 1 beats rule 4 (`--force` cannot
override the user-owned protection), rule 2 beats rule 3 (a skipped file is
reported as *skipped*, not as preserved — reporting it otherwise would tell a user
a file of theirs survived when nothing was ever there), and rule 4 does replace a
plain file, so `--force` is not inert.

**Cross-refs:** Checklist `CLI-004`, `DX-001`, `DX-002`, `CON-002`; Proposal
§5.2, §5.3, §12.1.

---

### §O-026 — `qqqai dev`: the tier-1 reload loop, and a watcher built on polling

**What was built.** `qqq-run::watch` (`DX-009`) and `qqq-run::dev` (`CLI-010`,
`DX-003`).

**Verified by driving it with real file edits, not simulated ones:**

```console
$ qqqai dev --reload-limit 2      # edited src/devapp.rs twice
devapp: 2 reload(s), listening on http://127.0.0.1:3000
  reload 1  component-swap  src/devapp.rs   992ms
  reload 2  component-swap  src/devapp.rs  1066ms

$ qqqai dev --reload-limit 1      # edited qqq.toml
  reload 1  full-restart    qqq.toml        190ms
            "the manifest changed; capabilities and limits must be re-resolved"
```

---

#### §O-026a — The watcher polls, and that is a deliberate choice

The obvious implementation uses OS notifications through a crate. Rejected for
four reasons, each specific to this runtime:

| Reason | Detail |
|---|---|
| Semantics leak across platforms | inotify splits a rename into two events, `ReadDirectoryChangesW` coalesces differently, macOS `FSEvents` has its own latency floor. A debounce tuned on Linux behaves differently on macOS, so "why did my rebuild fire twice" becomes a platform question. |
| Inode watches miss the commonest save | Editors that write a temp file and rename it over the original — `vim`, `emacs`, many `JetBrains` saves — produce a *different* inode, and a watch on the old one goes silent. This is the classic "hot reload stopped working" bug. |
| No notification flood to defend against | A build writing into the tree cannot make the watcher thrash, so the debounce stays simple enough to reason about. |
| Portable by construction | `(path, mtime, size)` is reported by every filesystem. |

The cost is latency bounded by the poll interval. It is **inside** the 50–300 ms
tier-1 budget rather than beating it inconsistently per platform, which is worth
more than being 90 ms faster on one OS and erratic on another.

---

#### §O-026b — The ignore defaults are what make the watcher terminate

`target/` is not an optimisation. If it is watched, a build writes into the
tree, the watcher sees it, and the rebuild triggers another rebuild — forever.
The dev server then appears to hang because it is compiling in a loop.

The tests pin this in both directions: `the_build_directory_is_ignored` and
`a_change_inside_an_ignored_directory_is_invisible` on one side, and
`real_source_is_never_ignored` on the other — because a watcher that ignores too
much **silently stops working**, which is worse than one that ignores too little.
A further test (`a_rule_matches_components_not_substrings`) pins that `targets.rs`
is not `target/`, and `distribution.rs` is not `dist/`.

---

#### §O-026c — Size is compared as well as mtime, because mtime alone misses real edits

A file saved twice within the filesystem's timestamp resolution has the same
mtime. Editors are fast, and some filesystems have coarse clocks. Comparing only
mtime means a real edit is reported as "no change", and the dev server silently
does nothing — the worst failure mode available, because the user sees no error.
Size as a second signal catches the common case where the two saves differ in
length.

---

#### §O-026d — The pure half is separated from the impure half, so timing is testable

`IgnoreRules` and `Debouncer` take no filesystem action; only `Snapshot` reads
the disk. Crucially, `Debouncer::observe` and `should_fire` **take the current
instant as a parameter** rather than calling `Instant::now()`.

That makes the debounce a pure function of `(events, time)`, so every timing
behaviour is tested without sleeping: a burst coalescing into one trigger, a slow
drip still coalescing while it continues, a change arriving exactly on the window
boundary, observing zero changes not arming the trigger, and a backwards clock
not panicking. **Tests that sleep are slow and flaky; tests that pass a timestamp
are neither.**

This is the same split as `plan`/`plan_pure` (§O-023), and it was made for the
same reason after that lesson: environment-dependent behaviour must be reachable
through a pure entry point, or its tests are testing the machine.

---

#### §O-026e — Tier selection is security-relevant, not an optimisation

A `qqq.toml` edit must force a **full restart**, never a component swap. The
linker and the store are built once per instance and hold authority. A swap
reuses them, so:

* A **granted** capability would not take effect — the new code would be denied
  something the user just granted, and it would look like a bug in their code.
* A **revoked** capability would keep working until the process restarted. A
  developer could remove a grant, run their tests, see them pass, and ship.

The second is the dangerous one: it is exactly the drift the capability model
exists to prevent. So the strictest tier wins when changes are mixed, and the
reason string names the cause so a user wondering why their edit cost 1.5 seconds
can see it was the manifest.

---

#### §O-026f — Two flags added beyond the Proposal's list, to make the loop verifiable

The Proposal lists `--port`, `--open`, `--https`, `--inspect`. Two more were
added: `--once` compiles and exits, and `--reload-limit N` bounds the watch loop.

**An unbounded loop that cannot be bounded is a loop that cannot be tested.** The
verified behaviour in §O-026 — two edits producing two reloads with the right
tier — is only checkable because the loop can be told to stop after N cycles. The
alternative would have been to report "the loop is implemented" on the strength
of reading the code.

---

#### §O-026g — The missing listener is stated, not hidden

There is no HTTP listener yet (`CLI-011`, `qqq-serve`). `dev` therefore compiles
and reloads but serves nothing, and **says so in its human output and in a JSON
`notes` field** rather than appearing to listen.

A dev server that prints `Listening on http://127.0.0.1:3000` and does not listen
would be a stub wearing a working command's clothes — the failure mode this
project's working rules forbid. The port is still reported, because it is the
address `serve` will use and a user needs to know it before it works.

**Cross-refs:** Checklist `CLI-010`, `DX-003`, `DX-009`, `DX-006`, `DX-007`;
Proposal §6.6, §12.1.

---

### §O-027 — `qqq-serve` begins: the route table, and `OQ-007` resolved

**What was built.** `qqq-serve::route` (`SRV-003`): a segment radix trie that
turns a request path into a handler, built once at load and never mutated.

**`OQ-007` is resolved, and the checklist left it genuinely open.** Checklist
`SRV-006` asks whether `wasi:http` is the foundation or whether a custom
interface is required. **`wasi:http` is the foundation; `qqq:http` extends it.**

The reasoning:

* `wasi:http` is the only HTTP interface a component can import without
  QQQ-specific toolchain support. Building on it is what makes the
  five-language claim real rather than aspirational — a Go or Python component
  reaches QQQ's server through the interface it would use anywhere else.
* But `wasi:http` has no route table, no per-route capability scoping, and no
  way to express "this handler may read but not write". Those are QQQ's
  contributions, and they belong in an extension rather than a fork.
* The `qqq:http` WIT in this repository already said so — its module comment
  reads *"Built over `wasi:http`, adding the routing and headers an application
  actually needs while keeping the guest's view of a body a **stream** rather
  than a buffer."* The WIT had answered the question before the checklist asked
  it, which is a sign the interface was designed rather than accreted.

**The consequence that matters:** the route table is **host-side**. A guest never
sees a pattern; it is handed a matched request with parameters already extracted.
Pattern syntax therefore stays out of the ABI and can change without a WIT
version bump — the property that makes an extension safe to evolve.

---

#### §O-027a — Two bugs the tests caught, both in the trie's shared structure

Both were found by tests written *before* the fix, and both were cases a
hand-written router gets wrong.

**Bug one: a wildcard did not match an empty remainder.** `walk` returned early
when the path was exhausted and no handler sat on the node — so `/files/*rest`
never answered `/files`, because the wildcard is a *child* and the early return
never reached it. The terminal case must try **both** a handler on this node and
a wildcard child.

**Bug two: capture names collided between routes sharing a prefix.** This is the
subtle one, and it is structural rather than a slip.

The trie is **shared** between patterns that differ only in their capture names.
`/a/:x/c` and `/a/:y/b` walk the same `a` node and the same param child; only the
final segment differs. A node-level `param_name` can therefore hold only one of
`x` or `y` — whichever registered first — and the other route reports the wrong
parameter name.

The test that caught it was written for a *different* purpose. It was checking
that a failed branch does not leak parameters into a succeeding branch, using two
patterns that happened to share a prefix:

```rust
let t = table(&[("/a/:x/c", "xc"), ("/a/:y/b", "yb")]);
let m = t.match_route(Method::Get, "/a/1/b").expect("must match");
assert_eq!(m.params.get("y"), Some("1"));   // got None
```

**The fix was to move the names off the trie entirely.** The trie now carries
only *structure*; each `Route` carries its own pattern's segments, so the names
travel with the route that declared them. The walk produces capture *values* in
pattern order and `bind` pairs them with the matched route's names.

That is a better design regardless of the bug: it means two routes can share every
node but their terminals, which is the entire point of a trie, without the nodes
having to arbitrate between them.

**The generalisation.** A shared structure must hold only what is genuinely
shared. A node that caches a name from whichever pattern created it first is
holding per-route data in a per-tree slot, and the collision is then a matter of
registration order — invisible until two routes happen to differ in a capture
name, which is exactly the case a small test table misses.

---

#### §O-027b — Why a segment trie rather than a character trie

"Radix trie" in routing means two different things and the difference matters:

* A **character** trie shares string prefixes, so `/api/v1` and `/api/v2` share
  the `/api/v` chain.
* A **segment** trie splits on `/` and stores one node per segment.

Segment wins here because **every route parameter is a whole segment**.
`/orders/:id` matches `/orders/42`, never `/orders/4x2`. With a character trie, a
parameter node must carry "match until the next `/`" logic, and every wildcard
boundary becomes a place to get an off-by-one wrong. With a segment trie a
parameter is a node meaning "whatever segment is here", and the boundary is
`split('/')` — which the standard library gets right.

The memory saving of a character trie is real and irrelevant at this scale: a
routing table is tens to hundreds of entries, built once, held for the process's
lifetime.

---

#### §O-027c — Priority is a total order, and it is not insertion order

When several patterns could match, exactly one must win, and the choice must not
depend on the order routes appear in `qqq.toml`. Otherwise reordering a config
file silently changes which handler runs — a bug nearly invisible in a diff.

| Rank | Kind | Example |
|---|---|---|
| 0 | literal | `/orders/new` |
| 1 | parameter | `/orders/:id` |
| 2 | wildcard | `/files/*rest` |

The walk implements this directly by trying literal, then param, then wildcard,
and returning the first hit — no post-filtering, no tie-break step. A test
(`specificity_does_not_depend_on_insertion_order`) builds the same table in both
orders and asserts every path matches identically.

The failure this prevents is specific: with a parameter ranked above a literal,
`/orders/new` could never be reached — it would always be captured as an order
id, and the bug would present as a confusing 404 from inside the wrong handler.

---

#### §O-027d — What `qqq-serve` does not do, stated in the crate root

The crate lists its own gaps in a table at the top of `lib.rs`: HTTP/1.1
(`SRV-001`), HTTP/2 (`SRV-002`), streaming bodies (`SRV-004`), TLS (`SRV-007`),
WebSockets and SSE (`SRV-009`, `SRV-010`). A reader of the file knows exactly
what exists without reading the checklist.

The reason to name them is the same as §O-026g: a listener that accepted
connections **without** the limits `SRV-005` and `SRV-011` require — no
`max_request_bytes` enforced during streaming, no graceful drain — would be worse
than no listener, because it would look like a server. Building the route table
first is the ordering that avoids shipping that.

**Cross-refs:** Checklist `SRV-003`, `SRV-006`, `OQ-007`, `CON-007`; Proposal
§6.4, §4.3.

---

### §O-028 — The HTTP/1.1 request parser: bombs become test inputs

**What was built.** `qqq-serve::http1` (`SRV-001` parsing half, `SRV-020` limit
half). 40 tests, all of them attack scenarios.

**The decision that made the tests possible:** parsing takes a byte slice and
returns a head or an error. It does not read, allocate a socket, or block. Every
failure mode Proposal §6.4 names is therefore expressible as an input:

| Attack | Input | Result |
|---|---|---|
| header bomb | 110 headers | 431, connection closes |
| oversized header | one 8 KiB+ header | 431, names the header |
| oversized head | 64 KiB+ head | 431 |
| request flood | 8 KiB+ target | 431 |
| smuggling | `Content-Length` + `Transfer-Encoding` | 400, connection closes |
| smuggling | two `Content-Length` | 400, rejected even when equal |
| body bomb | declared over the cap | 413, **before** the body is read |

**A parser coupled to a socket can only be tested by being attacked. This one is
tested by being handed the attack.** That is the whole reason for the separation.

---

#### §O-028a — Limits are checked during the parse, not after buffering

The tempting implementation reads until `\r\n\r\n` and then validates. That is
**unbounded work driven by the peer**: the check happens after the memory is
already spent, so a header bomb costs the memory it was designed to cost and the
limit only decides what error message follows.

Every bound here is checked as the parse proceeds, so a header bomb is refused
after [`MAX_HEADERS`] headers rather than after the buffer fills. Each limit is a
count or a length, never a timeout — timeouts depend on the socket and belong to
`SRV-012`.

---

#### §O-028b — A limit on each part is not a limit on the whole

`MAX_HEADERS` (100) × `MAX_HEADER_BYTES` (8 KiB) is 800 KiB. Each bound is
satisfied and the total is eight times what the project wants to spend on a
request head. `MAX_HEAD_BYTES` (64 KiB) is the backstop that makes the total
bounded, and it is checked *first*, before any scanning.

This is worth stating because the mistake looks like completeness: three limits
were specified and three were implemented, and the composition is still
unbounded.

---

#### §O-028c — Three refusals that are security checks rather than validation

**Both framing headers → refuse.** Which of `Content-Length` and
`Transfer-Encoding` determines the body length is exactly what two
implementations disagree about, and that disagreement is the attack. Refusing is
the only answer that does not depend on being right about the other party.

**Two `Content-Length` headers → refuse, even when they agree.** A proxy that
rewrites one would desynchronise; the redundancy itself is the signature.

**A header name with a space or a control character → refuse.** RFC 9110 §5.1
defines a field name as a token. A name containing a space is how a header is
smuggled past a proxy that splits on whitespace where the origin splits on the
colon.

Each has a positive control: `every_legal_header_name_character_is_accepted`
walks every character the RFC permits, so the name check cannot degenerate into
rejecting legitimate headers.

---

#### §O-028d — Keep-alive defaults differ by version, and both directions are tested

HTTP/1.1 defaults to **keep-alive**; HTTP/1.0 defaults to **close**. Assuming
either unconditionally is a bug in a different direction each way:

* Assume keep-alive: HTTP/1.0 connections are held open until they time out.
* Assume close: every HTTP/1.1 connection is torn down per request, turning a
  persistent-connection protocol into a per-request one.

`keep_alive_defaults_differ_by_version` asserts both, and two further tests cover
`Connection: close` and `Connection: keep-alive` overriding the default in each
direction.

---

#### §O-028e — Status codes chosen to be actionable, not uniform

| Code | When | Why not 400 |
|---|---|---|
| 431 | a limit was hit | the client can obey by sending less; 400 tells them nothing |
| 413 | the body cap was hit | distinct from a syntax error, and RFC-defined |
| 505 | an unsupported version | the client asked for something coherent we do not speak |
| 400 | syntax, smuggling | the request is wrong, and no smaller version of it is right |

The `closes_connection` property is separate from the status, because a 431 for
an oversized *head* is safe to answer and continue, while a 431 for too many
headers is not: the parser's view of where this request ends is untrustworthy,
and continuing to read risks interpreting body bytes as the next request — which
is the smuggling attack itself.

**Cross-refs:** Checklist `SRV-001`, `SRV-005`, `SRV-020`, `SEC-016`; Proposal
§6.4.

---

### §O-029 — The status policy, and a lint that pointed at a real problem

**What was built.** `qqq-serve::response` — response serialisation and, more
importantly, the mapping from a host failure to an HTTP status.

**The mapping is a product decision, not a translation.** A status determines
what the client does next, so each choice is a claim about the world:

| Failure | Status | The claim |
|---|---|---|
| guest trap, QQQ bug | 500 | our side is broken; retrying changes nothing |
| fuel exhausted, hard limit | 500 | a bug detector fired, not capacity |
| fuel exhausted, soft limit | 503 + `Retry-After` | the limit is a capacity bound |
| epoch deadline exceeded | 504 | the request was fine; we were too slow |
| pool exhausted | 503 + `Retry-After` | shedding load; a retry can succeed |
| capability denied | **500, not 403** | no credential the client sends can help |

**Fuel is the only row that changes with configuration**, and that is
deliberate. A hard limit means the guest ran longer than any real request
should, so infinite-loop protection caught it — telling a client to retry sends
it back into the same wall. `soft_fuel` is the caller declaring the limit to be
a capacity bound, and 503 is then honest.

**An epoch timeout is 504, never 500.** §9.3 says it is *"counted as a timeout,
never as a crash"*. A 500 tells a client its request was malformed-by-us; 504
tells it the request was fine and we were too slow, which is what happened and
what a retry can fix.

**A capability denial is 500, not 403**, and this one is counterintuitive enough
to state twice. A 403 says "you may not", which implies a different credential
would help. Nothing the client sends changes the outcome — the manifest does not
grant the capability. 500 is honest, and the remediation lives in the log where
the operator can see it.

---

#### §O-029a — Clippy flagged duplicate match arms, and it was right for a reason the lint does not know

The first implementation returned `(status, retry, close)` tuples from one big
`match`. Three separate code groups produced `(500, false, false)`, and clippy
reported identical arms.

**The lint was correct, and the problem was worse than the lint.** Writing the
same tuple three times states *"these are the same"* without saying **why** —
and the why is the entire policy. A reader cannot tell "the guest is broken"
from "the manifest is wrong" when both are spelled `(500, false, false)`.

**The fix was to name the classes**, which the lint made visible but could not
have produced:

```rust
pub enum Failure {
    GuestFault,        // the guest or QQQ malfunctioned
    Misconfiguration,  // the deployment is wrong; not 403
    HardLimit,         // a bug detector fired
    Timeout,           // 504, never 500
    OverCapacity,      // shed load; the only class that says retry
    ListenerFault,
}
```

This changed what the tests can assert. `error_response(&err(code)).status ==
500` cannot distinguish the classes, because they share the number. But
`classify(code, false) == Failure::Misconfiguration` is a claim about the
**reason**, and `only_over_capacity_says_retry` becomes expressible at all — a
property that was previously implied by a tuple nobody could read.

**The generalisable lesson, and it is the third time this pattern has appeared
(§O-020a, §O-025c):** a compile-time or lint-time signal about *structure* often
indicates a modelling problem rather than a formatting one. The instinct to
silence it — `#[allow]`, or merging the arms to match — would have deleted the
policy. The right response is to ask what the duplication is failing to say.

---

#### §O-029b — The response body never contains an error code

A `QQQ-` identifier names an internal condition. Returning it tells an attacker
which subsystem failed and gives an integrator a string to depend on that is not
part of the published contract. So the code goes to the access log and a status
phrase goes to the client.

Tested across the whole catalogue: `the_response_body_never_leaks_an_error_code`
walks every `ErrorCode` and asserts none appears in the body, and
`error_bodies_are_minimal` bounds every body at 64 bytes — a verbose error page
is an information leak with a nicer font.

---

#### §O-029c — Three framing rules that prevent a desynchronised stream

1. **`Content-Length` is always emitted, even for an empty body.** A response
   with neither it nor `Transfer-Encoding` leaves the client guessing where it
   ends, and the only correct guess is "the connection closed" — which defeats
   keep-alive entirely.
2. **The measured body length wins over any caller-supplied header.** A caller
   cannot desynchronise the stream by setting a `Content-Length` that disagrees
   with what it passes in.
3. **A status that forbids a body gets none.** 204, 304 and every 1xx. Emitting
   one is a framing error: the client reads it and the bytes become the next
   response's status line.

A fourth is subtler: a caller cannot smuggle a `Transfer-Encoding` header into a
body writer that is not using chunked framing. The header is filtered, because a
response that declares a framing it is not using is worse than one that declares
nothing.

**Cross-refs:** Checklist `SRV-001`, `SRV-011`, `HOST-012`, `SEC-016`; Proposal
§6.4, §9.3.

---

### §O-030 — The connection lifecycle: keep-alive, the header timeout, and drain

**What was built.** `qqq-serve::conn` (`SRV-011`, `SRV-012`) — a state machine
that decides what a connection does next. It owns no socket and never reads a
clock; every timing input is a parameter, the same discipline as the debouncer in
`qqq-run::watch` (`§O-026d`).

**Verified:** 34 tests, covering keep-alive, the request cap, both timeouts, the
drain path, the ledger, and the close-reason classification.

---

#### §O-030a — The header timeout and the idle timeout measure different things, and one cannot replace the other

This is the subtlest decision in the module, and getting it wrong makes
slow-loris **easier** than idle probing.

A client that opens a connection and sends nothing is idle, and the idle timeout
closes it. But a client that sends one byte per minute is *not idle* — it is
mid-head — so the idle timeout never fires, and it holds a connection slot
indefinitely while sending almost nothing. That is precisely the slow-loris
attack Proposal §6.4 names.

So there are two clocks:

| Timeout | Measures | Default |
|---|---|---|
| idle | between requests | 75 s |
| header | during a request head | 10 s |

**The header timeout must be shorter**, and a test asserts it
(`the_header_timeout_is_shorter_than_the_idle_timeout`). If it were longer, a
client mid-head would be treated *more* leniently than one sitting idle, which
inverts the intent. Ten seconds is generous for a head a real client sends in one
or two packets.

---

#### §O-030b — Whether a parse error closes the connection is the parser's decision, not this module's

`Connection::on_parse_error` takes a `&ParseError` rather than a bare "it
failed", and consults `ParseError::closes_connection` (from `§O-028e`).

**Why the indirection is load-bearing.** The rule is: after a framing error, the
parser's view of where this request ends is untrustworthy, so reading on risks
interpreting body bytes as the next request — which *is* the smuggling attack.
That rule already lives in the parser, where the knowledge is. Re-deriving it
here would create a second copy, and two copies of a security rule eventually
disagree; the disagreement would be a vulnerability, not a bug report.

A test walks every error that claims to close and asserts the connection
actually closes, so the two cannot drift apart silently.

---

#### §O-030c — An in-flight request is never interrupted, except by the drain deadline

The order of checks in `poll` is the policy, and two orderings matter:

**In-flight beats idle.** A request being handled is not idle, so no timeout
applies. The guest's own epoch deadline governs it and produces a **504 rather
than a reset** — which is what keeps a slow request classifiable by the client
(`§O-029`).

**Drain deadline beats in-flight.** This is the exception, and it is deliberate:
a drain that never completes is worse than an abrupt one, because an operator
cannot distinguish "still draining" from "stuck". A deploy that hangs is an
incident; a deploy that forces one slow request closed at the deadline is a
metric. Both boundaries are tested, at 4 999 ms and 5 001 ms.

---

#### §O-030d — The ledger is per tenant, drops entries at zero, and raises a zero ceiling

Three small decisions, each with a reason worth keeping:

**Per tenant, not global.** A global limit lets one tenant starve every other by
opening connections. `one_tenant_cannot_starve_another` is the test that states
this directly, and it is the property that makes the runtime multi-tenant rather
than merely multi-process.

**Entries removed at zero.** A map that keeps a key per tenant ever seen grows
without bound — in the component whose entire job is to bound something. Tested
by cycling a thousand tenants and asserting the map is empty.

**A ceiling of zero becomes one.** A tenant allowed no connections is a
configuration mistake rather than an intent, and silently rejecting every request
would make it hard to diagnose. One connection at least produces an error the
operator can see.

---

#### §O-030e — Close reasons are classified, because "closed" is not a metric

A process whose connections all close with `HeaderTimeout` is being scanned. One
where they close with `DrainDeadline` needs a longer drain timeout. A bare closed
counter cannot tell them apart, so `CloseReason::is_healthy` splits the eight
reasons into routine (`ClientRequested`, `ServerRequested`, `RequestLimit`,
`ShutdownIdle`) and symptomatic (the four timeouts and errors).

A test asserts every variant lands on the right side, so adding a reason later
forces a deliberate choice rather than defaulting into "healthy".

**Cross-refs:** Checklist `SRV-011`, `SRV-012`, `SRV-001`, `HOST-010`; Proposal
§6.4, §4.2.

---

### §O-031 — `qqq-io`: the reactor, and a platform divergence refused

**What was built.** `qqq-io` was a 9-line stub; it is now the crate that owns the
async runtime dependency (`ARCH-006`). That placement is the design: everything
above it — `qqq-serve`'s routing, parsing and connection state — is synchronous
and pure, so a future `io_uring` backend is a second module here rather than a
rewrite above.

**Verified by binding real sockets**, which is the only way to test an accept
loop: 8 integration tests covering bind, accept one, accept sixteen, data flowing
over an accepted stream, a pre-signalled shutdown, a shutdown mid-idle,
an occupied port, and sixteen connections balancing exactly across four shards.
Every wait is bounded, so a broken loop fails in seconds rather than hanging CI.

---

#### §O-031a — `SO_REUSEPORT` is deliberately not used, and the reason is CI

Proposal §4.2 implies kernel-side sharding, and `SO_REUSEPORT` is the classic way
to build it: several sockets bind one port and the kernel spreads accepts across
them. It is the right answer on Linux.

**And it behaves differently elsewhere.** macOS implements it with a different
distribution strategy; Windows has it in recent versions with different semantics
again. Setting it and hoping would mean sharding behaves one way in Linux CI and
another on a developer's Mac — which is precisely the class of platform
divergence §4.2 exists to prevent, and exactly the divergence the three-platform
matrix in `§O-022` was built to catch.

So assignment is **userspace round-robin**: one acceptor, connections handed to
shards in order. Identical behaviour on every platform.

**The honest cost is stated in the crate documentation rather than hidden:** one
extra hop between the accepting thread and the shard that reads the socket. On a
connection carrying hundreds of requests that is once per connection, not once
per request — and it is recorded as *unmeasured* rather than claimed to be
negligible. `PERF-016` is annotated partial for that reason.

---

#### §O-031b — The accept batch is bounded, and the yield happens whether or not the batch filled

The obvious loop is "accept until there is nothing to accept, then yield". Under
a connection flood there is *always* something to accept, so that loop never
yields — and the consequences are specific: health checks, metrics scrapes and
the shutdown signal are all delayed by exactly the load that makes them matter. A
server that cannot report its own saturation is a server nobody can operate.

Bounding the batch at 128 and yielding at the boundary makes the yield happen at
a fixed point regardless of load. The cost is one `yield_now` per 128 accepts,
which is nothing against the syscall cost of the accepts themselves.

---

#### §O-031c — Round-robin, not a hash of the peer address

Hashing the peer address to pick a shard sounds attractive — it gives affinity,
and affinity suggests locality. It is wrong twice:

1. **A NAT or proxy makes it meaningless.** Thousands of clients behind one
   address all hash to one shard, which is the opposite of balancing, and it
   fails silently because the hash is doing what it was told.
2. **It leaks information.** A client that observes which shard answers can use
   the hash to correlate connections it believes are separate. The capability
   model goes to considerable trouble to close covert channels (`CAP-013`,
   §O-027c); a client-visible value that varies with the peer address is one.

Round-robin has neither property. The only thing it gives up is affinity that was
not real.

---

#### §O-031d — Hostnames are refused in a listen address

`--listen example.com:80` is refused, with a remediation that explains why:
binding to a hostname binds to whatever it resolves to on *this* machine at
*this* moment. Two deployments of the same manifest would bind different
addresses, which is a deployment-dependent behaviour rather than a configuration
one — and NN-5 says nothing important is inferred.

IP literals and `localhost` are accepted. The parsing is hand-written rather than
delegated to `SocketAddr`, because a listen address is a user-facing string and
the error for a typo has to name what was wrong: `[::1:8080` gets "opens a
bracket and never closes it" rather than an opaque parse failure.

One subtle case is covered explicitly: an **unbracketed** IPv6 literal has many
colons and the port is the last one, so `::1:8080` is split with `rsplit_once`.
Splitting on the first colon — the obvious implementation — yields an empty host
and `:1`, and the test that pins this is named for the case.

---

#### §O-031e — Clippy caught a `MutexGuard` held across an `await`

In one of the new integration tests, a lock guard was held while awaiting. That
is a real deadlock hazard rather than a style nit: the guard is not `Send`-safe
across a suspension point in the general case, and the failure mode is a hang
that appears only under contention.

The fix is a scope, and the reason it is worth recording is that this is the
second time in this round that a lint pointed at a genuine defect rather than a
formatting preference (`§O-029a` was the first). Silencing such a lint would have
shipped the hazard.

**Cross-refs:** Checklist `ARCH-006`, `PERF-016`, `PERF-003`, `SRV-001`,
`ARCH-011`; Proposal §4.2, §4.4, §6.4.

---

### §O-032 — `qqq-pkg` begins: semver, the lockfile, and the content store

The package layer has three jobs before any solver can exist: decide what a
version *means* (`semver.rs`), record what was resolved (`lock.rs`), and hold the
bytes (`store.rs`). Each was written against the Checklist item that names it,
and the section closes at **78 tests** for the crate, **754** for the workspace,
with clippy clean at `-D warnings`.

---

#### §O-032a — `Version` has no pre-release field, and `^1.0.0` therefore over-promises

`qqq-core::ids::Version` is `{ major, minor, patch }` and its parser *rejects*
pre-release (`1.2.3-beta`) and build metadata (`1.2.3+build`). That was a
deliberate simplification, and writing the semver layer made its consequence
concrete rather than theoretical:

> `^1.0.0` cannot express "must not adopt `1.1.0-beta.1`", because
> `1.1.0-beta.1` is not representable in the type the requirement ranges over.

This is not a bug in the parser — the parser is honest, and it refuses input it
cannot represent instead of silently truncating `1.2.3-beta` to `1.2.3`. It is a
gap in the version model that propagates into `PKG-007`'s promise that a locked
version is **immutable**. If the registry ever publishes a pre-release, a
caret requirement will treat it as its release, and the lockfile's guarantee is
weaker than the documentation claims.

The gap is now *recorded in the tests* rather than in a comment:
`pre_releases_are_not_representable_and_this_records_it` asserts the parse
fails, and names the checklist item it constrains. Four tests that had been
written against an imagined `Version.pre` field — which never existed — were
deleted; they were not testing the code, they were testing my memory of it.

The fix is a real change to `PKG-007` semantics (adding `pre: Option<String>`
and ordering rules) and is deferred, not forgotten. `§O-032a` is the record.

---

#### §O-032b — The caret rule under `1.0`, and why `^0.2.3` is not `>=0.2.3`

The caret operator is the one piece of semver where a plausible implementation is
wrong in a way that only bites in production. Above `1.0.0` the rule is
mechanical: `^1.2.3` = `>=1.2.3, <2.0.0`. Below `1.0.0` it is not:

| Requirement | Correct range | The naive `>=x, <x+1` |
|---|---|---|
| `^0.2.3` | `>=0.2.3, <0.3.0` | `>=0.2.3, <1.0.0` ← admits breaking changes |
| `^0.0.3` | `>=0.0.3, <0.0.4` | `>=0.0.3, <0.1.0` ← admits breaking changes |

Cargo's rule is that the caret pins everything left of the first non-zero
component. A naive implementation passes every test written with `^1.x`
requirements and then silently accepts an incompatible `0.x` upgrade — exactly
the class of defect that reaches users, because `0.x` is what pre-1.0 libraries
publish. The tests include the two rows above by name.

---

#### §O-032c — The lockfile covers itself with a hash, and verifies it on read

`qqq.lock` is a file a human can edit, and a lockfile that has been edited is
indistinguishable from one that has not unless something checks. Every entry is
hashed together with a covering hash, computed over fields joined by NUL
separators — chosen because no field may contain a NUL, so no two distinct field
sets can produce the same digest input. A hand-edited lockfile is therefore
*detected* on read rather than trusted.

The NUL separator is the whole defence. Joining with `-` or `:` would let
`["a-b", "c"]` and `["a", "b-c"]` collide, and the collision is silent: the file
would verify and the wrong packages would install.

---

#### §O-032d — Two clippy findings that were real, and one that was mine

Clippy at `-D warnings` failed the new crate three times, and the three cases
split cleanly:

1. **`match_same_arms` in `lock.rs`** — `Syntax` and `EmptyField` had the same
   remediation string. The lint is right that the arms are identical, but merging
   them would have been the wrong fix: the two failures have *different causes*
   (malformed TOML versus a present-but-empty field) and the remediation should
   say which. Fixed by giving each a remediation that names its own cause, which
   is what the user actually needs at the moment they see it.
2. **`case_sensitive_file_extension_comparisons` in `store.rs`** — `list()`
   skipped sidecars with `name.ends_with(".meta")`. On a case-insensitive
   filesystem a `.META` file is the *same file* as `.meta`, so the store would
   list a phantom artifact on Linux and not on macOS or Windows. That is a
   genuine platform divergence, and `listing_treats_an_upper_case_sidecar_as_a_sidecar`
   now pins it.
3. **`implicit_clone`** — my own new test called `.to_path_buf()` on a value
   `with_extension` already returned as `PathBuf`. Mine, and trivial.

The pattern in (1) and (2) is the same one `§O-029a` and `§O-031e` recorded, and
it is worth stating plainly: **on this project clippy has repeatedly flagged
correctness, not taste.** The instinct to `#[allow]` a lint that fires on new
code has been wrong every time it has been tempting.

---

### §O-033 — `[dependencies]` was silently ignored, and how it was found

Starting `CLI-005` (`qqqai add`) required knowing where a dependency *goes*, so
the manifest model in `qqq-cap` was the first thing to read. It did not model
`[dependencies]` at all.

That alone would be an ordinary gap. What made it a defect is the interaction
with two other facts:

1. `Manifest` is **not** `deny_unknown_fields` at the top level (deliberately —
   the per-capability structs below it are, which gives a better error).
2. So a `qqq.toml` containing `[dependencies]` parsed **successfully**, with the
   table discarded.

Verified against the real binary, not reasoned about: a manifest with a
dependency and `qqqai caps` printed `app: no capabilities granted` and exited
`0`. The user had written a dependency; the tool had read the file; nothing
connected the two. The failure mode is the worst shape available — a silent
success, on the one input a package manager exists to process.

---

#### §O-033a — A dependency that silently does not exist is worse than one that fails to resolve

The instinct is to rank failures by severity: a resolution error is annoying, a
silent no-op is harmless because nothing broke. That ranking is backwards here,
and the reason is *who discovers it and when*.

A resolution failure is discovered by the person who just typed the command, in
the directory they are working in, seconds after they wrote the line — holding
all the context needed to fix it. A silently-dropped dependency is discovered by
whoever runs the code, at the point the import is missing or the behaviour is
wrong, in an environment they may not control, with a stack trace that points at
their own source. The cheap failure and the expensive failure are the same event
with the diagnosis attached or removed.

This is why `[dependencies]` is now modelled rather than tolerated, and why the
regression test asserts the **count** and not just `is_ok`: the old code also
returned `Ok`, so a test that only checked for success would have passed before
the fix and would pass again if the field were ever removed.

---

#### §O-033b — Writing the test found a second instance of the same bug

`[dev-dependencies]` is spelled with a hyphen; the Rust field is
`dev_dependencies`. Serde does not bridge that automatically, so the field
parsed as **empty** — the identical silent-drop defect I was in the middle of
fixing, reproduced in my own new code, four lines away from the comment
explaining why silent drops are unacceptable.

The test caught it on the first run (`left: 0, right: 1`). This is the third time
this round that a test written to *pin* a property instead found a defect, and
it is the strongest argument for the discipline in `§O-032a`: a test that asserts
a value is a claim that can be refuted, while a test that asserts `is_ok()` is a
claim that cannot. `is_ok()` would have passed here.

The fix is `#[serde(rename = "dev-dependencies")]`, and the serialization test
was updated to check the hyphenated key — otherwise it would have asserted the
absence of a key that was never going to be present.

---

#### §O-033c — Where a requirement is validated, when the crate graph forbids the obvious answer

The natural place to reject `>=1.0 <2.0` is the real `Requirement` parser, which
lives in `qqq-pkg::semver` and has its own tests. `qqq-cap` cannot call it:
`qqq-pkg` depends on `qqq-cap`, so the call would be a cycle.

Three options, and the reasoning matters more than the choice:

| Option | Why not |
|---|---|
| Duplicate the parser in `qqq-cap` | Two implementations of "is this a valid requirement" that would eventually disagree; the disagreement appears as a resolution failure on a manifest that validated. |
| Move `Requirement` down into `qqq-core` | Arguable, but `qqq-core` is the error/identity layer and a requirement grammar is neither. |
| **Shape-check in `qqq-cap`, grammar-check in `qqqai add`** | Chosen. Each crate checks what it can decide honestly. |

The last row is the honest division. `qqq-cap` decides what is decidable from
the string alone — empty, absurdly long, whitespace without a comma — and names
the **table and package** in the error. `qqqai add`, which links `qqq-pkg`,
parses the real grammar *before writing*, which is the only moment the user is
still present to be told about a typo.

The error text is the deliverable here. Verified through the binary:

```
error[QQQ-2002]: field `dev-dependencies.qqqai/assert` is invalid:
  `>=1.0 <2.0` contains a space but no comma; a range is written `>=1.0, <2.0`
```

Serde alone cannot produce this. The `Dependency` enum is untagged, so a
malformed entry reports `field <unknown>: data did not match any variant` — true,
and useless. Validating after parse is what makes the message name the entry.

---

#### §O-033d — Clippy's `unused_self`, and a wrong fix caught before committing

`validate_dependencies` was written as a method and read nothing from `self`.
Clippy flagged it, correctly, and the fix is to make it an associated function.

Worth recording because the *first* attempt at that fix was wrong: I edited a doc
comment instead of the signature, which duplicated the comment and left `&self`
in place. Re-reading the region showed the function was already correct, so the
bad edit was discarded rather than committed — two edits were then needed in the
right places: the signature, and the two call sites.

The general lesson: `edit` anchored on a doc comment is a poor way to change a
signature, because doc comments repeat across a file. Anchoring on the code
being changed is what makes the edit unambiguous.

---

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
| 2026-09-19 | `qqq-pkg` opened (`§O-032`). `semver.rs` (`Requirement`/`Op`, caret-under-1.0 rule), `lock.rs` (`Lockfile`, `LockDiff::compute`, NUL-separated covering hash verified on read), `store.rs` (`Digest`, two-level fan-out `StoreLayout`, verified reads). The pre-release gap in `qqq-core::Version` recorded as `§O-032a` with the test that pins it; four tests written against a non-existent `Version.pre` field deleted. Three clippy findings fixed, two of which were real defects (`§O-032d`). | Architect |
| 2026-09-19 | `[dependencies]` and `[dev-dependencies]` were **silently ignored** by `Manifest`: the struct did not model them and is not `deny_unknown_fields` at the top level, so a manifest declaring a dependency parsed successfully with the table discarded (`qqqai caps` printed "no capabilities granted" and exited 0). Both tables are now modelled, validated, and named in errors (`§O-033`). Writing the test found the *same* defect again in new code — `[dev-dependencies]` needs an explicit serde `rename`, and the hyphenated key parsed as empty (`§O-033b`). Requirement validation is split by what each crate can honestly decide, because `qqq-pkg` depends on `qqq-cap` and the real parser is therefore unreachable from the manifest layer (`§O-033c`). | Architect |

*End of `QQQ-Observations-and-Memories.md`.*
