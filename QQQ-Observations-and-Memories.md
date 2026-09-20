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

> **This is the ADR for `ARCH-005`.** It is written to the template in
> `docs/adr/README.md` — decision, context, alternatives, consequences, revisit
> trigger — rather than as a bare statement, because the *reason* is what a
> future maintainer cannot recover from the code.

**Decision.** The portable default is **Tokio's multi-threaded runtime with a
sharded acceptor**: each worker thread owns a set of listener shards, so a
connection is accepted and served on the same core for its whole life. io_uring
is an **opt-in Linux backend behind a flag**, adopted only if it earns its
complexity with measured results.

**Context.** The source conversation explicitly asked whether Tokio or a
thread-per-core runtime (monoio/glommio) is better, and the question is a real
one rather than a stylistic preference: a shared work queue means cross-core
cache-line bouncing, which is a genuine cost at high core counts, and
thread-per-core is the standard answer.

What made it a decision rather than a default is the platform matrix. QQQ targets
five platforms (§11.1) and **io_uring does not exist on macOS or Windows**. Two of
the three candidate runtimes are therefore unavailable on two of the five
targets.

| Option | Strength | Fatal weakness for QQQ |
|---|---|---|
| **Tokio multi-threaded** | Battle-tested; portable to every target including Windows; integrates with Wasmtime's async support and `wasmtime-wasi-http` | Shared work queue → cross-core cache-line bouncing at very high core counts |
| **monoio / glommio (thread-per-core)** | No cross-core synchronisation; maximum single-core throughput | **Linux-only.** io_uring does not exist on macOS or Windows, so choosing this as the only backend means QQQ cannot run on half its target platforms. It also conflicts with Wasmtime's own executor model, which expects a Tokio-compatible reactor |
| **Rewrite the reactor** | Perfect fit, no compromise | A multi-year detour with **no differentiation**. The differentiation is the capability layer, not the event loop |

**Consequences — what this makes easy.** One runtime, one set of semantics, and
WASI integration that already exists and is maintained upstream. `qqq-io` can
expose a reactor abstraction without owning an event loop, which is what keeps the
crate small and the `unsafe` count at zero.

**Consequences — what this makes hard, stated rather than glossed.**

1. **We inherit Tokio's cooperative-budget semantics.** A host function that
   represents guest-visible blocking must not be subject to the host's
   cooperative budget, or it violates WASI's guarantees. Wasmtime already works
   around this internally for WASIp2 `poll`. QQQ mirrors that discipline, and it
   is written down as an invariant in §10.5 and tracked by **`HOST-017`** — which
   is still open, because no guest-visible-blocking host function exists yet.
2. **The sharded acceptor is a userspace approximation**, not a kernel guarantee.
   Assignment is round-robin over shards rather than `SO_REUSEPORT`, because the
   kernel option distributes differently on macOS and Windows — so the thing that
   is portable is also the thing that gives a weaker guarantee. `ARCH-006`
   implements it and 8 socket tests pin the behaviour.
3. **Two backends is two code paths.** io_uring behind a flag means a feature
   matrix, and the flag must not become the only path anybody tests.

**Explicitly rejected.** Rewriting the reactor. Recorded as a rejection rather
than deferred, because "we might rewrite it later" is how a detour gets funded.

**Revisit when.** Any of these, and not before:

* `PERF-014` produces a **measured, reproducible** advantage from io_uring on the
  reference workload — the flag then becomes a documented recommendation.
* A measured reactor problem appears that the capability model cannot solve. This
  is deliberate: the trigger is a *measurement*, not an intuition.
* Wasmtime's own executor model changes such that a Tokio-compatible reactor is no
  longer the natural fit.

**Cross-refs:** Proposal §4.2; Checklist `ARCH-005`, `ARCH-006`, `HOST-017`,
`PERF-014`; Observations `§D-006`.

---

### §D-006 — Default guest concurrency is async-single-threaded

> **This is the ADR for `ARCH-013`.** Written to the `docs/adr/README.md`
> template, for the same reason as `§D-005`.

**Decision.** Three guest concurrency models exist and QQQ states a policy for
each. Two are **supported**, one is **not enabled in V1**:

| Model | Wasm feature | V1 policy |
|---|---|---|
| **Async single-threaded** | Component Model `async`, `future`, `stream` (WASI 0.3) | **Default and recommended.** One logical task per request; concurrency comes from many instances, not many threads inside one |
| **Shared-memory threads** | Wasm `threads` proposal (`SharedMemory`) | **Enabled but discouraged**, behind an explicit manifest opt-in (`[limits] shared_memory = true`) |
| **Cooperative threads** | Component Model cooperative threads (gated 🧵) | **Not enabled in V1.** Requires stack switching, which Wasmtime still lists as work-in-progress; tracked as `FUT-004` |

**Context.** The async default is not a preference in the abstract — it is forced
by what Wasmtime 48 actually supports, and by the isolation model. This was
verified against the real toolchain while building `HOST-015`/`HOST-016` rather
than read from documentation.

**Alternatives considered.**

| Option | Why not |
|---|---|
| **Thread-per-request inside one instance** | Requires shared linear memory, which defeats per-instance memory accounting — the accounting that makes a memory limit a *security* control rather than a tuning knob. It also makes fuel accounting inexact, because two threads consume from one budget |
| **Cooperative threads as the default** | Not available: it needs stack switching, which upstream lists as work-in-progress. Choosing an unavailable default is not a decision |
| **One instance per request, no async at all** | Loses the reactor; a guest awaiting a host future would block the calling thread, which §4.2 forbids |

**Consequences — what this makes easy.** One memory per task, so the isolation
guarantee stays the strongest available; exact fuel accounting, because one task
draws from one budget; and a natural match to how request-scoped work actually
looks. Density — many instances — replaces threads, which is the same trade §4.4
step 14 makes for instantiation cost.

**Consequences — what this makes hard, and these are measured rather than
predicted.**

1. **The epoch yield requires a reactor that can spare a thread.** Measured while
   implementing `HOST-016`: a yielding guest returns `Pending` on the executor it
   runs on, so a **current-thread** runtime has no thread left to fire the tick
   timer — the guest yields forever and the executor never advances. This was
   observed as a *hang*, twice, in the test suite, and it is a real constraint on
   `qqq-serve` rather than a test artefact: **a single-threaded reactor cannot use
   this yield at all** (`§O-056b`).
2. **CPU-parallel workloads have no good answer inside one instance.** The
   escape is shared memory behind an opt-in, and the opt-in is discouraged
   precisely because it weakens accounting. A legitimate CPU-parallel workload is
   therefore a case where the recommended model is wrong, and the manifest must
   say so explicitly rather than the host discovering it.
3. **A guest that blocks in a host call still blocks the calling thread** on the
   synchronous path. The async path is the answer, which is why `HOST-015` is a
   prerequisite for `HOST-017`.

**Revisit when.**

* Wasmtime ships cooperative threads as stable — `FUT-004` then becomes a real
  option rather than a blocked one.
* A measured workload shows that instance-per-request density is the constraint
  rather than the answer — i.e. that parallelism *inside* a guest is worth the
  accounting loss.
* `OQ-005` (the shared-memory policy question) is resolved by a human decision.

**Cross-refs:** Proposal §4.7, §4.2; Checklist `ARCH-013`, `ARCH-014`, `HOST-015`,
`HOST-016`, `HOST-017`, `DET-012`, `FUT-004`, `OQ-005`; Observations `§O-056`.

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

### §D-010 — The nine layers are fixed, and authority flows down only

> **This is the ADR for `ARCH-001`.** It fixes the layer cake of Proposal §4.1
> and the authority-flow invariant that every other security decision depends on.

**Decision.** QQQ is **nine layers**, and two invariants hold across all of them:

1. **Authority only ever narrows as you go down.** L5 (Capability Engine) is the
   sole authority gate; nothing below it can widen a grant and nothing above it
   can bypass it.
2. **Guest code exists only inside L4 (Execution).** Layers L1–L3 run native, in
   the host process, and are never reachable from a guest except through an
   L5-mediated call.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ L9  ECOSYSTEM      registry · package manager · templates · conformance      │
│ L8  AGENT FACE     MCP server · schemas · error codes · capability reports   │
│ L7  DX             qqqai CLI · dev server + HMR · test runner · debugger     │
│ L6  PRODUCT APIS   WIT interfaces: http, fs, sql, kv, queue, crypto, ai…     │
│ L5  CAPABILITY     manifest → grants → linker → limits → audit               │
│     ENGINE         ★ this layer is why QQQ exists ★                          │
│ L4  EXECUTION      Wasmtime engine · pooling allocator · fuel · epochs       │
│ L3  SCHEDULER      thread-per-core shards · work stealing · backpressure     │
│ L2  I/O            Tokio (portable) │ io_uring (Linux, opt-in) │ IOCP/epoll  │
│ L1  PLATFORM       OS syscalls · mmap · signals · clocks · entropy           │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Context.** The layering is not decorative and not a documentation convenience:
it is the answer to *"where is the security boundary enforced, and what stops the
layer above from bypassing it?"* Two design pressures produced it:

* **The isolation claim requires a single gate.** §1.3's constraint A says no
  capability may be reachable by a guest except through a grant recorded in a
  signed manifest, enforced outside the guest's address space. That is only
  meaningful if there is exactly **one** place grants are evaluated — otherwise a
  second path is a second policy.
* **The multi-language claim requires capability parity.** §1.3's constraint B
  says no language may reach a host feature another cannot. That is only
  enforceable if host features are declared in one layer (L6) and bound in one
  place (L5), rather than being scattered across the runtime.

**Alternatives considered.**

| Option | Why not |
|---|---|
| **Fewer layers, merged** (e.g. L5 into L4) | The capability engine is the product; merging it into the engine makes "the server has permissions" and "this request has permissions" the same code path. §4.4 steps 7–8 happen **per instance**, and that only works if the binding step is a distinct layer with a distinct owner |
| **More layers, splitting L1/L2 by platform** | Produces a layer per OS rather than per responsibility, and makes the portability story *(which layers are platform-specific?)* harder to state rather than easier |
| **No explicit layer model; enforce by crate boundaries alone** | The crate topology (§4.3) is a *different* claim: it fixes compile-time dependencies, not runtime authority flow. `qqq-host` may not depend on `qqq-serve`, but that says nothing about whether an ungranted import can be reached. The two are complementary, and `ARCH-004` checks the other one |

**Consequences — what this makes easy.** One place to audit grants, one place to
add an interface, and a clean answer to "can a guest reach this?" — walk the
layers from L6 down and find the gate.

**Consequences — what this makes hard, stated rather than glossed.**

1. **Layer 5 must be correct or nothing is.** There is no defence in depth *below*
   it, by construction. That is why the link is built per-instance from grants
   only **and** re-checked at call time (`ARCH-012`, §4.4 step 11) — the second
   check is not redundant, it is the only compensation for having a single gate.
2. **A feature that cannot be expressed in WIT cannot ship** (`§D-008`). L6 is
   WIT interfaces, so this follows directly, and it means a genuinely
   non-expressible host feature has to be refused rather than added below the
   line.
3. **The layer count is a maintenance surface.** Nine stated layers invite a
   tenth; the invariant is what must not change, and a new layer has to justify
   itself against the two invariants rather than against convenience.

**Enforcement.** The invariants are checked, not asserted:

| Invariant | Enforced by |
|---|---|
| Authority only narrows | `no_widening_constructor_on_grants_exists_anywhere` — no widening primitive on `GrantSet` exists anywhere in the workspace (`ARCH-002`) |
| Authority only narrows, behaviourally | `qqq-cap`'s `no_overlay_can_ever_widen` — all six (layer × mode) combinations against a hostile overlay (`§O-050`) |
| Grants are re-checked at call time | `HOST-012`'s sibling in `linker.rs`; the `recheck` path (§4.4 step 11) |
| No crate depends upward | `no_crate_depends_on_a_crate_above_it` (`ARCH-004`) |

**Revisit when.** A capability cannot be expressed as a grant (which would mean
the gate is in the wrong place), or a measured performance problem traces to the
per-instance binding step, or the crate topology needs an edge that violates the
layer order — the last of which happened once already, when the Proposal's own
table listed `qqq-host` above `qqq-abi` (`§O-044`), and the *document* was the
thing out of date.

**Cross-refs:** Proposal §4.1, §4.3, §4.4, §1.3; Checklist `ARCH-001`, `ARCH-002`,
`ARCH-004`, `ARCH-011`, `ARCH-012`, `SEC-002`; Observations `§D-008`, `§O-044`,
`§O-050`.

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

### §O-034 — `qqqai add` exists, and the first run refuted the version model

`CLI-005` is implemented in `qqq-run::deps`: `add` and `remove` edit
`[dependencies]` and `[dev-dependencies]` in `qqq.toml`. Both are wired into the
dispatcher with the full documented flag set (`--dev`, `--exact`, `--feature`,
`--registry`, `name@version`), and both emit the shared JSON envelope.

---

#### §O-034a — Proposal §5.3 writes `version = "1.2"`, and the parser refused it

The first end-to-end run of `qqqai add qqqai/json@1.2` printed:

```text
error[QQQ-5004]: `1.2` is not a version requirement: `1.2` is not a valid version
```

`1.2` is not an edge case. It is the exact spelling in **Proposal §5.3's own
`qqq.toml` example**, and it is what every ecosystem's manifest accepts. The
requirement parser delegated to `qqq_core::Version::parse`, which requires all
three components, so a two-component version was rejected by the parser for the
file format whose documented body contains two-component versions.

This is the same lesson as `§O-028` and `§O-032a`, in its sharpest form yet:

> Both halves were individually correct and individually tested. `Version`
> correctly requires `major.minor.patch`, and `Requirement` correctly rejects
> what `Version` rejects. Dozens of unit tests passed. The **composition** was
> wrong, and no test written from the same mental model as the code could see
> it. Running the binary once found it.

The fix is a partial-version rule that fills missing components with `0`:

| Written | Means | As a caret requirement |
|---|---|---|
| `1` | `1.0.0` | `>=1.0.0, <2.0.0` |
| `1.2` | `1.2.0` | `>=1.2.0, <2.0.0` |

Zero-fill rather than wildcard (widget-and-fill) because it can only **widen** a
requirement, never narrow it — and because `>=1.2` already means `>=1.2.0`, so
having `>=1.2` and `^1.2` read the missing component differently would produce
resolutions nobody could explain.

Guarded at the same time, because widening a parser widens what it accepts:
four components (`1.2.3.4`) is refused rather than truncated — reading the first
three and dropping the fourth silently resolves something the author did not ask
for — and `1..3`, `1.`, `.`, `..` are each refused with a message naming the real
problem rather than reporting an empty string as a non-number.

---

#### §O-034b — Why `add` edits text instead of re-serializing the manifest

The obvious implementation parses `qqq.toml` into `Manifest`, mutates the map,
and serializes it back. That is rejected, and the reason is what `qqq.toml`
*is*: a human-owned file whose comments record why a capability was granted.
§5.3's own example annotates `shared_memory = false` with `# see §4.7`. A tool
that deletes the argument for a security decision has done something worse than
failing.

Three concrete costs of round-tripping:

1. **Comments are destroyed** — including inline ones and the reasoning in them.
2. **Every key is reordered** into struct field order, so a one-line addition
   produces a whole-file diff, and a whole-file diff is where review stops.
3. **Unmodelled data is lost silently** — which is precisely the `§O-033` defect
   this release is already fixing, and it would be reintroduced by the tool
   meant to edit the file.

So the edit is surgical: locate the table, insert or replace one line, leave
every other byte alone. The result is then **re-parsed before it is published**,
so the edit is textual but never unverified — a manifest that does not parse can
never replace one that does. `add_then_remove_restores_the_original_bytes`
asserts the round trip is byte-exact, not merely equivalent, which is the
property that makes the textual approach worth its complexity.

Verified on the real binary — note the comment and the untouched `[limits]`:

```toml
[limits]
# keep this comment
fuel = 1000

[dependencies]
"qqqai/json" = "1.2"
```

---

#### §O-034c — The write is atomic because `qqq.toml` is the one unrecoverable file

Losing `qqq.toml` makes a project unbuildable and its content cannot be
regenerated — it is the only file that cannot be reconstructed from anything
else. A crash or a full disk midway through a naive write leaves a truncated
manifest.

The edit goes to a temporary file in the same directory and is `rename`d over
the target, so a reader sees either the old bytes or the new bytes and never a
prefix of either. On validation failure the temporary file is removed and the
target is untouched — asserted by a test that also checks no `.qqqtmp` file is
left behind, because a temp file accumulating next to the manifest is a second,
quieter defect.

---

#### §O-034d — The error contract, checked against the shell rather than assumed

One run looked like all three error paths exited `0`, which would have been a
real defect: a script branching on the exit code would treat a failed `remove`
as success. Checking with the pipeline redirected showed the truth:

| Case | Exit |
|---|---|
| success | `0` |
| dependency not found | `1` |
| bad requirement, missing argument, unknown flag | `2` |

The `0` was PowerShell reporting the exit of the *pipeline*, not the process.
Worth recording because the wrong reading would have sent me to fix code that
was already correct — and the right reading only came from measuring
differently, not from reasoning harder about the code.

---

### §O-035 — `qqqai install`, and the capability diff §5.4 exists for

`CLI-006` is implemented in `qqq-run::install`. The command reads and verifies
`qqq.lock`, resolves the manifest against its pins, prints the **capability
diff**, and writes the lockfile atomically.

---

#### §O-035a — The command's job is showing authority, not downloading

§5.4 states the reason `qqq-pkg` exists before the registry does:

> *"`caps` is recorded per dependency. `qqqai install` prints a **capability
> diff** — 'this update adds `http.client` to `qqqai/telemetry`'. Supply-chain
> attacks today hide in code; here the **authority** delta is visible in the
> diff."*

So the deliverable is not "fetch packages". It is **showing what an install does
to the project's authority**, and the implementation is shaped around that:

* `escalation` is a **denormalized top-level field**, not something an agent
  computes by walking a list. §5.4's claim is that CI can branch on an authority
  change; a claim like that is only true if branching is one comparison.
* The summary **leads with the escalation** when there is one, rather than
  burying it after "wrote lockfile". A supply-chain signal that appears in the
  fourth clause of a sentence is a signal that gets skimmed.
* The test asserts the §5.4 example directly: `qqqai/telemetry` going
  `1.0.0 → 1.1.0` while gaining `http.client` must set `has_escalation()`.

---

#### §O-035b — Three booleans became an enum, because the flags are ordered

`--locked`, `--frozen` and `--offline` were first written as three `bool` fields.
Clippy's `struct_excessive_bools` fired, and unlike a style lint this one pointed
at a real modelling error: **the flags are ordered by strictness**, and
independent booleans let a caller express contradictions — `frozen` without
`locked`, or `frozen` *and* `offline` meaning two different things at once.

`LockMode` is now `Update < Offline < Locked < Frozen`, with:

| Mode | Requires current lockfile | Forbids network | May write |
|---|---|---|---|
| `Update` | no | no | yes |
| `Offline` | no | **yes** | yes |
| `Locked` | **yes** | no | no |
| `Frozen` | **yes** | **yes** | no |

Combining flags takes the **strictest**, so no combination can silently weaken
the strongest flag the user wrote. `--frozen --offline` resolving to `frozen` is
pinned by a test.

The strictness order is a hand-written `strictness()` rank rather than
`#[derive(Ord)]`. A derived order would depend on which line each variant sits
on, so reordering the enum for readability would silently change what a flag
combination means.

**The same lint fired a second time on `InstallOutput`, and there the correct
answer was different.** Those booleans describe *outcomes*, not a mode, so an
enum would be wrong. Inspecting them showed `locked` and `offline` were both
derivable from `mode` — the same fact recorded twice, which is how `--json`
output drifts out of agreement with itself. They were **deleted**, and `mode` is
now the single source of truth. One lint, two findings, two different fixes, and
neither was `#[allow]`.

---

#### §O-035c — Writing a lockfile that lists unfetched packages would be the worst outcome available

There is no registry (`PKG-006`), so nothing can be fetched. The tempting
implementation resolves what it can, writes a lockfile containing the rest
"optimistically", and reports success.

That is rejected, and the reason is what a lockfile *is*: a promise about bytes.
The next command would trust it, and the content-addressed store would be asked
for a digest it has never seen — producing a failure at a later step, in a
different command, with no indication that the cause was an install that lied.
This is `§O-033a`'s argument applied to a second surface: **the cheap failure
with the diagnosis attached beats the expensive one without it.**

So the command does the half that is real and is precise about the half that is
not:

```
error[QQQ-5001]: could not fetch `qqqai/json`: it is not in `qqq.lock` and
  there is no registry to resolve it from

  → the QQQ registry is not built yet (Checklist `PKG-006`), so only
    dependencies already in `qqq.lock` resolve
```

The ordering of the checks is deliberate too: `--locked` is evaluated **before**
the fetch check, so a CI job with a stale lockfile reports "out of date" — which
the developer can act on — rather than "no registry", which they cannot.

---

#### §O-035d — A pin the manifest no longer accepts must not survive

`resolve` carries a lockfile pin across only if it still satisfies the manifest's
requirement. Carrying it unconditionally would be simpler and wrong: a manifest
edited to demand `2.0` while the lockfile pins `1.2` is exactly the state
`--locked` exists to catch, and preserving the pin would make `--locked` pass on
a lockfile that contradicts its manifest.

The failure mode of the *check* is the subtle one. `satisfies` returns `false`
when the requirement fails to parse — not `true`. Returning `true` on a parse
error would let a malformed requirement silently keep a stale pin, which is the
opposite of the intent, and it is the sort of default that reads as reasonable
until it ships.

---

### §O-036 — Running the scaffolded project found four defects the test suite could not

Having learned in `§O-033`/`§O-034` that the binary finds what tests miss, this
round began by *using* a project rather than reading code: `qqqai new`, then
`add`, `install`, `caps`, `inspect`, `why`, `doctor`, `build` — the first ten
minutes of Proposal §12.1, run for real.

Four defects, all of them in the surface rather than the engine, and all of them
invisible to the 256 unit tests that passed at the time.

---

#### §O-036a — In human format, `summary()` **is** the output

The root cause of three of the four. `Output::emit` does this:

```rust
Format::Human => self.write_line(&value.summary()),
```

There is no second renderer. A command's `summary()` is its complete human
output, so **any field not included there does not exist for a human reader**.
Every one of these commands had complete, correct `to_json` output while the
terminal showed a fragment:

| Command | Printed | Withheld |
|---|---|---|
| `qqqai caps` | `app: 2 capabilities across 2 namespaces` | **the capability names** |
| `qqqai inspect` | `app: 2 capabilities, 2 interfaces, posture: exposed` | the interfaces, the limits |
| `qqqai why fs.read` | `fs.read DENIED` | **the stanza that grants it** |
| `qqqai doctor` | `all 3 checks passed` | which checks ran |

`caps` is the clearest case. The command whose entire purpose is *listing
capabilities* printed a count and not one name, and the names were sitting in a
struct field two lines away.

**Why the tests missed it.** The unit tests asserted on struct fields and on
`summary().contains("2 capabilities")` — which passed. One test even rationalized
the gap in a comment: *"the summary reports counts; the namespace names live in
the structured field, which is what an agent reads."* That reasoning is the bug
stated as a justification. Humans read the human output; designing the
human surface for a machine reader is how a tool becomes unusable by the people
it was built for.

**The fix is a contract, not four patches.** In human format the output must
carry the payload, and the tests now assert it that way — on the strings a user
sees, for the reasons a user ran the command.

---

#### §O-036b — `qqqai doctor` exited `0` when a check failed

The most serious finding of the round, and the one with real-world consequences:
`doctor` printed *"1 of 3 checks need attention"* and returned exit code **0**.

A CI step, or a shell `qqqai doctor || exit 1`, would treat a broken environment
as healthy. This is `§M-006`'s lesson in a new place — **a diagnostic that
cannot fail is not a diagnostic** — and it is worse than a missing feature,
because it gives a caller false confidence in exactly the situation where
certainty was requested.

Now exits **69 (`UNAVAILABLE`)** on failure and `0` on success. `UNAVAILABLE`
rather than `FAILURE` deliberately: nothing is broken inside QQQ, the
*environment* is not ready, and a caller deciding whether to retry, report or
reinstall needs that distinction.

Both directions are pinned by tests: a failing run must exit non-zero, and a
passing run must exit zero. Without the second, the first would also pass if
`doctor` simply always failed.

---

#### §O-036c — The parser refused the syntax its own error messages recommend

`qqqai add qqqai/json@">=1.0, <2.0"` failed with:

```text
error[QQQ-5004]: `>=1.0, <2.0` is not a version requirement
```

while the remediation printed beneath it says:

```text
→ write a version like `1.2`, `^1.2.3`, `~1.2.3`, `>=1.0, <2.0` or `*`
```

The parser's module docs justified this: *"Deliberately absent: `1.2.*`
wildcards, `||` unions, and comma lists."* The first two exclusions are sound. The
third conflated two different things:

* **`,` is a conjunction.** `>=1.0, <2.0` means both bounds hold — which is
  precisely the bounded range the caret and tilde already expand into
  internally. Refusing it is refusing a syntax the engine already computes.
* **`||` is a disjunction.** It admits versions from unrelated spans, which is
  the form that hides a dependency's true range.

`qqq-cap`'s shape check (written in this same session, `§O-033c`) *requires* a
comma in a range-shaped requirement, so three parts of the codebase disagreed
about the grammar and only the end-to-end test noticed.

`Requirement` now holds a `Vec<Clause>` that must **all** hold. A single-bound
requirement is a conjunction of one, so `matches` needs no special case, and
`||` remains excluded.

**The generalizable failure:** an error message is an interface. It makes a
promise about what the tool accepts, and that promise has to be tested like any
other. `add_accepts_the_version_form_the_proposal_writes` now parses every form
appearing in the remediation text — the test would have failed before the fix.

---

#### §O-036d — `qqq-run` had no integration tests, which is why all of the above shipped

Three defects reached a built binary with 256 passing unit tests around them,
and the reason is structural rather than careless: **every test was written from
the same mental model as the code.** A unit test can confirm `DoctorOutput`
contains a failing check; it cannot observe that the *process* still exits `0`.

`crates/qqq-run/tests/cli.rs` now spawns the real binary and asserts on what a
user or a CI job sees — stdout, stderr, and exit codes, never library internals.
24 tests, covering:

* the exit-code contract in both directions (`doctor` pass and fail);
* human output carrying its payload (`caps` names, `inspect` lists, `why` stanza,
  `doctor` checks);
* the `add`/`remove` manifest round trip, including comment preservation;
* `install`'s lockfile contract, including refusing a tampered file;
* the JSON envelope and the `qqqai` naming invariant.

The suite is deliberately hermetic: `HOME`/`USERPROFILE` are redirected into the
sandbox, so no test can pass because of the developer's machine.

This is the layer that was missing. `§O-032a` said a test written from the same
mental model as the code cannot refute that model; the corollary, learned here,
is that the refutation has to be *structural* — a separate suite that consumes
the artifact the way a user does, rather than a better-written test inside the
same module.

---

### §O-037 — `qqqai update`, and designing the seam before the registry exists

`CLI-007` is implemented in `qqq-run::update`. The command moves dependencies
forward, reports the capability diff, and is precise about what it cannot do.

---

#### §O-037a — `--latest` is a separate flag because the default is a safety property

The two strategies are not a preference, they are a promise about what QQQ will
do while the user is not looking:

| Strategy | Bounded by |
|---|---|
| *(default)* `WithinRequirement` | the manifest's requirement |
| `--latest` → `Newest` | nothing |

Defaulting to `--latest` would resolve `^1.2.3` to `2.0.0` — turning a
conservative constraint into a breaking upgrade, and doing it while the user
believes they asked for a routine refresh. That is the single most damaging
thing a package manager can do by default, and the fix is that crossing the
requirement requires typing a word.

**The decision is a pure function.** `decide(name, pinned, requirement,
available, strategy)` takes every input as a parameter and touches no
filesystem, network or clock. That makes every branch reachable from a unit
test — including the ones a real registry makes hard to produce, such as "a
newer version exists but the requirement forbids it".

Three defaults inside it are each the safe direction of an asymmetry:

* An **unparsable requirement** keeps the pin. The opposite default — read it as
  `*` — turns a typo into an unbounded upgrade.
* An **unparsable pin** keeps the pin, because moving off a version we cannot
  read is guessing.
* An **unparsable candidate** is skipped, not fatal, so one malformed registry
  entry does not break the update of every other package.

---

#### §O-037b — The best version is chosen by semver, not by list position

`decide` compares versions rather than taking the last admissible element of the
list. A registry is not required to return versions sorted, and a mirror that
changes its ordering must not change what QQQ installs. Taking `.last()` is a bug
that appears only when infrastructure changes, in a place nobody would look.

The test feeds the list out of order (`1.9.0, 1.2.0, 1.5.0`) and asserts `1.9.0`.

---

#### §O-037c — `VersionSource`, so the registry is an implementation and not a rewrite

The registry does not exist. The tempting shape is a function that returns an
empty list today and grows a network call later — which means **every branch
involving a newer version is untested until the day it ships**.

Instead, the seam is a trait:

```rust
pub trait VersionSource {
    fn available(&self, name: &str) -> Vec<String>;
}
```

with `NoRegistry` (the real answer today) and `FixedVersions` (for tests). The
consequence is that `plan`, `decide` and `apply` are *fully* exercised now:
a move within range, a move blocked by the requirement, `--latest` crossing it,
an unparsable candidate among valid ones, a package the manifest does not
declare. When `PKG-006` lands, the registry becomes one more implementation of a
trait whose behaviour is already pinned.

The trait is deliberately **not** a network abstraction: no error case, no
async. A source that cannot answer returns an empty list, and the caller reports
"nothing newer" rather than failing the whole update. A registry outage must not
stop a user from updating the packages resolvable from the store.

---

#### §O-037d — A "keep" must explain itself

`Decision::Keep` carries a `reason`, and `--dry-run` prints it:

```text
kept:
  qqqai/json  1.2.3 — no published version above `1.2.3` satisfies `^1.2.3`
```

Without it, a no-op update is **indistinguishable from a broken one**. The user
runs `update`, nothing moves, and they have no way to tell whether the tool
checked, or whether the requirement is what is holding them back, or whether the
registry is unreachable. The reason answers the question they actually asked —
"why is this not updating?" — and it costs one string.

This is `§O-036a` from the other direction: there, output withheld data the user
needed; here, a decision withholds its justification.

---

#### §O-037e — `--latest` plus `exact = true` is refused, not resolved

An `exact = true` dependency says "this version and no other". `--latest` says
"take the newest". Silently letting one win is how a user gets a major upgrade
they did not ask for, so the combination is a hard error naming both ways out:
remove `exact`, or drop `--latest`.

The general rule this belongs to: **when two inputs state opposite intents,
refuse rather than pick**. Precedence is a decision the tool makes on the user's
behalf about their own intent, and it is invisible in the command they typed.

---

### §O-038 — `qqqai inspect <artifact>`, and a security report that named the wrong capability

The Proposal is specific about this command. §5.2: *"`qqqai inspect <artifact>`
— **Static capability report.** What can this do, without running it."* §7 states
the guarantee it backs: *"Grant is auditable before execution."*

Two defects stood between the code and that claim, and neither was visible
without pointing the command at a real artifact.

---

#### §O-038a — The command ignored its argument and answered a different question

`qqqai inspect <path>` accepted a path, discarded it, and reported the
**manifest's** capabilities regardless. Verified against the binary:

```text
$ qqqai inspect definitely-not-here.wasm
app: 0 capabilities, 0 interfaces, posture: minimal
```

A file that does not exist produced a confident report about `qqq.toml`.

For a command whose purpose is auditing an **untrusted artifact**, this is the
worst available failure. The user asks "what does this file want?", receives a
precise-looking answer about their own project, and has no way to tell that the
answer was to a different question. `§O-033a`'s argument applies with more force
here than anywhere else it has been used: the diagnosis was not merely missing,
it was **replaced by a plausible wrong one** on the surface whose whole job is to
be trustworthy.

`inspect` now dispatches on the argument. An artifact path compiles the component
— without instantiating it — and reads its import list. A path that cannot be
read or parsed is an **error**, never a fallback to the manifest, because falling
back is precisely the behaviour being fixed.

The mode split is worth stating plainly, since one command answers two questions:

| Invocation | Question | Source |
|---|---|---|
| `qqqai inspect` | what is this project allowed to do? | the manifest |
| `qqqai inspect <artifact>` | what does this file require? | the component's imports |

Verified that the second needs **no manifest at all** — which matters, because
the primary use is a file someone handed you, in a directory that is not a
project.

---

#### §O-038b — Package-level lookup reported the wrong half of `qqq:clock`

With inspection wired up, an artifact importing `qqq:clock/wall-clock@1.0.0` was
reported as requiring **`clock.monotonic`**.

The cause is a granularity mismatch that had been invisible because only one
consumer existed. `qqq-abi`'s registry maps capability → interface at **package**
level:

```text
"qqq:clock@1.0.0"  unlocked by  [ClockWall, ClockMonotonic]
```

That is correct for the linker (it binds the package) and correct for an error
message (the user needs a stanza name). It cannot express *which* of a package's
interfaces one capability unlocks — and several packages contain several:

| Package | Interfaces |
|---|---|
| `qqq:clock` | `wall-clock`, `monotonic-clock` |
| `qqq:crypto` | `random`, `hashing`, `hmac`, `aead`, `signing` |
| `qqq:http` | `http`, `incoming-handler` |

So `capability_for_interface` reduced the import to `qqq:clock` and returned
whichever capability the registry listed first. It happened to be monotonic.

**The fix is a second, precise table** (`interface_path_for`) rather than a change
to the existing one: the package-level mapping still serves its two consumers,
and the new function answers the interface-level question that `inspect` needs.
A lookup that returns the wrong capability on an audit surface is not imprecise,
it is wrong — so the new function returns `None` for anything it cannot name
exactly, and the caller reports that as an **unmapped interface** rather than
papering over it with a plausible neighbour.

Verified against three artifacts, which now produce three distinct answers:

| Import | Capability |
|---|---|
| `qqq:clock/wall-clock@1.0.0` | `clock.wall` |
| `qqq:clock/monotonic-clock@1.0.0` | `clock.monotonic` |
| `qqq:crypto/aead@1.0.0` | `crypto.aead` |

---

#### §O-038c — Understating authority is the one failure an audit surface must not have

One interface can be unlocked by **several** capabilities, and the two rules
collide:

* `qqq:fs/filesystem` is unlocked by `FsRead`, `FsWrite` and `FsWatch`.
* `qqq:http/http` carries both `send` (outbound) and `incoming-authority` (which
  server is serving), so importing it implies `http.client` **and** `http.server`.

Reporting the first match would understate the artifact — an artifact requiring
`fs.write` would be reported as `fs.read`, and its posture as `contained` when it
is `exposed`. So the mapping returns the **strongest** capability implied by the
interface.

That introduces a coupling that needed pinning: the ranking must agree with
`classify_posture`'s notion of exposure. If they drifted, a report could be
internally consistent and still understate the risk. The test iterates **every**
capability and asserts the two agree — the same positive-control discipline as
`§M-006`, applied to a pair of functions rather than to a validator.

Two further corrections came from reading the WIT rather than assuming:

* `qqq:http/http` was mapped to `http.client`, which understated a component that
  can also serve. It is now mapped to the stronger of the pair.
* `qqq:http/incoming-handler` is **exported** by a server, not imported, so it
  never appears in an import list. Mapping it was dead code.

---

#### §O-038d — Tests that skip are tests that cannot fail

Five new integration tests build their fixtures with `wasm-tools parse`. The first
run passed — because every one of them **skipped**: the helper had passed a
`--features` flag that `wasm-tools parse` does not accept, so no fixture was ever
built, and a `run_raw` that panicked on a missing program made the failure look
like an environment problem.

This is `§M-006` in a new place: **a test that cannot fail is worse than no test,
because it manufactures confidence.** Two changes:

1. The bogus flag was removed, and the skip now prints
   `SKIPPED: no wasm-tools available - this test did not run` — loud enough that
   a passing suite does not read as coverage it does not have.
2. `run_raw` returns a failing `Run` instead of panicking, so "no encoder" is
   distinguishable from "the encoder rejected my input".

The suite now runs 37 tests with **zero skips**, and the artifact path is
exercised in 0.03s per test rather than silently bypassed.

---

### §O-039 — `inspect --diff`: the authority delta as a CI gate

`CLI-015`'s remaining half. `qqqai inspect A --diff B` reports the authority
difference between two artifacts. The direction reads **B → A**: the artifact
named with `--diff` is the *before*.

---

#### §O-039a — A gain fails the process; a loss does not

The asymmetry is deliberate and is the same reasoning as `§O-036b`:

| Delta | Exit | Why |
|---|---|---|
| authority gained | **non-zero** | the event §5.4 exists to surface |
| authority lost | `0` | a reduction cannot hurt anyone |
| unchanged | `0` | a clean comparison must not fail the build |

Exiting non-zero on a gain is what makes the flag usable as a CI gate **without
parsing output**. Exiting non-zero on a *loss* would be worse than useless: it
would fail builds for changes that improve security, and a check that fires on
improvements is a check people learn to bypass — which costs more than the check
was worth.

---

#### §O-039b — A covert channel escalates even when the posture band does not move

The subtle rule, and the one worth recording. Posture is a three-level band
(`minimal` < `contained` < `exposed`), and some genuinely significant grants
cannot move it:

* `clock.wall` and `crypto.random` are `Ambient`. Added to a component that
  already imports anything else, the band stays `contained`.

But §10.5 singles exactly these out: *"a guest that reads the wall clock can
encode information in **when** something happened, which is a covert channel the
audit stream cannot see."*

So `escalation` is true if the posture worsened **or** if any added capability
`is_covert_channel()`. A diff that compared only posture bands would silently
pass an artifact that just gained an unobservable information channel.

Verified against real artifacts — adding `clock.wall` to a monotonic-only
component:

```text
AUTHORITY ESCALATION: mono.wasm → wall2.wasm
  + clock.wall           (ambient)  [covert channel]
  - clock.monotonic      (ambient)

Posture: contained → contained
```

Same band, escalation flagged, exit `1`. The capability's own kind and channel
status are carried into the output rather than left for the reader to look up,
because the reader is the person deciding whether to accept the change.

---

#### §O-039c — The comparison is over capabilities, not interfaces

Two artifacts may import different interfaces whose capability sets overlap. An
artifact that stops importing `qqq:clock/wall-clock` while starting to import
`qqq:clock/monotonic-clock` has not gained or lost anything, and an
interface-level diff would report two changes that cancel — leaving the reader to
work out that nothing happened.

The question is about **authority**, so the comparison is over authority. Both
digests are carried so the diff is tied to the bytes it describes; "this artifact
gained `fs.write`" without saying *which* artifact is not evidence.

---

### §O-040 — The checklist was understating the work by 26 items

P0 (Foundation) reported **0 of 101 done** while the workspace had 910 passing
tests, a three-OS CI matrix, all three canonical documents, and an Apache-2.0
licence. The work was done and never recorded.

---

#### §O-040a — An out-of-date checklist is worse than a missing one

The reflex is to treat a stale checklist as bookkeeping debt — untidy, not
harmful. That is wrong in a specific and expensive way: **it makes remaining work
look larger than it is.** A reader planning the next milestone against "0 of 101"
concludes the foundation is untouched and re-plans work that is finished.

It also hides what has already been paid for. Twenty-six items were complete
before this round; that cost was already borne and the register showed none of it.

So the fix is not "tick more diligently next time". It is to make the check
**mechanical**: `tools/audit_p0.py` maps each P0 item to a concrete artefact and
reports what exists. It is deliberately a **report, not a gate** — the same
choice `check_xrefs.py` makes — because failing CI on a low count pressures
ticking over building, and ticking without reading is how the drift happened.

What the tool cannot do is stated in its header: `FND-008` (branch protection) is
a repository setting and `LIC-002` (legal review) is an external action. Both are
reported as unverifiable rather than guessed at, so the boundary is visible
instead of a confident wrong answer.

---

#### §O-040b — The reverse cross-reference check did not exist, and adding it found three dangling decisions

`check_xrefs.py` check `[10]` catches the Proposal citing a `§D-` identifier that
does not exist. There was **no check** for the reverse: a decision defined in
Observations and cited from nowhere.

That is not hypothetical. Six of the nine decisions were once *write-only* — the
Proposal never mentioned them, so a reader of the Proposal alone would never
learn they existed. It was found by reading, not by the validator, and fixed by
hand. `[10]` could not catch it, because it only knows about citations that
already exist.

Adding check `[10b]` took a few lines and **immediately found three more**:
`§D-002` (five languages), `§D-008` (WIT interface first), `§D-009` (README as a
sales surface). Each named Proposal sections in its own cross-refs, but no
Proposal section named the decision — a one-way link that reads as connected and
is not. All three are now cited where they belong.

A fault injection strips a citation and asserts the check fires, so `[10b]`
cannot become a check that always passes. **8/8 injections detected.**

The generalizable lesson: a link that exists in one direction is not a link.
A register that nothing reads back is decoration.

---

#### §O-040c — `cargo deny check` had been failing on every run, and the escape hatch hid it

The supply-chain CI job carried `continue-on-error: true` on both steps, with a
note that `deny.toml` would land "with LIC-007".

With no `deny.toml`, cargo-deny falls back to its **default** allowlist and then
rejects this project's actual dependencies — it failed on `addr2line`'s
`Apache-2.0 OR MIT`, a licence nobody would refuse. So the check failed
unconditionally, and `continue-on-error` meant nobody saw it.

This is `§M-006` in a third guise: **an unconditionally-failing check and an
unconditionally-passing one carry exactly the same information.** Both are noise;
the first is merely noisier.

`deny.toml` now exists, derived from `cargo metadata` over the real tree rather
than written from expectation, and both escape hatches are removed. Two details
worth recording:

* **`GPL-2.0-only` and `LGPL-2.1-or-later` are deliberately *not* in the
  allowlist**, even though they appear in the dependency graph. Both appear only
  inside disjunctions that also offer a permissive branch, and cargo-deny
  evaluates OR-expressions by checking whether *any* branch is allowed. Listing
  the copyleft branch would permit it **alone**, which is a different and
  unacceptable grant.
* The `bans` section denies a crate literally named `qqq`. The naming rule is
  already enforced for the binary we build by a constant and a test; this
  enforces it for what we depend on.

`cargo machete` was also finding **three real unused dependencies** —
`qqq-abi → qqq-core`, `qqq-pkg → qqq-cap` and `qqq-pkg → serde_json`. Verified
by grepping for each import before removing. Both checks now pass with no escape
hatch.

---

#### §O-040d — Six crates declared a README that did not exist

`readme = "README.md"` in `Cargo.toml` while the file was absent. That is not
cosmetic: `cargo publish` fails on a missing readme, so the crate was
unpublishable and nothing said so until the moment someone tried.

Writing the five missing READMEs produced its own lesson, four times over — **a
README is a set of claims, and each one has to be checked against the source**:

| Claim I wrote | Reality |
|---|---|
| `grants.narrow(&[Capability::FsRead])` | `narrow` takes an `Overlay`, not a slice |
| `qqqai schema --wit` emits the interfaces | no such flag exists |
| five of the eight principle names | the real names are quite different |

Each was written fluently and each was wrong. The correction is not "be more
careful" — it is that **prose describing an API is an unverified assertion until
you grep for the API.** Every remaining claim was then verified: `Instance::run`
does consume `self`, `EngineConfig::deterministic` exists, the five exit codes are
exactly `0/1/2/69/70`, and a trap does exit `1` rather than `70`.

The READMEs also state scope honestly. `qqq-pkg`'s table marks
hard-link/reflink materialization as **not implemented**, and `qqq-run`'s marks
ten of its commands the same way. A README that implies a capability exists is
the same defect as a ticking checklist item that is not finished.

---

### §O-041 — The objective audit passes, and a check that was failing on nothing

`tools/audit_requirements.py` reports **30/30**. It had been reporting 29/30 for
as long as anyone ran it, on a condition the repository does not have.

---

#### §O-041a — Three wrong diagnoses of one symptom, and what finally worked

The symptom: `git status` reported the three canonical documents modified,
`git diff` showed nothing, and `git ls-files --eol` read `i/lf w/crlf`.

| Attempt | Diagnosis | How it failed |
|---|---|---|
| 1 | "`eol=lf` overrides `autocrlf`" — written into `.gitattributes` as fact | It does not. The attribute governs the commit; `autocrlf` governs the checkout. |
| 2 | "`core.autocrlf=false` fixes it" — written into `.gitattributes` as fact | One `git add` looked clean, so I concluded. The drift returned on the next operation. |
| 3 | "`text=auto` is the cause; use `text`" | Improved the attribute, did not remove the symptom. |

Each diagnosis came from **one observation** and went into a comment as a
conclusion. The comments then outlived the beliefs, which is the more expensive
half: a wrong cause written down is a wrong cause someone will trust.

What worked was **measuring the right artifact**. The question was never what the
working tree contains; it is what was *committed*:

```text
git cat-file -p HEAD:QQQ-Checklist-V1.md   -> 0 CRLF, 1,549 LF
git ls-files --eol QQQ-Checklist-V1.md     -> i/lf  w/crlf
```

The committed blob is correct. The checkout is untidy. **Every "failure" was
about the untidy checkout.**

So the fix was not to the repository at all — it was to the checks. Both
`normalize_eol.py` and `audit_requirements.py` now test committed content:

| Tool | Tested | Now tests |
|---|---|---|
| `normalize_eol.py` | working-tree bytes | the `i/` column of `git ls-files --eol`; FAIL only if a **blob** holds CRLF |
| `audit_requirements.py` | `git status --porcelain` | `git diff HEAD` plus untracked paths |

`text eol=lf` on the three documents remains, pinned by path rather than by
extension — the other Markdown in the repository has never drifted, and widening
a rule to cover a symptom it does not explain is how a fix becomes a new bug.

**The generalizable failure, which this project has now recorded three times in
three guises:** a check that fails on a condition the repository does not have is
indistinguishable from a check that always fails (`§M-006`, `§O-040c`). The
correction each time has been to test the thing that actually matters rather than
the thing that was easy to observe.

**And the process lesson:** an instrumented sequence — normalize, count, add,
count, status, count — found the writer in fewer steps than either guess took.
Measuring between each step beats reasoning about which step is at fault.

---

#### §O-041b — A hardcoded count in a report goes stale silently

`audit_requirements.py` carried the label `"validator self-test passes (7/7)"` as
a **literal**. An eighth fault injection was added; the check still passed, so
nothing failed, and the report confidently printed a wrong number.

The label is now derived from the harness output. That also makes a *decrease*
visible: `8 -> 7` would be noticed rather than absorbed.

The same staleness appeared in `ci.yml`, where a comment said the harness "breaks
the corpus seven ways". That one was **deleted rather than corrected** — the
harness prints its own count, and a number restated in a comment is a number that
will go stale again.

The rule: **a report must read its numbers, not restate them.** A literal that
describes a measurement is a claim that will eventually be false, and it fails by
being quietly wrong rather than loudly broken.

---

### §O-042 — `qqqai test`, and a determinism check that cried wolf

`CLI-012` is implemented in `qqq-run::test_runner`. Discovery, filtering,
`--dry-run` and `--json` work, and `--trials N` — the first of §6.7's
architecture-enabled features — is implemented and honest about its limits.

---

#### §O-042a — Attribution took three attempts, and each wrong one was confidently wrong

A test's source file has to be right: a report that says a failure is in
`src/the_crate_builds.rs` sends the reader to a path that does not exist.

| Attempt | Method | What went wrong |
|---|---|---|
| 1 | first `::` segment of the test name | `the_crate_builds` has no `::`; a test at the crate root got a fabricated path |
| 2 | join `Running` headers to cargo's JSON | correct mapping, but cargo **buffers**: every header precedes every test, so the flat list still had to be split across binaries by count |
| 3 | **run each test binary directly** | nothing — attribution is exact by construction |

Attempt 2 was the interesting failure, because it *looked* solved. The join was
built from real cargo JSON, the test passed, and the output showed source paths
for the first time. It was still wrong: `tests::the_root_route_greets`, a unit
test in `src/app.rs`, was attributed to `tests/smoke.rs`, because the even split
across two binaries guessed.

The lesson is the one this project keeps meeting in new clothes: **a plausible
answer that is right most of the time is more dangerous than an obviously wrong
one**, because it is believed. The fix was not to tune the heuristic but to
remove it, at the cost of one process per test target.

---

#### §O-042b — The determinism check reported a stable suite as nondeterministic

The serious finding, and the reason it matters is that `--trials N` is the
feature that justifies a QQQ test runner existing at all.

Measured on a scaffolded project whose tests are perfectly deterministic:

```text
$ qqqai test --trials 3
NONDETERMINISTIC: 1 of 2 test(s) produced different output across 3 trials
```

The cause: the trial runner compared **raw stdout and stderr**, which include
libtest's own bookkeeping:

```text
test result: ok. 1 passed; 0 failed; ... finished in 0.01s
                                          ^^^^^^^^^^^^^^^^^ differs every run
```

So the check fired on every test that printed a summary line — that is, on every
test. Output is now normalised: per-test status, panic messages and the test's
own printed output are kept; durations, cargo's progress lines and the
`filtered out` count are dropped. The exit status carries pass/fail, so nothing
about the outcome is lost.

**A determinism check that fires on a stable suite is worse than no check.** It
teaches the reader to disregard the one signal the feature exists to produce,
and the next real flake is ignored. The same argument as `§O-040c`'s
unconditionally-failing check, from the other direction: both carry zero
information, and both train people to stop looking.

Two tests pin it — one asserting that runs differing only in timing compare
equal, and a **positive control** asserting that a real output difference is
still detected. Without the control, a normaliser that stripped everything would
pass the first test and detect nothing.

---

#### §O-042c — I diagnosed the symptom as a flaky test, twice, before measuring

The failure appeared as `test_trials_runs_each_test_repeatedly ... FAILED`
roughly every other full-suite run, and passed in isolation. That signature says
"test interference", so I did the two things that signature suggests: gave each
sandbox its own `CARGO_TARGET_DIR`, then re-ran with `--test-threads=1`.

Neither helped, and the second result was the informative one: single-threaded
passed, parallel failed — which is *also* consistent with a flaky test, so it did
not discriminate. What settled it was reading the failure's **stdout** rather
than its assertion:

```text
NONDETERMINISTIC: 1 of 2 test(s) produced different output across 3 trials
```

That is not an infrastructure error at all. The "flakiness" was the real bug
(`§O-042b`) surfacing intermittently: the timing lines differ between runs, and
under load they differ more often. Four consecutive clean full-suite runs after
the fix.

The cost of the wrong reading is specific: I spent two fixes on test
infrastructure for a defect in the product, and both changes were plausible
enough to keep. **The failure output was available the whole time.** Reading what
a test printed before theorising about why it printed it is the same lesson as
`§O-041a`, one round later.

---

#### §O-042d — The local fix was correct and insufficient, and one diagnostic found both CI bugs

`--trials` was fixed locally (`§O-042b`) and **CI still failed** with the same
report. The check was right that something differed; the fix had simply not
addressed the real cause.

Two differences in CI's environment, neither present locally:

| Difference | Effect |
|---|---|
| `--verbose` on a warm build | emits `Fresh <crate>` and `Finished … in 0.47s`, which a local run never printed because nothing was fresh |
| `CARGO_TERM_COLOR=always` | wraps every verb in SGR escapes, so `starts_with("Blocking")` never matched `\x1b[1m\x1b[92m    Blocking\x1b[0m …` |

**Both were found by the same instrument**, added in the same change that fixed
the first bug: a diagnostic that prints **what differed** rather than only that
something did. Its first output, verbatim:

```text
qqqai test: trial divergence in `tests::adding_works`:
  line 4: "\u{1b}[1m\u{1b}[92m    Blocking\u{1b}[0m waiting for file lock on
  package cache" vs "\u{1b}[1m\u{1b}[92m    Finished\u{1b}[0m … in 0.02s"
```

Two CI-only causes named in one line, after two rounds of theorising had found
neither. The generalizable rule: **a diagnostic that reports a difference must
print the difference.** Reporting only its existence forces guessing, and the
guessing was the expensive part — `§O-042c` had already spent two fixes on the
wrong component for exactly this reason.

The rules are now by **shape** rather than an enumerated prefix list: a line is
kept if it carries test behaviour, dropped if it reports on the runner. An
enumerated list is the same mistake as enumerating a toolchain's error variants
— correct until the environment changes, and then wrong in a way that implicates
the code under observation. The conservative direction is deliberate: an
unmatched line is **kept**, so a stripper that fails to recognise something
cannot hide a real divergence.

**Three further real defects surfaced while building it**, each caught by a test:

1. `strip_ansi` used a peekable iterator and tried to rewind it. A consuming
   iterator cannot be rewound, so the lookahead had already advanced and the
   "put it back" step targeted the wrong position — bytes vanished silently.
2. The replacement scanned up to 24 bytes for any `m`. On `ESC[1no terminator`
   it found the `m` inside "ter**m**inator" and deleted everything before it,
   producing `"inator"`. A stripper that eats arbitrary text is the dangerous
   direction, because the bytes it removes are the ones being compared. The scan
   now accepts only digits and semicolons before the `m`.
3. A byte-wise copy mangled multi-byte UTF-8, so a test printing accented text
   would have its output corrupted **deterministically** — which reads as
   agreement rather than as damage.

And one wrong test of mine: I asserted that `ESC[1mno terminator` was unchanged,
but `ESC[1m` *is* a complete SGR sequence. Reading the assertion's own two values
made that obvious in seconds; theorising would not have.

Verified with the exact CI command under CI's colour setting: three consecutive
clean runs locally, then **green on CI** — the only proof that counts for a
defect that appears nowhere else.

---

### §O-043 — `qqqai run` enforced the right thing and said the wrong thing

Pointing `run` at a real artifact — rather than reading the code — found two
defects on the path that enforces the project's central claim.

---

#### §O-043a — The enforcement works; the advice for fixing it did not

Running a component that imports `qqq:clock/wall-clock@1.0.0` on a manifest that
grants nothing produces:

```text
error[QQQ-6003]: the component imports `qqq:clock/wall-clock@1.0.0` that no grant provides
  missing: qqq:clock/wall-clock@1.0.0
  capability: clock.monotonic          <-- wrong
```

The refusal is correct. The **remediation is wrong**: it names `clock.monotonic`,
the other half of the same package, so a user following the advice adds a stanza
that leaves the component still failing — on the one error whose entire purpose
is saying what to add.

`run` used the package-level mapping that `§O-038b` removed from `inspect`. Same
defect, same function, one surface fixed and the other missed.

---

#### §O-043b — Fixing a defect in one surface is not fixing it in the others

This is the round's generalizable finding, and it is worth stating as a rule:

> When a defect is caused by a **shared** helper, fixing it at one call site
> leaves every other call site wrong — and the remaining ones are harder to find,
> because the fix has already been made and the codebase *feels* corrected.

Why `run` was missed while `inspect` was fixed:

| | `inspect` | `run` |
|---|---|---|
| How the wrong answer appeared | a wrong capability **in the report** | a wrong capability **in a remediation line** |
| Who reads it | anyone inspecting an artifact | someone already looking at an error, primed to trust the fix |
| Visibility | the report is the deliverable | the advice is an aside |

The second column is uniformly worse: the reader is in a hurry, has just been
told something failed, and is looking for something to *do*. A wrong instruction
is more likely to be followed there than a wrong fact is to be believed.

**The structural fix was to delete the second mapping, not to update the caller.**
`capability_for_interface` is gone; `capability_for_import` is the only function
that answers this question, and the trap it leaves behind — a doc comment
explaining that the package-level answer is "the right granularity for an error
message" — is gone with it.

That comment is the part worth dwelling on. It was *specific*, *plausible*, and
*about the exact case that was wrong*. It had survived because it was true often
enough, and because a second helper that is nearly right compiles, has passing
tests, and requires every new caller to know which of the two to pick.

**The audit that found it:** `grep capability_for_interface` across the whole
workspace. After the `run` fix the only remaining uses were tests — so the
function had no production caller at all and still existed, which is what a
"shared helper" looks like once its last real user has moved on.

---

#### §O-043c — A bare positional named the artifact, or rather did not

`qqqai run ./needs-clock.wasm` **succeeded**, because the positional was appended
to the component's arguments: the command ran the project's built component
instead, and reported `app: ran in 63 µs`.

The user gets a confident answer about a file they did not run. This is the same
class as `inspect` discarding its path (`§O-038a`) — the argument is accepted and
silently ignored — and it is the more dangerous variant, because `run`
**executes** something.

The remediation text beside the code already said *"use `--` before arguments
meant for the component"*, so the fix was to make the code match the documented
contract rather than invent one. Proposal §5.2 lists `--args` for passing
component arguments; a bare positional naming the artifact is what a user types.

The `run` enforcement path now has five integration tests, having had none:

| Test | Property |
|---|---|
| `run_refuses_an_ungranted_import_and_names_the_right_capability` | refusal, **and** the implicated capability is asserted on the `capability:` line specifically |
| `run_executes_when_the_capability_is_granted` | the **positive control** — without it, a `run` that refused everything would pass the first test |
| `a_cap_flag_cannot_widen_the_manifest` | narrowing-only, asserted at the command line rather than only in the resolver |
| `a_positional_names_the_artifact` | the §O-043c fix |
| `run_dry_run_checks_grants_without_executing` | the rehearsal pre-flights but does not execute |

One of those tests was wrong before it was right: a blunt
`!output.contains("clock.monotonic")` failed on the **legitimate** stanza, which
lists both options for the package. The assertion now checks the `capability:`
line alone — which is the line that was wrong — rather than searching the whole
error text, where the real signal would have been lost in a screen of advice.

---

### §O-044 — The crate topology had two violations, and the document was the thing out of date

Proposal §4.3 states an invariant in bold: **"No crate may depend on a crate
above it in this list."** Checking it for the first time found two violations.

| Table said | Reality | Why the table is impossible |
|---|---|---|
| `qqq-host` above `qqq-abi` | `qqq-host` → `qqq-abi` | the linker is *built from* `qqq_abi::interfaces()`; a host without the ABI would hard-code its own interface list — the duplicated-source-of-truth problem the registry exists to prevent |
| `qqq-run` above `qqq-pkg` | `qqq-run` → `qqq-pkg` | the CLI resolves and installs dependencies; `qqqai add` is impossible if the package manager depends on the CLI |

Both were correctable in exactly **one** direction. `qqq-abi` must precede
`qqq-host` because the interface registry lives with the WIT definitions and
everything else binds to it; `qqq-pkg` must precede `qqq-run` because the CLI is
a *consumer* of the package manager. Inverting either would have produced a
build that works and an architecture that cannot be split — which is the
distribution channel §4.3 gives as its own reason for the topology.

**The document was wrong, not the code.** That is the distinction worth
recording: an invariant stated in bold, violated by the code, and *false of the
table that stated it*. A reader who checked — as the invariant invites — would
have concluded the architecture was broken and had no way to tell that the
prose was the stale artefact.

The order is now a topological order and is **enforced** by
`tools/check_topology.py`, which reads `cargo metadata` (the *resolved* graph,
including any edge a workspace-level dependency would create) rather than the
`Cargo.toml` files.

---

#### §O-044a — `qqq-core` has no I/O today, and "today" is the problem

The same section says `qqq-core` has **"No I/O"**. It does — `serde` and
`serde_json` only — but that was a fact about the present, not a rule, and it is
the crate every other crate depends on. A single `tokio` edge there is pulled
into all of them, and the way it arrives is a convenience import during some
later change.

The check now asserts it, and — the part that matters — carries a **control**
that the rule is wired:

```python
probe_dep = {"name": "tokio"}
if probe_dep["name"] not in IO_CRATES:
    errors.append("the no-I/O denylist does not flag `tokio`, so the rule is "
                  "misconfigured and would never fire")
```

Verified by deleting `tokio` from the denylist and watching the run fail with
exactly that message. Without the control, a misspelled entry or an inverted
comparison would leave the script printing `TOPOLOGY OK` forever — `§M-006` for
the fourth time, in a fourth domain.

---

#### §O-044b — Both rules are proven to fire, not merely to pass

The topology check was fault-injected twice before being wired into CI:

| Injection | Result |
|---|---|
| swap `qqq-abi`/`qqq-host` in the expected order | `FAIL: qqq-host (position 2) depends on qqq-abi (position 3)` |
| remove `tokio` from the no-I/O denylist | `FAIL: the denylist does not flag tokio` |

and both restored to `TOPOLOGY OK`. This is the discipline `self_test_xrefs.py`
established for the document graph, applied to a second kind of invariant: a
check earns its place in CI by being shown able to fail for the right reason.

It is also now part of the objective audit, so `tools/audit_requirements.py`
reports **32** requirements rather than 30 — the two additions being the crate
topology and WIT validation, both of which were being run in CI already but were
not part of the "is the objective met?" answer.

---

### §O-045 — `qqq-debug` built, and a tick that claimed DWARF mapping which did not exist

`qqq-debug` is implemented: it extracts a real DWARF source map from a built
component. Building it exposed a tick that was **wrong**, and a scaffold defect
that made the feature useless for user code.

---

#### §O-045a — `HOST-009` was ticked for DWARF mapping that did not exist

The item read *"structured trap reporting with guest backtrace and DWARF source
mapping when available"* and was ticked with the justification *"`Trap` carries
the Wasmtime frames and a human message"*. That justification does not mention
DWARF, and it could not: nothing in the workspace resolved a single source line.

Measured:

| Claim | Reality |
|---|---|
| `WasmFrame` has `file` and `line` fields | true — and **nothing ever populated them outside tests** |
| `Trap::with_backtrace` exists | true — and its only callers were in `trap.rs`'s own test module |
| `Instance::run` reports a backtrace | false — `trap_from(&raw)` takes a **formatted string**, so the `WasmBacktrace` is discarded before anything could read it |

A real trap therefore produced an empty `backtrace` vector, on a tick that said
the feature was done. The item is now `Partial` with the remaining work named.

**The pattern, in its third form this session.** `§O-038b` was a wrong *answer*,
`§O-043a` a wrong *instruction*, and this is a **field that exists and is never
filled** — the same defect with the evidence sitting in a struct definition
rather than in output. In all three the code compiles, the tests pass, and the
gap is exactly where the type says there is none.

---

#### §O-045b — The DWARF was one level down, in the nested core module

The first extraction reported `the artifact carries no DWARF sections` for an
artifact that `wasm-tools objdump` showed to be 265 KB of it.

The cause: `qqqai build` emits a **component** (layer 1), which wraps a **core
module** (layer 0) in section id `1`. The DWARF lives in the core module's own
section table. My parser walked the outer table, found a module wrapper and no
custom sections — **correct about what it read, reading the wrong table**.

That is a distinct failure mode from the ones above, and worth separating: not a
wrong answer, not a missing field, but a **right answer about the wrong
artifact**. The fix recurses into nested modules, bounded by `MAX_NESTING`
because the input is untrusted.

The regression test builds the nesting synthetically, since the structure — not
the bytes — is what broke it.

---

#### §O-045c — The scaffold's debug info existed and covered only the standard library

With extraction working, the map named `alloc.rs`, `cmp.rs`, `dlmalloc.c`,
`metadata.rs` — real files, none of them mine. `src/lib.rs` was absent.

The cause is a **scaffold defect**, not a mapper one: the template is a pure
library with **no exported symbol**, and `lto = true` with nothing referencing a
crate eliminates it and its debug info together. Verified by adding one
`#[no_mangle] pub extern "C"` function to a scaffolded project: `app.rs` appeared
in the DWARF immediately.

Two consequences recorded rather than one:

1. **`debug = true` is now in the generated `Cargo.toml`.** Without it there is
   no DWARF at all, and a release-mode trap reports an offset.
2. **The comment beside it says `debug = true` is necessary and not sufficient**,
   because that is what was measured. Claiming the setting fixes source lines
   would be the `§O-043a` mistake again — a plausible instruction that does not
   achieve what it says.

The remaining fix is the **guest ABI export** — the `qqq:http/incoming-handler`
implementation a real project needs anyway — which is a larger change than this
round and is tracked separately.

---

#### §O-045d — Three test bugs found by asserting against real output

Each of these would have looked like a product defect:

| Assertion | Reality |
|---|---|
| `map` contains `src/lib.rs` | the toolchain records bare **`lib.rs`**; the directory is resolved separately |
| the failure message's first ten files | the fixture **was** in the map, at position twelve — the assertion was reading its own truncation |
| `parse_custom_sections` returns `Option` | after the nesting fix it is infallible, and clippy was right |

The second is the instructive one: the diagnostic was informative and the
assertion consumed the diagnostic's sample instead of the data. A truncated
`Vec` built for a message is not the thing to assert on, and the two were one
variable apart.

---

### §O-046 — The trap backtrace join, and two assertions that could not fail

`HOST-009`'s remaining half is done: a real trap now carries frames.

---

#### §O-046a — The fix was one type change

`Instance::trap_from` took `&str` — the caller's `format!("{e:#}")` — so the
`Wasmtime` backtrace was discarded **before** anything could read it. Changing
the parameter to `&wasmtime::Error` is the whole fix, plus a constructor that
reads `WasmBacktrace::frames()` and maps each `FrameInfo` to a `WasmFrame`.

The name comes from the module's **name section** (`func_name`) and the location
from **DWARF** (`symbols()`), deliberately split: the name section is present in
every build and needs no debug info, so a frame is still *named* in an artifact
built without `debug = true` — the common case — and this way no demangler is
needed, since a DWARF symbol name is mangled and demangling is a heuristic that
is occasionally wrong.

`qqqai run` now sets `debug_info = true` on its engine. Both settings are needed
and they are different: `debug = true` in the project's profile decides whether
DWARF is **emitted**; `debug_info` on the engine decides whether it is **read**.
`EngineConfig::default()` leaves the second off — correct for a server, where the
artifact is untrusted and nobody reads a source line, and wrong for the CLI,
whose entire audience is a developer staring at a failed run.

---

#### §O-046b — Two of my three new assertions could not fail

Both were caught by fault injection rather than by reading.

**First: `contains("backtrace") || contains("spin")`.** It passed with the frames
dropped, because the trap's own `detail` string contains `spin` — the assertion
was satisfied by something other than the property it named. Fixed to
`contains("frame 0:")`, which is what `Trap::to_error` actually produces when a
frame exists (each frame becomes a cause).

**Second: `!contains("backtrace: []")`.** It passed in *both* states, because
nothing ever renders that string. The assertion named a phrase the codebase does
not emit, and a phrase that is never emitted cannot distinguish anything.

The mechanism that found both was injecting the defect:

```rust
// trap.rs, from_wasmtime_error
if !frames.is_empty() {
    trap.backtrace = frames;
}
```

replaced with `drop(frames);`, then running the suite. **Three tests failed, as
they should** — and the first run of that injection showed only one failing,
which is how the other two were found to be vacuous.

**This is the round's generalizable finding, and it closes a loop.** `§O-045a`
recorded that a *test constructed from the same mental model as the code cannot
refute that model*. These two assertions were written **while fixing that
defect**, by the same author, in the same file, minutes later — and were equally
unable to refute anything. The lesson did not transfer by being written down; it
transferred by injecting a fault and watching which tests stayed green.

The practical rule: **after adding a test for a bug, break the fix and confirm
the test fails.** If it does not, the test is describing the fix rather than the
bug, and it will not catch the next one either.

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

### §M-007 — Four changelog rows destroyed by anchoring `edit` on the last row

**What happened.** Appending a row to the change-log table in this document was done four times by passing the *previous last row* as `old_string` and the old row plus the new one as `new_string`. Each time, the replacement was written correctly in intent but the old row was dropped from the replacement text on at least one attempt, silently deleting the row above the one being added.

The deletions were only caught because each new row was preceded by re-reading the table to confirm the previous entry survived — which is exactly the check that should have been unnecessary. Three of the four were caught immediately; the fourth was caught only when searching for an unrelated string.

**Fix.** The rows were restored from `git diff`, and the pattern in the repository is now: when appending to a table or list, `old_string` is the **smallest anchor that is unique** — a heading or a blank line — never a large block that has to be reproduced verbatim in `new_string`.

**Lesson.** This is the same class as `§O-033d`: **an `edit` anchored on a long literal is a rewrite, not an insertion.** The tool replaces exactly what it is given, so any part of `old_string` not repeated in `new_string` is deleted. For a one-line addition, the anchor should be one line, not five. A writer who has to reproduce existing content in order to append to it will eventually reproduce it wrong.

**Evidence it was a real risk and not just carelessness:** the loss was silent. `edit` reported success, the document still parsed, the validator still passed — because a missing changelog row breaks no invariant. Only a human or a targeted search would notice. A destructive edit to prose has no compiler.

**Repeated in the same session, which is the more useful finding.** While writing
`§O-036`, an `edit` anchored on `## 4. MISTAKES AND FIXES` used that heading as
its trailing context and did not reproduce it, so **the section heading was
deleted**. It was caught only because the section list was re-checked afterwards.
The same thing had happened earlier to the `§M-001` boundary in `§O-035`.

So the fix written above — "anchor on the smallest unique string" — was correct
and was then not followed twice more within the hour. Recording that plainly,
because the pattern is now clear enough to name:

> **An `edit` whose `old_string` contains a heading is an edit that will delete
> the heading.** When appending a section, the anchor must be the *existing*
> content that stays, never the boundary that the new content is meant to sit
> before. If the new text ends with `## 4. MISTAKES AND FIXES`, the heading is
> still in `new_string`; if it does not, the heading is gone.

The reliable check, which caught it both times, is to re-list the document's
top-level headings after any edit that touches a section boundary. That check is
now the habit; a note in this document was not enough.

**A fourth occurrence, and the reason a note was not enough.** It happened again
while writing `§O-041`: the `## 4. MISTAKES AND FIXES` heading was deleted, and
it was caught only by re-listing the headings — for the fourth time. A lesson
recorded three times and repeated a fourth is not a lesson; it is a missing
mechanism.

So the mechanism now exists. `check_xrefs.py` **check `[12]`** asserts that the
Observations document contains all nine of its numbered top-level sections, in
order. Deleting a heading is exactly the failure that has recurred, and it is
mechanically detectable: the document has a fixed skeleton and a missing rib is
visible.

Verified by a fault injection that removes a heading and asserts the check
fires, so `[12]` cannot become a check that always passes. See `self_test_xrefs.py`.

The generalizable form: **when the same mistake recurs after being written down,
the writing-down was not the fix.** The fix is a check — something that fails
loudly without a person remembering to look.

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

### §S-001 — `.scratch/witprobe/` — **CLOSED**

**Marker in code:** the crate is deleted, so the marker is gone with it.

**What it was.** A throwaway crate that made the proposal's Wasmtime claims
falsifiable. It served its purpose: all four claims verified, plus a control case
(`§O-006`).

**Closed by `FND-011`.** The four assertions are now permanent tests in
`crates/qqq-host/tests/engine.rs`, each with its control:

| Ported test | Claim | Control |
|---|---|---|
| `an_unsatisfied_import_fails_instantiation_and_names_it` | an absent import fails instantiation | sibling test `a_component_with_no_imports_instantiates_and_runs` |
| `fuel_exhaustion_traps_the_guest_and_the_host_survives` | fuel bounds work; the host survives | runs a second guest after the trap |
| `an_epoch_interruption_stops_a_spinning_guest` | epochs bound time, independently of fuel | a concurrent ticker, so the test cannot hang instead of failing |

**What the port did NOT carry across, stated rather than glossed:**

* **The p50/p99 instantiation measurement** (`PERF-003`). The probe printed a
  regression baseline; the ported tests assert behaviour, not latency. A wall-clock
  threshold in a unit test is flaky on shared CI runners, so the honest place for
  it is the benchmark suite — which does not exist yet. `PERF-003` remains open
  and this is the reason.
* **The four WAT/ABI findings in `§O-007`.** They are recorded in this document
  and in `qqq-abi`'s internals; they were not re-ported as tests.

So the stub is closed for what it was *for* — falsifying the architecture claims —
while the performance baseline it also produced is explicitly still owed.

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
13. **When a test fails, ask *which artifact is wrong* — code, test, or helper — and measure the observable.** Two diagnoses were written as fact in one session and both were backwards; one `eprintln!` of bytes actually written settled each in a single run. (`§O-047d`)
14. **A test whose failure mode has not been demonstrated is not evidence.** Five times now, an assertion named a defect it could not refute. Reinject the defect and watch which tests stay green. (`§O-047b`, `§O-046b`, `§M-006`)

---

### §O-047 — The accept loop is joined, and a body was preserved by one half and refetched by the other

**What was built.** `qqq-serve::server` — the accept loop joining the pieces §6.4 specifies, each of which had been built and tested *separately*: the route table, the head parser, the response writer, the connection state machine, and the `qqq-io` listener. Every part existed and nothing ran them together. `SRV-001` is now complete: HTTP/1.1 with keep-alive, idle and header timeouts, a per-tenant ceiling, graceful drain on shutdown, and a real socket suite (`crates/qqq-serve/tests/socket.rs`).

#### §O-047a — The defect

`read_head` stops at the head terminator and keeps the remainder, with a comment saying it must not be discarded — those bytes are the body and the kernel has already delivered them (`buf.drain(..end)`). `drain_body` then consumed the body **from the socket** (`stream.read(...)`), reading bytes the buffer already held.

When head and body arrive in one segment, one `read` puts both in `buf`; the head is parsed, the body is set aside, and `drain_body` then waits on the socket for `content-length` bytes that are no longer there. The framing offset drifts by exactly the buffered amount and the **next** request line begins mid-body — a `400` on the second request of a connection whose first was answered perfectly.

**Fix.** `drain_body` takes `&mut buf` and consumes the buffered remainder first, reading the socket only for what is still owed; `read_head` no longer clears the buffer, which it had no right to do since `buf` outlives one call and belongs to the connection loop. With **no** `content-length`, the buffer is deliberately preserved, because it holds the next pipelined request.

**Class, not incident.** Two correct halves disagreed about **who owns a piece of state** — `§O-045a`'s shape a third time (the DWARF one level down; `is_open` vs `will_keep_alive`). When one function preserves something, the consumer of that thing must read the preservation, and the handoff must be observable.

#### §O-047b — The test could not fail for it

A test already existed naming this exact failure mode, and it passed throughout. The defect was reinjected to check the suite was live — `buf.clear()` restored — and **all nine socket tests still passed**, so the test was evidence of nothing.

Established by instrumentation, not reasoning: `eprintln!("buf.len()={}", buf.len())` at the top of `drain_body` reported `5` *with the defect present*, so the body was still buffered and the clear had nothing to discard. `write_all` of 71 bytes over loopback was delivered as **two** reads here — head, then body — so the body never entered `buf` on the head's iteration and the path under test never ran. This is the **fifth** occurrence of `§O-046b`: an assertion that cannot refute what it names. The lesson was written down four times and still did not transfer, because writing it down is not what prevents it — **breaking the fix and watching which tests stay green is.**

#### §O-047c — A test that fails on injection and passes without it

`a_pipelined_request_survives_a_body_less_drain` writes two requests before reading either response, so the first `read` necessarily pulls the second into `buf`. Instrumented, the drain reports `buf.len()=59 cl=None` — 59 bytes, exactly the second request's size, with no `content-length` on the first. It is the only test reaching the preservation branch with bytes present, the branch that had a comment and no coverage, and it counts response starts rather than reusing a helper that assumes one response per read. Verified by injection: **fails** with `buf.clear()`, **passes** without.

#### §O-047d — Two wrong diagnoses of my own

The new test failed twice against a server that was **correct**, and both diagnoses were written into comments as fact before being checked — `§O-041a` again.

1. **Blamed the server's framing.** It was the test: the second request carried `connection: close`, which half-closes the socket after writing, so the read raced the FIN. Tracing `write_all` showed **96 then 115 bytes** actually written — both requests had been answered all along. Evidence said change the test.
2. **Blamed a buffer-clear bug.** It was the helper: `read_response` decodes one buffer, so both responses arriving together are returned by the **first** call and the second returns nothing. `read_until_two_responses` replaces it, and the file's own claim that pipelining is "not something this server implements" was refuted by the trace showing both responses on one socket.

**Rule.** On a failing test the first question is *which artifact is wrong*, answered by measuring the observable — one `eprintln!` each time — not by reading code and forming a theory.

**Also fixed:** clippy `-D warnings` was failing on two `unnested_or_patterns` in the WIP test file, which would have been red on CI. Workspace is green under `cargo fmt`, clippy, and the full suite.

---

### §M-008 — A restore from a stale backup silently reintroduced the defect

Backing `server.rs` up for fault injection, injecting, then restoring from that backup **put the original defect back**, because the backup predated the first fix. The suite failed and time was spent re-diagnosing a fixed defect.

**Fix.** Injection backups are re-taken at the moment the file is known-good, and after every restore the injected string is grepped for rather than assumed absent. A restore is an operation that needs verifying, not merely doing.

---

### §O-048 — Streaming bodies, and a cap that was enforced one step too late

**What was built.** `qqq-serve::body` — `SRV-004` and `SRV-005`. A pull-based body decoder: `BodyReader::poll_chunk(io, max)` yields the next piece of a `Content-Length` or `Transfer-Encoding: chunked` body, decoding chunk framing incrementally, skipping and discarding trailers, and enforcing `max_request_bytes` **as the bytes arrive**. 22 tests in `crates/qqq-serve/tests/body.rs`, 12 in `tests/socket.rs`.

**Why pull-based, in one sentence.** §6.4 says the cap is a *cap*, not a buffer: if the check happens after buffering, a client that sends 2 GiB to a 2 MiB limit has already made the host allocate it. Backpressure is the same argument from the other side — a decoder that pre-buffers has read from the socket regardless of what the handler wanted.

---

#### §O-048a — The cap was enforced, but only after the guest had already answered

`server::serve_connection` dispatched the handler and **then** drained the body. Every unit test passed, because the decoder was correct.

The socket test `a_chunked_body_past_the_cap_is_cut_off` sent a 3 MiB chunked body against a 2 MiB cap and got:

```
HTTP/1.1 200 OK
```

The guest ran, the response was written, and only then did the drain discover the body was too large. `SRV-005` says the cap is enforced *during* streaming; here it was enforced during streaming but **after the request had already succeeded**, which is the same as not enforcing it for the purpose the limit exists.

**Fix.** The body is consumed before dispatch. A body that is malformed or over the cap is answered `413`-class (`QQQ-6006`, added to the taxonomy — a *client* fault that must not be a 5xx) and the connection closes, because the framing offset is no longer knowable. The post-response drain was deleted rather than kept: two consumers of one body is two places to be wrong.

**Verified by injection, not by the passing suite.** The ordering defect was put back — drain moved to after the response — and `a_chunked_body_past_the_cap_is_cut_off` **failed**, while the other 11 socket tests and all 22 body tests stayed green. That is a test aimed at exactly one defect, which is what a test should be. Note the converse case too: removing the drain *entirely* made that test **pass** (nothing is read, so no 200 is produced) while two others failed — a reminder that "the test is green" says nothing until you know which failures it can and cannot see.

---

#### §O-048b — The decoder closed a connection the server had been closing for want of it

`drain_body` returned `false` for any chunked body, ending the connection, with a comment saying why: discarding chunked framing without decoding it leaves the offset at a place only a decoder knows, and that is a request-smuggling shape. That was honest while no decoder existed.

With the decoder built, the same request must now be answered **and** the connection reused. `a_chunked_body_is_decoded_and_the_connection_is_reused` asserts both halves, because either alone passes for a server that is still wrong: answering then closing satisfies a status assertion, and reusing without decoding answers the second request from the middle of a chunk.

---

#### §O-048c — Six fault injections, and a false alarm that was worth more than the injections

`tools/fault_inject_body.ps1` breaks one invariant at a time and reports which tests catch it. **All 6 were detected**: cap not enforced; chunk CRLF not consumed; trailers not consumed; caller's `max` ignored (backpressure); dual-framing head accepted (smuggling); chunk-size line ignored.

Writing it produced three silent-failure lessons in one file, each of which would have made the script lie:

1. **The first version matched `"\r\n"` against an LF-only file**, so every injection silently failed to apply and the script reported "ALL DETECTED" against unmodified source. Injections now assert they applied before the suite runs, and the *absence* of the marker after restore is a separate check (`§M-008`).
2. **`Set-Content -NoNewline` on multi-line replacements concatenated lines**, corrupting the file while the diff looked plausible. The script is line-based now.
3. **The final "everything restored" run reported 7 failures** on a file that was **byte-identical to its backup**. The cause was cargo running the previously compiled test binary: the script rewrites the source several times per second and the rebuild decision was ambiguous. Each run now stamps the mtime first, and a failing final run prints the backup hash comparison before anything else is concluded.

Lesson 3 is the one to keep. An automated check that fails for a reason outside the system under test is worse than no check, because the natural response is to distrust the *result* rather than the harness — and the fix was in the harness.

---

### §O-049 — Five failing tests, and the code was right in all five

**The situation.** An HTTP/2 implementation was delegated: frame layer, HPACK, flow control, stream machine, connection machine. It produced the frame layer (70 KB, 35 tests) and HPACK (108 KB, 71 tests) before running out of context, leaving `flow.rs`, `stream.rs` and `h2/conn.rs` unwritten — so `mod.rs` declared modules that did not exist, the module was excluded from the tree, and ~234 KB of code was **inert**: never compiled by CI, and its 106 tests had never run.

**Decision: salvage rather than revert.** The code is good — no stubs, RFC citations, real tests. Three compile errors stood in the way (a `&Option<&str>` deref; a test helper returning `Frame<'_>` that borrowed its own local buffer; two tests referencing a `parsed` the rewrite removed). All three were mechanical.

### §O-053 — TLS and mTLS, and a walker that found no common name in any certificate

**What was built.** `qqq-serve::tls` — `SRV-007` and `SRV-008`. A rustls
configuration with an **explicit cipher policy** (no silent defaults: an
unspecified algorithm is refused rather than chosen), TLS 1.3 preferred with 1.2
permitted, ALPN negotiation for `h2` and `http/1.1`, certificate sources
(`Files`, `Platform`, and `Acme` refused by name rather than silently degraded),
`ClientAuth` in `None`/`Required`/`Optional` modes, and `PeerIdentity` extraction
from a verified client certificate. 35 unit tests and 21 end-to-end handshake
tests over a real TLS handshake.

#### §O-053a — `PeerIdentity::subject()` returned "no common name" for every certificate

`common_name_of` located the subject by searching the **`Certificate`'s own
children for tag `[3]` (`0xA3`)**, on the belief that `[3]` wrapped
`TBSCertificate`.

It does not. `[3]` is the **extensions** field *inside* `TBSCertificate`, and a
real certificate's children are `SEQUENCE, SEQUENCE, BIT STRING`. Measured on a
generated certificate: **`0x30, 0x30, 0x03`** — there is no `0xA3` at that level
at all. So the search returned `None` for **every** certificate ever presented,
and an operator reading an mTLS access log would have seen
`(subject has no common name)` for every authenticated peer.

**Fix.** The TBS certificate is the first child of the outer `SEQUENCE`, read
positionally — the earlier failure was *caused* by searching for a distinctive
tag, so searching harder was not the answer.

**Why no test caught it, which is the actual finding.** The unit tests exercised
`walk_rdn_sequence` against hand-built DER and passed. `common_name_of` — the
function that finds the subject *inside a certificate* — had **no test using a
real certificate**. The fixtures wrapped their `Name` in a `[3]` that no real
certificate produces: **the test encoded the same misunderstanding as the
code**, and two artifacts sharing a wrong assumption cannot correct each other.
Only the end-to-end mTLS test, which reaches the function with real bytes, found
it.

A `common_name_of_finds_the_cn_in_a_real_certificate` test now uses a generated
certificate, with a control asserting an organisation-only subject yields `None`
(so a walker returning a constant, or the first attribute it sees, fails too).
Verified by injection: reinstating the `0xA3` search fails the new test.

#### §O-053b — Three fixture comments that asserted rcgen's behaviour, wrongly

Three separate test-fixture beliefs were wrong, and each was written as a
confident comment, which is what made it durable:

1. **`generate_simple_self_signed` does not derive the subject CN from the SAN.**
   A comment asserted it does; measured, the subject CN is rcgen's default
   `"rcgen self signed cert"` whatever name is passed. The fixture now sets the
   distinguished name explicitly, which is also what a real certificate does —
   a subject is not derived from its SANs.
2. **The handshake connected to `localhost` while the certificate was issued for
   `qqq-test-server`.** Nine tests failed with `left: None, right: Some(...)` on
   ALPN or version — identical, uninformative output for one cause. Naming the
   cause (the helper now carries a `failure` reason) turned nine opaque failures
   into one readable line, and it was a two-word defect.
3. **Disjoint ALPN lists refuse the handshake**, they do not complete without a
   protocol. A test asserted the opposite with a comment explaining that
   continuing "is correct TLS". It is not: RFC 7301 requires
   `no_application_protocol`, and a server that continued would leave the client
   speaking h2 to a server that agreed to nothing.

**The pattern across all three.** Each was a claim about a *third party's*
behaviour, written as prose in a comment where nothing could check it. The
project's rule — verify claims rather than assert them — had been applied to its
own code and to the Proposal, and not to its dependencies or its fixtures. A
wrong comment about `rcgen` is as costly as a wrong comment about QQQ.

---

### §M-009 — Three agents in one working tree, and they deleted each other's files

**What happened.** Two long-running implementation tasks were delegated in
parallel — HTTP/2 (`SRV-002`) and TLS (`SRV-007`/`SRV-008`) — while the main
session continued in the same checkout. Each wrote a *new* file, so there was no
merge conflict; the collision was in `crates/qqq-serve/src/lib.rs`, which both
had to edit to register their module.

The h2 agent, unable to build because the TLS file was mid-write and failing,
resolved it the way that unblocked *it*: it moved `tls.rs` to
`.scratch/tls_stashed_by_h2_worker.rs` and commented out `pub mod tls;` in
`lib.rs`, twice. The TLS agent, mid-verification, found its 73 KB source file
deleted underneath it and its module unregistered, and asked whether to race the
other agent or wait.

Both agents behaved reasonably given what each could see. The coordination bug
was mine: the rule "destructive edits to shared tree state" was never stated,
because I had assumed new-file-only work was inherently conflict-free. It is not
— the module registry is a single shared file every new module must touch.

**Cost.** One file deleted twice, one agent blocked mid-verification, one
inconclusive build, and a stash of parallel work that had to be set aside. The
loss was time rather than code, because both agents kept copies.

**Fix, applied now.** The h2 agent was interrupted (it had produced
`flow.rs` and `stream.rs` but not `h2/conn.rs`, and its interruption left a
stray brace in `stream.rs`). Long-running delegations that touch a shared
workspace run **one at a time**. Where parallelism is genuinely wanted, the
crates involved are separated first, or the work is committed to a branch per
agent.

**The rule, stated so it is not relearned.** A shared working tree is a mutually
exclusive resource for any task that edits *registration* files — module roots,
`Cargo.toml`, `lib.rs`, the checklist. "It only adds new files" is not
sufficient, because the new file is useless until something registers it, and
that something is shared.

---

### §O-051 — The first checklist item found ticked that was not true

**What was found.** Auditing `qqq-host` against its checklist entries, `HOST-016` — *"Implement `epoch_deadline_async_yield_and_update` so a guest yield does not stall the reactor"* — was marked done with the note *"Done: Host functions registered per interface in `host_clock` and `host_crypto`."*

That note describes host-function registration. It has nothing to do with epoch yielding.

**Verified against source, not inferred.** Searching every crate for epoch machinery:

| Present | Absent |
|---|---|
| `Config::epoch_interruption(true)` (`config.rs`) | `epoch_deadline_async_yield_and_update` |
| `Store::set_epoch_deadline(1)` (`instance.rs`) | `epoch_deadline_callback` |
| `limits.epoch_deadline_ms` modelled and parsed | `epoch_deadline_trap` |

The interrupt machinery exists and an expiry **traps** — it does not yield. There is no yield mechanism at all, which is precisely what the item asks for.

**And the mis-attribution was already known.** `linker.rs` carries a comment (`§O-020d`) saying in as many words: *"An earlier version cited `HOST-016`, which is `epoch_deadline_async_yield_and_update` — a scheduling concern, not interface implementation."* The wrong citation was corrected **in the code comment** and the checklist tick was never revisited. That is the interesting part: the correction was written down in one artifact and not propagated to the other, so the register a reader actually counts kept claiming work that had not been done.

**Corrected.** `HOST-016` is now `[!]` blocked, with the reason and the blocking item named. `HOST-015` carries the verified evidence that no `*_async` API exists anywhere in `qqq-host` — `Instance::run` is synchronous (`TypedFunc::call` on a `&mut Store`) — which is both the real gap and the reason `HOST-016` cannot proceed: the async variant requires an async path.

**Why this matters more than the item.** A ticked item is a claim to a reader who will not re-derive it. This project's whole method is that claims are verified rather than asserted, and this is the first item in 81 found ticked without the work behind it. One is not a pattern; the *mechanism* is what to watch — a correction recorded in one document and not the other, which `check [8]`/`[9]`/`[10b]` catch for decisions and do not yet catch for checklist ticks.

---

#### §O-049a — Then five tests failed, and every one was the test's fault

This is the part worth recording, because the failure mode is asymmetric. A failing test usually means broken code, and the correct response is to fix the code. Here it was the opposite five times, and *adjusting the implementation until the red went away* would have broken working code in four different places.

1. **RFC 7541 C.6.2 and C.6.3 decoded standalone.** They are the **second and third blocks of a sequence**: C.6.1 inserts headers into the dynamic table, C.6.2 reuses them by index, C.6.3 reuses entries C.6.2 evicted and replaced. A fresh decoder cannot decode a middle block, and the error it produced — `index 65 names no entry in the dynamic table` — was **correct behaviour**. The first instinct was that the dynamic-table indexing was off by one. It was not. Both vectors now chain through C.6.1 on one decoder, which is what the RFC's example actually is.
2. **The entry-size test expected 54 for `cache-control: no-cache`.** It is 13 + 8 + 32 = **53**. What caught it was the test having *four* cases: three matched and one did not, so the odd one out was visible. A single literal would have read as an implementation bug.
3. **A Huffman "compresses" assertion over all 256 byte values is simply false.** RFC 7541's code is tuned for HTTP header text: printable ASCII is 5–6 bits, high bytes run to 30, so the full range *expands* 256 bytes to 583. The unconditional property is the round trip, which stays; the compression claim now lives on HTTP-shaped input. An assertion true of only some inputs is a latent flake.
4. **PING's wrong-length case was tested with stream id 1**, which is itself illegal — PING is connection-level and must carry stream id 0. The parser correctly reported `BadStreamId` before `BadLength`, and the test asserted one error while triggering an earlier one.

#### §O-049b — The verification that makes the salvage defensible

Correcting five tests creates an obvious hazard: the corrections could be shaping the tests to fit whatever the code happens to do. So the RFC vectors were fault-injected — the HPACK dynamic-table lookup moved by one — and **10 tests failed, including both chained C.6 vectors**. They are evidence, not decoration.

**The general lesson.** When a test fails, the question is *which artifact is wrong* — and the answer is not "the test" merely because the test is convenient to change, nor "the code" merely because tests usually find code bugs. Here the tiebreaker was the RFC: the vectors are external ground truth, and the code agreed with them once the state sequence was right. Where no external authority exists, the honest move is to inject the defect and see whether the test can fail at all (`§O-048c`).

---

### §O-050 — The narrowing invariant, verified rather than believed

**The claim.** §D-008 and `CAP-010`, and `§8.8` of the short list: *"Capabilities are denied by default and no overlay can ever widen them. If that invariant breaks, the product has no reason to exist."*

This is the one claim in the corpus that a reader should not have to take on faith — every other guarantee degrades gracefully, and this one does not.

**It is enforced structurally, and that was checked in source.** The only way to combine two `GrantSet`s is `GrantSet::narrow`. There is no union and no widen, and a search for `capabilities.insert` / `capabilities.extend` across `qqq-cap` finds **nothing outside that one function** — so widening is not prevented by a check that could be forgotten, it is prevented by the absence of a code path. `narrow` additionally refuses an overlay whose layer claims granting authority (`debug_assert` plus a non-effect), so a programming error in a future overlay cannot become an escalation.

**Verified by injection.** The test `no_overlay_can_ever_widen` starts from the **empty** set, constructs a hostile overlay holding **every** capability, and tries all six (layer × mode) combinations, asserting the result is still empty. Injecting a union into `narrow` makes **13 tests fail**, that one among them.

**Why this is recorded.** A safety invariant that is only asserted in prose is a liability: it reads as true, so nobody tests it, and it is load-bearing precisely because it is never exercised by ordinary use. This one has a test that fails when it is broken, and the structural absence of the widening path back it up. The claim can now be cited with evidence rather than repeated.

---

### §O-063 — Two more contract checks, and the one where the first implementation certified the bug

**What was built.** `tools/check_no_ambient.py` (`CON-010`, `CON-018`) and
`tools/check_batch_first.py` (`CON-012`), each with a fault-injection harness.
Five checkers and five harnesses now guard the WIT contract surface.

#### §O-063a — `CON-010`: the allowlist is the load-bearing part

The rule is §2.5's *"no environment-variable reads, no CWD dependencies, no
implicit config discovery inside the runtime."* It is checked at the **source**,
because the violation is an absence of discipline in code no test exercises: a
host interface reading `QQQ_CONFIG` on a path nobody tests behaves identically to
a correct one under every test that does not set it, and differently on a
developer's machine.

The interesting design question is not what to forbid but **how to exempt**.
Three decisions:

| Construct | Verdict | Why |
|---|---|---|
| `std::env::consts::{ARCH,OS,FAMILY}` | allowed | Compile-time constants of the **build**, not of the running environment. `config.rs` uses them for the target triple and is correct to |
| `cap::normalize::RealEnv`'s `var_os` | exempt, **per construct** | Environment access there goes through the `HostEnv` **trait** with a fake in tests — the remedy NN-5 asks for, not a violation of it |
| A `#[cfg(test)]` `temp_dir` | exempt | Forbidding it pushes test authors toward fixed repository paths, which is worse |

**The exemption is scoped to `(file, construct)`, not to the file.** That is
asserted by an injection rather than trusted: the harness plants a bare
`std::env::var` *beside* the exempted `var_os` in the same file, and it must still
fail. A file-level exemption would have passed it silently — and would have been
the obvious way to "fix" a false positive.

The harness also carries a **negative control**: a `temp_dir` inside
`#[cfg(test)]` must NOT be reported. A checker that flags test code gets worked
around rather than obeyed, and a harness that never tested this would not notice
if the exemption broke.

#### §O-063b — `CON-012`: the rule is only half decidable, and pretending otherwise generates paperwork

§4.5: *"a host interface that would naturally be called in a loop must instead
accept a batch."* The operative phrase — *would naturally be called in a loop* —
is a judgement about usage.

**The first implementation demanded that every singular function be classified.**
It produced 23 demanded classifications, including `sql.txn.commit`,
`trace.span.event`, `http.incoming-handler.handle`, `kv.store.delete` and
`trace.start-span`. Those are *inherently* singular: committing a transaction in a
loop is not a chatty interface, it is what transactions are. A tool that demands a
written excuse for each of them is not enforcing a rule — it is generating
**paperwork**, and paperwork gets `# allow`-ed away, at which point the check is
dead while appearing to pass.

So the scope was narrowed to the decidable half:

> **Every declared batch pair must be real, must actually take a collection, and
> must agree with its singular form on the error type.**

The pair list is **declared**, not inferred from the `-many` naming convention:
inference works today and breaks the first time a batch form is named
differently, and a declared entry naming a function that no longer exists is
itself a failure, so the list cannot rot.

The negative control is that adding a new **unpaired** singular function must
**not** fail — which is precisely the behaviour the first version got wrong.

#### §O-063c — "Does the signature contain `list<`" certified the exact defect it existed to find

The second rule is *"the batch form must actually take a collection."* The first
implementation asked whether the signature contained `list<`. It does — in
`digest-many(input: list<u8>)`, which is **one buffer**: exactly what the singular
form already takes. A batch form in name only, and the crude test **passed it**.

That is the worst class of checker defect. Not a false positive, which is noisy
and gets fixed, and not a false negative in code nobody looks at — but a check
that **certifies the specific bug it was written for**, so the bug ships with a
green tick beside it.

The fix inspects the **element type**: a scalar element (`u8`, `u16`, …) means a
buffer rather than a collection, while `list<list<_>>`, `list<string>`,
`list<tuple<_>>` and `stream<_>` count. The injection that exposed it —
`digest-many` rewritten to take one buffer — is now a permanent part of the
harness.

This is the second time in two items that writing the harness found a defect in
the *checker* rather than in the corpus (`§O-062b` was the first), and both were
found by an injection, not by reading the code.

#### §O-063d — A WIT scoping rule the injection had to respect

The error-mismatch injection went through three attempts, and the middle one
taught something about the language:

```
$ wasm-tools component wit bad.wit
error: name `hmac-error` does not exist
```

**WIT types are interface-scoped.** `hmac-error` is declared in the
`hmac` interface, so it is invisible from `hashing` even though both live in
`qqq-crypto.wit`. Constructing the defect therefore requires the second variant
to be declared **in the same interface** as the pair — verified with a two-variant
probe before writing the injection.

Worth recording because it is a constraint on any future checker that reasons
about type names: a name is not global to a file, so file-level name resolution
is wrong in the same way `(file, function)` keys were wrong in `§O-062b`.

#### §O-063e — Five checkers, five harnesses

| Checker | Rule | Injections | Control |
|---|---|---|---|
| `check_wit.py` | every interface parses | — (external: `wasm-tools`) | — |
| `check_wit_since.py` | `@since` mandatory | 3 | — |
| `check_wit_errors.py` | typed errors | 3 | — |
| `check_no_ambient.py` | no hidden global state | 4 | test code not reported |
| `check_batch_first.py` | batch pairs consistent | 3 | unpaired singular accepted |

**13 injections plus 2 negative controls**, all passing. Every one of the five
harnesses has found a defect in its own checker at least once.

---

### §O-062 — The typed-error rule: three checker defects, each of which called a correct file broken

**What was built.** `tools/check_wit_errors.py` (`CON-009`) and
`tools/fault_inject_wit_errors.py`. The corpus goes from unenforced to **13/13
interfaces conforming, 73 functions checked, 19 declared infallible by name**.

#### §O-062a — "Every function returns `result`" is the wrong rule, and the right one needs an allowlist

Proposal §2.5 says *"every **fallible** host call returns a typed error"*. The
emphasis is not decoration:

* `clock.timezone() -> string` returns `"UTC"`. There is no failure to represent.
* `crypto.decrypt(...) -> result<list<u8>, aead-error>` fails when a tag does not
  verify.

A check of "every function returns `result`" would flag the first and be wrong.
The rule that works is:

> Every fallible function returns `result<T, E>`, **and every infallible one is
> named in an allowlist with the category that makes it infallible.**

The allowlist is the point rather than a workaround. It converts "this cannot
fail" from an **omission** — invisible, unargued — into a **claim someone wrote
down**, which is exactly what NN-5 asks for. A new function with no `result` and
no entry fails the check, so its author has to decide which category it falls
into rather than defaulting into one silently.

**Two entries are security properties rather than conveniences.**
`secrets.exists(name) -> bool` returns a boolean *by design*, so a guest cannot
probe a secret's value, length or type — only whether a code path is available.
An error type there would itself be a disclosure channel. And `sql.statement.
close()` is infallible because a closer that can fail forces every caller into a
cleanup path it cannot act on; the host owns the connection and releases it on
instance teardown regardless.

**The rule's second half is also enforced.** `result<T, string>` and
`result<T, u32>` parse perfectly and defeat *"not a status code buried in a
payload"*, so the error side must be a **named WIT variant**. That is what gives
a caller in any of the five target languages an exhaustive `match` rather than an
integer to compare against constants.

#### §O-062b — Three defects, all in the wrong direction

Every one of the three made the checker report a **correct** file as broken.
That direction matters more than the opposite: a checker with false positives is
noisy, the noise makes people distrust it, and the cheap fix is to weaken it —
whereas a false negative is silent and a missing check.

| Defect | Symptom | Fix |
|---|---|---|
| Line-at-a-time scanning | `crypto.encrypt` and `crypto.decrypt` reported as having no `result` — they have one, spanning five lines | The declaration is accumulated until the terminating `;` and examined whole |
| A bare-name allowlist key | `qqq-clock.wit:now` could not express that `wall-clock.now` is fallible and `monotonic-clock.now` is not, so a correct file was reported as self-contradictory | The key is `file.wit:interface[.resource].function`, unambiguous by construction |
| Clearing interface and resource scope together | `database.databases` mislabelled as `database.statement.databases` | Separate depths for the interface and the resource, so a closed resource leaves the interface in scope |

The second is the instructive one: **the same function name in two interfaces
with different failure modes** is not a hypothetical, it is the current state of
`qqq-clock.wit`, and any key scheme that assumes a name is unique across a file
is wrong about this repository today.

#### §O-062c — Three injections, all parseable

```
  DETECTED  fallible function with no result
  DETECTED  primitive error type
  DETECTED  stale allowlist entry

ALL 3 TYPED-ERROR FAULT INJECTIONS DETECTED
```

All three leave the WIT **parseable**, and the harness verifies that with
`wasm-tools` before counting a detection — an injection that breaks the parser
proves nothing about this checker, which is the discipline `§O-048c` and
`§O-058e` established and `§O-061c` applied again.

The third injection targets the *checker's own source*: a stale allowlist entry
that names a function which no longer exists. Without it the allowlist grows
without bound, each stale entry silently exempting nothing, and the list stops
being a record of decisions. The harness edits `tools/check_wit_errors.py`,
restores it, and verifies the restore by re-reading the file.

---

### §O-061 — The WIT versioning policy: a parser proves the language, not the contract

**What was built.** `tools/check_wit_since.py` (`CON-007`, `CON-008`),
`tools/add_wit_since.py` (the one-time migration), and
`tools/fault_inject_wit_since.py`. **73 `@since` annotations added across 13
interfaces**, taking the corpus from 0 to 13 conforming.

#### §O-061a — `wasm-tools` accepts a WIT file with no annotations at all

This was verified before writing the checker rather than assumed, and it is the
entire justification for the checker existing:

```
$ wasm-tools component wit test2.wit
package test:anno2@1.0.0;
interface foo { now: func() -> u64; }
$ echo $?
0
```

So `tools/check_wit.py` — which runs `wasm-tools component wit` on every file —
proves each file **parses** while saying nothing about whether the annotation
policy is followed. The measured state before this work was **0 of 13 interfaces
conforming, 0 annotations across 73 exported functions**.

The distinction is the same one `check_wit.py`'s own docstring makes about
structural tests versus parsers: *"a structural test checks the shape of your
model; a parser checks the language."* This adds the third question — **is the
contract complete?** — which neither of the other two answers.

#### §O-061b — The case that justifies the whole checker: a misplaced annotation still parses

A `@since` gate attaches to the **next item**. Put it on a `use` line instead of
on the function below, and:

* the file **still parses** — `wasm-tools` accepts it and exits 0;
* the function is left with **no** annotation;
* and the annotation now claims something about a `use` declaration.

That is valid WIT with a wrong contract. A parser cannot see it, a structural
test cannot see it, and a reviewer reading a 78-line file will miss it more often
than they will catch it. It is exactly the failure mode NN-5 exists to prevent —
*"nothing important is inferred"* — and it is why the policy check earns its
place beside the parser rather than duplicating it.

`tools/fault_inject_wit_since.py` injects it by **moving** an annotation off its
function and onto the `use` line above, and the check catches it.

#### §O-061c — Two harness defects, both of which looked like checker defects

Both were caught by the harness's own honesty checks rather than by reading the
code, which is the point of building them in.

**First: an injection that added rather than moved.** The misplaced-annotation
injection inserted a `@since` onto the `use` line while leaving the function's
own annotation in place. So no violation existed, the checker correctly passed,
and the harness reported **MISSED** — a *harness* defect presented as a *checker*
defect. Fixed by moving instead of adding.

**Second: a rule the parser already enforces.** The "`@since` above the package
version" injection produced:

```
error: feature gate cannot reference unreleased version 9.9.9 of
       package [qqq:clock@1.0.0] (current version 1.0.0)
```

`wasm-tools` rejects it outright, so **no parseable WIT file can trigger that
checker rule**. The harness reported `BROKEN` — correctly, since the injector's
contract is that an injection must parse — and the rule is now documented as
**deliberately not injected**, with the reason, rather than deleted. It costs one
comparison and its message names the contradiction rather than the parser's, so
it stays as defence in depth; what must not happen is a future reader believing
this harness exercises it.

This is the seventh instance of the instrument-reporting-on-itself family
(`§M-008`, `§O-048c`, `§O-056e`, `§O-058e`, `§O-058f`, `§O-060d`). The pattern
that keeps working is mechanical: **check that the injected artifact changed,
parses, and fails for the stated reason** — three cheap assertions that between
them caught every one of the seven.

#### §O-061d — Why the migration is a script and not 73 hand edits

`tools/add_wit_since.py` inserts each annotation immediately before its function,
after any doc comment, and is idempotent — it skips a function whose preceding
line is already `@since`. Hand-editing 73 sites across 13 files would have
introduced at least one misplacement, and a misplacement is precisely the defect
`§O-061b` describes as invisible.

The annotations are `1.0.0` for every function because every interface here ships
in the V1 line and none was released earlier, so "since 1.0.0" is a statement of
fact rather than a placeholder. A function added in the 1.1 line must say
`@since(version = 1.1.0)`, and the checker rejects anything above the package
version or below 1.0.0.

---

### §O-060 — The naming invariant is now enforced, not just settled

**What was built.** `crates/qqq-core/tests/naming.rs` — 4 tests enforcing `§D-001`,
plus `tools/fault_inject_naming.py`, which injects three realistic ways the rule
breaks and asserts each is caught.

#### §O-060a — Why "settled" needed a test

`§D-001` states the naming as *"deliberate, permanent — not a workaround awaiting
a better option"*, and the objective restates the consequence flatly:

> **a build producing a `qqq` binary is a defect.**

Before this, that was verified once, by hand: `cargo build -p qqq-run` produces
`qqqai.exe` and no `qqq.exe`. A verified-once fact is a fact that decays, and the
decay is cheap to introduce — a `[[bin]]` stanza added by hand, a package renamed
to match the brand, or a doc example teaching `qqq new`.

The naming is the project's **public install surface**: `cargo install qqqai` and
`npm install -g qqqai` either work or they do not. A rename is otherwise
discovered by users, not by CI.

#### §O-060b — Both halves of the binary rule, and why one is easy to miss

Cargo names the default binary after the **package**, unless a `[[bin]]` stanza
overrides it. `qqq-run` declares `[[bin]] name = "qqqai"`, which is the only
reason the default (`qqq-run`) is not produced. So the rule has two halves:

* a declared `[[bin]]` must be named `qqqai`;
* a crate with `src/main.rs` and **no** `[[bin]]` stanza produces its package name
  — which for a `qqq-*` package is neither `qqq` nor `qqqai`, and therefore also
  wrong.

The second half is the one a check would miss by only grepping for
`name = "qqq"`. The test asserts both, and asserts that **exactly one** binary is
declared — so adding or removing one is a deliberate edit rather than a silent
change.

#### §O-060c — The documents are checked, and the scan distinguishes brand from command

The naming is also *instructions to users*. A README saying `qqq new` teaches a
command that does not exist, and the failure is discovered by someone following
the documentation exactly as written — worse than a wrong binary name, because the
documentation is the thing they trusted.

The scan cannot simply search for `qqq`: the brand appears legitimately everywhere
("QQQ is a runtime") and `qqq-` prefixes crate names. It looks for `qqq` followed
by one of **26 known subcommands**, and excludes a match preceded by `qqqai` or by
`-`. That is the difference between checking the property and checking the string.

#### §O-060d — All three injections detected, and the harness left `Cargo.lock` dirty

```
  DETECTED  binary named qqq
  DETECTED  document teaches `qqq new`
  DETECTED  package named qqq

ALL 3 NAMING FAULT INJECTIONS DETECTED
```

The first run left `Cargo.lock` modified. Cargo rewrites it whenever a manifest
changes — including an injected package rename — and the injector restored only
the manifest it had edited. Caught because `git status` was read after the run
rather than assumed clean, which is the discipline `§O-058f` established.

The fix backs up and verifies `Cargo.lock` alongside the sources. **That is a
general property of any manifest-editing injector**, and it is worth stating
because it is invisible: the harness reports success, the tree is dirty, and the
next commit carries a lock-file diff attributable to nothing.

This is the sixth instance of the instrument-reporting-on-itself family
(`§M-008`, `§O-048c`, `§O-056e`, `§O-058e`, `§O-058f`), and the second in a row
where the *harness* rather than the check was at fault. Running `git status` after
every injection run is now part of the routine.

---

### §O-059 — Architecture tests: three absences, one real defect, and a control for each

**What was built.** `crates/qqq-core/tests/architecture.rs` — 8 tests covering
`ARCH-002`, `ARCH-004` and `ARCH-008`, plus `tools/fault_inject_architecture.py`,
which injects three real violations and asserts each is detected.

#### §O-059a — Why these tests live in `qqq-core`, and why they read the filesystem

They are statements about the *workspace*, not about a crate. `qqq-core` is the
only crate every other crate depends on and that itself depends on nothing, so a
test there cannot create a cycle and cannot become unreachable — and `qqq-core` is
`ARCH-004`'s own strictest case, which gets a dedicated test.

They read the tree rather than using `include_str!`, and the reason is the point:
`include_str!` needs each path named at compile time, so **a newly created crate
would be invisible** — which is the exact failure these tests exist to prevent.
Reading the directory finds the new crate and fails on it, which is the right
response to an unannounced workspace member.

The cost is that a source-reading test is weaker than a compiler check. That is
acknowledged in the module docs rather than glossed: where a compiler check was
possible it was used, and these cover the residue no compiler can see — *which
crates exist* and *what their declared lint policy is*.

#### §O-059b — `ARCH-008` found a real defect: two crates weakened their own guarantee

`qqq-debug` and `qqq-sys` both declared:

```rust
#![cfg_attr(not(test), forbid(unsafe_code))]
```

That form permits `unsafe` under `cfg(test)`. So the guarantee was a property of
the **build configuration** rather than of the **source**: an `unsafe` block
introduced behind a `#[cfg(test)]` gate would have been silently legal, and the
release build's claim would still have read as true.

Neither crate contains a single `unsafe` — verified by searching every source
file — so the escape hatch was defensive rather than necessary. Both are now bare
`#![forbid(unsafe_code)]`, matching the other eight crates.

**Why the test caught it, which is the design detail.** The check does not ask
"does the file mention `forbid` and `unsafe_code`". It asks whether the attribute
is a **bare `#![forbid(...)]` or a `cfg_attr`-wrapped one**, and reports the two
separately. Both contain the same words, so a substring check would have accepted
the weaker form — and the weaker form is precisely the one that fails silently.

This is the second defect this checklist item has surfaced in code that looked
correct (`§O-053`'s `0xA3` search was the first), and both were found by a check
that distinguished a *form* rather than a *presence*.

#### §O-059c — The topology injection created a cycle, and a cycle is a different protection

The first version of the `ARCH-004` injection gave `qqq-cap` a dependency on
`qqq-serve`. Cargo rejected the workspace outright:

```
error: cyclic package dependency: package `qqq-abi` depends on itself
```

`qqq-serve` already depends on `qqq-cap`, so the injected edge closed a loop. The
harness reported **`BROKEN`, not `DETECTED`** — correctly, because the test never
ran. **Cargo prevents cycles; it does not prevent upward edges**, and those are
different properties: `qqq-cap → qqq-serve` with no existing path back would have
compiled fine and inverted the layering silently.

The injection now targets `qqq-debug` (position 9, which depends only on
`qqq-core`), giving an edge that is upward **and** acyclic. That is the case the
test exists to catch, and it is now detected.

**The general rule this establishes**, and it is the same one `§O-058e` reached
from the other direction: an injection must be **valid but wrong**. A dependency
cycle is invalid, so Cargo catches it and the test under test is never consulted.
A fault-injection harness that accepts "the build broke" as success is measuring
the compiler, not the check.

#### §O-059d — Three absences, and a positive control for each

Every one of the three tests asserts an *absence*: no upward dependency, no
missing `forbid`, no widening constructor. **An absence is trivially satisfied by
a scanner that finds nothing**, which is the failure mode `§M-006` names.

Each therefore has a control:

| Test | Control |
|---|---|
| `no_crate_depends_on_a_crate_above_it` | asserts `checked > 0` — at least one `qqq-*` edge was actually examined |
| `every_non_exception_crate_forbids_unsafe_code` | asserts `checked >= 9` — nine crates were inspected |
| `no_widening_constructor_on_grants_exists_anywhere` | asserts an `impl GrantSet` block was found, so the scanner reads real code |
| **all of them** | `the_architecture_scanner_finds_real_files` — asserts `crate_dirs`, `walk` and `package_name` all return real data |

And the injections in §O-059e prove each test can fail *for its own reason*, which
is the strongest form: a control proves the input was real, an injection proves
the assertion is live.

#### §O-059e — All three injections detected

```
  DETECTED  topology (upward dependency)
  DETECTED  unsafe policy (bare allow)
  DETECTED  grant widening (union on GrantSet)

ALL 3 ARCHITECTURE FAULT INJECTIONS DETECTED
```

The harness restores from a `tempfile` copy — not from `.scratch/`, which is
gitignored and absent on a fresh checkout (`§O-058f`), and it verifies the
restore by re-reading the file rather than trusting `finally`. Wired into CI.

#### §O-059f — Three `unsafe` exception crates, merged into one — a deviation from §4.3

`ARCH-009` requires a written safety argument *per `unsafe`-permitting crate*.
The Proposal names three:

| §4.3 crate | Purpose | This workspace |
|---|---|---|
| `qqq-io-uring` | io_uring reactor backend (`PERF-014`) | **merged into `qqq-sys`** |
| `qqq-mem-hugepage` | Hugepage-backed linear memory | **merged into `qqq-sys`** |
| `qqq-sys-signals` | Signal handling for epoch ticking | **merged into `qqq-sys`** |

**The decision.** One exception crate, `qqq-sys`, with one `SAFETY.md` and one
review process, rather than three.

**Why.** Three crates each holding one `forbid` to remove is three documents,
three reviews and three places a policy can drift — and the drift is exactly what
`ARCH-009`'s per-crate argument exists to prevent. Multiplying the paperwork that
prevents drift is a poor way to prevent it. One document covering the whole
exception surface is strictly easier to keep correct.

**The cost, which is real.** One crate means one boundary to cross rather than
three narrow ones, so a mistake in the exception process has a larger blast
radius. The mitigation is that the process is enforced by a test
(`the_unsafe_exception_was_granted_through_its_process`, plus
`tools/fault_inject_safety_arg.py`) rather than by the crate boundary — so the
guarantee does not depend on having chosen the right granularity.

**Revisit when.** `qqq-sys` exceeds roughly 1,500 lines, or the three concerns
develop genuinely different review requirements. The split is mechanical: the
modules already map one-to-one onto the three named crates.

**Why this is recorded here and not as an `OQ-` entry.** `OQ-001` … `OQ-012` are
all allocated and mirrored in Proposal Appendix C, and the cross-reference
validator rejects an `OQ-` identifier the Proposal does not cite. This is a
decision the repository can make and defend, not a question requiring a founder —
so it belongs in the observations register, which is what `docs/adr/README.md`
says the register is for.

**The `SAFETY.md` was written before the code.** That is deliberate, and it
initially *failed* the exception-process test, whose first version treated
"argument present, `unsafe` still forbidden" as stale. That was wrong: writing the
argument **ahead** of the implementation is how an argument gets reviewed as a
design decision rather than rationalised afterwards. The test was corrected to
permit that state, and `tools/fault_inject_safety_arg.py` now injects only the one
state that is a genuine violation — `unsafe` permitted with nothing written down.

---

### §O-058 — `HOST-011`: a guard that compiles away, and the check that had to be a source check

**What was built.** `crates/qqq-host/src/guard.rs`, wired into all six registered
host functions. 11 unit tests plus one enforcement test; the crate goes from 153
tests to 161.

#### §O-058a — A wrapper, not a `panic::set_hook`, and the difference is the design

The obvious implementation of "convert host panics into traps" is a global panic
hook. It does not work, and the reason is worth stating because it looks like it
should: **a hook intercepts reporting, not unwinding.** It cannot stop a panic,
and it is process-wide — so installing one in `qqq-host` would also swallow
panics in `qqq-serve`, `qqq-run` and `qqq-debug`, converting genuine host bugs
into silence everywhere rather than containing them at one boundary.

`catch_unwind` at the host/guest boundary is the only mechanism that both stops
the unwind and applies exactly where the requirement does. The wrapper is
therefore the design, not an implementation detail.

#### §O-058b — Why this is a security boundary rather than robustness

Every host function is a closure called from *inside* Wasmtime's execution of
guest code. A panic there unwinds through the engine's frames and out into
whatever the host was doing — a request task, in `qqq-serve`. `Cargo.toml` sets
`panic = "abort"` for the release profile, so the third consequence is not a
dropped connection but a **dead process**: one guest finding one panicking host
function takes down every tenant on the host. §7.2's adversary model explicitly
includes hostile guests, which is what makes this a vulnerability rather than a
robustness gap.

A defensive detail that follows: the panic payload must **not** reach the guest,
because it can contain host paths, internals and guest-supplied data. The guest
gets the interface name and nothing else; the message goes to `PanicReport` for
the host log. `the_panic_payload_is_not_forwarded_to_the_guest` pins it with a
path-shaped secret.

#### §O-058c — A new error code, in the `6xxx` host class and deliberately not `3xxx`

`QQQ-6007 HostPanicContained`. The guest did nothing wrong, and the class
carries that judgement: reporting a host defect as a guest trap would send an
operator to inspect the wrong artifact, and would make an attacker's successful
panic read as misbehaving guest code rather than the host bug it is. The same
reasoning produced a separate `TrapLabel::HostPanic` metric label, so a
dashboard can alert on contained panics without conflating them with guest
misbehaviour.

#### §O-058d — The enforcement had to be a source check, because no runtime test can reach the failure

This is the interesting part. The guard is a wrapper, so:

* a host function added **without** it compiles perfectly;
* it passes every test anyone would write, because tests exercise inputs that do
  not panic;
* its defect appears only when a guest finds the panicking path — and then it
  appears as a **dead process**, not a failing test.

So there is no runtime test that can enforce this, and the rule exists precisely
to prevent a failure no test can reach. `every_host_function_is_panic_guarded`
counts `func_wrap(` against `guard::guard(` across the registration files.

**Counting rather than listing names** is the property that matters: a list of
six known functions would go stale the moment somebody registered the seventh
interface — which is exactly when the check is most needed, since new host code
is where new panics live.

**And it reads production code only** — everything before `#[cfg(test)]`. The
first version counted the whole file and failed with *"host_clock.rs registers 6
host functions but only 5 are wrapped"*. The sixth is a `func_wrap` inside the
test module, registering a fake function in a test's own linker to probe how
Wasmtime reports a registration. That is not a host function a guest can reach,
and wrapping it would test the guard rather than the thing under test. Truncating
at the test module keeps the check honest — a new unguarded registration in
*production* code still fails it — while not forcing a wrong change to test code.

#### §O-058e — Proving the check can fail, and getting the injection right the second time

`tools/fault_inject_guard.py` removes one guard, asserts the check goes red with
the right message, and restores the file.

**The first version of the injection proved nothing.** It replaced the guard call
with `let _unguarded = move || {`, which produced a **syntax error** — the runner
reported `INJECTION NOT DETECTED` only because the harness checks for a *compile*
failure separately, and the crate had not compiled at all. It was the harness's
refusal to accept a non-compiling injection that exposed this, and the script now
says so in its own docstring: the injection must produce **valid Rust that is
merely unguarded**, or the check cannot run and nothing is learned.

This is the fourth appearance of the same family of mistake — an instrument that
reports on itself rather than on the system under test: `§M-008` (stale backup),
`§O-048c` (fault-injection script reporting 7 failures on an unchanged file), and
`§O-056e` (stale test binary). All four involve a tool that writes a file back to
a previous state. The lesson is not "be careful with injections" but **assert
that the injected artifact compiled and changed**, which is what this script and
`tools/fault_inject_body.ps1` now both do.

Verified after the fix: the injection is detected with *"registers 5 host
functions but only 4 are wrapped"*, and the file is restored to 5 guards with no
`INJECTED` marker. The injector is wired into CI.

---

#### §O-058f — The fault-injector could never have run in CI, and it failed on the first push

The commit that added `tools/fault_inject_guard.py` went red on CI immediately:

```
FileNotFoundError: [Errno 2] No such file or directory:
'.scratch/host_clock_inject.bak'
```

`.scratch/` is gitignored (`.gitignore` line 52), so it does not exist on a fresh
`actions/checkout`. **The script passed locally and could never have passed in
CI** — verified rather than assumed: `git ls-files` reports 134 tracked files and
not one under `.scratch/`.

That is an environment-dependent defect *inside a check*, which is the worst
place to have one. A check whose result depends on what happens to be on the
machine is not measuring the repository; it is measuring the machine. The whole
point of this harness is to prove the guard check is live, and it was itself
proving nothing outside one developer's working tree.

The backup moved to `tempfile.TemporaryDirectory`, which always exists and cleans
up after itself. Two further changes came from the same incident:

* **The restore is verified, not trusted.** A `finally` covers an exception but
  not a hard kill, and a fault-injection harness that leaves the tree modified on
  failure is worse than no harness — it converts a red check into a corrupted
  working tree. The script re-reads the file after restoring and exits `3` if it
  differs from the original.
* **The compile-failure branch no longer overlaps the detection branch**, and all
  three properties are written into the docstring so the next injector does not
  rediscover them.

Green after the fix, with the new step running on Linux for the first time.

**The pattern, now with five instances.** Every one of `§M-008`, `§O-048c`,
`§O-056e`, `§O-058e` and now `§O-058f` is a *tool that reports on itself rather
than on the system under test*: a stale backup, an injection that did not
compile, a stale test binary, a syntactically invalid injection, and a path that
exists only locally. They cluster because fault-injection and restore tooling is
the only place this project writes a file backward — and that operation is where
an instrument silently stops measuring what it claims to.

**The check that would have caught this one**, and did not exist: run the
injector from a clean checkout before wiring it into CI. The `git ls-files`
comparison above is the cheap version of that, and it is worth doing for any
script that touches paths outside the tracked tree.

---

### §O-057 — Metrics and the pool: the cardinality rule made structural, and a double-count in my own test

**What was built.** `crates/qqq-host/src/metrics.rs` and
`crates/qqq-host/src/pool.rs` — `HOST-019` and `HOST-012`. 36 new tests; the
crate goes from 122 to 153.

#### §O-057a — §10.2 asks for a lint; the type system is a better answer

The proposal states the cardinality discipline plainly and names its enforcement
mechanism:

> **Cardinality discipline:** no metric label may take an unbounded value (no raw
> paths, no user IDs, no full URLs). **Enforced by a lint on metric definitions.**

A lint over metric definitions is hard to write and easy to bypass, because a
label is a `&str` at the call site — the lint would have to reason about what
values flow into it, which is a data-flow analysis dressed up as a lint. The rule
is enforced here *before* that point instead:

* `TrapLabel` is a closed enum whose variants map to fixed `ErrorCode`s. There is
  no constructor from a string, so a formatted guest message cannot become a
  label even by accident.
* `Metrics` has **no** `label(name, value: &str)` method at all. A caller who
  wants a new dimension must add a typed label, which is a visible change in a
  reviewable file rather than a quiet one at a call site.
* A test asserts every label string is lowercase, non-empty and distinct — and
  another asserts every variant has its own counter, because two variants sharing
  an index would silently merge their counts in a way a "traps are recorded" test
  passes straight through.

The threat this closes is concrete: a hostile guest controls much of a trap's
text, so a message-derived label lets one component create a new time series per
request. That is a denial-of-service against whatever scrapes the numbers, and it
is a security bug rather than a metrics-tidiness bug.

#### §O-057b — My own test found a real double-count, in the series a capacity planner would use

`note_created()` incremented `created`, and `note_acquire(_, false)` incremented
it too. So a fresh acquisition counted **twice**, and the
`qqq_instance_created_total` series over-reported by exactly the number of cold
starts — which is the number a capacity planner reads to decide how large a pool
should be.

The failure surfaced as a Prometheus-format test asserting the string
`qqq_instance_created_total 1` against output containing `... 2`. The assertion
looked like a formatting check and was in fact catching an arithmetic defect two
layers down.

**The fix was to split the responsibilities rather than to change the number.**
`note_created` counts an instantiation; `note_acquire` records latency for a
fresh instance and increments counters only for a pool *hit*. An instance is
created once and acquired once per use, and the two are separate events — the old
code conflated them because the call sites happened to be adjacent.

#### §O-057c — Two decisions in the pool that are load-bearing, not stylistic

**The reservation is a compare-exchange loop.** The obvious implementation —
`if in_use < capacity { in_use += 1 }` — is a load followed by a store. Two
threads that both read `in_use == capacity - 1` both decide there is room, and
the pool exceeds its capacity under precisely the contention that makes capacity
matter. `concurrent_acquires_never_exceed_capacity` runs 16 threads × 500
attempts against a capacity of 8 and asserts the observed peak never exceeds 8.
A load-then-store implementation fails it; nothing weaker would have.

**Draining is checked before capacity.** The natural order is to check whether
there is room, then whether the host is going away. Reversed, a host mid-shutdown
with one free slot accepts new work and is killed with the request in flight —
the exact outcome draining exists to prevent, and one whose symptom is a client
timeout rather than a shutdown bug. The test pins both the refusal *and* the
absence of a `retry-after` field, because advising a retry against a host that is
not coming back turns an orderly shutdown into a retry storm that outlives the
process.

**Discard is not a variant of release.** `Pool::discard` and `Pool::release`
return the same `ReleaseOutcome` type, but only `release` returns the slot to the
free list. `a_discarded_instance_is_never_reused` acquires, discards, and asserts
the *next* acquisition reports `pooled == false` — i.e. that the replacement is
fresh. This is §4.4 step 14 and `HOST-010`: a trapped instance's memory may hold
half-written state, and returning it to the pool hands the next request a
contaminated context.

#### §O-057d — `Retry-After` is computed, and the floor matters more than the formula

`HOST-012` requires 503 with `Retry-After` and says nothing about the value. A
constant is wrong in both directions at once: too short and every refused client
retries into the same saturation, keeping the pool at 100 %; too long and clients
idle while capacity is free. The estimate here is the time for one capacity's
worth of work at the caller's observed throughput.

The part worth writing down is the **floor of one second**, not the formula. A
fast-but-saturated host computes a sub-second estimate, and `Retry-After: 0`
means "retry immediately" to every client library — the precise stampede the
header exists to prevent. `retry_after_is_never_zero_and_is_bounded` covers the
fast case (10 000 req/s → 1 s), the ordinary case (10 req/s → 10 s), and the
absurd case (0.1 req/s → clamped to 60 s rather than an hour).

Passing throughput in as an argument rather than measuring it here keeps `Pool`
free of a clock and therefore deterministic in tests — the same reason
`Instance::run_measured` returns a duration instead of logging it.

---

### §O-056 — `HOST-015`/`HOST-016`: the epoch yield, and the call that forbids synchronous entry

**What was built.** The async execution path in `qqq-host`, which is `HOST-015`
(*"Use `*_async` Wasmtime APIs throughout"*) and `HOST-016` (*"Implement
`epoch_deadline_async_yield_and_update` so a guest yield does not stall the
reactor"*). `HOST-016` had been marked `[!]` blocked on `HOST-015` after `§O-051`
found it falsely ticked.

`Instance::create_async` / `Instance::run_async` /
`Instance::run_async_measured` join the existing synchronous trio, and
`ExecutionMode` records which path an instance was built for. Four tests cover
it, including a pair that differ in exactly one variable — the entry point — and
assert **opposite** outcomes on the same spinning guest and the same engine.

#### §O-056a — `epoch_deadline_async_yield_and_update` is not a policy, it is an entry-point restriction

The first implementation installed the yield policy on **every** store, with a
comment asserting it was "a no-op under the synchronous path". That was wrong,
and every synchronous test in the module failed immediately with:

```
store configuration requires that `*_async` functions are used instead
```

Read in Wasmtime's source rather than inferred from the message. `Store::
epoch_deadline_async_yield_and_update` (`runtime/store/async_.rs`) calls
`set_async_required(Asyncness::Yes)`, and `StoreOpaque::validate_sync_call`
(`runtime/store.rs`) is the first thing a synchronous entry point runs:

```rust
pub(crate) fn validate_sync_call(&self) -> Result<()> {
    if self.async_state.async_required {
        bail!("store configuration requires that `*_async` functions are used instead");
    }
}
```

So the call does not merely *take effect* on async entry — **it forbids
synchronous entry outright, starting at instantiation**, because instantiation
is itself a synchronous entry. The consequence for the design is that the two
paths need two constructors and two instantiators (`instantiate` vs
`instantiate_async`), and that `ExecutionMode` documents a fact Wasmtime
enforces rather than a convention this crate maintains.

**This is the third time this session that a comment stated a third-party
behaviour wrongly and only the compiler or a test caught it** (`§O-053b` is the
second). The pattern is consistent: a claim about a dependency's semantics is
written as prose where nothing checks it.

#### §O-056b — The test hung CI twice, and the first fix was still a race

`#[tokio::test]` builds a **current-thread** runtime. A yielding guest returns
`Pending` on the executor it is running on; on a single-threaded runtime there is
no other thread to fire the timer that drives the next epoch tick, so the test
did not fail — it **hung the entire suite**, twice, for ten minutes each, leaving
orphaned `qqq_host-*.exe` processes that then held the test binary and produced a
*second*, unrelated failure (`LNK1104: cannot open file`).

Diagnosed by running the tests `--test-threads=1` and watching which name was
last printed before silence. Reading the test body and reasoning about it had
already produced two wrong conclusions (fuel budget, tick interval), both of
which were "fixed" without effect.

Adding `flavor = "multi_thread"` fixed it **locally and not in CI**. The test
still proved yielding by *absence of completion* — start an infinite guest, bump
the epoch, assert it has not returned inside a 60 ms window — which is a
wall-clock race. On a loaded two-core CI runner the ticker task never got a
thread, the epoch never fired, and `cargo test` sat for over ten minutes on both
macOS and Ubuntu with no output. Two jobs, no logs, no failure message: the worst
diagnostic state a check can be in.

**The structural fix was to remove the race, not to widen the timeout.** The test
now asserts on the *terminal code* instead of on elapsed time:

| Entry | Terminal code | Why |
|---|---|---|
| async (`create_async` + `run_async`) | `QQQ-3002 FuelExhausted` | it yielded through 25 epoch expiries and ran until its fuel ran out |
| sync (`create` + `run`) | `QQQ-3003 EpochDeadlineExceeded` | it trapped at the second expiry |

The ticker also moved from a Tokio task to a **dedicated OS thread**, so it makes
progress even when the guest saturates the executor. That is the deeper finding,
and it is a constraint on `qqq-serve`: **a reactor that cannot spare a thread for
the ticker cannot use this yield at all.** The test that could only pass on an
idle machine was telling the truth about the deployment requirement.

The assertion is now a *positive* statement ("it ran out of fuel") rather than a
*negative* one ("it had not returned yet"), so it cannot pass because a timer
failed to fire.

#### §O-056c — Five test failures that were the test's arithmetic, not the code

The yield test failed five times before passing, and **every failure was in the
test**:

| Attempt | Construction | What actually happened |
|---|---|---|
| 1 | 10 M fuel, 20 ms tick | `QQQ-3002 FuelExhausted` — the default budget burns in ~2 ms |
| 2 | 100 G fuel, 5 ms tick | still `FuelExhausted` |
| 3 | 2 T fuel, 1 ms tick | **hung** — 2 T means minutes, not milliseconds |
| 4 | 200 M fuel, current-thread runtime | **deadlocked** — no thread to fire the ticker |
| 5 | 200 M, multi-thread, OS-thread ticker, assert on code | **passed in 0.05 s** |

The sync control had the same defect in the other direction: with the default
fuel it reported `QQQ-3002`, and only after raising the budget did it report
`QQQ-3003` — the epoch trap it was supposed to observe. **A control that passes
for the wrong reason is worse than no control**, because it certifies the wrong
mechanism.

The numbers that finally made this tractable were **measured, not guessed**, with
a temporary example that spun the same guest twice under a 200 M budget:

| Entry | Elapsed | Ticks | Terminal code | Fuel/ms |
|---|---|---|---|---|
| sync | 2.1 ms | 2 | `EpochDeadlineExceeded` | ~100 M |
| async | 44.8 ms | 25 | `FuelExhausted` | ~4.5 M |

The async guest runs **22× slower per unit of fuel** because it spends its time
yielding — which is the yield working, and also the number that makes a 200 M
budget the right one. Three of the four failed attempts would have been correct
on the first try had the rate been measured before the budget was chosen.

One further wrong assertion, worth recording because it is the `§O-051` shape:
the sync test searched the trap's *text* for "epoch" or "interrupt". Wasmtime's
message for an epoch preemption is *"wasm trap: interrupt"*, which contains
neither — `trap.rs` already maps it to `ErrorCode::EpochDeadlineExceeded`, has
its own test for that mapping, and the assertion belonged on the code all along.

#### §O-056d — The livelock guard, moved from a test to the compiler

A `delta` of `0` would extend the epoch deadline by nothing, so a guest would
yield forever without progressing — a livelock presenting as a hung guest with
no trap to explain it. The first version guarded this with
`assert!(EPOCH_YIELD_TICKS > 0)` in a test. Clippy's `assertions_on_constants`
rejected it, correctly: an assertion over a `const` is a constant expression
that either always passes or never compiles, so it carries no information
(`§M-006`).

The rule is now a `const _: () = assert!(...)` in `lib.rs`, evaluated at compile
time. **Verified by injection**: setting the constant to `0` fails the build
with `error[E0080]: evaluation panicked: EPOCH_YIELD_TICKS must be at least 1`,
and restoring it compiles. The test that remains asserts only the *pinned value*
(`== 1`), so retuning the constant is a deliberate edit with a failing test
rather than a silent change.

#### §O-056e — A stale test binary made a correct tree look broken

After fault-injecting the yield policy away and restoring it, the async test kept
failing — and the failure was **not** in the restored code. `cargo test` reused a
test binary built from the injected source, because the restore wrote the file
back at the same size and a timestamp cargo did not treat as newer. The failure
message was identical to the injected one, which is what made it convincing.

It also produced a wrong diagnosis: the rerun failed in **0.01 s**, and a 200 M
async run takes ~45 ms. That discrepancy — too fast by three orders of magnitude
— is the tell, and checking it is faster than reading the code.

Third appearance of this hazard in the project: `§M-008` recorded a stale-backup
restore reintroducing a defect, and `§O-048c` recorded a fault-injection script
reporting seven failures against a file byte-identical to its backup for the same
reason. All three involve fault injection or a backup restore — the operations
that write a file back to a previous state. **Rule: after restoring from a
backup, force provenance to change** (`touch` the file, or `cargo clean -p
<crate>`). `tools/fault_inject_body.ps1` already documents this; the same care
was not taken by hand.

#### §O-056f — Fault injection proves the two tests measure the yield

With the yield policy removed (`if false && context ==
ExecutionContext::Async`), the suite reports:

```
an_epoch_expiry_traps_on_the_synchronous_path ... ok
an_epoch_expiry_yields_on_the_async_path ... FAILED
  Got EpochDeadlineExceeded: QQQ-3003: the guest exceeded its wall-clock deadline
```

The **control stays green and the test under test goes red**, which is the
strongest form this pair can take: the failure names the exact mechanism, and the
control proves the epoch machinery was still working when the async assertion
failed. Restoring the policy turns both green. The claim "the epoch yield is
implemented" is therefore evidence, not assertion.

---

### §O-054 — `cargo deny` was failing two ways at once, and one was hiding the other

**What was found.** The workspace was green on `cargo check`, `cargo clippy -D
warnings` and every test, and CI's supply-chain job was nevertheless **red** —
for two independent reasons, stacked so that only the first was visible.

**Failure one: `rustls-pemfile` is unmaintained (`RUSTSEC-2025-0134`).** It was a
*direct* dependency of `qqq-serve`, pulled in by the TLS work. `deny.toml` sets
`unmaintained = "workspace"` precisely so that an unmaintained crate we depend on
*directly* fails while an unmaintained *transitive* one does not, so the advisory
was correct and not a false positive. The repository was archived in August 2025
and the advisory directs users to the PEM parsing that now lives in
`rustls-pki-types`, of which the old crate was already a thin wrapper.

**The fix was to remove the dependency, not to ignore the advisory.** An ignored
advisory on a direct dependency is a decision to keep something nobody
maintains, and an `ignore = [...]` entry has to be re-affirmed silently forever;
`deny.toml` states that policy and this is the first case that tested it.
`CertificateDer` and `PrivateKeyDer` both implement
`rustls_pki_types::pem::PemObject`, so `CertificateDer::pem_slice_iter` replaces
`rustls_pemfile::certs` and `PrivateKeyDer::from_pem_slice` replaces
`rustls_pemfile::private_key`. Nothing else in the workspace used the crate, and
`cargo machete` confirms it.

**Failure two: `ISC` was missing from the licence allowlist.** It is the licence
of `untrusted`, reached via `ring` → `rcgen` and via `rustls-webpki`, and it is
permissive, OSI-approved and FSF-Free/Libre. It was **not** in `[licenses].allow`
— while the comment block twenty lines above the list *named it as present*:

> `#   Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unlicense,`

So the prose and the list had drifted, and the drift was invisible for the
structural reason below.

**Why the second failure was hidden, which is the actual finding.** `cargo deny
check` evaluates `advisories` first and the run exits non-zero on the errors it
finds there; with `advisories` failing, the licence failure was masked behind it.
A reader sees "advisories FAILED", fixes the advisory, and stops. The licence
failure surfaced only when the advisory was repaired and the command was re-run.

This is the same shape as `§M-006` and `§O-051`: **a check that cannot run
carries exactly as much information as a check that passes.** A red check that
fails for reason 1 tells you nothing about reason 2, and there was no signal
distinguishing "one problem" from "two problems stacked".

**Removal side-effects, all improvements.** Deleting the crate also deleted two
`BufReader` layers that existed only to satisfy `rustls_pemfile`'s `Read` bound,
and with them the reader-lifetime dance in `tests/tls.rs` whose comment explained
that `certs` borrows the reader. The `PemObject` API is slice-based, so the items
are `'static` and come straight out of the iterator. The stale doc comments that
still named `rustls_pemfile` were corrected in the same pass.

**Verified, not assumed.** `cargo deny check` now reports
`advisories ok, bans ok, licenses ok, sources ok`. The TLS tests were re-run
after the swap: 21 end-to-end handshake tests and 35 unit tests pass, so the
`PemObject` path parses the same certificates, the empty-chain refusal still
fires, and the "a PEM block is not a certificate" check — which rejects `AAAA` as
a three-byte certificate — is unchanged in behaviour and now cites
`pem_slice_iter` rather than the removed crate.

**Recorded so it is not relearned.** When a CI check goes red, fix it and run it
again before believing it is green, and treat "the first failing section" as a
statement about report order rather than about how many things are wrong.

---

### §O-055 — The tree was green locally and red in CI, and nothing local said so

**What was found.** Every local gate passed — `cargo check`, `cargo clippy
--workspace --all-targets -- -D warnings`, `cargo test --workspace`,
`tools/check_xrefs.py`, `tools/self_test_xrefs.py` (9/9), `tools/check_topology.py`
— while `cargo deny check` was failing on two counts (`§O-054`) and the last
edit to `tls.rs` had left three `unused` warnings behind.

**The gap that made this possible.** `cargo deny` and `cargo machete` are CI
steps and were not part of any local script. The working rule "verify every claim
with real commands" was being satisfied against the commands that were
*remembered*, and the supply-chain commands were not among them. A check that is
only ever run by CI is a check the author never sees fail.

**Fix, and the standing rule.** `tools/audit_requirements.py` is the single
command that runs the whole gate set, and its last requirement is "no uncommitted
changes". It reported **31/32**, failing only on the dirty tree — which is what
made the state visible at all. The rule that follows: **before every commit, run
`python tools/audit_requirements.py`, not a subset of it.** The audit exists to
answer "is this actually done", and running a hand-picked subset of it answers a
different, easier question.

**Correction to a claim in this document.** `§O-053` describes the TLS work as
complete and says nothing about the dependency it left behind. The TLS *feature*
was complete; the *tree* was not healthy, and the two are different claims. This
entry is the correction.

---

## 9. CHANGE LOG

| Date | Change | Author |
|---|---|---|
| 2026-09-19 | Document opened. Initial decisions `§D-001` … `§D-009`, observations `§O-001` … `§O-008`, mistakes `§M-001` … `§M-006`, corrections `§C-001` … `§C-006`, stubs `§S-001` … `§S-005`, questions `§Q-001` … `§Q-012`. | Architect |
| 2026-09-19 | Verification round. All four load-bearing architecture claims verified against Wasmtime 48.0.2 (`§O-006`); four WAT/ABI findings recorded (`§O-007`); two Wasmtime API differences recorded (`§O-008`); validator self-test built and **7/7 fault injections detected** (`§M-006`), which exposed and fixed two real defects: Appendix A/Observations correction drift, and Proposal decision citations that were write-only. `check [8]`, `[9]`, `[10]`, `[11]` added to the validator; self-test wired into CI. | Architect |
| 2026-09-19 | `qqq-pkg` opened (`§O-032`). `semver.rs` (`Requirement`/`Op`, caret-under-1.0 rule), `lock.rs` (`Lockfile`, `LockDiff::compute`, NUL-separated covering hash verified on read), `store.rs` (`Digest`, two-level fan-out `StoreLayout`, verified reads). The pre-release gap in `qqq-core::Version` recorded as `§O-032a` with the test that pins it; four tests written against a non-existent `Version.pre` field deleted. Three clippy findings fixed, two of which were real defects (`§O-032d`). | Architect |
| 2026-09-19 | `[dependencies]` and `[dev-dependencies]` were **silently ignored** by `Manifest`: the struct did not model them and is not `deny_unknown_fields` at the top level, so a manifest declaring a dependency parsed successfully with the table discarded (`qqqai caps` printed "no capabilities granted" and exited 0). Both tables are now modelled, validated, and named in errors (`§O-033`). Writing the test found the *same* defect again in new code — `[dev-dependencies]` needs an explicit serde `rename`, and the hyphenated key parsed as empty (`§O-033b`). Requirement validation is split by what each crate can honestly decide, because `qqq-pkg` depends on `qqq-cap` and the real parser is therefore unreachable from the manifest layer (`§O-033c`). | Architect |
| 2026-09-19 | `CLI-005` implemented: `qqqai add` and `qqqai remove` (`qqq-run::deps`), with `--dev`, `--exact`, `--feature`, `--registry`, `name@version` and `--json`. The manifest is edited as **text** so comments and formatting survive, written atomically via temp-file + rename, and re-parsed before publishing (`§O-034b`, §O-034c). The first end-to-end run refuted the version model: `1.2` — the spelling Proposal §5.3 itself writes — was rejected because `Version` requires three components, so a partial-version rule with zero-fill now widens instead of refusing (`§O-034a`). | Architect |
| 2026-09-19 | `CLI-006` implemented: `qqqai install` (`qqq-run::install`), with `--locked`, `--frozen`, `--offline`, `--force` and `--dry-run`. `--locked`/`--frozen`/`--offline` were three booleans until clippy's `struct_excessive_bools` showed they are **ordered by strictness**, so they are now the `LockMode` enum with `Update < Offline < Locked < Frozen`; the same lint on the output struct showed `locked` and `offline` were derivable from `mode` and they were deleted (`§O-035b`). Reports the §5.4 capability diff with `escalation` as a first-class field. Fails with `QQQ-5001` rather than writing a lockfile that promises bytes nobody fetched, because a lockfile that lies is discovered by a later command with no trace of the cause (`§O-035c`). | Architect |

| 2026-09-19 | **Four defects found by *using* a scaffolded project**, all in the surface and all invisible to 256 passing unit tests (`§O-036`). `qqqai caps` printed a count and not one capability name; `inspect`, `why` and `doctor` likewise withheld their payload — because in human format `summary()` **is** the entire output and the tests asserted on struct fields (`§O-036a`). `qqqai doctor` **exited `0` when a check failed**, so CI treated a broken environment as healthy; now exits 69 (`§O-036b`). The requirement parser **refused `>=1.0, <2.0`** — the syntax its own remediation text recommends — because the design note conflated a comma *conjunction* with a `\|\|` *disjunction*; comma lists are now supported as a `Vec<Clause>` (`§O-036c`). Structural fix: `crates/qqq-run/tests/cli.rs`, 24 tests that spawn the real binary and assert on stdout, stderr and exit codes rather than library internals (`§O-036d`). | Architect |
| 2026-09-19 | `§M-007` repeated twice in the same session: an `edit` anchored on a section heading deleted the heading, in `§O-035` and again in `§O-036`. The rule is now stated operationally — when appending a section, never anchor on the boundary the new content sits before. | Architect |

| 2026-09-19 | `CLI-007` implemented: `qqqai update` (`qqq-run::update`), with `--latest` and `--dry-run`. The default strategy honours the manifest's requirement and `--latest` crosses it, because defaulting to the newest version would resolve `^1.2.3` to `2.0.0` while the user believes they asked for a routine refresh (`§O-037a`). `VersionSource` is the seam the registry will plug into, so every decision branch — including ones needing a newer version — is exercised today rather than first tested when `PKG-006` lands (`§O-037c`). A kept package always carries a reason, since a no-op update that explains nothing is indistinguishable from a broken one (`§O-037d`). `--latest` with `exact = true` is refused rather than resolved by precedence (`§O-037e`). | Architect |

| 2026-09-19 | **`qqqai inspect <artifact>` implemented**, and two defects fixed on the way (`§O-038`). The command **ignored its path argument** and reported the manifest's capabilities regardless, so inspecting a nonexistent file produced a confident report about `qqq.toml` — on the surface that exists to make a grant auditable before execution, a plausible wrong answer is worse than none (`§O-038a`). With inspection wired up, an artifact importing `qqq:clock/wall-clock` was reported as requiring `clock.monotonic`, because the registry maps capability → interface at *package* level and several packages hold several interfaces; a precise `interface_path_for` table now answers at interface level (`§O-038b`). One interface can imply several capabilities, so the mapping returns the **strongest** — understating authority is the one failure an audit surface must not have — and a positive-control test asserts the ranking agrees with `classify_posture` for every capability (`§O-038c`). Five fixture-building tests initially **skipped silently** because of an invented `--features` flag; skips are now loud (`§O-038d`). | Architect |

| 2026-09-19 | **`qqqai inspect --diff` implemented** (`CLI-015` complete): the authority delta between two artifacts, which is §5.4's central supply-chain question. A gain **exits non-zero** so the flag is a CI gate without parsing output, while a loss reports and succeeds — failing on a security *improvement* is a check people learn to bypass (`§O-039a`). A gain of a **covert channel** escalates even when the posture band does not move, because `clock.wall` and `crypto.random` are `Ambient` and §10.5 singles them out as channels the audit stream cannot see (`§O-039b`). The comparison is over capabilities rather than interfaces, so an artifact that swaps one interface for another with the same authority reports no change (`§O-039c`). | Architect |

| 2026-09-19 | **P0 (Foundation) was understating the work by 26 items**: it reported 0 of 101 done while the workspace held 910 tests, a three-OS CI matrix and all three canonical documents (`§O-040a`). `tools/audit_p0.py` now maps each P0 item to a concrete artefact and reports what exists — a report, not a gate, because failing CI on a low count pressures ticking over building. **`check [10b]` added** to `check_xrefs.py`, catching a decision defined but never cited; it immediately found three dangling decisions (`§D-002`, `§D-008`, `§D-009`), each now cited. **`cargo deny check` had been failing on every run** because no `deny.toml` existed, and `continue-on-error` hid it; `deny.toml` is now derived from the real dependency graph and both escape hatches are removed, which also surfaced three genuinely unused dependencies (`§O-040c`). Six crates declared a README that did not exist; all five missing READMEs written, with every API claim verified against source after four fluent-but-wrong ones were caught (`§O-040d`). `.scratch/witprobe` deleted and its four assertions ported to `crates/qqq-host/tests/engine.rs` with controls. | Architect |
| 2026-09-19 | **The objective audit passes: 30/30**, after three wrong diagnoses of one symptom. `git status` listed three documents modified while `git diff` showed nothing; each diagnosis was written into a comment as fact and each was wrong. What settled it was measuring the **committed blob** (`git cat-file -p HEAD:…` → 0 CRLF, 1,549 LF) rather than the working tree: the checkout drifts, the content is correct. Both `normalize_eol.py` and `audit_requirements.py` now test committed content, removing a check that failed on a condition the repository does not have (`§O-041a`). The audit label `"passes (7/7)"` was a hardcoded literal that went stale when an eighth injection was added; labels are now read from the run (`§O-041b`). `check [12]` added after the Observations heading was deleted for the **fourth** time — and building it caught a real defect in the check itself, which used a substring search and would have passed on a document that lost its section (`§M-007`). | Architect |

| 2026-09-19 | **`CLI-012` implemented: `qqqai test`** (`qqq-run::test_runner`). Discovery runs **each test binary directly**, which makes a test's source file exact rather than inferred — after two wrong attempts, the second of which produced plausible paths that were wrong (`§O-042a`). `--trials N`, the first architecture-enabled feature from §6.7, **reported a perfectly deterministic suite as nondeterministic** because it compared raw output including libtest's `finished in 0.01s`; output is now normalised, with a positive control asserting a real difference is still detected (`§O-042b`). I diagnosed that as test flakiness twice before reading the failure's stdout, which had the answer in it (`§O-042c`). `check [12]` caught the section-heading deletion this round, which is what it was built for. | Architect |

| 2026-09-19 | The `--trials` fix (`§O-042b`) was **correct and insufficient**: CI failed again for two further reasons — `--verbose` emitting `Fresh`/`Finished` lines on a warm build, and `CARGO_TERM_COLOR=always` wrapping verbs in SGR escapes. **Both were named in one line of output by the trial-divergence diagnostic added in the same change**, the instrument that prints *what* differed rather than only that something did (`§O-042d`). Rules are now shape-based rather than an enumerated prefix list, since an enumerated list is the same mistake as enumerating a toolchain's error variants. Building it surfaced three further real defects and one wrong test of mine. **Green on CI** — the only proof that counts for a defect that appears nowhere else. | Architect |

| 2026-09-19 | **`qqqai run` enforced correctly and advised incorrectly.** The refusal of an ungranted import is right; the remediation named `clock.monotonic` for a component importing `qqq:clock/wall-clock` — the other half of the same package, so following the advice would leave the component still failing (`§O-043a`). This was the **same defect** fixed in `inspect` last session, missed here because `run` shows it in a remediation line rather than a report: a reader already looking at an error is likelier to follow a wrong instruction than to believe a wrong fact (`§O-043b`). The structural fix was **deleting the second mapping**, not updating the caller — a shared helper fixed at one call site leaves the others wrong, and they are harder to find because the codebase feels corrected. Also: a bare positional was appended to the *component's* arguments, so `qqqai run ./x.wasm` ran the built component and reported success (`§O-043c`). Five integration tests now cover the enforcement path, which had none. `check [12]` caught the section-heading deletion again. | Architect |

| 2026-09-19 | **The crate topology had two violations of its own stated invariant** — "no crate may depend on a crate above it in this list". The table listed `qqq-host` above `qqq-abi` and `qqq-run` above `qqq-pkg`; both are impossible, because the linker is *built from* the interface registry and the CLI resolves dependencies *via* the package manager. **The document was wrong, not the code** — an invariant stated in bold, false of the table that stated it, so a reader who checked would have concluded the architecture was broken (`§O-044`). `tools/check_topology.py` now enforces it from `cargo metadata`, and asserts `qqq-core` has no I/O **with a control proving the rule is wired** (`§O-044a`). Both rules were fault-injected before being wired into CI (`§O-044b`), and both joined the objective audit, which now reports **32** requirements. `check [12]` caught the section-heading deletion a third time. | Architect |

| 2026-09-19 | **The audit reported a missing tool as a validation failure**, turning CI red on the commit that added the topology check. `check_wit.py` needs `wasm-tools`, which the document-checking job does not install; the audit treated its absence as a failed requirement. The two cases are now distinguished — "the tool ran and the interfaces are broken" is a defect, "the tool is not here" is not — because reporting the second as PASS would hide the first and reporting it as FAIL makes the audit depend on what happens to be installed. `check_wit.py` itself is unchanged and correct: absence is failure *for its own job*, and the audit is a different caller with a different question. | Architect |

| 2026-09-19 | **`qqq-debug` implemented** — real DWARF source-map extraction from a built component, with 24 unit tests and 4 end-to-end tests that compile a project and map real offsets. Building it exposed a **wrong tick**: `HOST-009` claimed DWARF mapping while `WasmFrame.file`/`line` were never populated outside tests and `Instance::run` discarded Wasmtime's backtrace into a formatted string; the item is now `Partial` with the join named (`§O-045a`). The DWARF was **one level down**, inside the core module a component wraps, so the first parser reported "no DWARF" for a 265 KB artifact full of it — a right answer about the wrong table (`§O-045b`). And the **scaffold's own debug info covered only the standard library**, because `lto = true` with no exported symbol eliminates the crate; `debug = true` added, with a comment saying it is necessary and *not* sufficient (`§O-045c`). `check [12]` caught the heading deletion a fourth time. | Architect |

| 2026-09-19 | **The trap backtrace join is done** — `HOST-009`'s remaining half. `Instance::trap_from` now takes the `wasmtime::Error` rather than a formatted string, so a real trap carries frames; the name comes from the module's name section and the location from DWARF, deliberately split so a frame is named even without `debug = true`. `qqqai run` sets `debug_info = true`, since a CLI exists to help a developer read a failure (`§O-046a`). **Two of the three new assertions could not fail** and were caught only by injecting the defect: one was satisfied by the trap's own detail string, the other named a phrase the codebase never emits. Both were written *while fixing* `§O-045a`'s "tests cannot refute their own mental model" — the lesson did not transfer by being written down, it transferred by breaking the fix and watching which tests stayed green (`§O-046b`). | Architect |

| 2026-09-19 | **`SRV-001` complete — the accept loop is joined, and finishing it found the defect the WIP had introduced (`§O-047`).** The half-built work left three compile errors: a missing `Failure::BadRequest` arm in `as_str`, and `parse_error_response` referenced but never written. Completing the taxonomy surfaced a **real body-drain desync**: `read_head` preserved the bytes after the head terminator (`buf.drain(..end)`) while `drain_body` read the body from the *socket* — so a client whose head and body arrived in one segment had its body discarded and the connection advanced past it. `§O-047a`. **The test written for that defect could not fail for it**: with `buf.clear()` reinstated, all nine socket tests still passed, because the kernel delivered head and body in separate reads so the body never entered the buffer. `§O-047b` (the `§O-046b` trap, fifth occurrence). A new pipelining test now reaches the body-less drain branch with 59 bytes buffered and **fails on injection, passes without** — `§O-047c`. Writing it produced two wrong diagnoses of my own, both recorded: a `connection: close` on the second pipelined request fails against a *correct* server because the half-close races the read, and `read_response` decodes one buffer so it returns **both** responses at once. Tracing `write_all` (96 then 115 bytes) is what distinguished server correctness from test assumption. `§O-047d`. | Architect |

| 2026-09-19 | **`SRV-004` and `SRV-005` implemented — `qqq-serve::body`, a pull-based body decoder for `Content-Length` and chunked bodies, 22 unit tests and 12 socket tests (`§O-048`).** The design is forced by §6.4: the cap must be a cap and not a buffer, or a client that sends 2 GiB to a 2 MiB limit has already made the host allocate it; and backpressure is not expressible over a buffer, because a decoder that pre-buffers has read from the socket regardless of what the handler wanted. **The server had been enforcing the cap one step too late**: the handler was dispatched *before* the body was drained, so a 3 MiB chunked body against a 2 MiB cap was answered `**200 OK**` — the guest ran, the response was written, and only then did the drain find the body too large (`§O-048a`). The body is now consumed before dispatch, the answer is `QQQ-6006` (new code — a *client* fault that must not be a 5xx), and the post-response drain was deleted so one body has one consumer. Verified by putting the ordering defect back: `a_chunked_body_past_the_cap_is_cut_off` **failed** while the other 11 socket and all 22 body tests stayed green — and, conversely, deleting the drain *entirely* made that test **pass** while two others failed, which is why "the suite is green" is worth nothing until you know which failures a test can see. The chunked-body connection close that `drain_body` had been doing for want of a decoder is now gone: `§O-048b`. `tools/fault_inject_body.ps1` breaks six invariants and **all six were detected**, but the script itself lied three times before it worked: a `\r\n` match against an LF-only file made every injection no-op while reporting success; `-NoNewline` concatenated lines; and the final run reported **7 failures on a file byte-identical to its backup** because cargo ran a stale test binary. All three fixed, and the third — a check failing outside the system under test — is recorded as the most expensive kind of false alarm (`§O-048c`). | Architect |

| 2026-09-19 | **The delegated HTTP/2 work was salvaged, and five failing tests were wrong in all five cases (`§O-049`).** A subagent produced the frame layer (70 KB, 35 tests) and HPACK (108 KB, 71 tests) then ran out of context before `flow.rs`, `stream.rs` and `h2/conn.rs`, so `mod.rs` declared modules that did not exist, the whole module was excluded from the tree, and **~234 KB of code had never been compiled by CI** — its 106 tests had never run. Salvaged rather than reverted: the code is good, the three compile errors were mechanical (a `&Option<&str>` deref, a test helper returning `Frame<'_>` that borrowed its own buffer, two tests referencing a removed `parsed`). Then five tests failed and **the code was right every time** — RFC 7541 C.6.2/C.6.3 are the *second and third* blocks of a sequence and cannot be decoded on a fresh table (the `index 65 names no entry` error was correct behaviour, and the first instinct — an HPACK indexing bug — was wrong); `cache-control: no-cache` is 53 bytes and not 54, caught only because the test had four cases and three agreed; a Huffman "compresses" assertion over all 256 bytes is simply false, since high bytes run to 30 bits and 256 bytes expand to 583; and PING's wrong-length case used stream id 1, which is itself illegal, so the parser correctly reported the earlier error. Adjusting the implementation to silence those reds would have broken working code in four places; the tiebreaker was the RFC's own vectors as external ground truth. Verified by injection: moving the dynamic-table lookup by one fails 10 tests including both chained C.6 vectors, so the corrections are evidence and not tests shaped to fit the code (`§O-049b`). | Architect |

| 2026-09-19 | **The narrowing invariant was verified by injection rather than believed (`§O-050`).** §D-008 / `CAP-010` says *no configuration layer may ever widen a grant*, and §8.8 singles it out as the one guarantee whose failure would remove the product's reason to exist. It is enforced **structurally**: `GrantSet::narrow` is the only combinator, there is no union or widen, and a search for `capabilities.insert`/`.extend` across `qqq-cap` finds nothing outside that one function — so widening is prevented by the absence of a code path rather than by a check that could be forgotten. `no_overlay_can_ever_widen` starts from the **empty** set, builds a hostile overlay holding every capability, and tries all six (layer × mode) combinations; injecting a union into `narrow` fails **13 tests**, that one among them. Recorded because a safety invariant asserted only in prose reads as true and therefore never gets tested. | Architect |

| 2026-09-19 | **The first checklist item found ticked that was not true (`§O-051`).** `HOST-016` — `epoch_deadline_async_yield_and_update` — was marked done with a note describing *host-function registration*, which is unrelated. Verified in source: `epoch_interruption(true)` and `set_epoch_deadline(1)` exist (an expiry **traps**), but no `epoch_deadline_async_yield_and_update`, no `epoch_deadline_callback` and no `epoch_deadline_trap` exist anywhere, so there is no yield mechanism at all. `HOST-015` is likewise not done: `Instance::run` is **synchronous** (`TypedFunc::call`) and the crate contains no `*_async` API, against Proposal §6.1 line 944 and §4.2. `HOST-016` is now `[!]` blocked on `HOST-015`. **The mis-attribution was already known** — `linker.rs`'s `§O-020d` comment says the `HOST-016` citation was wrong — but the correction was made in the code and never propagated to the checklist, so the register a reader counts kept claiming work nobody had done. Eight-one items reviewed; one false tick found. | Architect |

| 2026-09-19 | **Three agents in one working tree deleted each other's files (`§M-009`).** HTTP/2 and TLS were delegated in parallel while the main session kept working. Both wrote *new* files, so there was no merge conflict — but both had to edit `lib.rs` to register their module, and that is a single shared file. The h2 agent, blocked by the TLS file failing to compile, moved `tls.rs` to `.scratch/` and commented out `pub mod tls;`, twice; the TLS agent found its 73 KB source deleted mid-verification. Both agents did something reasonable given what each could see; the coordination bug was mine, because I assumed new-file work is inherently conflict-free. The h2 agent was interrupted (`flow.rs` and `stream.rs` written, `h2/conn.rs` not, and a stray brace left by the interruption); its work is preserved. **Rule:** a shared working tree is a mutually exclusive resource for any task that edits a *registration* file — module roots, `Cargo.toml`, `lib.rs`, the checklist. One long-running delegation at a time. | Architect |

| 2026-09-19 | **`SRV-007` and `SRV-008` implemented: `qqq-serve::tls` (`§O-053`).** An explicit cipher policy — an unspecified algorithm is *refused*, not defaulted — TLS 1.3 preferred with 1.2 permitted, ALPN for `h2`/`http/1.1`, certificate sources (`Files`, `Platform`, and `Acme` refused by name), `ClientAuth` in `None`/`Required`/`Optional`, and `PeerIdentity` from a verified client certificate; 35 unit tests and 21 real-handshake tests. **A real defect was found by the end-to-end mTLS test and by nothing else**: `common_name_of` searched the `Certificate`'s children for tag `[3]`, believing `[3]` wrapped `TBSCertificate` — but `[3]` is the *extensions* field inside TBS, and a real certificate's children are `0x30, 0x30, 0x03`. The search returned `None` for **every** certificate, so an mTLS access log read `(subject has no common name)` for every peer. **The unit tests could not catch it because they encoded the same misunderstanding**: the fixtures wrapped their `Name` in a `[3]` no real certificate produces, and two artifacts sharing a wrong assumption cannot correct each other (`§O-053a`). Three further fixture comments asserted third-party behaviour wrongly — `generate_simple_self_signed` does not derive the subject CN from the SAN; the handshake dialled `localhost` while the certificate was for `qqq-test-server`, turning nine failures into one uninformative `left: None`; and disjoint ALPN lists *refuse* the handshake rather than completing without a protocol (`§O-053b`). Every claim about `rcgen` and `rustls` was a prose comment nobody could check — the project verified its own code and its Proposal, but not its dependencies or its fixtures. Verified by injection: reinstating the `0xA3` search fails the new real-certificate test. | Architect |

| 2026-09-19 | **`cargo deny` was red two ways at once and one hid the other (`§O-054`, `§O-055`).** `cargo check`, `clippy -D warnings` and every test were green while the supply-chain job failed: `rustls-pemfile` is unmaintained (`RUSTSEC-2025-0134`) and was a **direct** dependency of `qqq-serve`, which `deny.toml`'s `unmaintained = "workspace"` policy is precisely shaped to catch. The fix was to **remove the dependency rather than ignore the advisory** — `PemObject` in `rustls-pki-types` is the same code the old crate wrapped, so `pem_slice_iter`/`from_pem_slice` replaced it, and with it went two `BufReader` layers that existed only for `rustls_pemfile`'s `Read` bound. Repairing that exposed a **second, masked failure**: `ISC` was absent from `[licenses].allow` while the comment twenty lines above the list *named it as present*, so prose and list had drifted; `cargo deny` evaluates `advisories` first and exits non-zero on it, so the licence failure never printed. **A red check that fails for reason 1 tells you nothing about reason 2** — the same shape as `§M-006` and `§O-051`. `cargo deny check` now reports `advisories ok, bans ok, licenses ok, sources ok`; the 21 handshake and 35 unit TLS tests pass unchanged. The deeper lesson is `§O-055`: `cargo deny` and `cargo machete` are CI-only steps with no local script, so the rule "verify with real commands" was being satisfied against the commands that were *remembered*. `tools/audit_requirements.py` is the full gate, its last requirement is a clean tree, and it reported **31/32** — which is what made the state visible. **Before every commit, run the audit, not a subset of it.** | Architect |

*End of `QQQ-Observations-and-Memories.md`.*