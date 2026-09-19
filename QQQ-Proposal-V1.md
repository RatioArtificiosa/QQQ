# QQQ — Technical Proposal v1.0

> **The AI-native, multi-language runtime that replaces Node.js and Bun.**
> Rust host · WebAssembly Component Model · capability-secure by default · deterministic by construction.

| Field | Value |
|---|---|
| **Document** | QQQ-Proposal-V1.md |
| **Version** | 1.0.0 |
| **Status** | Draft for founder review |
| **Date** | 2026-09-19 |
| **Product name** | **QQQ** |
| **CLI binary** | `qqqai` |
| **crate / npm package** | `qqqai` |
| **Domain** | `qqq.codes` |
| **Repository** | https://github.com/RatioArtificiosa/QQQ |
| **Companion documents** | [`QQQ-Checklist-V1.md`](./QQQ-Checklist-V1.md) · [`QQQ-Observations-and-Memories.md`](./QQQ-Observations-and-Memories.md) |

**How to read this document.** Every section ends with a **→ Checklist** line listing the exact checklist item IDs that implement it. Every checklist item names the section anchor it derives from. Anchors are stable and never renumbered once published; see [§0.5 Identifier and anchor discipline](#05-identifier-and-anchor-discipline).

---

## Table of Contents

- [§0 — Orientation](#0--orientation)
  - [§0.1 Executive summary](#01-executive-summary)
  - [§0.2 The thesis](#02-the-thesis)
  - [§0.3 Document map](#03-document-map)
  - [§0.4 How to read the cross-references](#04-how-to-read-the-cross-references)
  - [§0.5 Identifier and anchor discipline](#05-identifier-and-anchor-discipline)
  - [§0.6 Glossary](#06-glossary)
- [§1 — Why QQQ Exists](#1--why-qqq-exists)
- [§2 — The Eight Non-Negotiables, Operationalized](#2--the-eight-non-negotiables-operationalized)
- [§3 — Market, Positioning and Honest Competitive Analysis](#3--market-positioning-and-honest-competitive-analysis)
- [§4 — Architecture Overview](#4--architecture-overview)
- [§5 — Product Surface](#5--product-surface)
- [§6 — Subsystem Specifications](#6--subsystem-specifications)
- [§7 — Security and Trust Model](#7--security-and-trust-model)
- [§8 — AI-Agent-Native Design](#8--ai-agent-native-design)
- [§9 — Performance Engineering](#9--performance-engineering)
- [§10 — Telemetry, Observability and Determinism](#10--telemetry-observability-and-determinism)
- [§11 — Distribution, Packaging and Ecosystem](#11--distribution-packaging-and-ecosystem)
- [§12 — Developer and Agent Experience](#12--developer-and-agent-experience)
- [§13 — Business Model, Licensing and Governance](#13--business-model-licensing-and-governance)
- [§14 — Delivery Plan, Milestones and Budget](#14--delivery-plan-milestones-and-budget)
- [§15 — Risk Register](#15--risk-register)
- [§16 — Definition of Done for V1](#16--definition-of-done-for-v1)
- [§17 — Beyond V1](#17--beyond-v1)
- [Appendix A — Source document reconciliation](#appendix-a--source-document-reconciliation)
- [Appendix B — Verified external facts](#appendix-b--verified-external-facts)
- [Appendix C — Open questions and pending decisions](#appendix-c--open-questions-and-pending-decisions)

---

# §0 — Orientation

## §0.1 Executive summary

**QQQ is a runtime, not a framework in the web-app sense.** The word "framework" in the original brief means *the complete execution ecosystem* — the thing you install once and then build everything else on top of, exactly the way `node` and `bun` are things you install once.

QQQ executes **WebAssembly components** — not JavaScript — on a **Rust host** built on **Wasmtime**, with the **Component Model** as the single interface language, **WASI 0.3** as the system interface, and a **capability-based security model** where a module has *zero* ambient authority by default. Users write in Rust, TypeScript/AssemblyScript, Go, Python or C/C++, compile once to a `.wasm` component, and run the identical artifact on a laptop, a container, a serverless platform, a browser, or an AI agent's sandbox.

Three claims define the product. Each is falsifiable, each is measured, and each is the subject of a benchmark suite that ships in the repository:

1. **It is faster where it counts.** Not on a `hello world` HTTP loop — Bun has spent years on that and we may lose there. QQQ wins on **real applications**: CPU-bound logic, serialization, cryptography, data processing, multi-core scaling, and above all **p99 tail latency**, because there is no garbage collector anywhere in the request path to introduce a pause.
2. **It is the only runtime where running untrusted code is the *default posture*, not a feature flag.** An AI agent can generate a module, and the platform can prove — before execution — what that module is capable of, because capability grants live in a signed manifest and the guest physically cannot reach a syscall it was not handed.
3. **It is the only runtime designed with a machine as a first-class user.** Every command, every error, every diagnostic, every capability report has a stable, versioned, schema-published machine-readable form. An agent that has never seen QQQ can be given `qqqai schema --all` and write correct code against this platform from a cold start.

**What V1 is.** An installable, production-usable runtime shipping five first-class language toolchains, a package manager, a dev server with hot reload, a test runner, a signed capability model, an agent protocol, and a published benchmark suite — targeting Linux x86_64/aarch64, macOS x86_64/aarch64, and Windows x86_64.

**What V1 is not.** It is not a JavaScript runtime. It does not run `npm` packages unmodified. It is not a drop-in `node` replacement for a legacy Express app. It is a deliberate bet that the next decade of software looks more like *"many languages, compiled, isolated, agent-written"* than *"one dynamic language, interpreted, human-written"* — and that the runtime underneath that decade is not yet built.

**The honest bottom line.** This is a multi-year, multi-million-dollar systems project competing with two extremely well-funded incumbents and a dozen adjacent platforms. It is winnable, but only by being *categorically* different rather than *marginally* faster. Section §3 says exactly where we win, where we lose, and what would make me call the whole thing off.

→ **Checklist:** `FND-001`, `FND-002`, `FND-003`, `FND-004`, `FND-005`, `DOC-001`

---

## §0.2 The thesis

Most runtime proposals fail because they answer the wrong question. "How do we make X faster?" is the wrong question, because the incumbent gets to copy your optimizations, and because users do not switch runtimes to save 30% on a synthetic benchmark. They switch when **their actual constraints change**.

QQQ is built on four shifts that are already visible and that no incumbent is architected to absorb:

**Shift 1 — Code is increasingly written by machines, and nobody trusts it.**
An AI agent can produce a working service in ninety seconds. It can also produce a service that exfiltrates a database, opens a reverse shell, or burns $40,000 of GPU time in a loop. Today's runtimes answer this with process boundaries, containers and prayer. Containers are a *deployment* boundary, not a *security* boundary with a proof; they are also heavy — tens of milliseconds and tens of megabytes per isolation unit. QQQ makes the isolation unit the **component**: sub-millisecond to instantiate, kilobytes of state, with a machine-checkable capability manifest that says exactly what the code may touch. This is not a feature. It is the entire reason the architecture is Wasm-based.

**Shift 2 — Language monocultures are over, but runtime monocultures persist.**
A modern backend team genuinely uses Python for data, Go for services, Rust for hot paths, TypeScript for glue and C for a legacy codec. Today those are five separate deployables, five dependency trees, five security postures and five build systems, glued together over HTTP or FFI. The Component Model makes them **one artifact graph with one type system**, statically linkable and statically checkable. QQQ's job is to make that practical rather than theoretical.

**Shift 3 — Cloud economics and tail latency have become the product.**
At scale, the two numbers that decide architecture are *cost per request* and *p99 latency*. Both are dominated by memory footprint and GC pauses. A Node or Bun worker holds tens of megabytes alive just to exist; a QQQ component instance holds kilobytes. A JIT'd JavaScript runtime pauses; QQQ does not. This is a structural advantage that does not require winning a micro-benchmark.

**Shift 4 — Agents are a distribution channel, and they need contracts.**
When a human picks a stack, they read a blog post and form a vibe. When an agent picks a stack, it reads a schema and checks that its generated code validates. The runtime that publishes better machine contracts will be chosen more often by agents, and agents increasingly write the code. This is a compounding advantage that starts small and becomes decisive.

**Therefore the thesis is:** *build the runtime that serves the four shifts at once, and accept losing the synthetic-benchmark war to win the structural one.*

→ **Checklist:** `FND-006`, `FND-007`, `POS-001`, `POS-002`

---

## §0.3 Document map

| Document | Purpose | Audience |
|---|---|---|
| `QQQ-Proposal-V1.md` (this file) | What we build, why, how, at what cost, with what risks | Founder, investors, senior engineers, architects |
| [`QQQ-Checklist-V1.md`](./QQQ-Checklist-V1.md) | Executable work breakdown; every item cites this document | Engineers, project managers, agents doing the work |
| [`QQQ-Observations-and-Memories.md`](./QQQ-Observations-and-Memories.md) | Decisions, rationale, mistakes, corrections, stubs, open threads | Future maintainers — human and machine |

→ **Checklist:** `DOC-001`, `DOC-002`, `DOC-003`, `DOC-004`, `DOC-005`

---

## §0.4 How to read the cross-references

**Proposal → Checklist.** At the end of every section you will find a line of the form:

```
→ **Checklist:**
```

Those are the checklist items that implement this section. If a section has no checklist line, it is narrative or justification only, and it says so.

**Checklist → Proposal.** Every checklist item carries a `→ §` field naming the exact section anchor it derives from, e.g. `→ §6.4 Capability Engine`.

**Verification.** The cross-reference graph is machine-checked. The repository ships `tools/check-xrefs/` which parses both documents and fails CI if:

- a checklist item cites a Proposal anchor that does not exist;
- a Proposal section cites a checklist ID that does not exist;
- an anchor appears twice;
- a checklist item has no Proposal citation;
- a Proposal section carrying implementation work has no checklist citation.

→ **Checklist:** `DOC-006`, `DOC-007`, `DOC-008`

---

## §0.5 Identifier and anchor discipline

Rules, all enforced by `tools/check-xrefs/`:

1. **Proposal anchors are derived from headings**, GitHub-flavoured, with the section number included: `## §6.4 Capability Engine` → `#64-capability-engine`. Anchors are **stable forever**. A section may be renamed in prose but its anchor never changes, because checklist items point at it.
2. **If a section is retired, its anchor is tombstoned**, not deleted: the heading remains as `## §6.4 Capability Engine (retired — see §X)` so old links resolve.
3. **Checklist IDs are `AREA-NNN`**, zero-padded to three digits, never reused, never renumbered. Areas are fixed by [Checklist §1](./QQQ-Checklist-V1.md#1-areas). If an item is dropped it becomes `AREA-NNN [DROPPED → AREA-MMM]`, preserving the ID.
4. **Every checklist item has exactly one primary Proposal citation.** Secondary citations are allowed and use `also §…`.
5. **Stubs are marked inline in code** with `// QQQ-STUB(<CHECKLIST-ID>): …` and mirrored in the Observations document. No stub may exist without both markers.

→ **Checklist:** `DOC-006`, `DOC-007`, `DOC-009`, `DOC-010`

---

## §0.6 Glossary

Terms used precisely throughout. Where a term is contested in the industry, the definition here wins for this project.

| Term | Definition |
|---|---|
| **Host** | The native `qqqai` process. Rust. Owns the OS, the scheduler, the network listeners and the secrets. Never trusts the guest. |
| **Guest** | A WebAssembly **component** executed by the host. |
| **Component** | A binary `.wasm` file in the Component Model format (`version 0x1000d`), with typed imports/exports expressed in WIT. Distinct from a *core module* (`version 0x1`). |
| **Core module** | A classic Wasm module limited to `i32`/`i64`/`f32`/`f64` at its boundaries. May exist *inside* a component. |
| **WIT** | WebAssembly Interface Types — the IDL used to declare component interfaces. |
| **WASI** | WebAssembly System Interface. QQQ targets **WASI 0.3 (Preview 3)**, which introduces native `async`, `stream` and `future` types. |
| **Capability** | A *grant* of authority. QQQ components hold only the capabilities explicitly named in their manifest. There is no ambient authority. |
| **Manifest** | `qqq.toml`. Declares a project's identity, capabilities, resource limits, interfaces and dependencies. |
| **Lockfile** | `qqq.lock`. Resolves the entire dependency graph, with cryptographic digests. |
| **Fuel** | A deterministic, portable instruction budget consumed by executing Wasm. Used for metering and for provable CPU limits. |
| **Epoch** | A monotonic counter Wasmtime checks at loop back-edges, used to preempt long-running guests without instrumenting every instruction. |
| **Instance** | A live instantiation of a component, with its own linear memory and resource handles. |
| **Pool** | A preallocated set of memory/table slots from Wasmtime's pooling allocator, enabling microsecond instantiation. |
| **Deterministic mode** | An execution profile in which time, randomness, scheduling and floating-point are all seeded and controlled, so a run is bit-for-bit reproducible. |
| **Agent Face** | The set of machine-readable surfaces (CLI `--json`, schemas, `qqqai mcp`, error codes, capability reports) designed for AI agents. |
| **Fabric** | The commercial edition: org-wide policy, fleet attestation, SSO/RBAC, compliance evidence, air-gapped mirrors. **Not required to run QQQ.** |
| **SLO** | Service level objective. Numeric target with a measurement method. |
| **TTFA** | Time To First Answer — from `qqqai new` to a running HTTP endpoint, measured as a user-perceived duration (the launch metric). |

→ **Checklist:** `DOC-011`, `DOC-012`

---

# §1 — Why QQQ Exists

## §1.1 The problem, stated precisely

Node.js and Bun are both **single-language, garbage-collected, ambient-authority runtimes**. Every limitation that follows is a direct consequence of those three properties, not a bug someone forgot to fix:

| Property | Consequence |
|---|---|
| Single language (JS/TS) | Teams that need Python or Rust run a second runtime, and the two talk over HTTP. Type safety stops at the network boundary. |
| Garbage collection | Non-deterministic pauses in the request path. Tail latency is a distribution you cannot control. Memory per worker is tens of megabytes. |
| Ambient authority | A module can read any file, open any socket, and read the environment. Isolation requires a container — a heavy, coarse, unprovable boundary. Containers also do not stop *supply-chain* code, because it runs inside the same process as trusted code. |

Industry responses so far have been partial:

- **Deno** added permissions, but kept the single language and the GC.
- **Cloudflare Workers, Fastly Compute, Fermyon Spin** went Wasm-based — but each is a *platform* (you deploy to their cloud) rather than a *runtime you own*.
- **Wasmtime/Wasmer** are excellent engines but are infrastructure, not a developer *ecosystem*: no package manager, no app-level DX, no opinionated contracts.

**Nobody has shipped the whole stack: a Wasm-based runtime you own, with Node/Bun-class developer experience, designed for agents.** That is the gap QQQ occupies.

→ **Checklist:** `MKT-001`, `MKT-002`, `POS-001`

## §1.2 What we are deliberately not solving

Rejecting scope is how this project survives. V1 explicitly does **not** aim to:

- **Run unmodified npm packages.** `npm i express` will not work. We provide a conversion path (`qqqai migrate`, §12.7) and a curated registry, not an interpreter for the Node API surface. Attempting API-level Node compatibility is the single most common failure mode for runtimes that die.
- **Embed V8 or JavaScriptCore.** This re-imports every problem we are escaping: GC pauses, tens of megabytes of baseline memory, a thread-model conflict between a multi-threaded host and a single-threaded engine, and a decade of security surface.
- **Reimplement the low-level event loop.** Wasmtime, Tokio and (where appropriate) io_uring are world-class. We build the layer above them.
- **Win the "hello world" HTTP micro-benchmark.** We will compete there, and we will publish honest numbers, but it is not the thesis (see §9.1).

→ **Checklist:** `MKT-003`, `MKT-004`, `DOC-013`

## §1.3 The three structural advantages, restated as engineering constraints

Each advantage becomes a hard constraint that shapes design decisions elsewhere in this document.

**A. Isolation is the product.** *Constraint:* no capability may be reachable by a guest except through a grant recorded in a signed manifest, and the enforcement point must be outside the guest's address space. No "trusted mode" escape hatch in V1. See §7.

**B. Language pluralism is structural.** *Constraint:* no language may have access to a host feature that another language cannot reach. Every host capability is exposed as a WIT interface first and a language binding second. If a feature cannot be expressed in WIT, it does not ship. See §6.3.

**C. Determinism is achievable.** *Constraint:* any execution that touches time, randomness, scheduling or float arithmetic must route through a host-mediated interface that has a recorded, replayable record. If a guest can observe nondeterminism that the host did not grant, that is a bug. See §10.5.

→ **Checklist:** `SEC-001`, `LANG-001`, `DET-001`, `DET-002`

---

# §2 — The Eight Non-Negotiables, Operationalized

`docs/Notes.txt` defines eight principles. A principle that cannot be *tested* is a slogan. Below, each principle is restated as a concrete, checkable obligation with an enforcement mechanism, a measurement, and a place it can fail.

> **Design note.** These eight are treated as a *constitution*. The repository ships them as `PRINCIPLES.md` at the root, and the pull-request template requires the author to name any principle their change touches. Changes to `PRINCIPLES.md` require a heavyweight RFC and are expected to be rare.

## §2.1 NN-1 — AI Agents Are First-Class Users

**Operationalized as:** every user-facing surface has a machine-readable form whose schema is versioned, published, and stable within a major version.

| Enforcement | Mechanism |
|---|---|
| Every CLI command supports `--json` | Shared output layer; compile-time exhaustiveness so a new command cannot be added without a JSON shape (`FND-*`/`CLI-*`). |
| Schemas are published | `qqqai schema --all` emits JSON Schema for every machine surface, including itself. |
| Errors are codes, not sentences | Every error has a stable `QQQ-XXXX` code plus a machine-readable remediation hint. Free-form strings are supplementary. |
| Ambiguity is a defect | A "magic" or implicit behaviour is treated as a bug with a tracking ID, not as convenience. |

**Measurement:** an agent-only benchmark — a cold-start coding agent, given only the repository and a task, must produce a working QQQ service without human intervention. Target: ≥90% success on the reference task set. Tracked in `bench/agent-bench`.

**Where it fails:** if a command exists that is only usable interactively, or whose output shape changes without a version bump. CI fails on schema drift.

→ **Checklist:** `AGENT-001` … `AGENT-014`, `CLI-001`, `CLI-002`

## §2.2 NN-2 — Security and Isolation Are Non-Optional

**Operationalized as:** a guest has no authority the manifest did not grant, and the grant is enforced outside the guest.

| Enforcement | Mechanism |
|---|---|
| No ambient authority | The WASI linker is constructed *from the manifest*; an ungranted import is not merely denied at call time — it is absent, and instantiation fails with a clear code. |
| Grant is auditable before execution | `qqqai inspect ./app.component.wasm` reports required capabilities without running it. |
| Limits are enforceable | Memory, fuel, epoch deadline, instance count, open handles. A breach traps the guest, never the host. |
| Threat model is written down | §7.2 states assets, adversaries, and what is explicitly out of scope. |

**Measurement:** a red-team suite of ≥200 hostile guests (`tests/security/`), each of which must fail in a specified way. Zero host-memory-safety incidents across the fuzzing corpus.

**Where it fails:** any code path where a guest input reaches a host allocation, a path join, a format string or a subprocess without validation. Clippy lints and `unsafe` audits enforce this.

→ **Checklist:** `SEC-001` … `SEC-024`

## §2.3 NN-3 — Performance and Predictability Over Micro-Benchmarks

**Operationalized as:** published percentiles under realistic load, not single-shot peaks.

| Enforcement | Mechanism |
|---|---|
| Percentiles are the headline | Every benchmark report includes p50/p90/p99/p99.9, throughput at fixed concurrency, and RSS. |
| No GC in the host | The host is Rust; `#![forbid(unsafe_code)]` in all crates except three named, audited `qqq-*-unsafe` crates. |
| Tail-latency budget | p99 of a routed request ≤ 2 ms on reference hardware at 10k RPS for the reference app. |
| Cold start budget | Component instantiation ≤ 100 µs warm-pool, ≤ 5 ms cold-from-cache. |

**Measurement:** `bench/` with reproducible hardware notes, pinned toolchains, and a published methodology that states what it does *not* measure.

→ **Checklist:** `PERF-001` … `PERF-026`

## §2.4 NN-4 — Multi-Language by Design

**Operationalized as:** every host capability is a WIT interface; every language binding is generated from that WIT.

| Enforcement | Mechanism |
|---|---|
| WIT is the source of truth | `qqqai bindings` regenerates every language's types from `wit/`. Drift fails CI. |
| No privileged language | The reference application is implemented **five times** — Rust, TypeScript/AssemblyScript, Go, Python, C/C++ — and all five must pass the identical conformance suite. |
| Parity is measured | A parity matrix in CI: language × capability × supported. Any gap requires a written exception with an owner and a date. |

**Measurement:** the conformance suite runs identically across all five toolchains; the published parity matrix must show no unexplained gaps.

→ **Checklist:** `LANG-001` … `LANG-040`

## §2.5 NN-5 — Explicit Contracts Over Implicit Behavior

**Operationalized as:** nothing important is inferred.

| Enforcement | Mechanism |
|---|---|
| Interfaces are versioned | Every WIT package is versioned; `@since`/`@unstable` annotations are mandatory. |
| Errors are typed | Every fallible host call returns a typed error, not a status code buried in a payload. |
| No hidden global state | No environment-variable reads, no CWD dependencies, no implicit config discovery inside the runtime. Configuration is explicit, sourced from a known file or an explicit flag. |
| Capabilities are discoverable without execution | Static analysis over the component's import table plus the manifest. |

**Measurement:** `qqqai inspect --json` output is complete enough that an agent can decide whether to run a component without running it.

→ **Checklist:** `CON-001` … `CON-018`

## §2.6 NN-6 — Human + Machine Documentation Parity

**Operationalized as:** documentation is generated from the artifact, not written alongside it.

| Enforcement | Mechanism |
|---|---|
| Docs are built, not typed | WIT → reference docs; JSON Schema → CLI docs; `--help` → text from the same source. |
| Freshness is tested | A CI job builds a sample project against the *published* docs and fails if the docs describe an API that no longer exists. |
| Machine-readable docs | `llms.txt`, `llms-full.txt`, and per-interface Markdown suitable for retrieval. |

**Measurement:** zero doc-drift failures; every public API has an example that compiles in CI.

→ **Checklist:** `DOC-001` … `DOC-020`

## §2.7 NN-7 — Progressive Power, Safe Defaults

**Operationalized as:** `qqqai new` produces something that is secure and runs, and the ladder upward is explicitly signposted.

| Enforcement | Mechanism |
|---|---|
| Safe by default | A generated manifest grants **nothing** beyond what the template needs; adding a capability requires editing the manifest and the tool tells you exactly what to write. |
| Progressive disclosure | Three documented tiers: *Solo* (no config), *Team* (`qqq.toml` with limits and caps), *Fleet* (Fabric policy). |
| The powerful path is not closed | Anything a beginner cannot express is reachable via an explicit, documented escape — never by weakening the default. |

**Measurement:** the "first ten minutes" script runs on a clean machine and produces a secured, running service with zero configuration choices.

→ **Checklist:** `DX-001` … `DX-020`

## §2.8 NN-8 — Ecosystem Integrity and Long-Term Stewardship

> ⚠️ **This principle is in direct tension with the commercial licence direction chosen in `Observations §D-004`. That tension is real, is not hidden, and is resolved explicitly in [§13.2](#132-the-licence-model-and-why-nn-8-still-holds).**

**Operationalized as:** the thing you must install to *use* QQQ is genuinely open; the thing you *pay* for is governance and liability.

| Enforcement | Mechanism |
|---|---|
| Runtime is Apache-2.0, forever | The `qqqai` binary and all runtime crates. This is an irrevocable commitment for the V1 line. |
| Backward compatibility is a contract | SemVer, plus a documented deprecation policy with a minimum two-minor-version window and machine-readable migration guides. |
| Governance is written down | A public governance document with an explicit decision process before the first external contributor arrives — not after. |

**Measurement:** a published deprecation ledger; zero breaking changes inside a major version without a migration tool.

→ **Checklist:** `GOV-001` … `GOV-014`, `LIC-001` … `LIC-012`

---

# §3 — Market, Positioning and Honest Competitive Analysis

## §3.1 Who this is for

Four primary segments, in the order we should pursue them. The order matters because each segment funds and informs the next.

| # | Segment | Why they adopt | What they pay for |
|---|---|---|---|
| 1 | **AI-agent platform builders** | Need to execute model-generated code safely, at low latency, at scale. Today they build bespoke sandboxes on containers or embedded JS. | Fleet governance, attestation, throughput (Fabric) |
| 2 | **Edge / serverless / multi-tenant platforms** | Per-tenant isolation with microsecond cold start and kilobyte memory is the entire business model. | Density, cold start, support |
| 3 | **Polyglot backend teams** | They already run five runtimes and hate the seams. One artifact graph, one type system. | Support, migration tooling |
| 4 | **Performance-sensitive services** | p99 latency and memory cost dominate their bill. | Support, indemnification |

**Explicit non-targets for V1:** teams needing unmodified npm packages; teams whose product *is* a JavaScript framework runtime; hobbyist scripting.

→ **Checklist:** `MKT-005`, `MKT-006`, `GTM-001` … `GTM-008`

## §3.2 The competitive set, honestly

Nine relevant comparators. Columns are the axes that actually decide adoption.

| Platform | Execution model | Multi-language | Isolation story | Own it or rent it | Gap QQQ attacks |
|---|---|---|---|---|---|
| **Node.js** | V8 JIT, single-thread event loop | JS/TS only | Process/container | Own | GC tails, memory, language lock-in, ambient authority |
| **Bun** | JavaScriptCore, custom event loop | JS/TS only | Process/container | Own | Same as Node; also micro-bench-optimized, not structurally different |
| **Deno** | V8 + Rust host | JS/TS (+ limited) | Permission flags | Own | Single language, GC still present; permissions are coarse |
| **Cloudflare Workers** | V8 isolates | JS/Wasm | Platform-managed | Rent (their cloud) | You cannot self-host; vendor lock-in is total |
| **Fastly Compute** | Wasm (Wasmtime) | Multi | Wasm sandbox | Rent | Platform, not a runtime you own; DX is thin |
| **Fermyon Spin** | Wasm (Wasmtime) | Multi | Wasm sandbox | Own (OSS) | No app-level engine/CLI ecosystem; no agent contract layer |
| **Wasmer** | Wasm | Multi | Wasm sandbox | Own | Engine, not ecosystem; no package manager, no DX opinion |
| **Wasmtime (raw)** | Wasm | Multi | Wasm sandbox | Own | Infrastructure library; no product surface above the engine |
| **Docker / gVisor / Firecracker** | OS/VM isolation | Any | Strong but heavy | Own | ~10–100 ms cold start, ~MB–GB memory; far too coarse per agent action |

**The honest read.** We are not competing with Cloudflare or Fastly — they are potential *customers* (QQQ can be the engine inside their platform). We are not competing with Wasmtime — we are a superset product built *on* it, and should be a good citizen of the Bytecode Alliance ecosystem. We are competing with **Node and Bun for the default-runtime slot**, and with **Fermyon/Wasmer for the Wasm-app-framework slot**.

→ **Checklist:** `MKT-007`, `MKT-008`, `MKT-009`, `GTM-002`

## §3.3 Where we win, where we lose, and where we might be lying to ourselves

**We win decisively:**
- **p99/p99.9 tail latency.** No GC anywhere. This is structural, not tunable.
- **Memory density.** Kilobyte-scale instances versus megabyte-scale workers. At 1,000 tenants, the hosting bill difference is an order of magnitude.
- **Isolation strength and provability.** A capability manifest checkable without execution is something no container gives you.
- **Language reach.** Five first-class languages on one artifact graph.
- **Agent ergonomics.** Machine contracts are a designed-in product surface, not a `--json` flag bolted on.

**We lose, and should say so:**
- **`hello world` HTTP throughput.** Bun is exceptional here. We may reach parity; we should not promise to beat it. See §9.1.
- **Ecosystem size.** npm is ~3M packages. We start at zero. This is the single largest risk (R-01).
- **Familiarity.** Every JS developer already knows Node. Our onboarding cost is higher, and that cost is real.

**Where we might be lying to ourselves — flagged for honest re-examination at each milestone:**
- **"Wasm is near-native."** It is, for compute-bound code compiled with a good toolchain. It is *not* near-native for code that crosses the host boundary constantly (many small calls, string-heavy APIs). The canonical ABI has real cost. §9.3 quantifies it and §9.4 describes the mitigation (batched interfaces, `stream`/`future`, zero-copy where the type system allows).
- **"Multi-language is free."** It is not. Every toolchain has its own idea of what "compile to WASI 0.3" means, and three of our five target languages have immature or awkward Wasm stories. §6.10 is honest about per-language readiness.
- **"Agents will adopt us because we publish schemas."** Probably true eventually, but agent tool-use is currently shaped by training data and familiarity. Schemas help; they do not create pull on their own. This is why the agent story is paired with a concrete, unignorable use case: **agent sandboxing for code execution**.

→ **Checklist:** `MKT-010`, `MKT-011`, `POS-003`, `POS-004`

## §3.4 Positioning statement and the language we use

**Canonical positioning (one sentence):**

> **QQQ is the runtime built for humans and AI agents — secure by default, multi-language, and fast where real applications actually spend their time.**

**Tagline candidates (see `MKT-012` for the decision process):**
- *Run anything. Trust nothing. Pay for neither.*
- *The runtime where isolation is free.*
- *Five languages. One artifact. Zero ambient authority.*
- *Built so an agent can be given root and still do no harm.*

**Vocabulary rules** (enforced in all copy, docs and CLI text):
- Never say "Bun-killer". Say what is true.
- Never publish a benchmark without its methodology and its hardware.
- Never claim a capability we have not implemented behind a feature flag **and** tested.
- "Fast" always means "measured, here is the number, here is the file".

→ **Checklist:** `MKT-012`, `MKT-013`, `DOC-014`

---

# §4 — Architecture Overview

## §4.1 The layer cake

QQQ is nine layers. Data flows down on the request path; authority flows down on the trust path and never flows back up.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ L9  ECOSYSTEM      registry · package manager · templates · conformance      │
├──────────────────────────────────────────────────────────────────────────────┤
│ L8  AGENT FACE     MCP server · schemas · error codes · capability reports   │
├──────────────────────────────────────────────────────────────────────────────┤
│ L7  DX             qqqai CLI · dev server + HMR · test runner · debugger     │
├──────────────────────────────────────────────────────────────────────────────┤
│ L6  PRODUCT APIS   WIT interfaces: http, fs, sql, kv, queue, crypto, ai…     │
├──────────────────────────────────────────────────────────────────────────────┤
│ L5  CAPABILITY     manifest → grants → linker → limits → audit               │
│     ENGINE         ★ this layer is why QQQ exists ★                          │
├──────────────────────────────────────────────────────────────────────────────┤
│ L4  EXECUTION      Wasmtime engine · pooling allocator · fuel · epochs       │
├──────────────────────────────────────────────────────────────────────────────┤
│ L3  SCHEDULER      thread-per-core shards · work stealing · backpressure     │
├──────────────────────────────────────────────────────────────────────────────┤
│ L2  I/O            Tokio (portable) │ io_uring (Linux, opt-in) │ IOCP/epoll  │
├──────────────────────────────────────────────────────────────────────────────┤
│ L1  PLATFORM       OS syscalls · mmap · signals · clocks · entropy           │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Invariants across all layers:**

1. Authority only ever narrows as you go down. L5 is the sole authority gate; nothing below it can widen a grant, and nothing above it can bypass it.
2. Guest code exists only inside L4. Layers L1–L3 run native, in the host process, and are never reachable from a guest except through an L5-mediated call.
3. Every L6 host function is defined in WIT before it is implemented in Rust. A host function without a WIT definition does not compile into a release build.

→ **Checklist:** `ARCH-001`, `ARCH-002`, `ARCH-003`, `ARCH-004`

## §4.2 Process and thread model

**Decision: thread-per-core with work stealing *within* a shard group, implemented on Tokio's multi-threaded runtime, with an optional io_uring backend on Linux.**

This deserves justification, because the source conversation proposed both Tokio and monoio/glommio and asked which is better. The answer is nuanced:

| Option | Strength | Fatal weakness for QQQ |
|---|---|---|
| **Tokio multi-threaded** | Battle-tested, portable to all our targets including Windows, integrates with Wasmtime's async support and with `wasmtime-wasi-http` | Shared work queue means cross-core cache-line bouncing at very high core counts |
| **monoio / glommio (thread-per-core)** | No cross-core synchronization; maximum single-core throughput | **Linux-only.** io_uring does not exist on macOS or Windows. Choosing this as the only backend means QQQ cannot run on half our target platforms. Also conflicts with Wasmtime's own async executor model, which expects a Tokio-compatible reactor. |

**Resolution — a hybrid that is honest about cost:**

- **Default (all platforms):** Tokio multi-threaded runtime, one runtime per process, with a **sharded acceptor**: each worker thread owns a set of listener shards, so a connection is accepted and served on the same core for its whole life. This recovers ~most of the thread-per-core benefit (no cross-core handoff for the common path) while remaining portable.
- **Optional (Linux only, opt-in via `--io-backend io_uring`):** an io_uring-backed reactor behind a feature flag. Off by default until it demonstrates a measured, reproducible advantage on the reference workload (see `PERF-014`).
- **Explicitly not doing in V1:** replacing Tokio. Rewriting the async reactor is a multi-year detour with no differentiation. The differentiation is L5, not L2.

**Consequence to accept:** we inherit Tokio's cooperative-budget semantics. Wasmtime already works around this internally for WASI (upstream release notes note that WASIp2 `poll` calls explicitly opt out of Tokio's per-task cooperative budget). We mirror that discipline: **host functions that represent guest-visible blocking must not be subject to host cooperative budgets**, or we violate WASI guarantees. This is written down as an invariant in §10.5.

→ **Checklist:** `ARCH-005`, `ARCH-006`, `PERF-014`, `DET-003`

## §4.3 Crate topology

Deliberately modular. Every crate has a single responsibility, a stated stability tier, and an owner. **No crate may depend on a crate above it in this list.**

| Crate | Tier | Responsibility |
|---|---|---|
| `qqq-core` | stable | Shared types: IDs, error model, version, `Result`/`Error` codes. No I/O. |
| `qqq-cap` | stable | Capability model: manifest parsing, grant resolution, policy evaluation, audit records. |
| `qqq-host` | stable | Wasmtime integration: engine config, component compilation, pooling, fuel, epochs, store data. |
| `qqq-abi` | stable | WIT package + generated bindings for all host interfaces. |
| `qqq-io` | stable | Reactor abstraction over Tokio / io_uring. |
| `qqq-serve` | stable | The HTTP/dev server: routing, listener shards, HTTP/1.1, HTTP/2, HTTP/3 (QUIC) behind a flag. |
| `qqq-run` | stable | The CLI orchestration: `new`, `build`, `run`, `dev`, `test`, `deploy`. |
| `qqq-pkg` | beta | Registry client, solver, lockfile, content-addressed store. |
| `qqq-registry` | beta | Server side of the registry. |
| `qqq-debug` | beta | DWARF → source mapping, trap diagnostics, time-travel replay. |
| `qqq-fabric` | commercial | Org policy, attestation, SSO/RBAC, compliance evidence. **Separate repository and licence** (§13.2). |

**`unsafe` policy.** `#![forbid(unsafe_code)]` at the root of every crate above. The only exceptions are three narrowly-scoped crates that require it (`qqq-io-uring`, `qqq-mem-hugepage`, `qqq-sys-signals`), each with a written safety argument, each reviewed by a second maintainer, each with Miri coverage where applicable.

**Why this matters more than it looks:** the crates.io publish name is `qqqai`, and a modular workspace means third parties can depend on `qqq-host` or `qqq-cap` alone — for example to embed QQQ's capability engine inside their own product. That is a distribution channel that costs nothing.

→ **Checklist:** `ARCH-007`, `ARCH-008`, `ARCH-009`, `ARCH-010`, `SEC-020`

## §4.4 Request lifecycle — the detailed path

The single most important diagram in this document. Every design constraint elsewhere is visible here.

```
 1. LISTENER SHARD        kernel accepts; shard thread picks it up (same core)
 2. HTTP PARSE            hyper parses to a request head; body stays a stream
 3. ROUTE MATCH           radix/trie over host+path; no allocation on hot path
 4. TENANT RESOLVE        map host/path → tenant → component ID + manifest rev
 5. POLICY CHECK          is this principal allowed to invoke this export?   ← L5
 6. INSTANCE ACQUIRE      take a pooled instance (≈µs) or instantiate (≈ms)
 7. CAPABILITY BIND       build the store's linker for THIS instance: only
                          the grants in the manifest become imports           ← L5
 8. LIMIT BIND            memory cap, fuel budget, epoch deadline, handle cap ← L5
 9. REQUEST ADAPT         HTTP → wasi:http types; body becomes a stream
10. GUEST ENTRY           call the exported handler; host runs it async
11. HOST CALLS            guest calls back into L6 interfaces; each call is
                          re-checked against the grant set (defence in depth)
12. RESPONSE ADAPT        wasi:http response → HTTP; streams pass through
13. METER + TRACE         fuel delta, wall time, bytes, handle peak → telemetry
14. INSTANCE RELEASE      return to pool (reset) or drop (free)
15. AUDIT APPEND          capability-use record written to the audit ring
```

**Design consequences worth naming:**

- **Steps 7 and 8 happen per instance, not per process.** That is the difference between "the server has permissions" and "this request has permissions". Two tenants on the same host share zero authority.
- **Step 11 re-checks.** The grant set is consulted twice — at bind time and at call time. The second check is defence in depth against a host bug that mis-builds a linker. It is cheap (a set lookup on a `u32` capability ID) and it is non-negotiable.
- **Step 4 is the only place routing state lives.** No global router state, no `thread_local!` routing caches that could leak across tenants.
- **Step 14 is where density comes from.** A pooled instance's linear memory is reset, not freed. This is what makes sub-100 µs instantiation possible at high tenant counts.

→ **Checklist:** `ARCH-011`, `ARCH-012`, `SEC-002`, `PERF-003`, `PERF-004`, `OBS-001`

## §4.5 The ABI boundary — what crosses and at what cost

The Component Model Canonical ABI defines how rich types (strings, lists, records, variants, resources, `stream`, `future`) are lowered to core Wasm. It is **not free**, and pretending otherwise is how Wasm projects lose credibility.

| Boundary crossing | Approximate cost | Mitigation in QQQ |
|---|---|---|
| `u32`/`u64` scalar in/out | ~1–5 ns | None needed |
| Small string (<64 B) in/out | ~20–60 ns (copy into guest, validate) | Documented; batching API provided |
| Large byte buffers | O(n) copy | `stream<u8>` for anything large; `resource` handles for files and sockets so data never crosses for pass-through |
| Resource handle create/drop | ~10–30 ns + table slot | Pooled handle tables; documented lifetime rules |
| `async` call (WASI 0.3) | One `future` rendezvous | Preferred form for anything that can block |
| Many tiny calls (chatty design) | Dominant cost | **Design rule:** interfaces are specified to be *batch-first* — every list-shaped operation takes a list. See §6.3. |

**The design rule that saves us:** *chatty interfaces are a defect.* A host interface that would naturally be called in a loop must instead accept a batch. This is written into the WIT style guide (`CON-012`) and enforced in review. It is a small rule with an outsized performance effect, and it is the main reason QQQ can be fast despite the ABI.

→ **Checklist:** `CON-011`, `CON-012`, `PERF-005`, `PERF-006`

## §4.6 Where the artifacts live and how they move

```
 source ──▶ qqqai build ──▶ .component.wasm ──▶ qqqai deploy ──▶ running instance
   │            │                  │                  │
   │            │                  ├─► registry (CAS, signed)
   │            │                  ├─► OCI image (for k8s/containerd)
   │            │                  └─► AOT .cwasm (platform-specific, cached)
   │            └─ manifest + lockfile captured into the artifact
   └─ five toolchains, one output format
```

**Artifact model.** A QQQ "app" is a **binary** — a composed component — plus a **signed manifest envelope**. Build output is reproducible given the lockfile and toolchain pin. The `.cwasm` AOT artifact is a cache, never a source of truth; it is keyed by (component digest, engine version, target triple, config hash).

**Why composition matters here.** Component composition (linking a component's imports to other components' exports) happens at **build time** where possible and at **load time** where necessary. Build-time composition means the shipped artifact is closed: no surprise wiring at runtime, which is both faster and auditable.

→ **Checklist:** `PKG-001`, `PKG-002`, `PERF-007`, `SUP-001`

## §4.7 Concurrency model for guests

Three guest concurrency models exist and QQQ must state a policy for each.

| Model | Wasm feature | QQQ V1 policy |
|---|---|---|
| **Async single-threaded** | Component Model `async`, `future`, `stream` (WASI 0.3) | **Default and recommended.** One logical task per request; concurrency comes from many instances, not many threads inside one. |
| **Cooperative threads** | Component Model cooperative threads (gated, 🧵) | **Not enabled in V1.** Tracked as `FUT-004`. Requires stack switching, which Wasmtime still lists as work-in-progress. |
| **Shared-memory threads** | Wasm `threads` proposal (`SharedMemory`) | **Enabled but discouraged**, behind an explicit manifest opt-in (`[limits] shared_memory = true`). Rationale: shared linear memory is a large attack surface and defeats per-instance memory accounting. It exists for legitimately CPU-parallel workloads where the alternative is worse. |

**Why the default is async-single-threaded:** it preserves the strongest isolation guarantee (one memory per task), keeps fuel accounting exact, and matches how request-scoped work actually looks. Density replaces threads.

→ **Checklist:** `ARCH-013`, `ARCH-014`, `FUT-004`, `PERF-015`

---

# §5 — Product Surface

## §5.1 What a user actually installs

One binary. No runtime dependency, no package manager bootstrap, no `nvm`.

```bash
# macOS / Linux
curl -fsSL https://qqq.codes/install.sh | sh

# Windows
irm https://qqq.codes/install.ps1 | iex

# Rust users
cargo install qqqai

# Node/Bun users (thin wrapper that fetches the real binary, same as esbuild/biome do)
npm install -g qqqai

# Package managers
brew install qqqai          # macOS/Linux
scoop install qqqai         # Windows
winget install QQQ.QQQ      # Windows
```

**Size and startup targets** (these are SLOs, measured in CI on every commit, not aspirations):

| Metric | Target | Rationale |
|---|---|---|
| Download size (per platform, compressed) | ≤ 25 MB | Comparable to Bun; small enough for CI images |
| `qqqai --version` wall time | ≤ 15 ms | Cold process start with no project |
| `qqqai run` cold start (cached) | ≤ 40 ms | From process exec to listener accepting |
| Installed footprint (binary only) | ≤ 60 MB on disk | Fits in any container layer |

→ **Checklist:** `DIST-001` … `DIST-012`

## §5.2 The command surface

Complete V1 command set. Every command supports `--json`, and the JSON schema is published (§8.3). Commands marked ⚡ are on the hot path and get the strictest startup budget.

### Project lifecycle

| Command | Purpose | Key flags |
|---|---|---|
| `qqqai new <name>` ⚡ | Scaffold a project | `--lang rust\|ts\|go\|python\|cpp`, `--template http\|worker\|cli\|lib\|ai-tool`, `--no-git`, `--yes` |
| `qqqai init` ⚡ | Add QQQ to an existing directory | `--lang`, `--force` |
| `qqqai add <pkg>[@ver]` | Add a dependency | `--dev`, `--exact`, `--registry` |
| `qqqai remove <pkg>` | Remove a dependency | |
| `qqqai install` ⚡ | Resolve + fetch + verify | `--locked`, `--frozen`, `--offline` |
| `qqqai update` | Update within semver | `--latest`, `--dry-run` |

### Build and run

| Command | Purpose | Key flags |
|---|---|---|
| `qqqai build` | Compile to a `.component.wasm` | `--release`, `--target`, `--aot`, `--emit-cwasm`, `--reproducible` |
| `qqqai run` ⚡ | Execute | `--cap`, `--limit`, `--args`, `--env`, `--watch` |
| `qqqai dev` | Dev server + hot reload | `--port`, `--open`, `--https`, `--inspect` |
| `qqqai serve` | Production server | `--listen`, `--workers`, `--tls`, `--config` |
| `qqqai test` | Built-in test runner | `--filter`, `--coverage`, `--junit`, `--watch`, `--trials N` |
| `qqqai bench` | Benchmark harness | `--baseline`, `--json`, `--save` |
| `qqqai fmt` / `qqqai lint` | Delegate to the language toolchain, with a unified interface | `--check`, `--fix` |

### Inspection and trust — the surfaces that make QQQ different

| Command | Purpose | Key flags |
|---|---|---|
| `qqqai inspect <artifact>` ⚡ | **Static capability report.** What can this do, without running it. | `--json`, `--diff <other>` |
| `qqqai audit <artifact>` | Full security posture: caps, limits, supply chain, provenance | `--json`, `--sarif`, `--fail-on <severity>` |
| `qqqai verify <artifact>` | Verify signature + attestation | `--key`, `--policy`, `--json` |
| `qqqai caps` | Show effective grants for a project or running instance | `--explain`, `--json` |
| `qqqai why <resource>` | **Explain why a capability was or was not granted** | `--json` |
| `qqqai trace` | Live trace stream from a running app | `--filter`, `--jsonl` |
| `qqqai doctor` | Environment diagnosis with remediation steps | `--json`, `--fix` |

### Agent and integration

| Command | Purpose | Key flags |
|---|---|---|
| `qqqai mcp` | **Run as an MCP server** so any agent can drive QQQ natively | `--stdio`, `--http <addr>`, `--tools <set>` |
| `qqqai schema` | Emit JSON Schema for every machine surface | `--all`, `--command <name>`, `--errors` |
| `qqqai openapi` | Emit an OpenAPI description of a running app | `--out <file>` |
| `qqqai migrate` | Convert from Node/Bun/Deno with a written report | `--from node`, `--report` |

→ **Checklist:** `CLI-001` … `CLI-024`

## §5.3 The manifest — `qqq.toml`

The contract a user writes. Annotated in full because this file is the product.

```toml
# ─────────────────────────────────────────────────────────────────────────────
# qqq.toml — the QQQ project manifest
# Everything here is explicit. Nothing is discovered implicitly. (NN-5)
# ─────────────────────────────────────────────────────────────────────────────

[package]
name        = "orders-api"
version     = "0.1.0"
description = "Order intake and fulfilment API"
license     = "Apache-2.0"
authors     = ["Example Corp <dev@example.com>"]
edition     = "2026"             # compiler/ABI edition, not Rust edition
entrypoint  = "component:orders-api/handler@0.1.0"

[build]
language    = "rust"             # rust | ts | go | python | cpp
target      = "wasm32-wasip2"    # or wasm32-wasip3 when toolchains land
profile     = "release"
reproducible = true              # fails the build if output digest is unstable

# ── CAPABILITIES: the heart of the file ──────────────────────────────────────
# Absent means DENIED. There is no wildcard, no "allow all", no ambient
# authority. `qqqai add-cap <cap>` writes the correct stanza for you.
[capabilities]

  # HTTP — as a server, a client, or both. Scoped by host pattern.
  [capabilities.http]
  server  = true                                  # may receive requests
  client  = ["api.stripe.com:443", "*.internal.example.com:8443"]
  methods = ["GET", "POST", "PUT", "DELETE"]
  max_request_bytes  = "10MiB"
  max_response_bytes = "10MiB"

  # Filesystem — pre-opened directories only. Paths are host paths.
  [[capabilities.fs]]
  path  = "/var/lib/orders"
  mode  = "read-write"          # read-only | read-write | append-only
  quota = "5GiB"

  [[capabilities.fs]]
  path = "/etc/orders/config.json"
  mode = "read-only"

  # Databases — the host holds the credential; the guest never sees a password.
  [[capabilities.sql]]
  name     = "orders"
  driver   = "postgres"
  host     = "db.internal:5432"
  database = "orders"
  secret   = "env:ORDERS_DB_URL"       # resolved by the HOST at bind time
  pool     = 10
  readonly = false

  # Key-value store with namespacing enforced by the host
  [capabilities.kv]
  stores = ["sessions", "cart"]

  # Queues
  [[capabilities.queue]]
  name      = "orders.events"
  direction = "publish"

  # Cryptography. `random` is a capability, not a right.
  [capabilities.crypto]
  random   = true
  hash     = ["sha256", "sha512", "blake3"]
  hmac     = ["sha256"]
  aead     = ["aes-256-gcm", "chacha20-poly1305"]
  sign     = ["ed25519"]
  secrets  = ["env:JWT_SIGNING_KEY"]

  # Time. Grants a clock; may be fixed for determinism.
  [capabilities.clock]
  wall    = true
  monotonic = true
  timezone = "UTC"

  # Environment variables — individually named. Never a blanket inherit.
  [capabilities.env]
  allow = ["LOG_LEVEL", "REGION"]

  # Outbound DNS, if you want it separately from http client
  [capabilities.dns]
  resolve = ["api.stripe.com"]

  # Model inference — §6.9. Optional.
  [capabilities.ai]
  providers = ["local:ggml"]
  models    = ["*:<=4B"]           # size-constrained, enforced by the host
  max_tokens_per_request = 4096

# ── LIMITS: enforceable, introspectable, and always enforced ────────────────
[limits]
memory            = "128MiB"      # hard cap; growth beyond this traps
fuel              = 50_000_000    # deterministic instruction budget per request
epoch_deadline_ms = 5000          # wall-clock preemption backstop
max_instances     = 200           # concurrency ceiling per worker
max_open_handles  = 256
max_subrequests   = 32
max_response_time = "30s"
shared_memory     = false         # see §4.7

# ── DEPENDENCIES ────────────────────────────────────────────────────────────
[dependencies]
"qqqai/json"      = { version = "1.2", features = ["simd"] }
"qqqai/validate"  = { version = "2.0" }

[dev-dependencies]
"qqqai/assert"    = { version = "1.0" }

# ── NETWORK SURFACE ─────────────────────────────────────────────────────────
[server]
routes = [
  { path = "/orders",     methods = ["POST"],          handler = "create-order" },
  { path = "/orders/:id", methods = ["GET", "DELETE"], handler = "order-by-id" },
  { path = "/healthz",    methods = ["GET"],           handler = "health", auth = "none" },
]
default_auth = "bearer-jwt"       # none | bearer-jwt | mtls | signed-request

[server.cors]
allow_origins = ["https://app.example.com"]

# ── OBSERVABILITY ───────────────────────────────────────────────────────────
[telemetry]
traces  = true
metrics = ["latency", "fuel", "memory_peak", "handle_peak", "capability_use"]
logs    = { level = "info", format = "json" }
export  = [{ otlp = "http://otel-collector:4317" }]

# ── DETERMINISM (opt-in, §10.5) ─────────────────────────────────────────────
[determinism]
enabled     = false               # true for tests and replay
seed        = 0x51515151
fixed_clock = "2026-01-01T00:00:00Z"
fp_strict    = true               # forbids relaxed-SIMD fusion differences
```

**Why the manifest looks like this.** Every field answers a question an auditor, an agent, or a tired engineer at 3am will ask: *what can this touch, how much can it use, and who says so?* A file you can read in ninety seconds and answer those questions from is worth more than a file that is short.

→ **Checklist:** `CON-001` … `CON-018`, `SEC-003`, `DX-002` … `DX-010`

## §5.4 The lockfile — `qqq.lock`

Deterministic, fully-resolved, content-addressed, and reviewable in a pull request.

```toml
version = 1

[[package]]
name    = "qqqai/json"
version = "1.2.4"
source  = "registry+https://registry.qqq.codes"
digest  = "sha256:9f2c…"            # of the component artifact
wit     = "sha256:41ab…"            # of the generated interface digest
caps    = ["none"]                  # ← dependencies declare capabilities too
license = "Apache-2.0"

[[package]]
name    = "qqqai/validate"
version = "2.0.1"
digest  = "sha256:7710…"
caps    = ["clock.monotonic"]       # ← and they can only ever ask, never take
license = "Apache-2.0"

[metadata]
generated-by = "qqqai 1.0.0"
lockfile-hash = "sha256:0c9e…"
```

**Two features that matter more than they look:**

1. **`caps` is recorded per dependency.** `qqqai install` prints a **capability diff** — "this update adds `http.client` to `qqqai/telemetry`". Supply-chain attacks today hide in code; here the *authority* delta is visible in the diff. This is a genuinely new capability for the ecosystem and it addresses a real, expensive class of incident.
2. **`lockfile-hash` covers everything.** Any change to any resolved artifact changes the hash, so a build is either reproducible or it loudly is not.

→ **Checklist:** `PKG-003`, `PKG-004`, `SEC-015`, `SUP-002`

---

# §6 — Subsystem Specifications

Each subsection: purpose, interface, key decisions, failure modes, and the checklist items that build it.

## §6.1 `qqq-host` — the execution engine

**Purpose.** Own the Wasmtime engine and turn a component + a manifest into a running, limited, isolated instance.

**Interface (Rust, internal):**

```rust
pub struct Host { /* engine, pools, config, metrics */ }

impl Host {
    pub fn bootstrap(cfg: HostConfig) -> Result<Self>;
    pub fn load(&self, artifact: &Artifact, manifest: &Manifest) -> Result<LoadedComponent>;
    pub fn acquire(&self, c: &LoadedComponent, g: &Grants) -> Result<InstanceGuard>;
    pub fn release(&self, guard: InstanceGuard);
}
```

**Key decisions:**

| Decision | Choice | Why |
|---|---|---|
| Engine count | **One engine per host process**, multiple `Engine`s only when target/feature sets differ | Wasmtime `Engine` is shareable across threads; multiple engines duplicate compiled code |
| Compilation | AOT-first (`.cwasm`), JIT fallback | Cold start is the product; JIT-on-first-hit is unacceptable in production |
| Compilation parallelism | Cranelift parallel compilation, bounded by core count | Build latency matters for DX and for scale-out |
| Allocation | **Pooling allocator**, preallocated memory/table slots | Sub-100 µs instantiation; predictable RSS; no per-instance mmap churn |
| Preemption | **Epoch-based by default**, fuel where exact metering is needed | Epoch instrumentation is far cheaper than per-instruction fuel; fuel is reserved for billing/limiting precision |
| Limits | `StoreLimits` + manifest-derived thresholds | A limit the manifest cannot express is a limit an auditor cannot verify |
| Determinism | `Config::cranelift_nan_canonicalization` + fixed clock + seeded RNG in deterministic mode | §10.5 |
| Async | `*_async` APIs throughout, with `epoch_deadline_async_yield_and_update` | Wasmtime requires async APIs once any async host function exists |

**Failure modes and required behaviour:**

| Failure | Required behaviour |
|---|---|
| Guest traps | Host survives; structured trap with code, guest backtrace and (if DWARF present) source line; the instance is discarded, not reused |
| Guest exceeds memory | Trap `QQQ-3001`; host logs the peak; instance discarded |
| Guest exceeds fuel | Trap `QQQ-3002`; response is 503 with a `Retry-After` only if the manifest opted into soft limits |
| Guest exceeds epoch deadline | Trap `QQQ-3003`; counted as a timeout, never as a crash |
| Host function panics | **Never.** All host functions return `Result`; a panic in a host function is a bug of severity 1 and is caught by a panic hook that converts to a trap and pages on-call |
| Compilation fails | Load-time error with a stable code and the failing WIT interface named |
| Pool exhausted | Backpressure, not unbounded queueing: sheds load with 503 + `Retry-After`, and increments a saturation metric |

→ **Checklist:** `HOST-001` … `HOST-024`

## §6.2 `qqq-cap` — the capability engine

**Purpose.** The single authority gate. This is the subsystem that justifies the project.

**Model.** A capability is an opaque, typed, unforgeable grant token. There are three kinds:

| Kind | Example | Notes |
|---|---|---|
| **Resource capability** | read-only preopened directory handle | Backed by a host-side handle; the guest holds an index into its own table |
| **Operation capability** | "may call `sql.query` against database `orders`" | A policy decision + a parameterised binding |
| **Ambient capability** | "may read the wall clock", "may draw randomness" | Deliberately explicit, because both are classic covert channels |

**Resolution pipeline:**

```
qqq.toml [capabilities]
        │
        ▼
 1. PARSE       validate against JSON Schema (schema is published; §8.3)
 2. NORMALIZE   expand host patterns, resolve secret references, canonicalize paths
 3. DEVELOPER   developer-mode overlay (qqqai run --cap) — LOUD, non-production
 4. ORGANIZATION Fabric policy overlay — may only NARROW, never widen
 5. PLATFORM    deployment overlay (k8s annotations, env, config) — may only narrow
 6. RESOLVE     → Grants (a concrete, serializable set)
 7. BIND        → per-instance Linker containing exactly those imports
 8. RECORD      → the resolved Grants are hashed and attached to the audit record
```

**Hard rule:** every overlay may only **narrow**. There is no configuration, anywhere, that widens a developer's declared grant. This is what makes "the manifest is the truth" a property rather than a promise.

**Policy language.** Fabric uses a small, deliberately non-Turing-complete policy language (a restricted expression form over capability predicates). Rationale: policy must be statically analysable and provably terminating. It is *not* Rego, *not* CEL with extensions, and *not* arbitrary WASM. Users write:

```qqqpolicy
deny  http.client to host "*.onion"
allow sql.*      when subject.department == "engineering"
require mfa      when capability == "sign"
```

**The `qqqai why` command** is the killer DX affordance here: `qqqai why sql.orders` prints the full chain from manifest line → each overlay → final decision, with the rule that made it. This turns capability debugging from archaeology into a single command.

→ **Checklist:** `SEC-001` … `SEC-024`, `CAP-001` … `CAP-016`

## §6.3 `qqq-abi` — WIT interfaces as the single source of truth

**Purpose.** Define every host capability in WIT; generate every language binding from those definitions.

**The V1 interface set** (all under the `qqq:` namespace, versioned):

| Interface | Contents | Notes |
|---|---|---|
| `qqq:http@1.0` | server handler types, client, headers, request/response streaming | Built over `wasi:http`; adds routing and connection pooling |
| `qqq:fs@1.0` | opened directories, file handles, metadata, watch | Built over `wasi:filesystem`; adds quota and mode enforcement |
| `qqq:sql@1.0` | connection (from a named host-side pool), prepared statements, typed rows, transactions | Guest never sees credentials |
| `qqq:kv@1.0` | namespaced get/set/delete/scan with TTL | Backed by host-configured stores |
| `qqq:queue@1.0` | publish, subscribe (via `stream`), ack | |
| `qqq:crypto@1.0` | random, hash, hmac, aead, sign/verify, key derivation | Random is a capability |
| `qqq:clock@1.0` | wall, monotonic, timers, sleep | Controllable for determinism |
| `qqq:log@1.0` | structured, levelled logging with tenant attribution | |
| `qqq:trace@1.0` | spans, events, attributes | W3C Trace Context propagation |
| `qqq:secrets@1.0` | **use a named secret without ever reading it** | See below |
| `qqq:ai@1.0` | model inference with token accounting | §6.9 |
| `qqq:test@1.0` | assertions, property-test generation hooks | §6.7 |
| `qqq:agent@1.0` | self-description, capability introspection, structured progress | §8 |

**`qqq:secrets` deserves special mention** because it is a genuinely new primitive. Today, a service reads `DATABASE_URL` from the environment, which means the secret is *in the guest's memory* and can be exfiltrated by a compromised or malicious dependency. QQQ inverts this:

```wit
interface secrets {
    /// Use a secret to produce a result, without the secret ever entering
    /// guest memory. The secret is named; the guest can never read it.
    use: func(name: string, op: secret-op, input: list<u8>) -> result<list<u8>, secret-error>;
    /// Ask whether a secret exists (no value disclosed).
    exists: func(name: string) -> bool;
}
```

The canonical use — signing a JWT — becomes: the guest sends the *claims*, the host signs with a key the guest never learns. If the guest is fully compromised, it can ask for signatures (a capability the manifest granted) but cannot steal the key. **This eliminates an entire category of breach** and is the kind of feature that makes security teams adopt a platform.

**WIT style guide (enforced in review, `CON-011`):**
1. Batch-first: list-shaped operations take lists.
2. Streaming for anything that can exceed 64 KiB.
3. Explicit `result<T, E>`; no sentinel values, no `-1` returns.
4. No `option<option<T>>` ambiguity; model the domain.
5. Document every function with a `///` doc comment — it becomes the generated docs.
6. `@since(version = "1.0.0")` on every published function.

→ **Checklist:** `CON-001` … `CON-018`, `ABI-001` … `ABI-016`

## §6.4 `qqq-serve` — the HTTP and application server

**Purpose.** Turn a component into a network service, with production-grade connection handling.

**Scope in V1:** HTTP/1.1 (complete), HTTP/2 (complete), WebSockets over both, Server-Sent Events, gRPC via `wasi:http` + `qqq:grpc` (beta), HTTP/3/QUIC behind a flag (beta).

**Routing.** A compile-time-known route table from `qqq.toml`, compiled into a radix trie at load. No reflection, no runtime route registration, no dynamic dispatch on the hot path.

**Body handling.** Bodies are `stream<u8>` end-to-end. Backpressure propagates from the client socket through the host to the guest's stream and back. There is no point at which a request body is fully buffered unless the manifest asked for it (`max_request_bytes` is a *cap*, not a buffer).

**Connection management.** HTTP keep-alive, configurable idle timeouts, connection limits per tenant, graceful shutdown with in-flight request draining, and listener sharding (§4.2).

**TLS.** rustls, TLS 1.3 preferred, 1.2 permitted, with a documented cipher policy. Certificate sources: files, ACME (opt-in), or platform-provided. Client certificates (mTLS) are a supported `default_auth` mode.

**Failure modes:** slow-loris (mitigated by header read deadlines and per-connection rate limits), body bombs (mitigated by `max_request_bytes` enforced *during* streaming, not after), and header bombs (mitigated by caps on header count and size).

→ **Checklist:** `SRV-001` … `SRV-020`, `SEC-016`

## §6.5 `qqq-pkg` — package manager and registry

**Purpose.** A dependency manager that is fast, verifiable, and capability-aware.

**Design commitments:**

| Commitment | Detail |
|---|---|
| **Fast** | Content-addressed global store with hard-links/reflinks; parallel fetch; HTTP/3 where available; lockfile-first resolution |
| **Verifiable** | Every artifact is signed; signatures verified against a configurable trust policy; `--frozen` refuses to resolve anything not in the lockfile |
| **Capability-aware** | Dependencies declare capabilities; installing shows the **capability diff** (§5.4); transitive capability escalation is visible before it is accepted |
| **Reproducible** | The lockfile hash covers all resolved artifacts; rebuilds are bit-identical or the build fails |
| **Offline-capable** | `--offline` works fully from the store; air-gapped mirrors are a first-class Fabric feature |

**Registry.** `registry.qqq.codes`, itself a QQQ application (dogfooding from day one — if our own registry cannot run on our runtime, we have not shipped). Immutable versions, yank support, provenance attestation (SLSA-style), and a public API with a published schema.

**Namespaces.** `qqqai/*` reserved for the core team. Scoped names (`@org/pkg`) for organizations with verified ownership. No squatting protection by payment — by prove-your-identity, which keeps the ecosystem open.

→ **Checklist:** `PKG-001` … `PKG-024`, `SUP-001` … `SUP-012`

## §6.6 `qqq-run` — CLI and dev server

**Purpose.** The daily-driver surface.

**Hot reload (`qqqai dev`).** Three-tier strategy, chosen automatically:

| Tier | Mechanism | Latency | When |
|---|---|---|---|
| 1 | **Component swap** — rebuild the changed component, swap it into the running host, keep the host process | ~50–300 ms | Any code change (default) |
| 2 | **State-preserving swap** — same, but the host transfers serializable guest state across the swap where the guest declares it | ~100–500 ms | When `[dev] preserve_state = true` |
| 3 | **Full restart** — required when manifest capabilities or limits change | ~1–2 s | Manifest edits only |

Tier 1 is the breakthrough: because the guest is a *component instance*, not a language runtime's heap, replacing it is a pointer swap. Node and Bun fundamentally cannot do this — restarting means rebuilding the JS heap. **This is a visible, felt DX advantage that follows directly from the architecture.**

**Also in V1:** file watcher with debounce and ignore rules; HTTPS with locally-trusted certificates; a built-in inspector (Chrome DevTools Protocol adapter over DWARF, `qqq-debug`); request logging with tenant/trace correlation; and `--open` to launch a browser.

→ **Checklist:** `DX-001` … `DX-020`, `CLI-020` … `CLI-024`

## §6.7 `qqqai test` — test runner

**Purpose.** Testing that exploits the architecture rather than imitating one.

**Standard features:** test discovery per language, filtering, parallel execution, JUnit/TAP/JSON output, coverage (via Wasm-level instrumentation + DWARF source mapping), watch mode.

**Architecture-enabled features — these are the differentiators:**

| Feature | What it does | Why only QQQ can do it |
|---|---|---|
| **`--trials N` determinism check** | Runs a test N times under different seeds and scheduling; any output difference is a failure | Requires deterministic mode (§10.5) |
| **Deterministic replay** | A failing test records a replay log; `qqqai test --replay <log>` reproduces the exact run | Requires host-mediated time, RNG and scheduling |
| **Capability assertions** | `assert_caps!` fails a test if the code under test attempts a capability the test declared it should not need | Requires the capability engine |
| **Fuel assertions** | `assert_fuel_below!(n)` turns a performance regression into a test failure | Requires deterministic metering |
| **Property tests with shrinking** | Generated in the language, driven by the host harness, replayable | |
| **Cross-language conformance** | The same test suite runs against all five language implementations | Requires WIT as source of truth |

→ **Checklist:** `TEST-001` … `TEST-018`, `DET-010`

## §6.8 `qqqai migrate` — the adoption ramp

**Purpose.** Meet people where they are. This is the single most important go-to-market tool.

**Scope (V1, deliberately bounded):**

| Source | What migrates automatically | What you must rewrite |
|---|---|---|
| Node/Express | Route table, middleware ordering, JSON body handling, env-var access inventory, package inventory with alternatives suggested | Business logic (must be recompiled to Wasm), any Node API with no WASI equivalent |
| Bun | Same as Node, plus Bun-specific APIs flagged individually | |
| Deno | Permissions map almost 1:1 onto capabilities | |
| Raw Wasm | Wraps a core module into a component with a generated manifest | Imports must be satisfiable |

**Output is a report, not a black box:** `migration-report.md` + `migration-report.json` listing every file touched, every API with no equivalent, every capability inferred, and a **confidence score per file**. The agent face (§8) means an AI agent can consume that report and finish the migration autonomously — which is the intended workflow, and a substantial market advantage.

→ **Checklist:** `MIG-001` … `MIG-014`, `GTM-003`

## §6.9 `qqq:ai` — local inference as a capability

**Purpose.** Let a guest call a model without the host losing control of cost, data, or latency.

**Design principles:**
1. **The host owns the model, the memory and the accounting.** The guest gets an interface, not a pointer.
2. **Tokens are a metered resource**, exactly like fuel. `max_tokens_per_request` in the manifest is enforced by the host.
3. **Local-first.** The default provider is a local runtime (GGML-family) so nothing leaves the machine. Cloud providers are an explicit, separately-granted capability with a named endpoint.
4. **Never in the request path by default.** A model call is a 10–2000 ms operation; QQQ does not pretend otherwise. The interface is `async` and the docs say so loudly.

**Honest assessment:** this is a *differentiator we should build, but late*. It is V3 material unless an early design partner pulls it forward. The interface is specified now so that the capability model is coherent from the start, but implementation is deferred (`FUT-007`).

→ **Checklist:** `AI-001` … `AI-010`, `FUT-007`

## §6.10 Language toolchains — one per target language

The multi-language promise lives or dies here. Honest per-language status:

| Language | Compile path | V1 tier | Honest difficulty |
|---|---|---|---|
| **Rust** | `cargo build --target wasm32-wasip2` (native support) | **Tier A — excellent** | None. Rust is Wasm's best-supported language and the Component Model originated in the Rust ecosystem. |
| **TypeScript** | Via **AssemblyScript** (a TS subset). Optionally via a JS engine compiled *to* Wasm for compatibility mode. | **Tier A for AssemblyScript, Tier C for full TS** | AssemblyScript is not TypeScript: no full type system, different stdlib. Full TS requires an engine-in-Wasm (e.g. a JSC/V8 port or QuickJS), which is heavy and slower. **V1 ships AssemblyScript as "TypeScript"; the docs must never overstate this.** |
| **Go** | **TinyGo** (official Go support for Wasm components is still limited) | **Tier B — good, with caveats** | TinyGo has different runtime semantics, a reduced stdlib, and GC inside the guest. Standard Go's `wasm` targets remain weak for components. |
| **Python** | **CPython compiled to WASI** | **Tier B — works, with a size and startup cost** | CPython+stdlib to Wasm is multi-megabyte and has a noticeable init cost; mitigations are precompiled `.pyc` bundled in the component and an interpreter-instance pool. This is the biggest engineering unknown in the language matrix. |
| **C / C++** | `clang --target=wasm32-wasip2` + `wit-bindgen` | **Tier A — excellent** | Well-trodden. `wasm-ld` and `wit-bindgen` are mature. |

**The parity commitment.** All five must pass the identical conformance suite. Where a language cannot reach a capability (TinyGo and some networking APIs, for example), the gap is documented in the published parity matrix with an owner and a target date — never hidden.

**Why this matters for the product claim.** "Multi-language" is the hardest promise in this document and the one most likely to be quietly abandoned. The parity matrix in CI exists specifically so drift is *visible*.

→ **Checklist:** `LANG-001` … `LANG-040`

---

# §7 — Security and Trust Model

## §7.1 What we are defending, precisely

| Asset | Why it matters |
|---|---|
| Host process integrity | Compromise means total tenant compromise |
| Tenant data (memory, files, DB rows) | The primary harm |
| Secrets (keys, connection strings, tokens) | Enables lateral movement and long-term compromise |
| Host resources (CPU, memory, disk, network) | Denial of service, cost attacks |
| Supply chain integrity | A malicious dependency is the most likely real attack |
| Audit integrity | If logs can be forged, nothing else can be investigated |

## §7.2 Adversary model

| Adversary | Capability assumed | Primary defence |
|---|---|---|
| **Malicious guest** | Full control of guest code and guest memory; can craft adversarial Wasm | Wasm sandbox + capability grants + limits + trap-on-violation |
| **Malicious dependency** | Same, but arrives via the package manager | Capability diff at install (§5.4), signatures, provenance, `qqqai audit --fail-on` in CI |
| **Compromised tenant** | Legitimate but hostile within its own tenant | Per-tenant isolation; no cross-tenant handles; tenant-scoped audit |
| **Hostile network client** | Can send arbitrary HTTP | Header/body caps, deadlines, rate limits, TLS policy |
| **Insider with deploy access** | Can change configuration | Signed config, audit trail, Fabric RBAC, four-eyes policy on production changes |
| **Supply-chain nation-state** | Can compromise an upstream project | Reproducible builds, provenance attestation, hash pinning, mirrors |
| **Nation-state against the sandbox** | Can find Wasm escapes | Wasmtime's security process, our upgrade cadence, fuzzing, and honest disclosure of what we cannot defend against |

**Explicitly out of scope for V1** (stated so nobody assumes otherwise):
- A malicious **host** administrator. If you control the host process, you control everything. That is true of every runtime and honesty requires saying so.
- **Side-channel** attacks (cache timing, Spectre-class) across tenants. Wasmtime has mitigations and research continues; QQQ does not currently claim side-channel isolation between tenants, and the docs will say so.
- **Physical** access.
- **Denial of service by sheer volume** beyond what rate limiting and autoscaling can absorb.

## §7.3 The defence timeline — where we stop an attack

```
 supply chain ─▶ build ─▶ sign ─▶ publish ─▶ install ─▶ load ─▶ instantiate ─▶ call ─▶ run
      │           │        │        │          │         │          │           │       │
      │           │        │        │          │         │          │           │       └─ fuel/epoch
      │           │        │        │          │         │          │           └─ grant re-check (§4.4)
      │           │        │        │          │         │          └─ linker built from grants only
      │           │        │        │          │         └─ static capability report (qqqai inspect)
      │           │        │        │          └─ capability diff shown before accept
      │           │        │        └─ provenance attestation verified
      │           │        └─ signed artifact
      │           └─ reproducible build + SBOM emitted
      └─ dependency audit, hash pinning, mirror verification
```

Seven independent gates. An attacker must pass all of them. This is the actual product.

## §7.4 Cryptographic posture

| Purpose | Algorithm | Notes |
|---|---|---|
| Transport | TLS 1.3 (rustls) | 1.2 permitted; cipher policy documented and enforced |
| Artifact signing | Ed25519 | Small keys, fast verification, no parameter choices |
| Hashing | SHA-256 / BLAKE3 | SHA-256 for interop, BLAKE3 where we control both ends |
| AEAD | AES-256-GCM, ChaCha20-Poly1305 | Hardware-accelerated path selected at runtime |
| Password hashing | Argon2id | With documented parameters |
| Randomness | Host CSPRNG | `getrandom` → OS entropy; **never** a guest-supplied seed except in deterministic test mode |
| Post-quantum | Hybrid X25519+ML-KEM for TLS (opt-in) | Tracked `SEC-021`; standards are settling, so this is ahead of the curve, not behind |

**Policy:** no algorithm agility without a version bump. A manifest names algorithms explicitly; there are no "default" choices that could silently change under the user.

## §7.5 Hardening beyond Wasm

Wasm is the primary boundary but not the only layer:

| Layer | Technique | Availability |
|---|---|---|
| Host process | Dropped privileges, `no_new_privs`, minimal capabilities | Linux |
| Syscalls | seccomp-BPF allowlist after startup | Linux |
| Filesystem | Landlock LSM for defence in depth behind the capability engine | Linux ≥ 5.13 |
| Memory | W^X enforcement, guard pages, optional MPK | All |
| Network egress | Optional egress proxy with per-tenant policy | All |
| Container | Distroless image, read-only root, non-root user | All |

**Design rule:** none of these are *required* for QQQ's security claim. The capability engine is the boundary; these are depth. A host without seccomp is still safe against a malicious guest, and that is the property that makes QQQ deployable anywhere.

→ **Checklist:** `SEC-001` … `SEC-024`, `SEC-030` … `SEC-030`

---

# §8 — AI-Agent-Native Design

This section is the strategic core. Everything else is engineering; this is the reason the project has a chance to be *chosen* rather than merely *available*.

## §8.1 The four agent relationships

QQQ serves agents four distinct ways, and conflating them is a mistake:

| # | Relationship | What it needs from QQQ |
|---|---|---|
| 1 | **Agent as author** — an agent writes QQQ code | Great docs, predictable APIs, error messages that teach, `--json` everywhere |
| 2 | **Agent as operator** — an agent runs, deploys, debugs QQQ apps | MCP server, structured diagnostics, safe-by-default commands, dry-run everywhere |
| 3 | **Agent as host inside QQQ** — an agent runtime runs *on* QQQ | Isolation, density, cold start, per-session capability scoping |
| 4 | **Agent as adversary** — agents and their generated code are untrusted | The entire capability model (§7) |

Relationship 3 is the commercial wedge. Relationship 4 is why the architecture is what it is.

## §8.2 `qqqai mcp` — the Model Context Protocol server

QQQ ships a first-class MCP server. This means any MCP-capable agent (Claude, Cursor, custom frameworks) can drive QQQ without special integration work.

**Exposed tools (V1):**

| Tool | Purpose | Mutating? |
|---|---|---|
| `qqq_new` | Scaffold a project | Yes (dry-run supported) |
| `qqq_build` | Build, return structured diagnostics | No |
| `qqq_run` | Run with explicit capabilities | Yes |
| `qqq_test` | Run tests, return structured results | No |
| `qqq_inspect` | **Static capability report for an artifact** | No |
| `qqq_audit` | Security posture + SARIF | No |
| `qqq_caps_explain` | Why is this capability granted/denied | No |
| `qqq_dev_status` | Dev server state, recent errors | No |
| `qqq_schema` | Fetch JSON Schema for any surface | No |
| `qqq_logs` | Query structured logs | No |
| `qqq_metrics` | Query metrics | No |
| `qqq_trace` | Query traces | No |
| `qqq_doctor` | Environment diagnosis | No |
| `qqq_migrate_plan` | Analyse a Node/Bun project, return a migration plan (no writes) | No |

**Design rules for these tools:**
- Every tool returns **structured content**, never prose-only. A tool that returns a string nobody can parse is a wasted tool.
- Every mutating tool has a `dry_run` parameter, and the description tells the model to use it first.
- Tool descriptions are written *for a model*, then reviewed by a human — not the other way round.
- Errors return a `code`, a `remediation`, and a `docs_url`, so an agent can self-correct without a human.

## §8.3 The machine contract layer

**`qqqai schema --all`** emits a JSON document containing:

```jsonc
{
  "qqqai": "1.0.0",
  "schemaVersion": "1.0.0",
  "commands": { /* per-command input/output JSON Schema */ },
  "errors":   { /* every QQQ-XXXX code, its meaning and remediation */ },
  "manifest": { /* JSON Schema for qqq.toml */ },
  "capabilities": { /* every capability name, its parameters, its semantics */ },
  "wit":      { /* machine-readable interface descriptions */ },
  "mcp":      { /* MCP tool schemas */ }
}
```

This single document is what makes QQQ teachable to a model that has never seen it. It is versioned, it is stable within a major version, and CI fails if it drifts from the implementation.

**Error code format: `QQQ-<class><nnn>`**, with a fixed class table:

| Class | Domain | Example |
|---|---|---|
| 1xxx | Build / compile | `QQQ-1004` — WIT interface mismatch |
| 2xxx | Manifest / configuration | `QQQ-2007` — capability syntax invalid |
| 3xxx | Runtime guest trap | `QQQ-3001` — memory limit exceeded |
| 4xxx | Capability denial | `QQQ-4003` — `sql.query` not granted |
| 5xxx | Package / registry | `QQQ-5002` — signature verification failed |
| 6xxx | Host / infrastructure | `QQQ-6001` — instance pool exhausted |
| 7xxx | Agent / protocol | `QQQ-7001` — MCP tool argument validation failed |

Every code has a stable docs URL: `https://qqq.codes/errors/QQQ-4003`.

## §8.4 The "agent sandbox" reference architecture

The concrete, sellable use case. A platform wants to run model-generated code on behalf of users.

```
 user prompt ─▶ LLM ─▶ generated Python/Rust/TS ─▶ compile to component
                                                          │
                                                          ▼
                                    ┌─────────────────────────────────┐
                                    │  QQQ host                       │
                                    │  caps:  fs(/tmp/<session>) rw   │
                                    │         http.client([allowlist])│
                                    │         clock, random           │
                                    │  limits: 64MiB, 2e9 fuel, 5s    │
                                    │  no:    env, secrets, raw sockets│
                                    └─────────────────────────────────┘
                                                          │
                                                          ▼
                                    audit record: exactly what it touched
```

**What this gives a platform that containers do not:**
- ~100 µs instantiation versus ~10–100 ms — 100–1000× less overhead per execution
- KB-scale memory versus MB-scale — 100× more concurrent sessions per host
- **Provable** capability scope, checkable *before* execution
- Per-execution audit of exactly which capabilities were used
- Deterministic replay of any execution for post-incident analysis

This is a product a platform team will pay for, and it is the beachhead.

## §8.5 Making the codebase legible to machines

| Practice | Implementation |
|---|---|
| `llms.txt` at repo root and docs site | Curated index of what to read, in what order |
| `llms-full.txt` | Full documentation concatenated for context loading |
| WIT-first docs | Interfaces rendered to Markdown with examples per language |
| Machine-readable changelog | `CHANGELOG.json` alongside `CHANGELOG.md` |
| Machine-readable migration guides | `migrations/<version>.json` with exact find/replace and semantic transformations |
| Agent-readable test fixtures | Every error code has a minimal reproducer in `tests/agent-cookbook/` |
| Reference agent transcripts | Real, successful agent sessions committed as examples |

→ **Checklist:** `AGENT-001` … `AGENT-024`

---

# §9 — Performance Engineering

## §9.1 The honest benchmark position

We will publish a benchmark suite that is **harder to game than the ones we are compared against**, and we will report losses.

| Benchmark | What it measures | Our expected position |
|---|---|---|
| `hello` — empty HTTP response | Raw framework + runtime overhead | **Behind Bun, near/above Node.** Bun is exceptional here. |
| `json` — serialize 1 KB object | Serialization + ABI | **Ahead** |
| `route` — 100 routes, path params | Routing | **Ahead** |
| `db` — 10 queries against Postgres | Real I/O + pooling | **Ahead** (pool reuse, no GC) |
| `crypto` — 1 KB SHA-256 ×10k | Compiled compute | **Far ahead** |
| `template` — render 100-row HTML table | String building | **Ahead** |
| `cpu` — prime sieve / matrix multiply | Pure compute | **Far ahead** |
| `multi` — saturate 8 cores | Concurrency model | **Ahead** (no single-threaded event loop) |
| `tailp99` — 30-minute sustained load | Tail latency | **Far ahead** (no GC) |
| `cold` — instantiate and serve once | Cold start | **Far ahead** vs containers; comparable vs Bun |

**Methodology requirements** (published with every result): pinned hardware listed by model; pinned OS and kernel; pinned toolchain versions; warmup procedure stated; percentiles, not averages; concurrency levels disclosed; three repetitions with variance; the benchmark harness itself open source; and a "what this does not measure" section. A benchmark without these is marketing, and we should not publish it.

## §9.2 The performance budget

Numeric targets. These are the numbers engineering is held to, and each has a measurement method in `bench/`.

| Metric | Target | Measurement |
|---|---|---|
| Warm instance acquire | ≤ 100 µs p99 | Pooled instance, in-process timer |
| Cold instantiate (AOT cached) | ≤ 5 ms p99 | From `Component::deserialize` to callable |
| Cold instantiate (from `.wasm`) | ≤ 150 ms p99 | Includes Cranelift compilation |
| `qqqai --version` | ≤ 15 ms | Process spawn to exit |
| Routed request overhead (empty handler) | ≤ 60 µs p99 | Host-side, excluding guest work |
| RSS, idle host, 0 instances | ≤ 25 MB | `rss` after 60 s idle |
| RSS, 1000 idle instances | ≤ 350 MB | Pooled, 128 MiB caps but lazily grown |
| Throughput, reference app, 8 cores | ≥ 60k RPS | `json` benchmark, 1 KB payload |
| p99 request latency, reference app, 10k RPS | ≤ 2 ms | `tailp99` |
| Memory per instance, reference app | ≤ 256 KB | Pooled slot accounting |
| `qqqai build`, 10k LOC Rust | ≤ 20 s | Clean build, 8 cores |

> **✅ Measured baseline (2026-09-19).** The first budget line has already been **validated with large headroom**, by an independent probe run against Wasmtime 48.0.2 on the reference development machine. Instantiating a compiled component into a **brand-new `Store` per sample, with no pooling allocator at all** — the worst realistic case — measured **min 700 ns, p50 800 ns, p99 2.1 µs** over 500 samples.
>
> The proposal budgeted ≤ 100 µs p99 for the *pooled* path. The measured number is roughly **50× better than budget**, and the pooling allocator only improves on the unpooled figure. This is the strongest measured result in the project to date, and it directly underwrites the density argument in §3.3: at sub-microsecond instantiation, per-request isolation stops being a performance compromise and becomes free.
>
> Reproduce with `cargo run --release` in the verification probe crate. Full findings, including the three WAT/ABI details this cost us, are in `QQQ-Observations-and-Memories.md §O-006`.

**Anti-goal, stated explicitly:** we do not target winning synthetic HTTP micro-benchmarks. If we later win them, good; promising it sets us up to be judged on the one axis where we are structurally weakest.

## §9.3 The ABI cost, quantified honestly

The Component Model canonical ABI has real overhead. Approximate figures for planning (to be replaced by measured numbers in `PERF-005`):

| Operation | Approx. cost | Note |
|---|---|---|
| `u64` argument + return across boundary | ~2–5 ns | Effectively free |
| String `(ptr,len)` copy in, small | ~25–70 ns | Dominated by bounds checks and copy |
| `list<u32>` of 1000 elements | ~1–3 µs | O(n), unavoidable without shared memory |
| Resource handle create | ~15–40 ns | Table slot allocation |
| Async `future` rendezvous | ~100–400 ns | Acceptable; replaces a thread wakeup |
| `stream<u8>` chunk (64 KiB) | ~2–8 µs | Memory-bandwidth bound |

**The conclusion this forces:** QQQ is fast for *compute-heavy, few-crossings* workloads and merely competitive for *chatty, crossing-heavy* workloads. The design response is the batch-first WIT rule (§4.5) and `stream`/`resource` usage. The honest marketing response is to steer benchmarks and reference apps toward real application shapes, not microbenchmarks.

## §9.4 Specific optimizations planned

| Optimization | Expected effect | Risk |
|---|---|---|
| Pooling allocator with pre-warmed slots | Instantiation 10–100× | Memory overcommit if misconfigured |
| AOT `.cwasm` cache keyed by digest+config | Cold start 10–30× | Cache invalidation correctness |
| Module deduplication across tenants (same artifact = same compiled code) | Compile once, serve N | None; correctness preserved by digest keying |
| Listener-per-shard (no cross-core accept handoff) | ~5–15% throughput | More sockets; fine on all targets |
| Zero-copy response path for `stream` bodies | Avoids double buffering | Requires careful lifetime handling |
| SIMD via the `simd` proposal for JSON/parsing in `qqqai/json` | 2–10× on hot parse paths | Portability (all Tier 1 targets have SIMD) |
| `wasm_component_model_async` + `stream` | Avoids per-call rendezvous for streaming | WASI 0.3 maturity |
| Static routing trie, no allocations | ~10–20% on routing | None |
| Huge pages for guest linear memory | Fewer TLB misses | Platform support varies |
| Optional io_uring reactor (Linux) | 10–30% syscall-heavy paths | Complexity; hence opt-in |

→ **Checklist:** `PERF-001` … `PERF-026`

---

# §10 — Telemetry, Observability and Determinism

## §10.1 The three signals, plus one unique to QQQ

Standard: **traces** (W3C Trace Context, OTLP export), **metrics** (Prometheus + OTLP), **logs** (structured JSON with tenant and trace correlation).

**The QQQ-specific fourth signal: the capability audit stream.** Every capability use — granted, denied, and *attempted* — is recorded with tenant, component digest, manifest revision, function, and outcome. This is not a log; it is an evidence record, append-only, hash-chained, exportable as SARIF and as a compliance report.

Why it matters: "prove what this code did" is the question regulators, security teams and incident responders actually ask, and no other runtime can answer it structurally.

## §10.2 Metrics that ship by default

| Category | Metrics |
|---|---|
| Instance | acquired, created, released, pool saturation, acquire latency histogram |
| Execution | fuel consumed, epoch deadlines hit, traps by code |
| Memory | per-instance peak, host RSS, pool occupancy |
| HTTP | requests, status classes, latency histograms, body bytes, connection count |
| Capability | uses by capability, denials by capability, by tenant |
| Supply chain | artifacts loaded, signature checks, cache hit rate |
| Cost | fuel→CPU estimate, bytes egress, model tokens (if `qqq:ai` used) |

**Cardinality discipline:** no metric label may take an unbounded value (no raw paths, no user IDs, no full URLs). Enforced by a lint on metric definitions. High-cardinality data goes to traces, not metrics.

## §10.3 Logging

Structured JSON by default; human-readable in a TTY. Every line carries `trace_id`, `span_id`, `tenant`, `component`, `manifest_rev`, `level`, `msg`, `code?`. Redaction is applied by the **host**, not the guest, using manifest-declared secret names — so a guest cannot leak a secret it was never given (§6.3).

## §10.4 Distributed tracing

Automatic spans for: inbound request, routing, instance acquire, guest entry, each host capability call, outbound HTTP, DB queries, and instance release. Trace context propagates through `wasi:http` headers and through the `qqq:trace` interface. Sampling is host-controlled (head-based with tail sampling option) and *never* guest-controlled.

## §10.5 Determinism — the feature nobody else has

**The claim.** With `[determinism] enabled = true`, executing the same component with the same inputs produces a bit-identical result, and the execution is recorded in a replay log sufficient to reproduce it exactly — including any failure.

**How it works:**

| Source of nondeterminism | Control |
|---|---|
| Wall clock | `qqq:clock.wall` returns `determinism.fixed_clock`, advancing only by explicit host ticks |
| Monotonic clock | Virtualized; advances deterministically with fuel or explicit ticks |
| Randomness | `qqq:crypto.random` is a seeded CSPRNG (ChaCha20 with `determinism.seed`) |
| Async scheduling | A deterministic scheduler in deterministic mode: same poll order, same interleavings, single-threaded executor |
| Float behavior | `cranelift_nan_canonicalization` on; relaxed-SIMD fusion disabled in deterministic mode |
| HashMap iteration order | Banned in host interfaces exposed to guests; ordered maps only |
| Network timing | Recorded and replayed from the replay log (`--replay`) |
| Compilation | AOT artifact pinned by digest; same compiler version required for bit-identical codegen |
| Threads | Deterministic mode is single-threaded; shared memory is forbidden |

**What it enables:** deterministic replay debugging, reliable property-based testing, reproducible benchmarks, and — commercially — **auditable AI agent actions**, where you can replay exactly what an autonomous system did.

**Honest limits:** determinism holds for a given (artifact digest, engine version, target triple, config). It does not survive a Wasmtime upgrade that changes codegen in an observable way, and it cannot serialize true external I/O without recording it. Both limits are documented rather than papered over.

→ **Checklist:** `DET-001` … `DET-016`, `OBS-001` … `OBS-018`

---

# §11 — Distribution, Packaging and Ecosystem

## §11.1 Install channels, in priority order

| Channel | Priority | Notes |
|---|---|---|
| `install.sh` / `install.ps1` from `qqq.codes` | **P0** | Must work on a bare machine with only `sh`/`curl` or PowerShell |
| GitHub Releases (binaries + checksums + signatures) | **P0** | The source of truth for the installers |
| `cargo install qqqai` | **P0** | Rust-native users |
| `npm install -g qqqai` | **P0** | Reaches the largest developer population; thin wrapper fetching the real binary |
| Homebrew | **P1** | macOS/Linux expectation |
| Scoop + winget | **P1** | Windows expectation |
| Docker / OCI image | **P1** | `ghcr.io/qqqai/qqqai` |
| apt / dnf / apk repositories | **P2** | Once there is a stable release cadence |
| AUR, Nix, asdf, mise | **P2** | Community; we provide specs and support |

**Verification is part of distribution:** every binary ships with SHA-256 checksums, an Ed25519 signature, and a provenance attestation. `qqqai doctor` verifies its own binary. An installer that cannot be verified is an installer that will be backdoored eventually.

## §11.2 The registry and ecosystem

**`registry.qqq.codes`** — itself a QQQ application:

| Feature | Detail |
|---|---|
| Immutable versions | A published version can be yanked, never overwritten |
| Provenance | Every artifact carries a SLSA-style attestation of how it was built |
| Capability metadata | Every package declares its capabilities; the registry surfaces them on the package page and in the API |
| Search | Full-text over names, descriptions, interfaces, and *capabilities* — "find me a JSON parser that needs no capabilities" is a query you can actually run |
| Mirrors | Self-hostable; Fabric supports air-gapped mirrors |
| API | Fully documented, schema-published, rate-limited fairly |

**Ecosystem bootstrap plan** (this is the hard part, and it deserves honesty):
1. **Port the essentials ourselves.** JSON, HTTP client, validation, logging, testing, crypto, date/time, arrays/collections. Roughly 30 packages. This is not optional — an empty registry is a dead registry.
2. **Port a curated top-200 of high-value libraries** from the Node and Rust ecosystems, where licences permit and where the API is a good fit. Publish them under `qqqai/*` with the original authors credited.
3. **Make porting ridiculously easy.** `qqqai new --template lib` plus a published "port a library in an afternoon" guide, plus agent-assisted porting using `migrate`.
4. **Incentivize.** A public porting bounty program (the first 500 packages get a badge, upstream contributors get support, and high-value ports get direct grants).

## §11.3 Documentation as a product surface

| Artifact | Purpose |
|---|---|
| `docs.qqq.codes` | Human documentation, versioned per release |
| WIT reference | Generated, complete, with per-language examples |
| Recipes | Task-oriented: "connect to Postgres", "rate limit", "stream a large file", "run untrusted code" |
| Interactive playground | Run QQQ in a browser via a Wasm build of the host (V2) |
| Benchmarks dashboard | Live, reproducible results with hardware disclosure |
| Agent corpus | `llms.txt`, `llms-full.txt`, agent cookbook, reference transcripts |
| Error catalogue | Every `QQQ-XXXX` with cause, fix, and example |

→ **Checklist:** `DIST-001` … `DIST-020`, `PKG-001` … `PKG-024`, `DOC-001` … `DOC-020`

---

# §12 — Developer and Agent Experience

## §12.1 The first ten minutes (a spec, not a wish)

```bash
$ curl -fsSL https://qqq.codes/install.sh | sh
  ✓ qqqai 1.0.0 installed to ~/.local/bin

$ qqqai new orders-api --lang rust --template http
  ✓ Created orders-api/
  ✓ Wrote qqq.toml (0 capabilities granted — your app can't touch anything yet)
  ✓ Wrote src/lib.rs
  ✓ Wrote 2 tests
  Next:  cd orders-api && qqqai dev

$ cd orders-api && qqqai dev
  ✓ Compiled in 412ms
  ⟳ Listening on http://127.0.0.1:3000
  ⟳ Watching src/
  ⚠ This app has 0 capabilities. Add them to qqq.toml when you need them.
```

The warning is deliberate. **We tell the user what their code cannot do**, because the failure they will hit next is a capability denial, and a runtime that teaches its own security model at the moment of confusion beats one that teaches it in a README nobody reads.

## §12.2 Error message design standard

Every error message must contain, in this order:

1. **What happened**, in one sentence, no jargon.
2. **The stable code** (`QQQ-4003`) and a docs URL.
3. **Why** — the causal chain, not just the symptom.
4. **The fix**, as a runnable command or an exact diff where possible.
5. **A machine-readable block** in `--json` mode with `code`, `message`, `cause`, `remediation`, `docs`.

**Worked example — the standard we hold ourselves to:**

```
error[QQQ-4003]: capability denied

  The component "orders-api" tried to call sql.query against database "orders",
  but that capability is not granted by any configuration layer.

  → The manifest grants:  sql (none)
    Add this to qqq.toml:

        [[capabilities.sql]]
        name = "orders"
        driver = "postgres"
        host = "db.internal:5432"
        secret = "env:ORDERS_DB_URL"

  Why: capabilities are denied unless explicitly granted (PRINCIPLES.md §2.2).
       The organization policy "prod-baseline" does not widen grants.

  Run `qqqai why sql.orders` for the full resolution chain.
  Docs: https://qqq.codes/errors/QQQ-4003
```

## §12.3 The DX commitments (measurable, in CI)

| Commitment | Target | Enforced by |
|---|---|---|
| TTFA (install → running endpoint) | ≤ 3 minutes | CI job on a clean container |
| Time to first meaningful error message | ≤ 5 minutes for a deliberate mistake | Scripted DX test suite |
| Dev-server reload (tier 1) | ≤ 300 ms p50 | CI benchmark |
| `qqqai --help` for any command | ≤ 40 lines, actionable | Review standard |
| Every error code documented | 100% | CI check |
| Every public API has a compiling example | 100% | CI check |

→ **Checklist:** `DX-001` … `DX-020`

---

# §13 — Business Model, Licensing and Governance

## §13.1 The commercial problem, stated plainly

A runtime is infrastructure. Infrastructure has two revenue shapes: **support** (Red Hat) and **governance** (HashiCorp, Docker). Selling "the runtime itself" fails because a runtime's value grows with ubiquity, and charging for ubiquity is self-defeating.

## §13.2 The licence model, and why NN-8 still holds

> **This resolves the conflict flagged in §2.8.**

**Decision: open-core with a governance boundary, not a user-count boundary.**

| Component | Licence | Free for | Paid for |
|---|---|---|---|
| `qqqai` runtime, CLI, SDKs, package manager, dev server, test runner, all runtime crates | **Apache-2.0** | Everyone, always, including commercial use | — |
| `qqqai-caps`, `qqq-host`, `qqq-abi` as embeddable libraries | **Apache-2.0** | Everyone | — |
| **QQQ Fabric** (separate repo): org policy engine, fleet attestation, SSO/RBAC, compliance evidence export, air-gapped mirror, audit retention, multi-host control plane | **Business Source / commercial** | Individuals, solo developers, non-profits, and companies under $2M annual revenue (free personal & small-entity grant) | Companies above that threshold: subscription |
| **Commercial support** | Contract | — | SLAs, indemnification, named engineers |
| **Certification programme** | Contract | — | "QQQ Certified" for platforms and vendors |

**Why this satisfies both your instruction and NN-8:**

- Your instruction — *free for individuals and sole entrepreneurs, paid for small businesses to enterprises* — is implemented **at the Fabric layer**. An individual gets everything, including Fabric. A 20-person company pays for Fabric.
- NN-8 — *open source with a clear, permissive licence* — is satisfied for **the runtime**, which is the thing everyone must install. Nobody needs a lawyer to run `qqqai`.
- The commercial boundary sits exactly where enterprises actually pay: **governance, evidence, liability and support**. Not at "may I execute code".

**The honest trade-off.** This is not OSI open source for the Fabric component, and we should say so plainly rather than using weasel words like "open source" for a non-OSI licence. The Apache-2.0 runtime is irrevocable for the V1 line. If the community later demands the Fabric layer be opened, the fallback is a fair-source licence with a change date — pre-committed here so the decision is not made under pressure.

> ⚠️ **Not legal advice.** Licence texts require review by counsel before publication. See `Observations §O-011`.

## §13.3 Pricing sketch (for planning, not commitment)

| Tier | Who | Price | What |
|---|---|---|---|
| **Free** | Individuals, OSS, <$2M revenue | $0 | Everything, including Fabric |
| **Team** | Up to 25 engineers | ~$25/engineer/month | Fabric + email support |
| **Business** | Up to 250 | ~$60/engineer/month | + SSO, audit retention, 8×5 support SLA |
| **Enterprise** | 250+ | Custom | + indemnification, air-gapped, 24×7, TAM, custom SLA |
| **Platform/OEM** | Embedders | Custom | Redistribution rights, jointly-branded support |

Deliberately **no per-request, per-core, or per-deployment pricing.** Metering execution would contradict the entire premise of the product.

## §13.4 Go-to-market sequence

| Phase | Motion | Success signal |
|---|---|---|
| **0 — Credibility** | Publish the benchmark suite and the security model. Conference talks. Get criticized in public and respond well. | Respected engineers say "this is real, even if I'm not ready" |
| **1 — Agents** | `qqqai mcp`, the agent sandbox reference architecture, integrations with agent frameworks | Agent platforms embedding QQQ for code execution |
| **2 — Edge/serverless** | Density and cold-start case studies with real numbers | A platform publicly ships on QQQ |
| **3 — Polyglot teams** | Migration tooling, language parity, ported registry | First 100 production apps by teams not affiliated with us |
| **4 — Enterprise** | Fabric, compliance evidence, support | First paying enterprise contract |

**The single most important GTM decision:** do not market to JavaScript developers as "a faster Bun". Market to **platform teams that need to run untrusted code** and to **teams drowning in polyglot seams**. Those buyers have a problem QQQ solves completely, and they are not emotionally attached to npm.

→ **Checklist:** `GTM-001` … `GTM-014`, `LIC-001` … `LIC-012`, `GOV-001` … `GOV-014`

---

# §14 — Delivery Plan, Milestones and Budget

## §14.1 Milestones

| Milestone | Definition of done | Nominal duration (small team) |
|---|---|---|
| **M0 — Foundation** | Repo, CI, PRINCIPLES.md, licence, workspace skeleton, xref checker, ADR process | 2 weeks |
| **M1 — Heartbeat** | Load a hand-written component; call a host function; enforce memory + fuel + epoch; trap cleanly. No CLI niceties. | 6 weeks |
| **M2 — Capability engine** | Manifest → grants → linker; `qqqai inspect` produces a static capability report; denial is proven by test | 8 weeks |
| **M3 — HTTP** | `qqqai serve` runs a real component over HTTP/1.1 and HTTP/2; streaming bodies; TLS | 8 weeks |
| **M4 — DX v0** | `qqqai new/build/run/dev`; hot reload tier 1; error catalogue v1 | 8 weeks |
| **M5 — Language #2 and #3** | AssemblyScript and Go pass the conformance suite. This is the make-or-break milestone for the multi-language claim. | 12 weeks |
| **M6 — Package manager** | `qqqai add/install`, lockfile, registry MVP, capability diff | 10 weeks |
| **M7 — V1 private alpha** | Security audit #1 complete; benchmark suite published; first external users | 8 weeks |
| **M8 — Language #4 and #5** | Python (CPython/WASI) and C/C++ pass conformance | 12 weeks |
| **M9 — Agent face** | `qqqai mcp`, `schema --all`, agent cookbook, migration tool v1 | 8 weeks |
| **M10 — V1 public beta** | Docs, installers, registry public, two reference apps, security audit #2 | 10 weeks |
| **M11 — V1.0** | Stability guarantees in force, deprecation policy published, governance published | 6 weeks |

**Total: approximately 98 weeks (~23 months) for a small focused team.** This is the honest number for a runtime of this scope. It is not compressible by enthusiasm, and any plan that claims twelve months is lying to you.

## §14.2 Team composition

| Role | Count | Why |
|---|---|---|
| Systems/Rust engineer (Wasmtime depth) | 2 | The engine and capability layers are the product |
| Runtime/toolchain engineer | 1 | Language integrations, `wit-bindgen`, build pipeline |
| Platform/DevOps engineer | 1 | Release engineering, CI, registry, distro packaging |
| DX/full-stack engineer | 1 | CLI, dev server, error UX, docs tooling |
| Security engineer | 1 (part-time → full-time by M7) | Threat model, audits, fuzzing, capability review |
| Documentation/DevRel | 1 (from M5) | The ecosystem lives or dies here |
| Technical writer / docs engineer | 1 (from M7) | Machine + human docs parity |
| Founder/architect | 1 | Direction, RFCs, external |

**Minimum credible core: 5 engineers.** Below that, the language matrix will collapse and the multi-language claim becomes false.

## §14.3 Budget

| Category | Annual (USD, order of magnitude) |
|---|---|
| Salaries (6–8 people, blended) | $900k – $1.6M |
| Infrastructure (CI, registry, test hardware) | $40k – $90k |
| Security audits (2 external, pre-1.0) | $120k – $300k |
| Legal (licence, trademark, entity) | $30k – $80k |
| Tooling and licences | $15k – $40k |
| Marketing, conferences, docs site | $50k – $150k |
| **Total, to V1.0 (~2 years)** | **$2.3M – $4.5M** |

**This is the number a founder must plan around.** Anything materially below it means cutting a language, cutting security audits (not advisable), or extending the timeline.

## §14.4 What we would cut first, in order

If resources are constrained, cut in this order — and say so publicly rather than shipping a weaker version of a strong claim:

1. HTTP/3 and gRPC (keep HTTP/1.1 + HTTP/2)
2. Python and C/C++ (ship three languages, be honest that it is three)
3. `qqq:ai` (defer entirely — it is a differentiator, not a foundation)
4. Fabric (open the governance layer, monetise support only)
5. Windows support (ship Linux + macOS; Windows is a large tax for a smaller audience)
6. The registry (use OCI registries + git for distribution)

**Never cut:** the capability engine, the security audits, the conformance suite, or the benchmark honesty. Those are the product.

→ **Checklist:** `PLAN-001` … `PLAN-020`

---

# §15 — Risk Register

Likelihood × Impact. Every risk has an owner, a mitigation, and a **trigger** that tells us to change course.

| ID | Risk | L | I | Mitigation | Trigger to act |
|---|---|---|---|---|---|
| **R-01** | Ecosystem emptiness — no packages, so nobody can build anything real | **H** | **H** | Ship 30 core packages; curated ports; agent-assisted porting; bounties | <50 useful packages by M6 → reallocate 2 engineers to porting full-time |
| **R-02** | Language #3–#5 toolchains are too immature | **H** | **H** | Start language spikes at M1, not M8; contribute upstream to TinyGo/CPython-WASI | A language's spike fails twice → drop it from V1 and say so |
| **R-03** | Wasmtime API instability or a breaking change mid-project | M | H | Pin minor versions; vendor if needed; budget an upgrade sprint per quarter | Two consecutive upgrade sprints over 3 weeks |
| **R-04** | A Wasm sandbox escape with a CVE | M | **H** | Track Wasmtime advisories; ship upgrades within 72 h; defence-in-depth layers | Any CVE → immediate release + public advisory |
| **R-05** | Performance is not competitive even on our chosen axes | M | H | The tcp/ABI work is front-loaded (M3); measure early; pivot messaging to density/isolation if needed | M3 benchmarks miss budget by >2× |
| **R-06** | Node/Bun copy the security story (Deno-like permissions) | M | M | Our moat is the Component Model and provable isolation, which requires an architecture change they cannot make cheaply | A competitor ships component-level capability isolation → accelerate agent features |
| **R-07** | The licence model deters enterprise adoption | M | H | Apache-2.0 for the runtime; Fabric is additive; publish a clear FAQ; offer free Fabric for evaluation | Enterprise deals stall on licence → open more of Fabric |
| **R-08** | Security audit finds a structural flaw late | M | **H** | Audit #1 at M7, before public beta; architecture review at M2 | Any structural finding → halt feature work |
| **R-09** | Team/runway runs out before V1 | **H** | **H** | Milestone-gated scope cuts (§14.4); raise against M3 evidence, not M0 promises | <6 months runway before M7 → execute cut list |
| **R-10** | "Framework" positioning confuses the market (runtime vs web framework) | M | M | Ruthless vocabulary discipline (§3.4); always say "runtime" | Confusion persists in user research after 3 months |
| **R-11** | CPython-to-Wasm is too slow/large for production | M | M | Measure at M5; if unusable, mark Python "experimental" honestly | Component >20 MB or cold start >300 ms |
| **R-12** | Trademark friction over "QQQ" (Invesco ETF association) | M | M | File in software classes early; have `qqqai` as the fallback mark; legal review before launch | Any office action or cease-and-desist |
| **R-13** | Documentation/agent-contract drift makes agents generate wrong code | M | H | `check-xrefs` + schema drift CI + agent benchmark suite | Agent benchmark success <70% |
| **R-14** | WebAssembly Component Model / WASI standard changes | M | M | Track the standards process; isolate churn behind `qqq-abi`; version interfaces | A breaking ABI change in WASI 0.3+ |
| **R-15** | Founder/maintainer concentration — the project is one person's vision | **H** | **H** | Document everything (this corpus is the start); write governance; recruit a co-maintainer before M5 | Bus factor remains 1 at M5 |

**Honest framing for R-09 and R-15:** these are the risks most likely to actually kill the project. They are organizational, not technical. The technical plan in this document is sound; the execution risk is people and money.

→ **Checklist:** `RISK-001` … `RISK-015`

---

# §16 — Definition of Done for V1

V1.0 ships only when **every** item below is true and verifiable by a third party.

**Correctness**
- [ ] All five languages pass the identical conformance suite, or the parity matrix documents the gaps with owners and dates
- [ ] The reference application runs correctly under sustained load for 72 hours with zero crashes
- [ ] Deterministic mode produces bit-identical results across 10,000 trials

**Security**
- [ ] Two independent external audits complete; all critical and high findings fixed
- [ ] The hostile-guest suite (≥200 cases) passes with zero host memory-safety incidents
- [ ] `qqqai audit --fail-on high` is clean on all first-party packages
- [ ] Threat model published, including explicit non-goals

**Performance**
- [ ] Every numeric target in §9.2 met on reference hardware, with the harness public
- [ ] Benchmark suite published with methodology and honest losses

**Usability**
- [ ] TTFA ≤ 3 minutes on a clean machine, all three OSes
- [ ] 100% of error codes documented with remediation
- [ ] 100% of public APIs have a compiling example

**Agent-readiness**
- [ ] `qqqai schema --all` complete and drift-checked in CI
- [ ] MCP server exposes all V1 tools with structured output
- [ ] The agent benchmark meets its success target

**Sustainability**
- [ ] Licence, governance, contribution guide, and CODE_OF_CONDUCT published
- [ ] Deprecation policy written and in force
- [ ] At least two maintainers with commit rights and a documented succession plan
- [ ] A published support and security-response policy

→ **Checklist:** `DOD-001` … `DOD-024`

---

# §17 — Beyond V1

Explicitly deferred, but designed for. Each is recorded in the checklist as a stub with an owner.

| ID | Item | Rationale |
|---|---|---|
| `FUT-001` | **QQQ Fabric GA** — multi-host control plane, fleet policy, attestation | Commercial core |
| `FUT-002` | **Browser target** — QQQ host compiled to Wasm, running components in-browser | Same artifact, edge to client |
| `FUT-003` | **Native codegen escape hatch** — AOT-compile hot components to native with the sandbox replaced by MPK-based isolation | For workloads where even Wasm overhead is too much |
| `FUT-004` | **Cooperative threads** — Component Model 🧵 support | Needs Wasmtime maturity |
| `FUT-005` | **Distributed composition** — components calling components over the network transparently | The logical conclusion of the Component Model |
| `FUT-006` | **Formal verification** of the capability engine | The ultimate version of "provable isolation" |
| `FUT-007` | **`qqq:ai` implementation** — local inference as a metered capability | §6.9 |
| `FUT-008` | **GPU capability** — metered GPU access for AI workloads | Growing need |
| `FUT-009` | **Time-travel debugging** — record/replay with reverse stepping | Determinism makes this cheap |
| `FUT-010` | **QQQ Cloud** — a hosted platform | Only if the runtime wins on its own |
| `FUT-011` | **Hardware-backed attestation** (TPM/Secure Enclave) for the trust chain | Enterprise |
| `FUT-012` | **Registry federation** — private registries that mirror and extend the public one | Enterprise |

→ **Checklist:** `FUT-001` … `FUT-012`

---

# Appendix A — Source document reconciliation

The brief instructed: *"If you are fixing something or just working and see something wrong or missing, fix it, even if it is out of scope."* Six claims in the source corpus are stale, imprecise, or contradict the evidence. Each is corrected here and recorded in the Observations document.

| # | Source claim | Status | Correction |
|---|---|---|---|
| A-1 | `docs/QQQAI-Full-Conversation-Complete.md` describes Bun's "11-day Zig→Rust rewrite with 13,000+ unsafe memory blocks" as fact | **Unverifiable — treat as hearsay** | This claim originated in an AI-generated attachment and cannot be verified from primary sources. Our proposal must not rest on it. Bun is a serious engineering effort; we compete on architecture, not on the premise that they did it badly. |
| A-2 | "Bun is 42,000+ RPS" | **Unverified and version-dependent** | Numbers like this are hardware- and workload-specific and rot within months. We cite *our own* measured numbers only, with methodology. |
| A-3 | "Wasmtime" recommended without a version | **Corrected** | Pinned to **Wasmtime 48.x** (crates.io `newest` at time of writing: `48.0.2`, published 2026-09-10; `49.0.0-rc.1` is a release candidate). Engine upgrades are a scheduled activity, not an accident. |
| A-4 | WASI version never stated; implicitly Preview 2 | **Corrected** | QQQ targets **WASI 0.3 (Preview 3)**, which adds native `async`, `stream` and `future`. `wasi-http` in Wasmtime now has p3 enabled by default. Preview 2 remains supported for compatibility. |
| A-5 | `qqq` as crate/CLI name | **Corrected** | `qqq` is **taken on crates.io** (v0.2.0) and on npm (v0.0.6); `github.com/qqq` is an existing user account. Decision: product **QQQ**, CLI/crate/npm **`qqqai`** (verified free on all three), domain **qqq.codes**. |
| A-6 | "Open source with MIT or Apache-2.0" (NN-8) vs. the later instruction to charge businesses | **Genuine conflict, resolved** | §13.2: Apache-2.0 for the runtime (satisfying NN-8); commercial licence for the additive Fabric governance layer (satisfying the business requirement). The conflict is documented rather than hidden. |

**Also corrected silently throughout:** the source corpus uses "framework" loosely. This document uses **runtime** for the thing you install and **framework** only for the app-facing layer built on it, per §3.4 vocabulary discipline.

→ **Checklist:** `DOC-013`, `DOC-015`

---

# Appendix B — Verified external facts

Every external fact this proposal depends on, with its verification method. **Nothing in this proposal rests on an unverified claim.**

| # | Fact | Value at time of writing | Verified by |
|---|---|---|---|
| B-1 | Wasmtime latest stable | **48.0.2**, published 2026-09-10 | crates.io API `newest_version`; GitHub releases API |
| B-2 | Wasmtime latest RC | 49.0.0-rc.1 | crates.io API |
| B-3 | Wasmtime repo activity | 18,644 stars, 844 open issues, last push 2026-09-18 | GitHub API |
| B-4 | Wasmtime licence | Apache-2.0 WITH LLVM-exception | GitHub API `license`; docs.rs |
| B-5 | Component Model preview releases | 0.2.0 (shared-nothing/everything linking, resources, WIT); **0.3.0** (native concurrency: `async`, `stream`, `future`); 0.3.1 (`map<K,V>`, `implements`) | Component Model repo README (WebAssembly/component-model) |
| B-6 | WASI 0.3 = Preview 3 is current | Confirmed; "replacing the earlier explicit streams and polling interfaces with the component model's native, composable `async` functionality via the `future` and `stream` types" | WASI repo README (WebAssembly/WASI) |
| B-7 | Wasmtime Tier 1 Wasm proposals include `component-model`, `simd`, `gc`, `exception-handling`, `memory64`, `tail-call`, `multi-memory`, `relaxed-simd`, `wide-arithmetic` | Confirmed | Wasmtime `docs/stability-tiers.md` |
| B-8 | Wasmtime Tier 2 proposals include `threads`; `stack-switching` is 🚧 for Cranelift x86_64 and unsupported on aarch64 | Confirmed | Same document |
| B-9 | `wasi:http` p3 is enabled by default in `wasmtime-wasi-http` | Confirmed | Wasmtime 49.0.0 release notes |
| B-10 | WASI proposals past Preview 1 include `wasi-http`, `wasi-sockets`, `wasi-filesystem`, `wasi-clocks`, `wasi-random`, `wasi-io` | Confirmed as Tier 1 | `stability-tiers.md` |
| B-11 | `wasi-nn`, `wasi-config`, `wasi-keyvalue`, `wasi-tls`, `wasi-threads` are Tier 3 (unstable) | Confirmed | Same |
| B-12 | Wasmtime exposes `Config::epoch_interruption`, `Store::epoch_deadline_async_yield_and_update`, `Config::consume_fuel`, `Store::fuel_async_yield_interval`, `StoreLimitsBuilder`, `PoolingAllocationConfig`, `Module::serialize`/`deserialize`, `Component::new` | Confirmed | docs.rs API index for wasmtime 48.0.2 |
| B-13 | Wasmtime requires `*_async` APIs once async host functions, async limiters, or async fuel/epoch yields are configured | Confirmed | docs.rs crate documentation, "Async" section |
| B-14 | Wasmtime's WASIp2 implementation explicitly opts out of Tokio's per-task cooperative budget for `poll` calls | Confirmed | Wasmtime 49.0.0 release notes |
| B-15 | `qqq` on crates.io | **Taken** (v0.2.0, 131 downloads) | crates.io API |
| B-16 | `qqq` on npm | **Taken** (v0.0.6) | npm registry API |
| B-17 | `github.com/qqq` | **Taken** (personal user account) | GitHub API |
| B-18 | `qqqai` on crates.io / npm / GitHub | **Free on all three** | crates.io, npm registry, GitHub APIs |
| B-19 | `qqq-codes` on crates.io | Free | crates.io API |
| B-20 | `qx3` on crates.io / npm | Free | crates.io, npm APIs |
| B-21 | `github.com/qx3` | **Taken** (organization) | GitHub API |
| B-22 | `qqq.dev`, `qqq.run` | Registered (SOA records present) | DNS SOA query |
| B-23 | Local toolchain: rustc/cargo 1.97.1, rust-analyzer 1.97.1, targets x86_64-pc-windows-msvc only | Confirmed | `rustc --version`, `cargo --version`, `rustup target list --installed` |
| B-24 | Local auxiliary tooling: cargo-clippy, cargo-deny, cargo-machete present; Node v22.22.0; Bun 1.3.14; Python 3.13.2 | Confirmed | `~/.cargo/bin` listing; version commands |
| B-25 | `wasm-tools` and `wasmtime` CLIs are **not installed** on the dev machine | Confirmed | Command lookup failure |
| B-26 | GitHub CLI authenticated as `RatioArtificiosa` with `repo`, `workflow`, `gist`, `read:org` scopes | Confirmed | `gh auth status` |
| B-27 | Target repository `RatioArtificiosa/QQQ` is **public and empty** (no commits, no branches) | Confirmed | GitHub API `repos/.../contents`, `/branches`, `/commits` |
| B-28 | Component binaries report `WebAssembly (wasm) binary module version 0x1000d`; core modules `0x1` | Confirmed | Component Model documentation |
| B-29 | Component Model structural property: a component **may not export a memory**, so it cannot communicate indirectly through shared memory | Confirmed | Component Model documentation |
| B-30 | Component Model enables static analysis of component graphs (e.g. proving a business-logic component has no access to a PII component) | Confirmed | Component Model documentation |

**Facts explicitly NOT verified** (and therefore never relied upon): any throughput/RPS/startup figure for Node, Bun, Deno or QQQ; the Bun Zig→Rust rewrite narrative; any claim about a competitor's internal code quality. **These will be replaced with our own measurements (`PERF-001`) before any of them appears in marketing.**

→ **Checklist:** `DOC-016`

---

# Appendix C — Open questions and pending decisions

Items that are genuinely undecided. Each has an owner placeholder and a decision deadline; each is mirrored in the Observations document.

| ID | Question | Blocks | Needed by |
|---|---|---|---|
| Q-01 | Does the "Free for individuals and sole entrepreneurs" Fabric grant include companies with employees but low revenue, and how is revenue attested? | Licence text | M0 |
| Q-02 | AssemblyScript is a *subset* of TypeScript. Do we market it as "TypeScript" with a caveat, or as "AssemblyScript" with TypeScript familiarity as a selling point? | Positioning, docs | M5 |
| Q-03 | Is Python's CPython-to-WASI path good enough to be first-class, or does it ship as "experimental"? | Language matrix | M5 spike |
| Q-04 | Windows: first-class, or "supported, best-effort"? The cost is real and the audience is smaller. | Distribution, CI budget | M4 |
| Q-05 | Do we accept Wasm `threads`/shared memory at all, given it weakens per-instance accounting? | Limits model | M2 |
| Q-06 | Registry: build our own from day one, or bootstrap on OCI registries and move later? | Package manager | M6 |
| Q-07 | Is `wasi:http` sufficient as the HTTP foundation, or do we need a custom interface for performance? | Server design | M3 |
| Q-08 | Which licence for Fabric exactly — BSL 1.1 with a 4-year change date, Elastic License 2.0, or a custom grant? | Legal | M0 |
| Q-09 | Do we pursue Bytecode Alliance membership/adoption, and does that change the governance story? | Governance, credibility | M1 |
| Q-10 | OpenTelemetry: contribute our capability-audit semantic conventions upstream, or keep them QQQ-specific until stable? | Observability | M7 |
| Q-11 | Do we implement `qqq:ai` at all in the V1 line, or defer entirely to V2? | Scope | M7 |
| Q-12 | What is the deprecation window — two minor versions, or a fixed time period? | Stability contract | M0 |

→ **Checklist:** `OQ-001` … `OQ-012`

---

## Document control

| Field | Value |
|---|---|
| Applies to | QQQ v1.x |
| Supersedes | — |
| Reviewers | Founder, systems lead, security lead |
| Change process | Edits require an ADR; anchor changes are prohibited (§0.5) |
| Next review | At milestone M3, or on any change to `PRINCIPLES.md` |

*End of `QQQ-Proposal-V1.md`.*
