# The Eight Non-Negotiables

> These are the foundational rules of the QQQ project. They are written to be short enough to remember, precise enough to guide daily decisions, and strong enough to keep the vision coherent as the ecosystem grows.
>
> **Every major architectural, API, tooling and community decision is checked against this list.** The pull-request template requires the author to name any principle their change touches.
>
> This file is deliberately hard to change. Amendments require an RFC, a public comment period, and explicit maintainer consensus. See [`GOVERNANCE.md`](GOVERNANCE.md).

---

## 1. AI Agents Are First-Class Users

The runtime, CLI, APIs, error messages, documentation and packaging must be designed so that both human developers **and** AI agents can use them reliably, safely and productively.

- Structured, machine-readable outputs are the default, not an afterthought.
- Every public interface has a clear, stable, versioned contract that an agent can reason about.
- Ambiguity, hidden state, and "magic" that confuses models are treated as **bugs**.

> **Non-negotiable:** If an AI coding agent cannot reliably generate, inspect, modify, test or deploy code against the platform, the design is incomplete.

---

## 2. Security and Isolation Are Non-Optional

Untrusted or AI-generated code will run on this platform. Therefore security is a core feature, not a compliance checkbox.

- Capability-based security by default — explicit grants only.
- Strong sandboxing with clear, auditable boundaries.
- Resource limits (CPU, memory, time, network, filesystem) must be enforceable and introspectable.
- The host never trusts guest code.

> **Non-negotiable:** It must be straightforward to run third-party or AI-generated modules with least privilege and high confidence.

---

## 3. Performance and Predictability Over Micro-Benchmarks

The platform must deliver excellent real-world performance: low latency, high throughput, minimal memory, and predictable tail latencies.

- No garbage-collection pauses in the host.
- Near-native execution speed for guest code.
- Deterministic resource behaviour wherever possible.
- Cold starts and idle footprint must be extremely low.

> **Non-negotiable:** Synthetic "hello world" numbers are secondary. Behaviour under realistic load, multi-tenancy and long-running workloads is what matters.

---

## 4. Multi-Language by Design, Not by Accident

Users and agents must be able to write in multiple languages that compile to a common secure execution format — WebAssembly and the Component Model as the primary target.

- The host APIs are language-agnostic.
- First-class, well-documented paths for major languages.
- No privileged "primary" language that everything else is second-class to.

> **Non-negotiable:** The platform's value proposition includes language choice. Locking users into one language is a failure of the vision.

---

## 5. Explicit Contracts Over Implicit Behaviour

Clarity beats cleverness.

- Stable, versioned interfaces.
- Explicit error types and structured diagnostics.
- Minimal global state and hidden side effects.
- What a module can do must be discoverable **without running it**.

> **Non-negotiable:** An agent — or a careful human — must be able to understand the capabilities and requirements of any module from its metadata and contracts alone.

---

## 6. Human + Machine Documentation Parity

Documentation is a product surface for both audiences.

- Human-readable guides and examples of high quality.
- Machine-readable schemas, interface definitions and examples that agents can ingest reliably.
- Documentation stays in sync with the actual implementation, **treated as a correctness requirement**.

> **Non-negotiable:** Outdated or agent-hostile documentation is considered a defect.

---

## 7. Progressive Power, Safe Defaults

The platform should be simple to start with and extremely powerful when needed.

- Safe, restrictive defaults for new modules and projects.
- Progressive disclosure of advanced capabilities.
- No requirement to understand the full security or performance model on day one — yet the full model must remain accessible and enforceable.

> **Non-negotiable:** Power users and agents must never be forced to work around the platform; beginners must never be exposed to unnecessary danger by default.

---

## 8. Ecosystem Integrity and Long-Term Stewardship

This is intended to be given to the world as lasting infrastructure.

- Open source with a clear, permissive licence for the runtime.
- Stable governance and a contribution model that protects the core principles.
- Backward compatibility is treated seriously; breaking changes require strong justification and migration paths.
- The project optimizes for long-term reliability and clarity over short-term hype.

> **Non-negotiable:** Decisions that sacrifice long-term integrity for temporary popularity or growth are rejected.

---

## How these principles are enforced

A principle that cannot be tested is a slogan. Each one maps to concrete, checkable obligations:

| # | Enforcement mechanism | Where it lives |
|---|---|---|
| 1 | `--json` on every command; published JSON Schemas; stable error codes; schema-drift CI | `AGENT-001` … `AGENT-025` |
| 2 | Manifest-derived linker construction; per-instance grants; hostile-guest suite; limits | `SEC-001` … `SEC-030` |
| 3 | Published percentile budgets; performance regression CI; the benchmark methodology | `PERF-001` … `PERF-027` |
| 4 | WIT as source of truth; generated bindings; a five-language conformance suite; published parity matrix | `LANG-001` … `LANG-040` |
| 5 | Versioned interfaces; typed errors; CI checks for hidden global state | `CON-001` … `CON-018` |
| 6 | Generated docs; documentation-freshness CI; `llms.txt` | `DOC-001` … `DOC-021` |
| 7 | Zero-capability scaffolding; the three documented power tiers | `DX-001` … `DX-020` |
| 8 | Apache-2.0 runtime; published governance; deprecation policy; two-maintainer rule | `GOV-001` … `GOV-014`, `LIC-001` … `LIC-012` |

The identifiers above are checklist items in [`QQQ-Checklist-V1.md`](QQQ-Checklist-V1.md), each of which cites the proposal section that specifies it.

---

## A note on principle 8 and the commercial layer

Principle 8 says the ecosystem must be open. The project also has a commercial layer. These are reconciled by placing the boundary carefully:

- **The runtime — everything you need to execute code — is Apache-2.0, permanently.** No seat limits, no revenue limits, no telemetry.
- **QQQ Fabric** — organization-wide policy, fleet attestation, SSO/RBAC, compliance evidence, air-gapped mirrors — is a separately licensed commercial product. It is **additive**; nothing in the runtime depends on it.

Fabric is not OSI open source, and the project will not describe it as such. The runtime is genuinely open, and that commitment is irrevocable for the 1.x line.

---

<p align="center"><sub>Adopted 2026-09-19 · Amendments require an RFC</sub></p>
