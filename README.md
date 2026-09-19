# QQQ

### The runtime built for humans **and** AI agents.

**Secure by default. Multi-language. Fast where real applications actually spend their time.**

<p align="center">
  <a href="#-install">Install</a> ·
  <a href="#-the-60-second-version">Why</a> ·
  <a href="#-what-makes-it-different">Different</a> ·
  <a href="#-where-we-lose">Where we lose</a> ·
  <a href="#-pricing">Pricing</a> ·
  <a href="QQQ-Proposal-V1.md">Technical proposal</a>
</p>

---

## The 60-second version

Every runtime you have ever deployed shares three assumptions:

| Assumption | What it costs you |
|---|---|
| **One garbage-collected language** | Unpredictable pauses in the request path, and tens of megabytes of baseline memory *per worker* |
| **Ambient authority** | Any dependency can read any file, open any socket, and phone home. Isolation means a container — heavy, coarse, unprovable |
| **Humans are the only users** | The CLI is a text adventure. Machine integration is an afterthought bolted on as `--json` |

QQQ rejects all three.

It executes **WebAssembly components** on a **Rust host**, with a **capability model where a module has zero authority you did not explicitly grant it** — enforced *outside* the guest, checkable *before* execution.

```bash
qqqai new agent-sandbox --lang python
cd agent-sandbox && qqqai dev
```

```toml
# qqq.toml — the whole security model, readable in 30 seconds
[capabilities]
fs   = [{ path = "/tmp/session-42", mode = "read-write" }]
http = { client = ["api.example.com:443"] }
crypto = { random = true }

[limits]
memory = "64MiB"
fuel   = 2_000_000_000
epoch_deadline_ms = 5000
```

That file is the contract. Your code **cannot** read `/etc/passwd`, cannot open an arbitrary socket, cannot read an environment variable, and cannot outlive its fuel budget — not because a policy engine says no, but because those imports **do not exist** in the instance it runs in.

---

## Install

```bash
# macOS / Linux
curl -fsSL https://qqq.codes/install.sh | sh

# Windows
irm https://qqq.codes/install.ps1 | iex

# Rust
cargo install qqqai

# Node / Bun developers
npm install -g qqqai

# Package managers
brew install qqqai        # macOS / Linux
scoop install qqqai       # Windows
```

One binary. No runtime dependency. No version manager bootstrap.

---

## What makes it different

### 🔐 Isolation that is provable, not promised

Containers are a **deployment** boundary. QQQ components are a **security** boundary with a machine-checkable manifest.

Ask what any artifact can do — **without running it**:

```bash
$ qqqai inspect ./build/agent-sandbox.component.wasm
```

```json
{
  "component": "agent-sandbox@0.1.0",
  "capabilities": {
    "fs":     [{ "path": "/tmp/session-42", "mode": "read-write" }],
    "http":   { "client": ["api.example.com:443"] },
    "crypto": { "random": true }
  },
  "denied_by_default": ["env", "sql", "kv", "queue", "secrets", "dns"],
  "limits": { "memory": "64MiB", "fuel": 2000000000, "epoch_deadline_ms": 5000 }
}
```

An agent or an auditor can decide whether to run it **before** a single instruction executes. No other runtime gives you that.

And when a capability is missing, you get the *why*, not a cryptic denial:

```bash
$ qqqai why sql.orders
```

```
sql.orders  DENIED
  ├─ qqq.toml          grants: (none)
  ├─ org policy        "prod-baseline": no widening permitted
  └─ decision          no layer grants this capability

  To grant it, add to qqq.toml:
    [[capabilities.sql]]
    name = "orders"
    driver = "postgres"
    secret = "env:ORDERS_DB_URL"
```

**Secrets never enter guest memory.** The `qqq:secrets` interface lets a component *use* a key without ever *seeing* it. A fully compromised guest can request a signature; it cannot steal the signing key. That eliminates an entire category of breach.

### 🌍 Five languages, one artifact graph

Rust · TypeScript · Go · Python · C/C++

Write the hot path in Rust, the data pipeline in Python, the glue in TypeScript, the codec in C. They compile to **one component graph with one type system**, linked and type-checked together — no HTTP hop, no JSON serialization at the seam.

Python is the one that should stop you: **neither Node nor Bun can run Python at all.** QQQ treats it as a first-class citizen of the same runtime.

Every host capability is defined in WIT **first** and bound into each language **second**. If a language can't reach something, it's published in the parity matrix — not quietly omitted from the docs.

### ⚡ Fast where it counts

There is no garbage collector anywhere in the request path — not in the host, not between requests.

| | Node / Bun | QQQ |
|---|---|---|
| Isolation unit | Process / container | Component instance |
| Instantiation | ~10–100 ms | **microseconds** |
| Memory per unit | Tens of MB | **KB-scale** |
| GC pauses in request path | Yes | **None** |
| Languages | 1 | **5** |
| Capability scoping | Process-wide | **Per-instance, per-request** |

That is not a tuning difference. It is an architectural one.

### 🤖 Agents are users, not just tools

```bash
qqqai mcp
```

One command turns QQQ into an **MCP server**. Any MCP-capable agent can scaffold, build, test, inspect, audit, deploy and debug QQQ projects through structured tools — no bespoke integration.

Every command emits stable, versioned, schema-published JSON:

```bash
qqqai schema --all      # JSON Schema for every surface, including itself
```

Every error carries a stable code, a cause, a remediation, and a docs URL — so an agent that has never seen QQQ can self-correct without a human in the loop.

### 🧪 Determinism — replay any execution, bit for bit

```bash
qqqai test --trials 10000      # any output difference across runs is a failure
qqqai run --replay incident.log
```

Time, randomness, scheduling and float behaviour are all host-mediated and seeded. Reproduce a production incident exactly. Prove a property test is not flaky. **Replay precisely what an autonomous agent did.**

No competing runtime can offer this, because neither can control the nondeterminism its own engine introduces.

### ♻️ Instant reload

```
✓ Compiled in 412ms
⟳ Listening on http://127.0.0.1:3000
```

Because your code is a *component instance* and not a language heap, reloading is a pointer swap — not a process restart. Node and Bun fundamentally cannot do this; restarting means rebuilding the JS heap.

---

## Where we lose

We are going to publish numbers that make us look worse than our competitors, on purpose. A benchmark you can't argue with is worth more than one you can.

- **`hello world` HTTP throughput.** Bun is exceptional at this and has spent years optimizing for it. We may reach parity. We do not promise to beat it.
- **Ecosystem size.** npm has millions of packages. We are starting near zero, and we will be honest about how long closing that gap takes.
- **Familiarity.** Every JavaScript developer already knows Node. Our onboarding costs more, and that cost is real.
- **"Drop-in Node replacement."** This is not one. `npm i express` will not work. We provide a migration path and a conversion report — not an interpreter for the Node API surface, because that path kills runtimes.

Every performance claim we publish ships with its hardware, toolchain versions, concurrency levels, percentiles and methodology — and a section stating what the benchmark **does not** measure.

---

## Pricing

**The runtime is free. Forever. For everyone. Including your company.**

`qqqai` — the runtime, CLI, SDKs, package manager, dev server, test runner — is **Apache-2.0**. No seat limits. No revenue limits. No telemetry phone-home. Nothing to ask your legal team about before running code.

We charge for **governance, evidence, and liability** — never for the ability to execute.

| | Who | Fabric (governance) | Support |
|---|---|---|---|
| **Free** | Individuals, solo developers, non-profits, companies under $2M revenue | ✅ Included | Community |
| **Team** | Up to 25 engineers | ✅ Included | Email |
| **Business** | Up to 250 engineers | ✅ Included | 8×5 SLA |
| **Enterprise** | 250+ | ✅ Included | 24×7, indemnification, air-gapped |

**QQQ Fabric** is a separate, commercially-licensed product: organization-wide policy, fleet attestation, SSO/RBAC, compliance evidence export, audit retention, and air-gapped supply-chain mirrors.

> **Plain language:** if you are one person with an idea, you get everything, for free, including Fabric. If you are a company, the *runtime* is still free — you pay only if you want the governance layer.
>
> Fabric is **not** OSI open source, and we won't call it that. The runtime is.

---

## Principles

QQQ is built against **eight non-negotiables**, published in [`PRINCIPLES.md`](PRINCIPLES.md). They are treated as a constitution, not marketing copy. The PR template requires naming any principle your change touches.

1. **AI agents are first-class users** — if an agent can't reliably generate, inspect, modify, test or deploy against QQQ, the design is incomplete.
2. **Security and isolation are non-optional** — untrusted code will run here. That is the point.
3. **Performance and predictability over micro-benchmarks** — percentiles under realism, not peaks under ideal conditions.
4. **Multi-language by design** — no privileged language.
5. **Explicit contracts over implicit behavior** — no hidden state, no magic, typed errors.
6. **Human + machine documentation parity** — outdated docs are a defect, not a chore.
7. **Progressive power, safe defaults** — zero capabilities out of the box; power when you ask for it.
8. **Ecosystem integrity and long-term stewardship** — open, governed, and serious about backward compatibility.

---

## Status

**Pre-alpha.** This repository is the design corpus and the foundation. The runtime is being built in the open.

| Document | What it is |
|---|---|
| [`QQQ-Proposal-V1.md`](QQQ-Proposal-V1.md) | The complete technical proposal — architecture, security model, performance budgets, delivery plan, risk register |
| [`QQQ-Checklist-V1.md`](QQQ-Checklist-V1.md) | The executable work breakdown — 586 items, every one citing the proposal section it implements |
| [`QQQ-Observations-and-Memories.md`](QQQ-Observations-and-Memories.md) | Institutional memory — decisions and their reasons, mistakes and fixes, open questions |
| [`PRINCIPLES.md`](PRINCIPLES.md) | The eight non-negotiables |

The proposal and the checklist are **bidirectionally cross-referenced** and machine-verified. Every section of the proposal names the checklist items that implement it; every checklist item names the proposal section it derives from. CI fails the build if that graph breaks.

```bash
python tools/check_xrefs.py
```

We are not asking you to believe the numbers in this README. We are asking you to read the proposal, check our method, and tell us where we are wrong.

**Found a flaw?** That is the most valuable thing you can contribute right now. Open an issue.

---

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`PRINCIPLES.md`](PRINCIPLES.md) first. The RFC process governs changes to published interfaces and to the principles themselves.

**Security:** do not open a public issue. See [`SECURITY.md`](SECURITY.md).

---

<p align="center">
  <sub>Apache-2.0 · qqq.codes · Built on <a href="https://wasmtime.dev">Wasmtime</a> and the <a href="https://component-model.bytecodealliance.org">WebAssembly Component Model</a></sub>
</p>
<p align="center">
  <sub><em>Run anything. Trust nothing.</em></sub>
</p>
