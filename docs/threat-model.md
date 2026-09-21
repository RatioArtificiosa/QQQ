# QQQ threat model

The document this project would hand to a security reviewer. It states what is being
defended, from whom, and — critically — **which code is responsible for each**. A
threat model that names defences without naming the code that implements them is a
wish list; every claim here points at something a reader can open.

Expands Proposal §7.1 (assets) and §7.2 (adversaries). Read alongside
[`out-of-scope.md`](out-of-scope.md), which states what is *not* defended.

---

## 1. Method, and what it is not

This is a **design** threat model: it enumerates assets, adversaries and mitigations
by analysing the architecture, and it maps each mitigation to the component that
implements it.

It is **not** a validation. Nobody has attempted to break this system, because
`SEC-024` and `SEC-025` (the external audits) have not been commissioned. A design
model says "here is what we believe and why"; only an adversary can say whether the
belief holds. **The absence of a validation is the most important fact in this
document**, and it is stated first rather than buried.

> **Status: no external audit has occurred.** The two commissioning items are open.
> Every claim below is a design argument, not a validated result. When `SEC-024` and
> `SEC-025` complete, §4's last column changes — and until then, a reader should treat
> this document as the *author's* reasoning rather than as evidence.

That statement is not only prose: `tools/check_threat_model.py` fails the build if
this document claims external validation while the two audit items remain unticked.

---

## 2. Assets, and what compromising each costs

| # | Asset | Why it matters | Compromise cost |
|---|---|---|---|
| A1 | **Host process integrity** | Compromise means total tenant compromise — the sandbox is implemented *by* this process | Catastrophic |
| A2 | **Tenant data** (memory, files, DB rows) | The primary harm, and the one a user notices | Catastrophic |
| A3 | **Secrets** (keys, connection strings, tokens) | Enables lateral movement and long-term compromise | Severe |
| A4 | **Host resources** (CPU, memory, disk, network) | Denial of service and cost attacks | Service-affecting |
| A5 | **Supply-chain integrity** | §7.2 calls a malicious dependency the most likely real attack | Catastrophic |
| A6 | **Audit integrity** | If logs can be forged or deleted, nothing else can be investigated | Severe |

Listed in dependency order: A1's loss voids everything below it, which is why it is
first. A6 is last in the table and not least in importance — an incident that cannot
be reconstructed cannot be remediated with confidence.

---

## 3. Adversaries, and the code that defends each

The eight adversaries below are §7.2's list. For each: what they can do, what stops
them, **where that code lives**, and how it is tested.

### T1. Malicious guest

**Capability assumed.** Full control of guest code and guest memory; can craft
adversarial Wasm.

**Defence.** Wasm sandbox (Wasmtime) + capability grants + resource limits +
trap-on-violation.

| Layer | Where | Verified by |
|---|---|---|
| Guest cannot name an ungranted import — it is *absent*, not denied | `qqq-host` per-instance linker | `SEC-002`'s test |
| Fuel and epoch limits stop runaway guests | `qqq-host::quota` | `SEC-005`, `SEC-006` |
| Memory bounds enforced by the engine | `qqq-host` `StoreLimits` | `SEC-007` |
| Traps carry stable `QQQ-XXXX` codes | `qqq-core::error` | `SEC-008` |
| Grant re-checked at call time (defence in depth) | `qqq-cap::normalize` | `SEC-009` |

**Residual.** This is Wasmtime's sandbox, so T1's defence is only as strong as
Wasmtime's — see T7. QQQ's contribution is that a guest which escapes the *capability*
model still cannot reach a resource it was not granted, because the import is not
there to call.

**Tested by.** The hostile-guest suite (`SEC-004`, ≥200 cases), each with a specified
expected failure.

---

### T2. Malicious dependency

**Capability assumed.** Same as T1, but arriving through the package manager — the
supply-chain path.

**Defence.** Capability diff at install time, signature verification, provenance
attestation, and `qqqai audit --fail-on` in the consumer's CI.

**Where.** `qqq-pkg` (resolution, verification), `qqq-cap` (the diff),
`qqq-run audit` (the report).

**The property that matters.** Installing an update must not *silently* widen what the
dependency can do. A user who accepts a new version after seeing "this now requests
network access" has consented; one who is never told has not. This is why the diff is
shown before acceptance rather than after.

**Residual.** A dependency that is malicious *within the grants it already had* is
not caught by a diff. If `serde`-equivalent already had filesystem read and turns
malicious, no capability change signals it. Signature and provenance checks address
*who published it*, not *whether the code is honest*.

---

### T3. Compromised tenant

**Capability assumed.** Legitimate, but hostile within its own tenant.

**Defence.** Per-tenant isolation, no cross-tenant handles, tenant-scoped audit.

**Where.** `qqq-cap::egress` (per-tenant policy, `SEC-022`), `qqq-host` pool
partitioning, the audit stream's tenant scoping.

**The property that matters.** A tenant with a valid grant for its own resources must
gain nothing by attacking a neighbour. The mechanism is that handles are
tenant-scoped: a tenant holds an opaque handle, not a path or an address, so there is
no value it could supply that names another tenant's resource.

**Residual.** Side channels between tenants sharing a core — stated in
[`out-of-scope.md`](out-of-scope.md) §2 and not defended.

---

### T4. Hostile network client

**Capability assumed.** Can send arbitrary HTTP: malformed headers, oversized bodies,
slowloris, injection payloads.

**Defence.** Header and body caps, deadlines, rate limiting, TLS policy.

**Where.** `qqq-serve` (parsing, limits, TLS), `qqq-io` (accept loop, backpressure).

**The property that matters.** Every input has a bound *before* it is parsed, so a
malicious client cannot make the server allocate proportionally to what it sends.
Backpressure at the accept point (`qqq-io`) means an overloaded server defers work
rather than queueing it without limit.

**Tested by.** `qqq-serve`'s parsing tests, including the fuzz target
`component_load` and `manifest_parse` on the adjacent surfaces.

---

### T5. Insider with deploy access

**Capability assumed.** Can change configuration — not the binary, but what it is told
to do.

**Defence.** Signed configuration, audit trail, RBAC, four-eyes on production changes.

**Where.** `qqq-pkg` (config signing), the audit stream (immutability),
the Fabric layer (RBAC — **not implemented in V1**).

**Residual, stated plainly.** The Fabric RBAC and four-eyes controls are **Fleet-tier
features not present in V1**. In a V1 deployment the defence against T5 is the signed
configuration and the audit trail; an operator who can edit the config file *unsigned*
is not stopped, only recorded. This is a genuine V1 gap and is stated here rather than
implied to be covered.

---

### T6. Supply-chain nation-state

**Capability assumed.** Can compromise an upstream project — not just publish a
malicious package, but take over a legitimate one.

**Defence.** Reproducible builds, provenance attestation, hash pinning, mirrors.

**Where.** `.github/workflows/ci.yml` (SBOM, `SEC-028`), `Cargo.lock` (pinning),
`deny.toml` (licence and advisory policy), `docs/advisories/` (`SEC-023`).

**The property that matters.** Reproducibility means a compromised build machine
cannot alter the artifact without detection, because the output is a function of the
inputs. `Cargo.lock` is committed and CI builds with `--locked`, so the dependency set
cannot drift between the audited commit and the shipped binary.

**Residual.** Reproducibility proves the *build* was faithful; it says nothing about
whether a dependency's own source is honest. Provenance attestation addresses who
built what, which is a different question from whether it is safe.

---

### T7. Nation-state against the sandbox

**Capability assumed.** Can find Wasm escapes — the adversary with the most resources,
aimed at the boundary QQQ depends on.

**Defence.** Wasmtime's security process, QQQ's upgrade cadence, continuous fuzzing,
and honest disclosure of what is not defended.

**Where.** [`wasmtime-advisory-process.md`](wasmtime-advisory-process.md) (the
72-hour patching commitment), `.github/workflows/fuzz.yml` (nightly fuzzing),
`deny.toml` (advisory scanning on every commit).

**Residual, and this is the honest core of the whole document.** QQQ's sandbox **is**
Wasmtime's. A Wasmtime escape is out of the sandbox regardless of what a manifest
granted, and no amount of QQQ-side correctness changes that. The mitigation is a
*process* — patch within 72 hours of an upstream fix — not a property.

The secondary defence is that a guest which escapes Wasm still holds only capability
handles, not paths or addresses. That raises the cost of turning an escape into a
compromise, and it is not a guarantee.

---

### T8. Malicious host administrator

**Not defended.** See [`out-of-scope.md`](out-of-scope.md) §1. Listed here because a
threat model that omits the adversary it cannot stop is a threat model that implies it
can.

---

## 4. Mitigation coverage, and where it is thin

| Adversary | Primary defence implemented? | Validated by an adversary? |
|---|---|---|
| T1 Malicious guest | **Yes** — 200+ hostile-guest cases | No — design model only |
| T2 Malicious dependency | **Partly** — diff and signing; provenance partial | No |
| T3 Compromised tenant | **Yes** — tenant-scoped handles | No |
| T4 Hostile network client | **Yes** — bounds before parsing | No |
| T5 Insider with deploy access | **Partly** — signing and audit; RBAC is V1-absent | No |
| T6 Supply-chain nation-state | **Partly** — reproducible, pinned, SBOM | No |
| T7 Nation-state vs sandbox | **Process only** — 72-hour patching | No |
| T8 Malicious host admin | **No** — out of scope by design | N/A |

**Read the last column.** Nothing in this system has been attacked by someone trying
to break it. That is the state of a design-stage project, and a threat model that
presented its own reasoning as validation would be the most dangerous document here.

---

## 5. How this document is kept true

Two things decay in a threat model faster than anywhere else: the mapping from
mitigation to code, and the honesty about what is missing.

* **The mapping is checked.** Every `Where` column names a module that must exist;
  `tools/check_threat_model.py` fails the build when a named path is gone, so a
  refactor that moves a defence cannot leave this document pointing at nothing.
* **The out-of-scope list is checked** against `SECURITY.md` and the Proposal by
  `tools/check_security_scope.py` (`SEC-030`).
* **The absence of validation is stated**, and will be revised when `SEC-024` and
  `SEC-025` are commissioned. Until then, §4's last column is correct as written.

**Revisit when.** A new adversary class appears in §7.2; an audit completes; or a
mitigation moves to a different crate. The first two are events, the third is a
refactor — which is exactly why it is a check rather than a note.
