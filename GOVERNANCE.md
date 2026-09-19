# Governance

> Adopted 2026-09-19. This document exists **before** the first external contributor, on purpose: governance written under pressure is governance written badly.

## 1. What this project is

QQQ is an AI-native, multi-language runtime built on WebAssembly components. It is intended to be given to the world as lasting infrastructure, stewarded rather than owned.

Its constitution is [`PRINCIPLES.md`](PRINCIPLES.md) — the eight non-negotiables. Everything below exists to protect those principles across time, maintainer turnover, and commercial pressure.

## 2. Scope of governance

This document governs:

- the `qqqai` runtime and its crates (Apache-2.0)
- published interfaces: WIT packages, the `qqq.toml` manifest schema, the `qqq.lock` schema, CLI JSON output, and the error-code registry
- this repository's processes

It does **not** govern **QQQ Fabric**, which is a separately licensed commercial product with its own repository and its own (much lighter) process.

## 3. Roles

| Role | What it means | How you get it |
|---|---|---|
| **Contributor** | Anyone who opens an issue or PR | Show up |
| **Reviewer** | May approve PRs in a defined area | Sustained quality contributions; nominated by a maintainer |
| **Maintainer** | Merge rights, RFC votes, release authority | Demonstrated judgment over time; consensus of existing maintainers |
| **Founder** | Tie-breaking vote on RFCs until the project reaches 1.0 | Initial |

**Target: at least two maintainers before milestone M5.** Bus factor is currently one, and that is tracked as an active risk (`R-15`). This is a governance obligation, not an aspiration.

## 4. Decision process

| Change | Process |
|---|---|
| Bug fix, docs, tests | PR with review |
| New feature with an existing checklist item | PR with review |
| New checklist item | PR to `QQQ-Checklist-V1.md` + review |
| New or breaking published interface | **RFC** (7-day public comment) |
| Change to `PRINCIPLES.md` | **RFC** (14-day public comment) + maintainer consensus |
| Change to a published proposal anchor | **RFC** — anchors are stable forever by design |
| Security fix | Private, then coordinated disclosure |

### RFC process

1. Open a PR adding `docs/rfc/NNNN-title.md` using the template.
2. Public comment period (7 days normally, 14 for principles).
3. Maintainers reach consensus. The Founder breaks ties before 1.0.
4. Accepted RFCs are merged and the implementation lands against them.

An RFC that conflicts with a principle must either be redesigned or explicitly recorded as a rare, justified exception in the RFC itself. Silent exceptions are not permitted.

## 5. Backward compatibility

SemVer is a promise, not a convention.

| Surface | Guarantee |
|---|---|
| WIT interfaces | Versioned per package; additive changes only within a major version |
| `qqq.toml` schema | Additive within a major version; never silently repurposed |
| `qqq.lock` schema | Versioned; old lockfiles keep working or the tool rewrites them with a clear message |
| CLI JSON output | Additive within a major version; **schema drift fails CI** |
| Error codes | Never reused, never renumbered, never repurposed |
| Rust APIs | Per crate stability tier (§4.3 of the proposal); `stable` crates follow SemVer |

**Deprecation window:** two minor versions minimum, or the fixed period set by the open decision `OQ-012` — whichever is longer. Every deprecation ships with a machine-readable migration entry, so an agent can perform the migration autonomously.

## 6. Releases

- Releases are cut from `main` when the milestone exit criteria are met, not on a calendar.
- Every release publishes source, binaries for all supported targets, SHA-256 checksums, Ed25519 signatures, a provenance attestation, an SBOM, and a machine-readable changelog.
- Security releases may bypass the normal cadence. Patched engines ship within 72 hours of an upstream advisory (`SEC-014`).

## 7. Conflict of interest

Maintainers must disclose commercial interests that could influence a decision — particularly anything touching the runtime/Fabric licensing boundary. A maintainer with a material interest recuses from the relevant vote.

Decisions that would narrow the Apache-2.0 grant on the runtime are **out of scope for governance entirely**. That grant is irrevocable for the 1.x line and cannot be changed by any vote.

## 8. Amendments

This document is amended by RFC with a 14-day comment period and maintainer consensus.

---

<p align="center"><sub>Questions about governance? Open a Discussion.</sub></p>
