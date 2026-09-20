# qqq-host

The Wasmtime execution engine: pooling allocator, AOT-first compilation, fuel
and epoch limits, the trap taxonomy, and the per-instance linker.

Pins **Wasmtime 48.x** (`48.0.2`). Implements `QQQ-Proposal-V1.md` §6.1 and
Checklist `HOST-001` … `HOST-024`.

## Why the engine version is pinned, and why that is a decision

"Use Wasmtime" is not an engineering decision; it is the absence of one. A
systems project that does not pin its execution engine cannot reason about
security advisories, cannot schedule compatibility work, and cannot answer
"what exactly are we shipping?" — and it invites silent behavioural drift when a
dependency resolves to a new minor.

The 48.x line is pinned, `49.0.0-rc.1` exists and is **deliberately not
adopted** (a release candidate is not a release), and engine upgrades are a
scheduled activity with a 72-hour patch target on advisories. All churn is
isolated behind `qqq-abi`, so an engine upgrade is not a rewrite of the
capability model.

## The linker is built from the grants, and only the grants

This is the crate's central security property and it is stated as an absence:

> An ungranted import is **absent, not denied**.

`build_linker` registers host functions per capability. A guest that imports
`qqq:fs/filesystem` without `fs.read` gets a **link error**, not a host function
that returns "permission denied". A function that exists and refuses can be
probed for timing, error shape and side channels; a function that was never
linked cannot be called at all.

Call-time re-checks exist **as well**, deliberately redundantly, so a linker
mistake is still caught.

## Every trap discards the instance

| Condition | Code | Retryable | Instance reusable? |
|---|---|---|---|
| Memory limit exceeded | `QQQ-3001` | no | **no** — discard |
| Fuel exhausted | `QQQ-3002` | no | **no** — discard |
| Epoch deadline exceeded | `QQQ-3003` | no | **no** — discard |
| Invalid resource handle | `QQQ-3005` | no | **no** — discard |
| Guest panic | `QQQ-3006` | no | **no** — discard |
| Anything else | `QQQ-3004` | no | **no** — discard |

A trapped instance was interrupted mid-execution: its linear memory may hold
partially-written state, its handles may be half-closed, and its fuel is spent.
Returning it to the pool would hand the next request a contaminated context —
exactly the cross-request leak the capability model exists to prevent.

This is enforced by the **type system**, not by discipline: `Instance::run`
consumes `self`, so a trapped instance cannot be reused even by accident.

Traps are never retryable because the same input traps the same way. A caller
retrying identical input is burning budget; a caller retrying with *different*
input is making a product decision, not a retry.

## The trap taxonomy is a free function over `&str`

`classify_trap(detail: &str) -> ErrorCode` rather than something taking
Wasmtime's error type. Wasmtime's error is a boxed trait object whose variants
are not part of its stability contract, so the mapping is **testable without a
real engine** and does not force a rewrite when the engine is upgraded.

String matching is the honest choice here, and the patterns are documented with
the exact engine text they match.

## Determinism

`EngineConfig::deterministic()` fixes the clock and seeds the RNG, so the same
input produces a bit-identical run. The clock and randomness are virtualised in
`host_clock` and `ambient` rather than intercepted, which keeps the guest code
unchanged — a guest cannot detect that it is being replayed.

## Modules

| Module | Responsibility |
|---|---|
| `config` | `EngineConfig` — the Wasmtime configuration, including the pooling allocator |
| `instance` | `PreparedComponent`, `Instance`, `StoreLimits`; `imported_interfaces` |
| `linker` | `build_linker` — per-capability host registration |
| `trap` | `classify_trap`, `remediation_for` — failure → stable code |
| `ambient` | Randomness, hashing, and the ambient state a guest can observe |
| `host_clock` | Wall and monotonic clocks, virtualised for determinism |
| `host_crypto` | The `qqq:crypto` interface implementations |

## Checklist coverage

`HOST-001` … `HOST-024`, `CON-014`. See `QQQ-Proposal-V1.md` §6.1, §10.5.
