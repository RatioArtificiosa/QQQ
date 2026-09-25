# Stability tiers and the API-stability contract

**What this document is.** The promise each published surface makes about change. Proposal
§4.3 requires every crate to have "a single responsibility, a **stated stability tier**, and an
owner"; this page states the tiers and what each one commits to. `ARCH-010` and `CON-017`.

**How to read a tier.** A tier is a promise about *breaking changes*, not about quality. A
`beta` crate may be perfectly reliable and still change its API; a `stable` crate may have a
feature missing and still not break you.

---

## The tiers

| Tier | Breaking changes | Minimum notice | What you may rely on |
|---|---|---|---|
| **`stable`** | Not without a major version | One minor release, with the replacement named | The API compiles against your code across every patch and minor release |
| **`beta`** | Allowed in a minor release | Documented in the changelog | The API works as documented today; its shape may change |
| **`exception`** | Not applicable — this concerns `unsafe`, not versions | — | The crate may contain `unsafe`, granted through the process below |

---

## Which crate is which

Every crate declares its tier on the comment block above its entry in the workspace manifest
(`Cargo.toml`), and `tools/check_tiers.py` verifies that declaration against §4.3's table.
**This table is re-derived from that check** rather than maintained by hand:

| Crate | Tier | Responsibility |
|---|---|---|
| `qqq-core` | `stable` | Shared types: IDs, error model, version, `Result`/`Error` codes. No I/O |
| `qqq-cap` | `stable` | Capability model: manifest parsing, grant resolution, policy evaluation, audit records |
| `qqq-abi` | `stable` | WIT package + the interface registry: which capability unlocks which interface |
| `qqq-host` | `stable` | Wasmtime integration: engine config, component compilation, pooling, fuel, epochs, store data |
| `qqq-io` | `stable` | Reactor abstraction over Tokio / io_uring |
| `qqq-serve` | `stable` | The HTTP/dev server: routing, listener shards, HTTP/1.1, HTTP/2, HTTP/3 (QUIC) behind a flag |
| `qqq-run` | `stable` | The CLI orchestration: `new`, `build`, `run`, `dev`, `test`, `inspect`, `mcp` |
| `qqq-pkg` | `beta` | Registry client, solver, lockfile, content-addressed store |
| `qqq-debug` | `beta` | DWARF → source mapping, trap diagnostics, time-travel replay |
| `qqq-sys` | `exception` | Linux hardening. Designated for `unsafe`; currently contains none |
| `qqq-bench` | `stable` | The benchmark harness. Has no workspace dependency, so it can measure any crate without joining its graph |

### Two crates this workspace builds that §4.3's table does not name

Stated plainly rather than left for a reader to notice. `tools/check_tiers.py` reports both on
every run:

- **`qqq-sys`** — §4.3 mentions only a *different* planned crate, `qqq-sys-signals`, in its
  `unsafe` discussion. The built exception crate has no row of its own.
- **`qqq-bench`** — the benchmark harness. §4.3 has no row for it either; the ordering comment in
  `tools/check_topology.py` explains where it sits and why its lack of an internal dependency
  edge is deliberate.

Two crates §4.3 lists are **not built in this repository**: `qqq-registry` and `qqq-fabric`. The
latter is a separate repository and licence by design (§13.2).

---

## The **`exception`** tier is a process, not a label

`exception` does not mean "we did not decide". It means the crate may contain `unsafe`, and
that permission is granted through a written argument rather than an attribute edit.

The artifact is `crates/qqq-sys/SAFETY.md`. `crates/qqq-core/tests/architecture.rs` reads it and
the crate's lint attribute together, and exactly one combination is a violation:

| `SAFETY.md` | forbids `unsafe` | Verdict |
|---|---|---|
| absent | yes | Correct — no exception claimed |
| present | yes | Correct — the argument is written **ahead of** the code |
| present | no | Correct — the exception was granted through its process |
| absent | no | **A violation** — `unsafe` permitted with nothing written down |

`qqq-sys` is in the second row today: it is designated for `unsafe` and **contains none**,
because `nix` and `seccompiler` supply the primitives as safe functions. That is a recorded
decision, not an accident — see the comment at the top of `crates/qqq-sys/src/lib.rs`.

---

## The four surfaces and their contracts

`CON-017` asks for a stability promise per surface. They are not the same promise, because they
are not consumed the same way.

### 1. WIT interfaces (`wit/`)

| | |
|---|---|
| **Contract** | Interface *names* and *function signatures* are stable within a major version |
| **Adding** | A new interface, or a new function on an existing one, is a **minor** change |
| **Breaking** | Removing or renaming a function, or changing a parameter type, is a **major** change |
| **Deprecation** | Not yet defined — see `CON-015`, which is open |

The dependency direction matters here: a guest compiled against these interfaces runs on a host
that supports them, so a breaking change is a breaking change for every already-built artifact.

### 2. The manifest (`qqq.toml`)

| | |
|---|---|
| **Contract** | A manifest that parses today parses under any later version, with the same meaning |
| **Adding** | A new optional key is a **minor** change |
| **Breaking** | Rejecting a key that previously parsed, or changing what a key means, is **major** |
| **Reverting safely** | An unknown key is a **parse error, not a warning** — a manifest that is silently ignored is a capability that silently does nothing |

That last row is the security-relevant one. A typo'd capability key that produced a warning
instead of an error would read as "granted" to a human and as "absent" to the runtime.

### 3. The lockfile (`qqq.lock`)

| | |
|---|---|
| **Contract** | A lockfile written by one version resolves identically under any later version |
| **Adding** | A new field is a **minor** change; older versions ignore it |
| **Breaking** | A format version bump, which is explicit in the file |
| **Determinism** | Byte-identical output for identical inputs, on every platform |

### 4. CLI JSON output (`qqqai … --json`)

| | |
|---|---|
| **Contract** | The `error.code` field (`QQQ-nnnn`) is **permanent** — agents match on it |
| **Adding** | New fields, and new enum variants, are **minor** changes |
| **Breaking** | Removing a field, renaming one, or changing a code's meaning is **major** |
| **Codes are never reused** | A retired code is retired, not recycled for a new condition |

Every command supports `--json`, and `schema/cli-envelope.schema.json` is the machine-readable
form of this promise, checked in CI by `tools/gen_schemas.py --check`.

---

## How these promises are enforced

A promise with no check is a wish. Each row above names a mechanism:

| Surface | Enforced by |
|---|---|
| Crate tiers | `tools/check_tiers.py` (this document's own source), `tools/check_topology.py` |
| WIT | `tools/check_wit_style.py`, `tools/check_wit_reference.py`, 17 `.wit` files validating |
| Manifest | `schema/qqq-toml.schema.json`, `tools/gen_schemas.py --check` |
| Lockfile | `schema/qqq-lock.schema.json`, the same check |
| CLI JSON | `schema/cli-envelope.schema.json`, the error catalogue's round-trip test |

---

## What this document does not yet cover

Named rather than implied:

- **`CON-015` is open**: the deprecation mechanics in WIT — a `@deprecated` annotation carrying a
  removal version — are not defined. Until they are, the `stable` tier's "one minor release of
  notice" is a convention rather than a mechanism.
- **Version `0.0.0`**: the workspace is pre-release, so these tiers describe the contract that
  comes into force at 1.0. Until then every crate is technically `beta`; the tier records the
  *intent* that has been reviewed, which is why it is worth stating before it is enforceable.
- **`qqq-registry` and `qqq-fabric`** have no tier here because they are not built in this
  repository.
