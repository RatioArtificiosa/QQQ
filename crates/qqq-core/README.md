# qqq-core

Shared types for the QQQ runtime: identifiers, the version model, and the
stable `QQQ-XXXX` error contract.

**No I/O.** This crate sits at the bottom of the dependency graph
(`QQQ-Proposal-V1.md` §4.3) and every other crate depends on it, so it stays
pure and cheap to compile and test.

## The error contract

Every failure carries a stable code, a permanent docs URL, an optional cause
chain, and an actionable remediation.

```rust
use qqq_core::{Error, ErrorCode};

let err = Error::new(ErrorCode::CapabilityDenied, "sql.query is not granted")
    .with_context("component", "orders-api")
    .with_cause("no configuration layer grants sql.orders")
    .with_remediation("add [[capabilities.sql]] to qqq.toml");

assert_eq!(err.id(), "QQQ-4003");
assert!(!err.is_retryable());        // deterministic; retrying cannot help
assert!(err.render().contains("→")); // the fix is always shown
```

### Rules that are enforced, not requested

| Rule | Why | Test |
|---|---|---|
| Codes are **never reused or renumbered** | Logs, issues and support threads reference them forever | `codes_are_unique` |
| A code's thousands digit matches its class | `QQQ-2400` claiming to be a manifest error would mislead an agent | `class_matches_numeric_range` |
| `all()` stays numerically sorted | Makes an omission visible in review | `codes_are_sorted` |
| Every code round-trips from both number and id | Prevents a half-added code | `every_code_round_trips` |
| The seven examples documented in the proposal resolve | Docs and code cannot drift | `proposal_documented_examples_resolve` |
| `message` is **unstable**; `code` is the contract | Agents must match on the code | documented on `Error::message` |

### Retryability

`is_retryable()` is a **hint** derived from the error class. Only `Package` and
`Host` are retryable. Everything else is deterministic for the same input, and
a caller that retries wastes the budget it should spend backing off elsewhere.

## Identifiers

Newtypes, never bare `String` — a `TenantId` passed where a `ComponentId` is
expected is a cross-tenant leak, and the compiler should refuse it.

`TenantId`, `ComponentId`, `PackageName` all validate on construction:

- 1–64 characters
- lowercase ASCII letters, digits, `-`, `_`
- must begin with a letter, must not end with a separator

This is a **security** control, not a style rule: a package name reaches
directory paths, so `../etc/passwd` is rejected structurally.

## Naming

The brand is **QQQ**. The crate, npm package and binary are **`qqqai`**,
because `qqq` is taken on crates.io and npm (`QQQ-Observations-and-Memories.md`
§D-001). Both are exposed as constants, and a test asserts the invariant so the
decision cannot drift.

```rust
use qqq_core::{BINARY_NAME, BRAND_NAME};
assert_eq!(BINARY_NAME, "qqqai");
assert_eq!(BRAND_NAME, "QQQ");
```

## Checklist coverage

`ARCH-007`, `ARCH-008`, `CON-009`, `CON-016`, `AGENT-021`, `AGENT-022`.
See `QQQ-Proposal-V1.md` §4.3 and §8.3.
