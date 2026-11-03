// SPDX-License-Identifier: Apache-2.0

//! The call-time grant re-check, proveable — `ARCH-012`.
//!
//! # What the item asks, and what §4.4 says it is for
//!
//! > **ARCH-012** Implement the defence-in-depth re-check of grants at
//! > host-call time.
//!
//! §4.4, step 11:
//!
//! > **Step 11 re-checks.** The grant set is consulted twice — at bind time and
//! > at call time. The second check is defence in depth against a host bug that
//! > mis-builds a linker. It is cheap (a set lookup on a `u32` capability ID)
//! > and it is **non-negotiable**.
//!
//! # The audit that produced this module, and the two wrong answers it gave
//!
//! The first measurement looked for `grants.grants(` inside each `func_wrap`
//! body and reported **8 of 11 host functions with no call-time check**. That
//! number was wrong, and how it was wrong is the reason this module exists in
//! the shape it does.
//!
//! The check *is* reached for those functions — one layer down. `hashing.digest`
//! delegates to [`crate::ambient::hash_data`], which opens with
//! [`crate::ambient::require`]. A grep for the check in the registration body
//! measures where the text lives, not whether the authority is consulted —
//! `§O-071`'s lesson for the fourth time in this workspace.
//!
//! The second measurement was too generous in the other direction: having found
//! the delegation, it would be easy to conclude the item is complete. It is not,
//! because the property §4.4 states is not *"a check exists somewhere on each
//! path"* — it is *"the grant set is consulted twice, independently"*, and the
//! second consultation must not be something a later edit can drop without
//! anything noticing.
//!
//! # What actually enforces it, measured
//!
//! Three mechanisms, each covering a different layer, and the third is the one
//! this module adds:
//!
//! | Mechanism | Where | What it catches |
//! |---|---|---|
//! | **Conditional registration** | `host_clock::register`, `host_crypto::register` | An interface whose capability is absent is never bound, so its functions are not merely refused — they are **absent** |
//! | **Per-function re-check** | `wall-clock.now`, `monotonic-clock.now`, every path through [`crate::ambient::require`], and every `bindgen!` trait-method body (`random.get`, `hashing.digest`, `hmac.compute`, …) | A mis-built linker that bound the interface anyway |
//! | **Source-level totality** | [`AUDITED`], checked by [`audit`] | A **new** `func_wrap` added outside a gated registration path |
//!
//! The third is the addition. The first two are properties of the code as
//! written; the third is a property that survives the next edit, and without it
//! "every host function re-checks" is a claim about today's source that nothing
//! re-establishes tomorrow.
//!
//! # Why a table and not a `debug_assert` at each call site
//!
//! Because the failure mode is an **omission**, and an omission cannot raise an
//! assertion. A function that was never written cannot check anything, so the
//! only place to catch it is where the whole set is visible. That is the same
//! reasoning as [`crate::boundary`]'s table (`SEC-011`), and the same shape:
//! enumerate what exists, and fail when the enumeration and the source disagree.

use std::collections::BTreeSet;

use qqq_cap::capability::Capability;

/// One registered host function and the capability that justifies it.
///
/// # Why every field is present even when it looks redundant
///
/// Because a reader asking "can a guest call this without a grant?" needs the
/// answer in one place, and the answer is not always the obvious capability. The
/// `enforced_by` field names *how* the check happens, which is what makes a
/// reviewer able to disagree — `"registration"` is a weaker guarantee than
/// `"per-function"`, and the distinction is invisible if only a capability is
/// recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditedCall {
    /// The file the registration lives in, relative to `crates/qqq-host/src`.
    pub file: &'static str,
    /// The name passed to `func_wrap`.
    pub function: &'static str,
    /// The interface it belongs to, as the linker names it.
    pub interface: &'static str,
    /// The capability that must be granted for the guest to reach it, or `None`.
    ///
    /// # Why this is an `Option` and not a sentinel
    ///
    /// Because `qqq:test/assertions` is deliberately **not** capability-gated, and there is no
    /// `Capability` that means "none" -- every variant names a real authority. A sentinel would be a
    /// variant that lies about what it is.
    ///
    /// **`None` and [`Enforcement::Ungated`] travel together**, and
    /// `an_ungated_row_carries_no_capability` asserts the pairing rather than leaving it to a reader
    /// to notice. A row that said `None` with `PerFunction` would be describing a check on nothing.
    pub capability: Option<Capability>,
    /// How the call-time check is enforced.
    pub enforced_by: Enforcement,
}

/// How a host function's call-time authority is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Enforcement {
    /// The registration sits inside a gated `register` path (a `register_*`
    /// function for `func_wrap`, a grant-conditional `add_to_linker` for
    /// `bindgen!` trait methods), **and** the function's own body repeats
    /// the check.
    ///
    /// This is the strongest form §4.4 describes: the interface is absent
    /// without the grant, and the function refuses a mis-built linker.
    PerFunction,
    /// The registration sits inside a gated `register` path, and its body relies on
    /// a shared helper that performs the check.
    ///
    /// Equivalent to [`Self::PerFunction`] in force — the check happens on every
    /// call — but the check is not visible in the registration's own text, which
    /// is exactly what made the first audit of this item report a false gap.
    ViaHelper,
    /// The registration sits inside a gated `register` path and performs no check of
    /// its own, because it is a pure function of data the interface's own
    /// gating already covers — or because it exercises no authority at all
    /// (idempotent handle cleanup, public construction parameters).
    ///
    /// Current rows of this form: the AEAD length constants and the
    /// statement/transaction `close`/`drop` cleanup paths. Each names the
    /// gating grant explicitly, so a future edit that gives such a function
    /// a reason to read the store must move it to [`Self::PerFunction`] —
    /// a visible change to this table rather than an invisible one to a body.
    ///
    /// # Why this variant is allowed to exist
    ///
    /// Because the alternative is a redundant check whose presence would imply
    /// the interface *could* be reached without its grant. Recording the weaker
    /// form explicitly means a reviewer sees the claim rather than inferring
    /// consistency, and a future edit that gives such a function a reason to
    /// read the store must move it to [`Self::PerFunction`] — a visible change
    /// to this table rather than an invisible one to a body.
    InterfaceGated,
    /// The `func_wrap` is registered unconditionally and checks no capability, because the interface
    /// gates nothing.
    ///
    /// # Why this is a variant and not an absence
    ///
    /// Because "no capability is involved" is a **claim about the call**, and the three gating
    /// variants cannot make it. `qqq:test/assertions` is the first: an assertion interface is not a
    /// capability a guest is granted or denied, and what decides whether a guest gets it is whether a
    /// *runner* linked it -- `linker.rs` decides per-module, and a `serve` process must not link one.
    ///
    /// [`Enforcement::rechecks_each_call`] answers `false` here, and that is not a weakness: **an
    /// ungated call re-checks nothing because it gates nothing.**
    Ungated,
}

impl Enforcement {
    /// Whether the capability is consulted on every call, as opposed to the
    /// interface being absent without it.
    ///
    /// # Why this is a separate question from "is it safe"
    ///
    /// Because both answers are safe and they are not the same claim. A
    /// `PerFunction` row survives a mis-built linker; an `InterfaceGated` row
    /// does not, and neither does a `ViaHelper` row if its helper is edited.
    /// Collapsing them into one boolean is how a table like this stops being
    /// able to disagree with the code.
    #[must_use]
    pub const fn rechecks_each_call(self) -> bool {
        matches!(self, Self::PerFunction | Self::ViaHelper)
    }
}

/// Every host function the runtime registers, with its authority and how that
/// authority is enforced — `ARCH-012`.
///
/// # Why this is exhaustive by construction
///
/// [`audit`] compares this table against the source and fails when they
/// disagree in either direction, so a `func_wrap` added without a row here is a
/// test failure rather than an unexamined call path. That is the property that
/// makes the table a check rather than documentation.
pub const AUDITED: [AuditedCall; 80] = [
    AuditedCall {
        file: "host_clock.rs",
        function: "now",
        interface: "qqq:clock/wall-clock@1.0.0",
        capability: Some(Capability::ClockWall),
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_clock.rs",
        function: "resolution",
        interface: "qqq:clock/wall-clock@1.0.0",
        capability: Some(Capability::ClockWall),
        // Per-function re-check like `now`: the answer is configuration, not
        // a reading, but the body re-checks the grant anyway, so a mis-built
        // linker still denies.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_clock.rs",
        function: "timezone",
        interface: "qqq:clock/wall-clock@1.0.0",
        capability: Some(Capability::ClockWall),
        // Per-function re-check like `now`: the answer is the constant
        // `"UTC"`, but the body re-checks the grant anyway, so a mis-built
        // linker still denies.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_clock.rs",
        function: "now",
        interface: "qqq:clock/monotonic-clock@1.0.0",
        capability: Some(Capability::ClockMonotonic),
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_clock.rs",
        function: "resolution",
        interface: "qqq:clock/monotonic-clock@1.0.0",
        capability: Some(Capability::ClockMonotonic),
        // Per-function re-check like `now`: the answer is configuration, not
        // a reading, but the body re-checks the grant anyway, so a mis-built
        // linker still denies.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_test.rs",
        function: "mark-fuel",
        interface: "qqq:test/assertions@1.0.0",
        capability: None,
        // No capability is required, and the reason is that one does not exist to require:
        // an assertion interface is not a capability. It is linked when a runner drives the
        // guest and not when a server does -- see `Enforcement::Ungated`. Records the fuel *remaining* at a named mark, so a later reading subtracts.
        enforced_by: Enforcement::Ungated,
    },
    AuditedCall {
        file: "host_test.rs",
        function: "fuel-since",
        interface: "qqq:test/assertions@1.0.0",
        capability: None,
        // No capability is required, and the reason is that one does not exist to require:
        // an assertion interface is not a capability. It is linked when a runner drives the
        // guest and not when a server does -- see `Enforcement::Ungated`. Reads the mark table and the live counter; an unknown mark is `no-fuel-baseline`.
        enforced_by: Enforcement::Ungated,
    },
    AuditedCall {
        file: "host_test.rs",
        function: "assert-fuel-below",
        interface: "qqq:test/assertions@1.0.0",
        capability: None,
        // No capability is required, and the reason is that one does not exist to require:
        // an assertion interface is not a capability. It is linked when a runner drives the
        // guest and not when a server does -- see `Enforcement::Ungated`. The comparison the item names -- `TEST-008`'s ergonomic surface.
        enforced_by: Enforcement::Ungated,
    },
    AuditedCall {
        file: "host_test.rs",
        function: "assert-caps-only",
        interface: "qqq:test/assertions@1.0.0",
        capability: None,
        // No capability is required, and the reason is that one does not exist to require:
        // an assertion interface is not a capability. It is linked when a runner drives the
        // guest and not when a server does -- see `Enforcement::Ungated`. A bound on what the guest **attempted**, read from the audit stream -- `TEST-007`.
        enforced_by: Enforcement::Ungated,
    },
    AuditedCall {
        file: "host_test.rs",
        function: "assert-no-capability",
        interface: "qqq:test/assertions@1.0.0",
        capability: None,
        // No capability is required, and the reason is that one does not exist to require:
        // an assertion interface is not a capability. It is linked when a runner drives the
        // guest and not when a server does -- see `Enforcement::Ungated`. The strict form of the same query against a one-element set.
        enforced_by: Enforcement::Ungated,
    },
    AuditedCall {
        file: "host_test.rs",
        function: "report",
        interface: "qqq:test/assertions@1.0.0",
        capability: None,
        // No capability is required, and the reason is that one does not exist to require:
        // an assertion interface is not a capability. It is linked when a runner drives the
        // guest and not when a server does -- see `Enforcement::Ungated`. Appends a guest-evaluated assertion to the failure list, so one run reports every failure.
        enforced_by: Enforcement::Ungated,
    },
    AuditedCall {
        file: "host_wasi03.rs",
        function: "now",
        interface: "wasi:clocks/monotonic-clock@0.3.2",
        capability: Some(Capability::ClockMonotonic),
        // Per-function recheck, mirroring `host_clock`'s monotonic `now`:
        // registration is conditional on the grant AND the body re-checks it,
        // so a mis-built linker still denies. The audit's `UnbackedClaim`
        // check verifies the body consults the grant.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_wasi03.rs",
        function: "get-resolution",
        interface: "wasi:clocks/monotonic-clock@0.3.2",
        capability: Some(Capability::ClockMonotonic),
        // Per-function re-check like the 0.2 `resolution` it twins: the tick
        // interval is configuration, not a reading, but the body re-checks
        // the grant anyway, so a mis-built linker still denies.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_wasi03.rs",
        function: "wait-until",
        interface: "wasi:clocks/monotonic-clock@0.3.2",
        capability: None,
        // Ungated because there is no grant to check: the stub traps for every
        // caller, granted or not, naming the missing engine async support. It
        // is reachable only when the clock grant justified the instance, so an
        // ungranted guest never meets this trap — it fails closed earlier, at
        // instantiation, on the absent instance.
        enforced_by: Enforcement::Ungated,
    },
    AuditedCall {
        file: "host_wasi03.rs",
        function: "wait-for",
        interface: "wasi:clocks/monotonic-clock@0.3.2",
        capability: None,
        // As `wait-until` above: a named trap, not a grant decision.
        enforced_by: Enforcement::Ungated,
    },
    AuditedCall {
        file: "host_secrets.rs",
        function: "apply",
        interface: "qqq:secrets/secret-use@1.0.0",
        capability: Some(Capability::SecretUse),
        // Per-function re-check: registration is conditional on the grant
        // AND the body re-checks it, plus intersects the crypto grant for the
        // operation — a mis-built linker still denies.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_secrets.rs",
        function: "exists",
        interface: "qqq:secrets/secret-use@1.0.0",
        capability: Some(Capability::SecretUse),
        // Per-function re-check: registration is conditional on the grant AND
        // the body re-checks it (fail-closed to `false`), so a mis-built
        // linker still denies. The answer is a disclosure-safe boolean.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_secrets.rs",
        function: "permitted-operations",
        interface: "qqq:secrets/secret-use@1.0.0",
        capability: Some(Capability::SecretUse),
        // Per-function re-check: the body re-checks the grant (fail-closed
        // to an empty list), so a mis-built linker still denies. Names only,
        // never values.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_env.rs",
        function: "get",
        interface: "qqq:env/environment@1.0.0",
        capability: Some(Capability::EnvRead),
        // Per-function re-check: registration is conditional on the grant AND
        // the body re-checks it, so a mis-built linker still denies.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_env.rs",
        function: "get-or",
        interface: "qqq:env/environment@1.0.0",
        capability: Some(Capability::EnvRead),
        // The fallback applies to `unset` only; a denied read stays denied.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_env.rs",
        function: "allowed-names",
        interface: "qqq:env/environment@1.0.0",
        capability: Some(Capability::EnvRead),
        // Per-function re-check: the body re-checks the grant (fail-closed
        // to an empty list), so a mis-built linker still denies. Names only
        // (the manifest already publishes them), never values.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_wasi.rs",
        function: "get-random-bytes",
        interface: "wasi:random/random@0.2.12",
        capability: Some(Capability::CryptoRandom),
        // Per-function re-check: the shim shadows wasmtime's own
        // registration (which answers regardless of grants), so only the
        // body check stands between an ungranted guest and host entropy.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_wasi.rs",
        function: "get-random-u64",
        interface: "wasi:random/random@0.2.12",
        capability: Some(Capability::CryptoRandom),
        // Same shape as `get-random-bytes`: eight bytes from the same source.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_wasi.rs",
        function: "get-insecure-random-bytes",
        interface: "wasi:random/insecure@0.2.12",
        capability: Some(Capability::CryptoRandom),
        // Insecure is still entropy: same grant, same check, same source.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_wasi.rs",
        function: "get-insecure-random-u64",
        interface: "wasi:random/insecure@0.2.12",
        capability: Some(Capability::CryptoRandom),
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_wasi.rs",
        function: "insecure-seed",
        interface: "wasi:random/insecure-seed@0.2.12",
        capability: Some(Capability::CryptoRandom),
        // A seed is key material by another name: same grant, same check.
        enforced_by: Enforcement::PerFunction,
    },
    // -- bindgen entry points (`C4`) -------------------------------------
    //
    // Files that bind through the generated `add_to_linker` have no
    // `func_wrap`, so the scanner above learns them from `impl
    // bindings::…::Host*` blocks instead. Each row below names the
    // capability that justifies the call and how the body re-checks it;
    // where either of two direction grants opens the call, the row names
    // the first grant in the body's disjunction and the comment records
    // the other.
    AuditedCall {
        file: "host_crypto.rs",
        function: "get",
        interface: "qqq:crypto/random@1.0.0",
        capability: Some(Capability::CryptoRandom),
        // Seam re-check: an ungranted guest fails before the length is
        // judged, and the attempt records a row.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "digest",
        interface: "qqq:crypto/hashing@1.0.0",
        capability: Some(Capability::CryptoHash),
        // Delegates to the `hash_data` helper, which requires the grant
        // and enforces the input ceiling.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "digest-many",
        interface: "qqq:crypto/hashing@1.0.0",
        capability: Some(Capability::CryptoHash),
        // Same helper as `digest`, per input element.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "compute",
        interface: "qqq:crypto/hmac@1.0.0",
        capability: Some(Capability::CryptoHmac),
        // Seam re-check plus the algorithm allowlist per call.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "verify",
        interface: "qqq:crypto/hmac@1.0.0",
        capability: Some(Capability::CryptoHmac),
        // Same seam and allowlist as `compute`.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "nonce-length",
        interface: "qqq:crypto/aead@1.0.0",
        capability: Some(Capability::CryptoAead),
        // Public construction parameter, infallible by WIT design: no
        // per-call check, and registration is grant-gated, so a mis-built
        // linker still cannot move a byte (`encrypt`/`decrypt` re-check).
        enforced_by: Enforcement::InterfaceGated,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "key-length",
        interface: "qqq:crypto/aead@1.0.0",
        capability: Some(Capability::CryptoAead),
        // Same reasoning as `nonce-length`.
        enforced_by: Enforcement::InterfaceGated,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "encrypt",
        interface: "qqq:crypto/aead@1.0.0",
        capability: Some(Capability::CryptoAead),
        // Seam re-check plus the construction allowlist per call.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "decrypt",
        interface: "qqq:crypto/aead@1.0.0",
        capability: Some(Capability::CryptoAead),
        // Same seam and allowlist as `encrypt`.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "sign",
        interface: "qqq:crypto/signing@1.0.0",
        capability: Some(Capability::CryptoSign),
        // Seam re-check plus the algorithm allowlist per call.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "verify",
        interface: "qqq:crypto/signing@1.0.0",
        capability: Some(Capability::CryptoSign),
        // Same seam and allowlist as `sign`.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "public-key",
        interface: "qqq:crypto/signing@1.0.0",
        capability: Some(Capability::CryptoSign),
        // Same seam and allowlist as `sign`.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_dns.rs",
        function: "resolve",
        interface: "qqq:dns/resolver@1.0.0",
        capability: Some(Capability::DnsResolve),
        // Seam re-check, then the subrequest budget, then the allowlist:
        // an unlisted spray spends budget like a listed lookup.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_dns.rs",
        function: "resolve-many",
        interface: "qqq:dns/resolver@1.0.0",
        capability: Some(Capability::DnsResolve),
        // Same ordering as `resolve`, per entry through `resolve`.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_dns.rs",
        function: "allowed-names",
        interface: "qqq:dns/resolver@1.0.0",
        capability: Some(Capability::DnsResolve),
        // Infallible by WIT design; an ungranted caller gets an empty
        // list, learning nothing including membership.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_http.rs",
        function: "send",
        interface: "qqq:http/http@1.0.0",
        capability: Some(Capability::HttpClient),
        // Seam re-check; an ungranted send still charges budget and writes
        // the egress row, so probing cannot loop for free.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_http.rs",
        function: "incoming-authority",
        interface: "qqq:http/http@1.0.0",
        capability: Some(Capability::HttpServer),
        // Seam re-check; an ungranted caller gets the sentinel authority,
        // and the attempt records a row.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_kv.rs",
        function: "get",
        interface: "qqq:kv/store@1.0.0",
        capability: Some(Capability::KvRead),
        // Through the `check_read` helper: grant, name shape, membership.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_kv.rs",
        function: "set",
        interface: "qqq:kv/store@1.0.0",
        capability: Some(Capability::KvWrite),
        // Through the `check_write` helper: grant, name shape, membership.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_kv.rs",
        function: "delete",
        interface: "qqq:kv/store@1.0.0",
        capability: Some(Capability::KvWrite),
        // Same helper as `set`; deleting an absent key succeeds.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_kv.rs",
        function: "exists",
        interface: "qqq:kv/store@1.0.0",
        capability: Some(Capability::KvRead),
        // Same helper as `get`, without transferring the value.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_kv.rs",
        function: "keys",
        interface: "qqq:kv/store@1.0.0",
        capability: Some(Capability::KvRead),
        // Same helper as `get`, plus the prefix length gate.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_kv.rs",
        function: "get-many",
        interface: "qqq:kv/store@1.0.0",
        capability: Some(Capability::KvRead),
        // Same helper as `get`, plus the batch count and per-key gates.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_kv.rs",
        function: "stores",
        interface: "qqq:kv/store@1.0.0",
        capability: Some(Capability::KvRead),
        // Infallible by WIT design; either direction grant opens it (the
        // row names the first), and an ungranted caller gets an empty list.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_log.rs",
        function: "emit",
        interface: "qqq:log/logging@1.0.0",
        capability: Some(Capability::LogWrite),
        // Through the `emit_record` helper: grant, size, quota, redaction.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_log.rs",
        function: "emit-many",
        interface: "qqq:log/logging@1.0.0",
        capability: Some(Capability::LogWrite),
        // Grant and quota up front, then per-record validation with an
        // early-failing byte total; atomic, so a refused batch stores nothing.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_log.rs",
        function: "enabled",
        interface: "qqq:log/logging@1.0.0",
        capability: Some(Capability::LogWrite),
        // No level filter is configured, so the answer is the grant itself.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_queue.rs",
        function: "publish",
        interface: "qqq:queue/messaging@1.0.0",
        capability: Some(Capability::QueuePublish),
        // Through the `check_publish` helper: grant, then membership.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_queue.rs",
        function: "publish-many",
        interface: "qqq:queue/messaging@1.0.0",
        capability: Some(Capability::QueuePublish),
        // Same helper as `publish`, plus the batch count and per-body gates.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_queue.rs",
        function: "receive",
        interface: "qqq:queue/messaging@1.0.0",
        capability: Some(Capability::QueueSubscribe),
        // Through the `check_subscribe` helper: grant, then membership.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_queue.rs",
        function: "acknowledge",
        interface: "qqq:queue/messaging@1.0.0",
        capability: Some(Capability::QueueSubscribe),
        // Same helper as `receive`, plus the delivery-id length gate.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_queue.rs",
        function: "reject",
        interface: "qqq:queue/messaging@1.0.0",
        capability: Some(Capability::QueueSubscribe),
        // Same helper and id gate as `acknowledge`.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_queue.rs",
        function: "queues",
        interface: "qqq:queue/messaging@1.0.0",
        capability: Some(Capability::QueuePublish),
        // Infallible by WIT design; either direction grant opens it (the
        // row names the first), and an ungranted caller gets an empty list.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "prepare",
        interface: "qqq:sql/database@1.0.0",
        capability: Some(Capability::SqlQuery),
        // Either direction grant opens the call (the row names the first);
        // the statement's own nature decides the direction below.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "query-once",
        interface: "qqq:sql/database@1.0.0",
        capability: Some(Capability::SqlQuery),
        // Same dual-grant entry as `prepare`, one-shot.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "query",
        interface: "qqq:sql/database@1.0.0",
        capability: Some(Capability::SqlQuery),
        // Query-only grant; reads open read-only so a missing file fails
        // closed instead of materializing.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "execute",
        interface: "qqq:sql/database@1.0.0",
        capability: Some(Capability::SqlExecute),
        // Either direction grant opens the call (the row names the write
        // side); membership and direction follow, then the write runs.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "close",
        interface: "qqq:sql/database@1.0.0",
        capability: Some(Capability::SqlQuery),
        // Idempotent handle removal: registration is direction-gated, and
        // closing exercises no authority of its own.
        enforced_by: Enforcement::InterfaceGated,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "drop",
        interface: "qqq:sql/database@1.0.0",
        capability: Some(Capability::SqlQuery),
        // Same reasoning as `close`: cleanup, not authority.
        enforced_by: Enforcement::InterfaceGated,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "databases",
        interface: "qqq:sql/database@1.0.0",
        capability: Some(Capability::SqlQuery),
        // Infallible by WIT design; either direction grant opens it (the
        // row names the first), and an ungranted caller gets an empty list.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "begin",
        interface: "qqq:sql/transaction@1.0.0",
        capability: Some(Capability::SqlQuery),
        // Through the `check_any` helper: either direction grant opens a
        // transaction (the row names the first); direction is decided by
        // the statements inside it.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "prepare",
        interface: "qqq:sql/transaction@1.0.0",
        capability: Some(Capability::SqlQuery),
        // Same dual-grant entry as database `prepare`, plus the SQLite
        // open-transaction agreement check before minting.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "commit",
        interface: "qqq:sql/transaction@1.0.0",
        capability: Some(Capability::SqlQuery),
        // Through `check_any`; the journal write is charged like any
        // other execution.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "rollback",
        interface: "qqq:sql/transaction@1.0.0",
        capability: Some(Capability::SqlQuery),
        // Same helper and charging as `commit`.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "drop",
        interface: "qqq:sql/transaction@1.0.0",
        capability: Some(Capability::SqlQuery),
        // Dropping rolls back and invalidates: cleanup of the instance's
        // own handles, gated by the registration.
        enforced_by: Enforcement::InterfaceGated,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "query",
        interface: "qqq:sql/transaction@1.0.0",
        capability: Some(Capability::SqlQuery),
        // Query-only grant plus the SQLite open-transaction agreement
        // check before running.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_sql.rs",
        function: "execute",
        interface: "qqq:sql/transaction@1.0.0",
        capability: Some(Capability::SqlExecute),
        // Either direction grant opens the call (the row names the write
        // side); the write-membership check and the agreement check follow.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_trace.rs",
        function: "start-span",
        interface: "qqq:trace/tracing@1.0.0",
        capability: Some(Capability::TraceWrite),
        // Through the `start_span_impl` helper: seam re-check, then the
        // table bound.
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_trace.rs",
        function: "current-traceparent",
        interface: "qqq:trace/tracing@1.0.0",
        capability: Some(Capability::TraceWrite),
        // Seam re-check; an ungranted caller reads absent trace.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_trace.rs",
        function: "child",
        interface: "qqq:trace/tracing@1.0.0",
        capability: Some(Capability::TraceWrite),
        // Seam first, then liveness: the error kind never leaks handle
        // validity without the grant.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_trace.rs",
        function: "event",
        interface: "qqq:trace/tracing@1.0.0",
        capability: Some(Capability::TraceWrite),
        // Seam re-check with the length bound before liveness.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_trace.rs",
        function: "set-attributes",
        interface: "qqq:trace/tracing@1.0.0",
        capability: Some(Capability::TraceWrite),
        // Seam re-check, then liveness, then the per-value and total
        // byte caps.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_trace.rs",
        function: "set-error",
        interface: "qqq:trace/tracing@1.0.0",
        capability: Some(Capability::TraceWrite),
        // Seam re-check with the length bound before the failure flag.
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_trace.rs",
        function: "drop",
        interface: "qqq:trace/tracing@1.0.0",
        capability: Some(Capability::TraceWrite),
        // Seam re-check; a dropped handle is gone either way.
        enforced_by: Enforcement::PerFunction,
    },
];

/// Why the table once listed no `hmac`, `hashing`, or `qqq:crypto/random` rows.
///
/// # The rows that moved, and why the table did not follow — until `C4`
///
/// The first version of [`AUDITED`] listed eleven calls, including
/// `hmac-algorithm.name` and `hmac.get`, taken from the WIT's `hmac` interface
/// without checking whether the host implements it. Later `random.get`,
/// `hashing.digest` and `hashing.digest-many` were rows backed by
/// hand-written `func_wrap` bodies — until the WIT-conformance fix moved the
/// `qqq:crypto` interfaces to `bindgen!` trait implementations (a bare-shape
/// host failed to *instantiate* a WIT-conformant guest, which no table row
/// could express because the scanner only sees `func_wrap`).
///
/// `bindgen!` trait methods are not `func_wrap` registrations, so the
/// table's machinery — which matched scanned registrations against rows —
/// could not see them. (`CryptoRandom` stayed covered through the wasi random
/// shims, which are `func_wrap` with seam checks.) Their grant re-checks
/// were proven instead by direct execution tests on the trait
/// (`random_get_refuses_by_name`, `hashing_refuses_by_name`,
/// `hmac_grants_and_allowlist_are_checked`) and by the guest-compiled
/// `iface_crypto` probe. The `C4` review closed the gap the other way: the
/// scanner now learns `impl bindings::…::Host*` blocks too, so every
/// bindgen entry point has a row above and the execution tests pin the
/// behavior the rows claim.
///
/// A disagreement between [`AUDITED`] and the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditFinding {
    /// A registration in the source that no table row names.
    Unlisted {
        /// The file.
        file: String,
        /// The function name.
        function: String,
        /// The line, so the reader can look at it.
        line: usize,
    },
    /// A table row naming a registration the source does not contain.
    ///
    /// Keyed by `(file, interface, function)`, not `(file, function)`: the
    /// wall and monotonic clocks share function names in one file, and a
    /// two-part key let a present namesake vouch for a deleted row.
    Stale {
        /// The file.
        file: &'static str,
        /// The interface the row claims.
        interface: &'static str,
        /// The function name.
        function: &'static str,
    },
    /// A table entry claiming a per-function re-check where the body has none
    /// and does not delegate to a helper that does.
    UnbackedClaim {
        /// The file.
        file: &'static str,
        /// The function name.
        function: &'static str,
    },
}

impl std::fmt::Display for AuditFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unlisted {
                file,
                function,
                line,
            } => write!(
                f,
                "{file}:{line} registers `{function}`, which no entry in \
                 `arch012::AUDITED` names. Every host function must be listed \
                 with the capability that justifies it and how that capability \
                 is checked -- an unlisted one is a call path nobody has \
                 reasoned about."
            ),
            Self::Stale {
                file,
                interface,
                function,
            } => write!(
                f,
                "`arch012::AUDITED` lists `{file}`:`{interface}`/`{function}`, which the source \
                 does not register. A stale row makes the table claim coverage \
                 it does not have."
            ),
            Self::UnbackedClaim { file, function } => write!(
                f,
                "`arch012::AUDITED` claims `{file}`:`{function}` re-checks its \
                 capability on every call, but its body contains no \
                 `grants.grants(..)` and no call to a helper that has one. The \
                 claim in the table is not backed by the code."
            ),
        }
    }
}

/// A `func_wrap` found in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    /// The file it was found in.
    pub file: String,
    /// The instance the registration is attached to.
    pub interface: String,
    /// The name passed to `func_wrap`.
    pub function: String,
    /// The 1-based line.
    pub line: usize,
    /// Whether the body reaches a capability check, directly or via a helper
    /// this module knows about.
    pub checks_capability: bool,
}

/// Helpers that perform a capability check, so a `func_wrap` body that calls
/// one is counted as checked.
///
/// # Why a name list rather than a dataflow analysis
///
/// Because a dataflow analysis here would be a second implementation of Rust,
/// and the property it would establish is the one [`AUDITED`] already states by
/// hand and [`audit`] cross-checks. The list is short, explicit, and a helper
/// that starts gating must be added to it — whereupon the `UnbackedClaim` check
/// begins validating the rows that depend on it.
pub const CHECKING_HELPERS: [&str; 10] = [
    "hash_data(",
    "ambient::require(",
    "require_random(",
    // Per-module grant-gate helpers that bindgen bodies call instead of
    // checking inline: kv, sql and queue route their entry points through
    // these, log routes `emit` through `emit_record`, and trace routes
    // `start-span` through `start_span_impl` — so a body reaching one
    // re-checks the grant on every call.
    // (Quota helpers like `check_handles` are deliberately absent: a full
    // table is not a grant decision.)
    "check_read(",
    "check_write(",
    "check_any(",
    "check_publish(",
    "check_subscribe(",
    "emit_record(",
    "start_span_impl(",
];

/// Cross-check [`AUDITED`] against the source in `sources`.
///
/// # Errors
///
/// Returns every [`AuditFinding`], sorted, so a reader sees the whole gap
/// rather than the first item of it.
///
/// # Why this takes the sources as an argument
///
/// So it can be tested with a **fabricated** source set. A checker that can only
/// read the real tree cannot be proven to detect anything — it can only be
/// observed to pass, which is the defect `§M-006` records and `§O-092` records
/// again. The test suite drives it with a source containing an unlisted
/// `func_wrap` and a row claiming an unbacked re-check, and asserts both are
/// reported.
pub fn audit(sources: &[(String, String)]) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();

    for (file, text) in sources {
        for registered in scan(file, text) {
            // **Keyed by `(file, interface, function)`, not `(file, function)`.**
            // Two capabilities share a function name in one file --
            // `wall-clock.now` and `monotonic-clock.now`, and likewise
            // `resolution` -- so a two-part key made the audit able to match the
            // wrong row. The dangerous direction is `UnbackedClaim` passing
            // because a *namesake* is backed: `monotonic-clock.now` could lose
            // its grant check while `wall-clock.now` kept one.
            seen.insert((
                file.clone(),
                registered.interface.clone(),
                registered.function.clone(),
            ));
            let row = AUDITED.iter().find(|a| {
                a.file == file.as_str()
                    && a.function == registered.function.as_str()
                    && registered
                        .interface
                        .ends_with(interface_suffix(a.interface))
            });
            match row {
                None => findings.push(AuditFinding::Unlisted {
                    file: registered.file,
                    function: registered.function,
                    line: registered.line,
                }),
                Some(a) if a.enforced_by.rechecks_each_call() && !registered.checks_capability => {
                    findings.push(AuditFinding::UnbackedClaim {
                        file: a.file,
                        function: a.function,
                    });
                }
                Some(_) => {}
            }
        }
    }

    for row in &AUDITED {
        let named = seen.iter().any(|(f, i, fn_)| {
            f == row.file && fn_ == row.function && i.ends_with(interface_suffix(row.interface))
        });
        if !named {
            findings.push(AuditFinding::Stale {
                file: row.file,
                interface: row.interface,
                function: row.function,
            });
        }
    }

    findings.sort_by_key(ToString::to_string);
    findings.dedup();
    findings
}

/// The part of an interface name that follows the version, so a table row can
/// be matched against an interface path written in a registration.
///
/// `qqq:clock@1.0.0/wall-clock` becomes `wall-clock`, which is what the
/// registration writes as the instance name.
fn interface_suffix(interface: &str) -> &str {
    interface.rsplit('/').next().unwrap_or(interface)
}

/// Find every guest-callable registration in one **production** source, and
/// whether its body reaches a capability check.
///
/// `func_wrap("name", …)` call sites and `impl bindings::…::Host*` trait
/// methods alike; see `bindgen_methods` for the second shape.
///
/// # Why the scan strips comments and stops at the test module
///
/// The first version scanned the raw text and found **20** registrations where
/// the source has 11. The nine extras were diagnostic:
///
/// ```text
/// ("host_clock.rs", "engine", 409)          a test helper, inside #[cfg(test)]
/// ("host_crypto.rs", "{name}\\", 439)        an escaped quote in a doc comment
/// ("host_crypto.rs", "digest\\", 497..499)   doc-comment prose
/// ("host_crypto.rs", "get\\", 817)           doc-comment prose
/// ```
///
/// This is the defect `§O-071` already records for a *different* checker
/// (`SEC-011`'s boundary table): **"the name extractor read doc comments,
/// inventing `name` as a boundary because the source writes
/// ``func_wrap("name"`` in its own prose."** Recorded once, then repeated in new
/// code an hour later — which is why the fix has two independent halves rather
/// than one careful stripper.
///
/// # Why the body is taken as everything up to the *next* `func_wrap`
///
/// Because matching the closing brace of a closure whose body contains braces
/// needs a real parser, and a brace counter is a parser that is wrong on strings
/// and comments — both of which these bodies contain. Slicing to the next
/// registration is exact for this codebase's shape (one registration per
/// `func_wrap`, in order), and it fails **loudly** rather than silently if that
/// shape changes.
#[must_use]
pub fn scan(file: &str, text: &str) -> Vec<Registered> {
    let production = production_lines(file, text);
    let starts: Vec<usize> = production
        .match_indices("func_wrap(")
        .map(|(i, _)| i)
        .collect();
    let mut out = Vec::with_capacity(starts.len());
    for (idx, start) in starts.iter().enumerate() {
        let end = starts.get(idx + 1).copied().unwrap_or(production.len());
        let body = &production[*start..end];
        let Some(name) = function_name(body) else {
            continue;
        };
        // **The structural half.** A real `func_wrap` name is a WIT kebab-case
        // identifier. Anything else is prose that survived the stripper, and
        // rejecting it here means the audit reports a missing row rather than
        // inventing an unlisted function -- a loud failure in place of a quiet
        // one, and independent of how well the stripper works.
        if !is_identifier(&name) {
            continue;
        }
        // **Counted in `production`, whose line numbering is aligned with `text` on purpose.**
        // `production_lines` pushes exactly one `\n` per input line -- including the comment lines it
        // replaces with a bare newline -- so line `n` of `production` is line `n` of `text`.
        //
        // The previous version went the other way and derived a byte offset from the *lengths*:
        // `text.len() - (production.len() - start)`. That is the same position only while everything
        // after `start` is the same length in both strings, and it is not -- `production` has collapsed
        // every comment line to one byte -- so the index was arbitrary. It panicked with `not a char
        // boundary` the first time an edit moved it inside a multi-byte character, which is how a latent
        // defect waits: it needed the file to change length, not to change meaning.
        //
        // A `match_indices` boundary is always a char boundary, so this cannot panic.
        let line = production[..*start].matches('\n').count() + 1;
        let checks = {
            let code = code_without_strings_or_trailing_comments(body);
            code.contains("grants.grants(") || CHECKING_HELPERS.iter().any(|h| code.contains(h))
        };
        out.push(Registered {
            file: file.to_owned(),
            interface: instance_name(text, &production[..*start]),
            function: name,
            line,
            checks_capability: checks,
        });
    }
    // **Bindgen trait methods are registrations too.** Files that bind through
    // the generated `add_to_linker` (records, variants and resources need the
    // canonical ABI's lifting) have no `func_wrap`, so the loop above sees
    // none of their entry points — which is how whole capability modules
    // escaped the audit while its tests stayed green. An
    // `impl bindings::A::B::C::Host*` block contributes one registration per
    // `    fn name(` method, with the WIT interface resolved from the file's
    // own interface literals.
    out.extend(bindgen_methods(file, text, &production));
    // Collapse repeat registrations of one audit identity: `txn` and
    // `txn-statement` each define `drop` under the same WIT interface, so the
    // scan finds two sites for one `(interface, function)` key — and the
    // table, keyed the same way, holds one row covering both. The survivor
    // keeps the first line; its check flag is the AND of the twins, so a
    // checked twin never vouches for an unchecked one (that pair fails loud
    // as `UnbackedClaim` instead of passing quiet).
    let mut deduped: Vec<Registered> = Vec::with_capacity(out.len());
    for reg in out {
        match deduped
            .iter_mut()
            .find(|r| r.interface == reg.interface && r.function == reg.function)
        {
            // Same audit identity twice: keep the first line, AND the
            // check flags, so a checked twin never vouches for an
            // unchecked one.
            Some(first) => {
                first.checks_capability = first.checks_capability && reg.checks_capability;
            }
            None => deduped.push(reg),
        }
    }
    deduped
}

/// Every `bindings::…::Host*` trait-method registration in one production
/// source, and whether its body reaches a capability check.
///
/// Only guest-callable impl blocks count: `impl bindings::…::Host*` and
/// bare-trait `impl XxxHost for StoreData` shapes. Inherent `impl StoreData`
/// helpers are not guest-callable and must not appear here. Method bodies run
/// from their `    fn ` line to the next one, exactly like the `func_wrap`
/// slicing above — a shape change fails loud (a missing row) rather than
/// quiet.
fn bindgen_methods(file: &str, text: &str, production: &str) -> Vec<Registered> {
    let interfaces = wit_interfaces(text);
    let lines: Vec<&str> = production.lines().collect();
    let mut out = Vec::new();
    let mut idx = 0;
    while let Some(line) = lines.get(idx) {
        // Bindings impls name their path (`impl bindings::qqq::kv::store::Host
        // for …`); log and trace import the trait instead (`impl LogHost
        // for StoreData`). Both spell a guest-callable interface: the shared
        // test is a `Host`-naming trait implemented for the store.
        // Inherent blocks (`impl StoreData`), unrelated traits
        // (`impl Default`), and wasmtime-internal shims
        // (`impl HostWallClock for DeniedClock`,
        // `impl SecretCrypto for HostSecretCrypto`) match neither the trait
        // nor the recipient shape and stay invisible, as before.
        let path = if let Some(p) = line.strip_prefix("impl bindings::") {
            Some((p, false))
        } else if line.starts_with("impl ") && line.contains("Host") && is_store_recipient(line) {
            Some(("", true))
        } else {
            None
        };
        let Some((path, bare)) = path else {
            idx += 1;
            continue;
        };
        // The block runs to the next column-zero line (any top-level item)
        // or end of file; method bodies are always indented.
        let mut end = idx + 1;
        while let Some(next) = lines.get(end) {
            if next.is_empty() || next.starts_with(char::is_whitespace) {
                end += 1;
            } else {
                break;
            }
        }
        let interface = if bare {
            single_interface(&interfaces)
        } else {
            interface_for_path(path, &interfaces)
        };
        let mut m = idx + 1;
        while m < end {
            let method = lines.get(m).and_then(|l| l.strip_prefix("    fn "));
            let Some(rest) = method else {
                m += 1;
                continue;
            };
            let name_end = rest.find('(').unwrap_or(rest.len());
            let name = rest[..name_end].replace('_', "-");
            if !is_identifier(&name) {
                m += 1;
                continue;
            }
            let mut body = String::new();
            let mut mend = m + 1;
            while let Some(next) = lines.get(mend) {
                if mend >= end || next.starts_with("    fn ") || *next == "    }" {
                    break;
                }
                body.push_str(next);
                body.push('\n');
                mend += 1;
            }
            let code = code_without_strings_or_trailing_comments(&body);
            let checks = code.contains("grants.grants(")
                || CHECKING_HELPERS.iter().any(|h| code.contains(h));
            out.push(Registered {
                file: file.to_owned(),
                interface: interface.clone(),
                function: name,
                line: m + 1,
                checks_capability: checks,
            });
            m = mend;
        }
        idx = end;
    }
    out
}

/// Every WIT interface (`qqq:kv/store@1.0.0`) named in the source.
///
/// The `INTERFACE`-style constants and the `bindgen!` `interfaces` strings
/// both spell full interfaces; the latter packs several into one literal
/// (`"import qqq:sql/database@1.0.0; import …"`), so extraction is
/// token-shaped rather than literal-shaped: exactly one `:` then one `/`
/// then one `@version`, like the WIT package syntax itself.
fn wit_interfaces(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in source.split(|c: char| {
        !(c.is_ascii_alphanumeric() || c == ':' || c == '/' || c == '@' || c == '.' || c == '-')
    }) {
        let mut at_parts = token.split('@');
        let head = at_parts.next().unwrap_or("");
        let version = at_parts.next().unwrap_or("");
        if at_parts.next().is_some()
            || version.is_empty()
            || !version.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            continue;
        }
        let mut head_parts = head.split(':');
        let pkg = head_parts.next().unwrap_or("");
        let iface = head_parts.next().unwrap_or("");
        if head_parts.next().is_some() || pkg.is_empty() || iface.is_empty() || !iface.contains('/')
        {
            continue;
        }
        out.push(token.to_owned());
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Whether an `impl` line implements its trait for the store.
///
/// Guest-callable host traits are implemented for `StoreData` (itself or
/// `crate::linker::StoreData`); wasmtime-internal shims (`DeniedClock`,
/// `HostSecretCrypto`) and inherent blocks are not. The recipient is the
/// first token after ` for `.
fn is_store_recipient(line: &str) -> bool {
    let Some(at) = line.find(" for ") else {
        return false;
    };
    let after = line[at + " for ".len()..]
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
        .next()
        .unwrap_or("");
    after == "StoreData" || after.ends_with("::StoreData")
}

/// The file's single full WIT interface, when it names exactly one.
///
/// Bare-trait impls (`impl LogHost for …`) carry no path to resolve, so the
/// interface must be unambiguous in the file: exactly one literal shaped
/// `package/interface@version`. Two literals (crypto's five, sql's two) mean
/// the file's impls must use `bindings::` paths instead — an empty answer
/// here fails loud downstream rather than guessing.
fn single_interface(interfaces: &[String]) -> String {
    let full: Vec<&String> = interfaces
        .iter()
        .filter(|i| i.split('/').nth(1).is_some_and(|s| !s.is_empty()))
        .collect();
    if full.len() == 1 {
        full.first().map(|s| (*s).clone()).unwrap_or_default()
    } else {
        String::new()
    }
}

/// The full WIT interface for an `impl bindings::…` path, resolved against
/// the file's own interface literals.
///
/// `bindings::qqq::kv::store::Host` contributes the key `kv/store`, which
/// names the literal containing `kv/store@`. A path with no match yields an
/// empty interface, which matches no row — a loud `Unlisted` failure rather
/// than a quiet pass.
fn interface_for_path(path: &str, interfaces: &[String]) -> String {
    let segments: Vec<&str> = path.split("::").collect();
    let host_at = segments.iter().position(|s| s.starts_with("Host"));
    let end = host_at.unwrap_or(segments.len());
    if end < 2 {
        return String::new();
    }
    let (Some(a), Some(b)) = (segments.get(end - 2), segments.get(end - 1)) else {
        return String::new();
    };
    let key = format!("{a}/{b}");
    let needle = format!("{key}@");
    interfaces
        .iter()
        .find(|i| i.contains(&needle))
        .cloned()
        .unwrap_or_default()
}

/// The interface the registration is attached to, from the nearest preceding
/// `linker.instance(NAME)`.
///
/// # Why the nearest preceding instance is the right answer
///
/// Because every registration in this codebase is written as
/// `let mut inst = linker.instance(WALL_CLOCK)?;` followed by one or more
/// `inst.func_wrap(..)` calls, so the enclosing instance is the most recent one
/// opened above the call. A registration that opened no instance inherits the
/// previous one, which shows up as a wrong interface in a finding -- loud rather
/// than silent.
///
/// # Why the argument is resolved through the file's own constants
///
/// Because the registrations pass a **constant**, not a literal:
/// `linker.instance(RANDOM)`, `linker.instance(WALL_CLOCK)`. A resolver that
/// looked for `"` found nothing, every registration got an empty interface, no
/// row matched, and the audit reported all eight as unlisted -- which is how the
/// bug appeared. Resolving the identifier against the `pub const NAME: &str =
/// "..."` declarations in the same file is exact for this codebase and fails
/// loudly if it ever stops being: an unresolved name yields an empty interface,
/// which matches no row.
fn instance_name(source: &str, before: &str) -> String {
    let mut ident = String::new();
    for line in before.lines() {
        if let Some(i) = line.find(".instance(") {
            let rest = &line[i + ".instance(".len()..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            let candidate = &rest[..end];
            if !candidate.is_empty() {
                candidate.clone_into(&mut ident);
            }
        }
    }
    if ident.is_empty() {
        return String::new();
    }
    literal_of(source, &ident).unwrap_or_default()
}

/// The string literal a `pub const NAME: &str = "...";` declares, if any.
fn literal_of(source: &str, ident: &str) -> Option<String> {
    let needle = format!("const {ident}");
    for line in source.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("pub const ") && !trimmed.starts_with("const ") {
            continue;
        }
        if !line.contains(&needle) || !line.contains(": &str") {
            continue;
        }
        let eq = line.find('=')?;
        let rest = line.get(eq + 1..)?;
        let q = rest.find('"')?;
        let after = rest.get(q + 1..)?;
        let close = after.find('"')?;
        return Some(after.get(..close)?.to_owned());
    }
    None
}

/// Whether a candidate name is a WIT identifier rather than surviving prose.
///
/// # Why kebab-case is the test
///
/// Because it is what `func_wrap` is given everywhere in this workspace: the WIT
/// function name. A name containing `\\`, `{`, `}` or whitespace is a fragment
/// of a doc comment or a format string, and no registration in this codebase can
/// produce one. Widening this predicate to accept more would let prose back in;
/// narrowing it would drop a real registration, which the audit would then
/// report as a missing row.
fn is_identifier(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The source with comment lines removed and everything from `#[cfg(test)]`
/// onward dropped.
///
/// # Why line-based rather than a real lexer
///
/// Because a lexer is a component with its own bugs, and the property needed
/// here is only "no `func_wrap(` from a comment or a test survives". Both of
/// those are line-shaped in this codebase: doc comments occupy whole lines, and
/// the test module is a contiguous tail. A block comment spanning lines would
/// defeat it — and there is none in these files, which
/// `the_real_sources_contain_no_block_comments` asserts rather than assumes, so
/// the day one appears the suite says so instead of the audit quietly changing
/// its answer.
fn production_lines(file: &str, text: &str) -> String {
    let _ = file;
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") {
            break;
        }
        if trimmed.starts_with("//") {
            // Keep the newline so line numbers stay aligned with the original.
            out.push('\n');
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The first string literal passed to `func_wrap`.
///
/// # Why this looks for the literal after the paren rather than parsing
///
/// Because the only thing between `func_wrap(` and its first argument is
/// whitespace, and this codebase writes it on one line every time. A shape that
/// changed would produce `None` here, and `None` means the registration is
/// **skipped** — so the audit would report a missing row for a function that
/// exists, which is a loud failure rather than a quiet pass.
fn function_name(body: &str) -> Option<String> {
    let open = body.find('(')?;
    let rest = body.get(open + 1..)?;
    let quote = rest.find('"')?;
    let after = rest.get(quote + 1..)?;
    let close = after.find('"')?;
    Some(after.get(..close)?.to_owned())
}

/// The body with string literals and trailing comments blanked, for the
/// grant-check match.
///
/// A prose mention (`"see grants.grants(..) below"`, a commented-out
/// check) must not satisfy the claim: the audit would bless a body whose
/// only check is a sentence about checks. Whole-line comments and the test
/// module are already gone (`production_lines`); what remains is inline
/// strings (which may themselves contain `//`) and trailing comments —
/// handled here in that order, so a URL inside a string never starts a
/// comment. Lifetimes (`&'a`) are not char literals: only `'x'`, escapes,
/// and `\u{...}` open one, or the newline swallowed by a misread quote
/// shifts every line number after it.
fn code_without_strings_or_trailing_comments(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            out.push(' ');
            let mut escaped = false;
            for d in chars.by_ref() {
                out.push(' ');
                if escaped {
                    escaped = false;
                } else if d == '\\' {
                    escaped = true;
                } else if d == '"' {
                    break;
                } else if d == '\n' {
                    out.push('\n');
                }
            }
        } else if c == '/' && chars.peek() == Some(&'/') {
            for d in chars.by_ref() {
                if d == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else if c == '\'' {
            // A lifetime (`&'a`, `MutexGuard<'_, T>`) is not a literal:
            // only `'x'`, `'\\.'`, and `'\\u{...}'` open char literals, so
            // peek (without consuming) before deciding. Consuming the
            // quote of a lifetime would swallow the newline before the
            // real closing quote and shift every line number after it.
            let probe: String = chars.clone().take(10).collect();
            let len = if probe.len() >= 2 && probe.as_bytes().get(1) == Some(&b'\'') {
                2 // `'x'`: the peeked char plus the closing quote.
            } else if probe.starts_with('\\')
                && probe.len() >= 3
                && probe.as_bytes().get(2) == Some(&b'\'')
            {
                3 // `'\\.'`: backslash, escaped char, closing quote.
            } else if probe.starts_with("\\u{") {
                match probe.find('}') {
                    Some(end) if end <= 8 => end + 1,
                    _ => 0,
                }
            } else {
                0
            };
            if len == 0 {
                out.push(c);
            } else {
                out.push_str(&" ".repeat(len + 1));
                for _ in 0..len {
                    chars.next();
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Test indexing (`F-18`): assertions index vectors built inline above.
// One module-level reason, not per-site noise; shipping code above
// carries no such allowance.
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions index inline vectors"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// The real sources, taken from `ARCH-003`'s registry rather than listed again.
    ///
    /// # Why this no longer names its files
    ///
    /// It used to be `["host_clock.rs", "host_crypto.rs", "host_secrets.rs"]`, and **that list is a
    /// guard's width** -- the rule that a guard is only as wide as its file list. Adding `host_test.rs`
    /// made the omission visible in the loud direction, where the scan found eight registrations and
    /// the table listed fourteen. **The quiet direction is the one that matters**: a new host module
    /// with registrations would be absent from the scan while every row about it stayed green, and
    /// nothing would say so.
    ///
    /// `crate::arch003::HOST_SOURCES` is the one list. `every_host_module_is_scanned` asserts it is
    /// complete against the directory, and it arrives through `include_str!` -- which its own doc
    /// prefers to reading the disk, because *"the content is baked into the crate and cannot change
    /// between a check and the code it is checking."*
    fn real_sources() -> Vec<(String, String)> {
        crate::arch003::HOST_SOURCES
            .iter()
            .map(|(name, text)| ((*name).to_owned(), (*text).to_owned()))
            .collect()
    }

    /// **The check that survives the next edit.** Every host function in the
    /// real source must have a row, and every row must be backed.
    #[test]
    fn the_table_and_the_real_sources_agree() {
        let findings = audit(&real_sources());
        assert!(
            findings.is_empty(),
            "the ARCH-012 table disagrees with the source:\n{}",
            findings
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// The scan must actually find the registrations, or the agreement above is
    /// the agreement of two empty sets.
    #[test]
    fn the_scan_finds_every_registration_in_the_real_sources() {
        let found: Vec<Registered> = real_sources()
            .iter()
            .flat_map(|(f, t)| scan(f, t))
            .collect();
        assert_eq!(
            found.len(),
            AUDITED.len(),
            "scan found {} registrations, the table lists {}: {:?}",
            found.len(),
            AUDITED.len(),
            found
                .iter()
                .map(|r| (&r.file, &r.function, r.line))
                .collect::<Vec<_>>()
        );
    }

    /// **Fault injection 1: an unlisted `func_wrap` is reported.**
    #[test]
    fn an_unlisted_host_function_is_reported() {
        let source = r#"
            inst.func_wrap("brand-new", |_s, ()| Ok(()))?;
        "#;
        let findings = audit(&[("host_new.rs".to_owned(), source.to_owned())]);
        assert!(
            findings.iter().any(
                |f| matches!(f, AuditFinding::Unlisted { function, .. } if function == "brand-new")
            ),
            "{findings:?}"
        );
        let text = findings
            .iter()
            .find(|f| matches!(f, AuditFinding::Unlisted { .. }))
            .unwrap()
            .to_string();
        assert!(text.contains("host_new.rs"), "{text}");
        assert!(text.contains("nobody has reasoned about"), "{text}");
    }

    /// **Fault injection 2: a row claiming a per-function re-check that the
    /// body does not perform is reported.**
    ///
    /// This is the check that makes the table able to disagree with the code in
    /// the direction that matters: a table claiming *more* safety than exists.
    #[test]
    fn a_row_claiming_an_unbacked_re_check_is_reported() {
        // A realistic fixture: the instance is opened from the file's own
        // constant, exactly as `host_clock.rs` does it, so the interface
        // resolves and the row can be matched. A fixture that omitted the
        // `instance` line would produce an empty interface, no matching row and
        // an `Unlisted` finding instead -- which is why this fixture carries it.
        let source = r#"
            pub const WALL_CLOCK: &str = "qqq:clock/wall-clock@1.0.0";
            let mut inst = linker.instance(WALL_CLOCK)?;
            inst.func_wrap("now", |_store, (): ()| Ok((0u64,)))?;
        "#;
        let findings = audit(&[("host_clock.rs".to_owned(), source.to_owned())]);
        assert!(
            findings.iter().any(|f| matches!(
                f,
                AuditFinding::UnbackedClaim { function, .. } if *function == "now"
            )),
            "{findings:?}"
        );
    }

    /// A body that reaches a checking helper satisfies the claim, which is why
    /// `digest` is `ViaHelper` rather than `PerFunction`.
    #[test]
    fn a_body_reaching_a_checking_helper_satisfies_the_claim() {
        let source = r#"
            inst.func_wrap("digest", |store, (a, d)| {
                hash_data(store.data(), "sha256", &d)
            })?;
        "#;
        let findings = audit(&[("host_crypto.rs".to_owned(), source.to_owned())]);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f, AuditFinding::UnbackedClaim { .. })),
            "a body delegating to `hash_data` must satisfy the claim: {findings:?}"
        );
    }

    /// **Fault injection 3: a stale row is reported.** A table that lists a
    /// function the source no longer has claims coverage it does not have.
    #[test]
    fn a_stale_row_is_reported() {
        let findings = audit(&[]);
        assert!(
            !findings.is_empty(),
            "an empty source set must make rows stale"
        );
        assert!(
            findings
                .iter()
                .all(|f| matches!(f, AuditFinding::Stale { .. })),
            "{findings:?}"
        );
        // `Stale` is reported per `(file, interface, function)`: the wall and
        // monotonic clocks name the same functions in the same file, and a
        // two-part key let the surviving namesake vouch for a deleted row.
        // Every row is therefore its own finding on an empty source set.
        assert_eq!(findings.len(), AUDITED.len());
    }

    /// **Fault injection 3b: a namesake does not vouch for a deleted row.**
    ///
    /// `wall-clock.now` and `monotonic-clock.now` share file and function. A
    /// source that keeps the wall clock (with its check) but drops the
    /// monotonic registration must still report the monotonic row as stale —
    /// otherwise deleting `monotonic-clock.now`'s grant check passes the
    /// audit on the wall clock's back.
    #[test]
    fn a_namesake_does_not_vouch_for_a_deleted_row() {
        // A wall-clock `now` whose body reaches the grant check, mirroring
        // the real registration's shape without copying its exact text.
        let source = r#"
            pub const WALL_CLOCK: &str = "qqq:clock/wall-clock@1.0.0";
            let mut inst = linker.instance(WALL_CLOCK)?;
            inst.func_wrap("now", |store: StoreContextMut<'_, StoreData>, (): ()| {
                if !store.data().grants.grants(Capability::ClockWall) {
                    return Err(wasmtime::Error::msg("denied"));
                }
                Ok((0u64,))
            })?;
        "#;
        let findings = audit(&[("host_clock.rs".to_owned(), source.to_owned())]);
        assert!(
            findings.iter().any(|f| matches!(
                f,
                AuditFinding::Stale {
                    interface,
                    function,
                    ..
                } if interface.contains("monotonic-clock") && *function == "now"
            )),
            "dropping monotonic-clock.now must report its row as stale: {findings:?}"
        );
        assert!(
            !findings.iter().any(|f| matches!(
                f,
                AuditFinding::Stale {
                    interface,
                    function,
                    ..
                } if interface.contains("wall-clock") && *function == "now"
            )),
            "the surviving wall-clock.now must not be reported stale: {findings:?}"
        );
    }

    /// **`(file, function)` does not uniquely identify a row, and the audit must
    /// not pretend it does.**
    ///
    /// `wall-clock.now` and `monotonic-clock.now` share both, as do the two
    /// `resolution`s. With a two-part key, `UnbackedClaim` could pass a row
    /// because its *namesake* was backed -- `monotonic-clock.now` losing its
    /// grant check while `wall-clock.now` kept one. The key is therefore
    /// `(file, interface, function)`, and this test pins that it is unique.
    #[test]
    fn the_audited_identity_is_unique() {
        let keys: BTreeSet<(&str, &str, &str)> = AUDITED
            .iter()
            .map(|a| (a.file, a.interface, a.function))
            .collect();
        assert_eq!(
            keys.len(),
            AUDITED.len(),
            "two rows share (file, interface, function): {keys:?}"
        );

        let pairs: BTreeSet<(&str, &str)> = AUDITED.iter().map(|a| (a.file, a.function)).collect();
        assert!(
            pairs.len() < AUDITED.len(),
            "this test exists because the two-part key collides; if it no longer \
             does, the reasoning in `audit` needs revisiting"
        );
    }

    /// An unlisted function is not an unbacked claim: the two findings
    /// answer different questions (is it in the table at all vs does the
    /// table's re-check claim hold), and conflating them would hide one
    /// behind the other.
    ///
    /// Named honestly: this fixture has no `linker.instance(..)`, so the
    /// scan cannot attach an interface and the audit reports it (if at
    /// all) as unlisted, never as an unbacked claim. It pins the
    /// separation of the two findings, not any row's classification.
    #[test]
    fn an_unlisted_function_is_not_an_unbacked_claim() {
        let source = r#"
            inst.func_wrap("timezone", |_store, (): ()| Ok(("UTC".to_owned(),)))?;
        "#;
        let findings = audit(&[("host_clock.rs".to_owned(), source.to_owned())]);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f, AuditFinding::UnbackedClaim { .. })),
            "`timezone` is interface-gated and reads nothing: {findings:?}"
        );
    }

    /// A prose mention of a check is not a check: a body whose only
    /// `grants.grants(` sits inside a string literal or a trailing comment
    /// must still be reported as unbacked. This is the audit's own
    /// soundness property — a checker that counts mentions instead of
    /// calls would bless a body whose check is a sentence about checks.
    #[test]
    fn a_check_in_prose_does_not_back_the_claim() {
        let source = r#"
            pub const WALL_CLOCK: &str = "qqq:clock/wall-clock@1.0.0";
            let mut inst = linker.instance(WALL_CLOCK)?;
            inst.func_wrap("now", |store: StoreContextMut<'_, StoreData>, (): ()| {
                // grants.grants(Capability::ClockWall) — checked above, trust me.
                let label = "grants.grants(Capability::ClockWall)";
                let _ = label.len();
                Ok((0,))
            })?;
        "#;
        let findings = audit(&[("host_clock.rs".to_owned(), source.to_owned())]);
        assert!(
            findings.iter().any(|f| matches!(
                f,
                AuditFinding::UnbackedClaim { function, .. } if *function == "now"
            )),
            "a comment plus a string literal must not count as a check: {findings:?}"
        );
    }

    /// The positive control for the claim check: a `PerFunction` row whose
    /// body really does consult the grant produces no finding. Without
    /// it, a `scan` change that stopped seeing bodies would make the
    /// negative tests pass by proving nothing.
    #[test]
    fn a_real_check_in_the_body_backs_the_claim() {
        let source = r#"
            pub const WALL_CLOCK: &str = "qqq:clock/wall-clock@1.0.0";
            let mut inst = linker.instance(WALL_CLOCK)?;
            inst.func_wrap("now", |store: StoreContextMut<'_, StoreData>, (): ()| {
                if !store.data().grants.grants(Capability::ClockWall) {
                    return Err(wasmtime::Error::msg("denied"));
                }
                Ok((0,))
            })?;
        "#;
        let findings = audit(&[("host_clock.rs".to_owned(), source.to_owned())]);
        assert!(
            !findings.iter().any(|f| matches!(
                f,
                AuditFinding::UnbackedClaim { function, .. } if *function == "now"
            )),
            "a body that really checks must not be reported: {findings:?}"
        );
    }

    /// **A row that requires no capability must not claim an enforcement that checks one.**
    ///
    /// `capability: None` and [`Enforcement::Ungated`] describe the same call from two sides, so a row
    /// holding one without the other would be a claim this table cannot keep. **The pairing is the
    /// invariant**, and asserting it here is what lets the two stay two fields rather than collapsing
    /// into an enum that makes the mistake unrepresentable -- the rows are claims a reader checks, and
    /// this is the check.
    #[test]
    fn an_ungated_row_carries_no_capability() {
        for a in &AUDITED {
            assert_eq!(
                a.capability.is_none(),
                matches!(a.enforced_by, Enforcement::Ungated),
                "`{}` in `{}` disagrees with itself: capability {:?}, enforced_by {:?}",
                a.function,
                a.file,
                a.capability,
                a.enforced_by
            );
        }
    }

    /// The enforcement classification must be honest about which rows survive a
    /// mis-built linker.
    #[test]
    fn the_enforcement_classification_separates_the_two_kinds_of_safety() {
        assert!(Enforcement::PerFunction.rechecks_each_call());
        assert!(Enforcement::ViaHelper.rechecks_each_call());
        assert!(
            !Enforcement::InterfaceGated.rechecks_each_call(),
            "an interface-gated function does not consult the grant itself"
        );
    }

    /// Every row must name a real capability and a plausible file, so the table
    /// cannot rot into placeholders.
    #[test]
    fn every_row_is_wellformed() {
        for row in &AUDITED {
            assert!(!row.function.is_empty(), "{row:?}");
            assert!(
                row.interface.starts_with("qqq:") || row.interface.starts_with("wasi:"),
                "an interface must be namespaced: {row:?}"
            );
            assert_eq!(
                std::path::Path::new(row.file).extension(),
                Some(std::ffi::OsStr::new("rs")),
                "a row names a Rust file: {row:?}"
            );
        }
    }

    /// The table must cover every capability the two `register` paths can bind,
    /// or a granted capability with no audited call is a hole in the audit's
    /// premise.
    #[test]
    fn the_table_covers_every_capability_the_host_can_bind() {
        // `filter_map` drops the `None` rows, which is right: **a row requiring no capability
        // covers none**, so an ungated row must not enter the set this assertion is about.
        let covered: BTreeSet<Capability> = AUDITED.iter().filter_map(|a| a.capability).collect();
        for expected in [Capability::ClockWall, Capability::ClockMonotonic] {
            assert!(
                covered.contains(&expected),
                "`{expected}` is bindable but has no audited call"
            );
        }
        // `CryptoHash`, `CryptoHmac`, `CryptoAead` and `CryptoSign` are
        // covered through `bindgen!` trait-implementation rows (the scanner
        // learns `impl bindings::…::Host*` blocks as well as `func_wrap`),
        // with per-call re-checks proven by direct execution tests
        // (`random_get_refuses_by_name`, `hashing_refuses_by_name`,
        // `hmac_grants_and_allowlist_are_checked`) and the guest-compiled
        // `iface_crypto` probe.
        for present in [
            Capability::CryptoHash,
            Capability::CryptoHmac,
            Capability::CryptoAead,
            Capability::CryptoSign,
            Capability::CryptoRandom,
            Capability::DnsResolve,
            Capability::HttpClient,
            Capability::HttpServer,
            Capability::KvRead,
            Capability::KvWrite,
            Capability::LogWrite,
            Capability::QueuePublish,
            Capability::QueueSubscribe,
            Capability::SqlQuery,
            Capability::SqlExecute,
            Capability::TraceWrite,
        ] {
            assert!(
                covered.contains(&present),
                "a {present:?} row must exist; the scanner sees its registration"
            );
        }
    }

    /// **The capability this item used to pin: `CryptoHash` must be reached
    /// through a check.** `digest` is the function a guest actually calls, and a
    /// guest without the grant must not reach `hash_data`'s work. That property
    /// is now proven by execution (`hashing_refuses_by_name` calls the trait
    /// method directly for every refusal case, and the `iface_crypto` probe
    /// covers it through a real component), which subsumes the source-text
    /// assertion this test used to make — so the test asserts the coverage
    /// exists and names where, rather than re-asserting the table.
    #[test]
    fn the_hashing_functions_are_checked_by_execution() {
        // The trait methods consult the grant on every call: the allowlist
        // helper (`hash_data`) requires `CryptoHash`, and the boundary
        // sizes are enforced before it runs. This test pins the wiring
        // points rather than the behavior (behavior belongs to the
        // execution tests above): `digest` and `digest_many` must both
        // route through `hash_data`, so a future refactor that bypasses
        // the helper fails here even if every refusal case still passes.
        let source = include_str!("host_crypto.rs");
        for method in ["fn digest(", "fn digest_many("] {
            let at = source
                .find(method)
                .unwrap_or_else(|| panic!("the hashing trait method `{method}` must exist"));
            let body = &source[at..];
            let end = body.find("\n    }\n").expect("the method must be closed");
            assert!(
                body[..end].contains("hash_data("),
                "`{method}` must route through the allowlist helper `hash_data`; \
                 a path that computes without it consults no grant"
            );
        }
    }

    /// `function_name` must not be fooled by a name containing an escape.
    #[test]
    fn the_name_extractor_reads_the_first_literal() {
        assert_eq!(
            function_name(r#"func_wrap("now", |..| {})"#),
            Some("now".to_owned())
        );
        assert_eq!(
            function_name(r#"func_wrap(  "digest-many" , ..)"#),
            Some("digest-many".to_owned())
        );
        assert_eq!(function_name("func_wrap(no_literal)"), None);
    }

    /// The scan reports the line of the registration, so a finding points at
    /// the code.
    #[test]
    fn the_scan_reports_the_line_of_each_registration() {
        let source = "line one\nline two\ninst.func_wrap(\"x\", ..);\n";
        let found = scan("f.rs", source);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 3);
    }
}
