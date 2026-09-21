// SPDX-License-Identifier: Apache-2.0

//! `qqq-sys` -- see `QQQ-Proposal-V1.md` §4.3 for the crate topology.
//!
//! Implements the Linux hardening of Proposal §7.5 (`SEC-019`). See
//! [`harden`] for the design rule that shapes it — §7.5 states that *"none of
//! these are required for QQQ's security claim"*, and that sentence is the
//! specification: every step is optional, none is fatal, and nothing here is
//! needed for correctness.
//!
//! QQQ-STUB(ARCH-007) is discharged for the hardening surface only: the crate
//! now has real content, and the remaining §7.5 rows (`Landlock`, `capset`) are
//! named in [`harden`]'s module documentation as decisions rather than
//! oversights.

// `qqq-sys` is the crate Proposal §4.3 designates for `unsafe` OS-level
// primitives. It still contains **no `unsafe`**, and `SEC-019` was implemented
// without adding any: `nix` and `seccompiler` provide the primitives as safe
// functions, so the exception process is not triggered.
//
// That is a deliberate choice rather than an accident, and it is recorded here
// because the opposite choice was the obvious one. Writing `libc` calls in
// `unsafe` blocks would have required `SAFETY.md`'s status ledger to change
// rows 2 and 3 — a complete safety argument and a **second reviewer** — and
// `GOV-008` records that no second maintainer exists (bus factor 1, risk
// `R-15`). So the choice was: block on an unfillable precondition, or find a
// safe path. The safe path exists, and `src/harden.rs` explains why it is also
// the better one independent of the block.
//
// It is a **bare** `forbid`, not `cfg_attr(not(test), forbid(...))`. The
// conditional form permits `unsafe` under `cfg(test)`, so the first `unsafe`
// block added here would be silently legal if it sat behind a `#[cfg(test)]`
// gate — exactly the accidental precedent the exception process exists to
// prevent.
//
// `crates/qqq-core/tests/architecture.rs` reads this attribute and fails if it
// changes, with a message naming `SAFETY.md`. See `§O-059`.
#![forbid(unsafe_code)]

pub mod harden;

pub use harden::{
    harden, HardenPolicy, HardenReport, SeccompProfile, Step, StepOutcome, STEP_DROP_GID,
    STEP_DROP_UID, STEP_NO_NEW_PRIVS, STEP_ORDER, STEP_SECCOMP,
};
