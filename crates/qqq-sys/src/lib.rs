//! `qqq-sys` -- see `QQQ-Proposal-V1.md` §4.3 for the crate topology.
//!
//! Status: not yet implemented. Tracked by the checklist item(s) named in the
//! workspace manifest.
//!
//! QQQ-STUB(ARCH-007): crate declared so the architecture is enforced by the
//! build system from the first commit. Implementation lands with its checklist
//! item; see `QQQ-Observations-and-Memories.md` §6.

// `qqq-sys` is the crate Proposal §4.3 designates for `unsafe` OS-level
// primitives, and it is a **stub today**: it contains no `unsafe` at all, so it
// forbids it like every other crate. The exception is granted when the crate
// gains real content, and `ARCH-009` requires a written safety argument in
// `crates/qqq-sys/SAFETY.md` plus a second reviewer at that point.
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
