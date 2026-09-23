// SPDX-License-Identifier: Apache-2.0

//! # qqq-debug
//!
//! DWARF source mapping for QQQ: turning a Wasm bytecode offset into a file and
//! line a human can open.
//!
//! Implements the `qqq-debug` row of Proposal §4.3 and Checklist `HOST-009`.
//!
//! ## The problem this solves
//!
//! A trap reports a **Wasm bytecode offset**. That is precise and useless: no
//! tool a developer owns can turn `offset 0x1a3` into a line of Rust. Wasmtime
//! resolves frames *in memory* with `debug_info` enabled, but QQQ needs the
//! mapping in two places where there is no live engine to ask:
//!
//! 1. **A trap that crossed a process boundary.** The error travels as JSON to a
//!    log, a UI or an agent; by then the engine is gone.
//! 2. **A `.cwasm` cache.** The artifact is compiled once and reused, and the
//!    debug info that produced it is not necessarily alongside.
//!
//! So the mapping is a **lookup table extracted from the artifact**, held
//! independently of any engine.
//!
//! ## The rule that shapes this crate
//!
//! > **An unmapped frame reports no location. It never reports a guessed one.**
//!
//! A trap with `file: None` says "there is no debug info here", which a reader
//! interprets correctly. A trap with a *wrong* file and line sends them to a
//! place that does not explain the failure, and they will spend that time
//! believing the debug info is fine and their understanding is wrong.
//!
//! This is the same asymmetry as `§O-038b`'s interface mapping and `§O-043a`'s
//! remediation: a confident wrong answer costs more than an absent one, and it
//! costs more the further from the author it travels.
//!
//! ## What DWARF in a Wasm component actually looks like
//!
//! A Rust `wasm32-wasip2` build emits DWARF **inside the Wasm module**, in
//! custom sections: `.debug_info`, `.debug_line`, `.debug_abbrev` and the rest.
//! The convention for Wasm relocates the `debug_line` program so its addresses
//! are **bytecode offsets within the code section** — which is exactly what a
//! Wasmtime frame reports. The two line up without translation, and that is what
//! keeps this crate small.
//!
//! ## Determinism
//!
//! Extraction is a pure function of the artifact bytes: same bytes, same table,
//! same order. Entries are sorted by address, so a lookup is a binary search and
//! a `--json` diff of two runs is byte-identical.

// A **bare** `forbid`, not `cfg_attr(not(test), forbid(...))`.
//
// The conditional form permits `unsafe` under `cfg(test)`, which means the
// guarantee is a property of the build configuration rather than of the source:
// a test helper could introduce `unsafe` and the release build's claim would
// still read as true. §4.3 requires `#![forbid(unsafe_code)]` on every crate
// except the named exception crates, and `qqq-debug` is not one of them — it
// contains no `unsafe` at all, so the escape hatch was defensive rather than
// necessary.
//
// Found by `crates/qqq-core/tests/architecture.rs`, which reads this attribute
// and reports the conditional form separately from its absence. See `§O-059`.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod extract;
pub mod resolve;
pub mod source_map;

pub use extract::{extract, ExtractionReport};
pub use resolve::{render_frames, resolve_frames, ReportedFrame, ResolveReport};
pub use source_map::{FrameLocation, SourceMap};
