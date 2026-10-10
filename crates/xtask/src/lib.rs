// SPDX-License-Identifier: Apache-2.0

//! The `I-08` developer-workflows crate: one gate, fast hygiene, worktree
//! fault injection. See `crates/xtask/src/main.rs`.
//!
//! This library root exists for architectural uniformity, not for code:
//! `ARCH-008` requires `#![forbid(unsafe_code)]` at the root of every crate,
//! and `crates/qqq-core/tests/architecture.rs` requires every member to carry
//! a `src/lib.rs` so the attribute is checked where a reader looks for it.
//! The crate is binary-only by design (the `cargo xtask` alias runs the
//! binary); all logic lives in `main.rs`, and this file intentionally
//! declares no public items so the api-examples ratchet does not move.
#![forbid(unsafe_code)]
