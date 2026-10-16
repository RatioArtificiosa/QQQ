// SPDX-License-Identifier: Apache-2.0

//! HTTP/2: HPACK only — the framing, streams, flow control and
//! multiplexing moved to hyper (`F-16` Option A, Wave 8).
//!
//! What was here: a complete in-house HTTP/2 protocol implementation
//! (`frame`, `hpack`, `flow`, `stream`, `conn`, plus `error` and
//! `settings`), built for Checklist `SRV-002` and never wired to a
//! listener — `crate::server` serves HTTP/1.1 only, and the hyper
//! path owns all h2 framing since the migration. Deleted 2026-10-16
//! (`§O-732`) on parity evidence: h2spec 145/145 plus 146/146
//! strict green against the hyper driver, the §O-676 flood budgets
//! green over hyper, and zero references outside this module's own
//! tests. What stays, and why:
//!
//! - [`hpack`] stays: the hyper conformance tests speak raw h2 and
//!   need an independent HPACK codec (`hyper_h2`, `hyper_tls`,
//!   `hyper_streaming`, `hyper_h2ws`). It is test harness, not
//!   transport — Hyper owns framing, HPACK tables, streams, and
//!   flow control on the serve path, and no separate direct h2
//!   dependency exists by the owner's non-negotiable.
//! - [`error`] stays with it: the RFC wire codes are shared
//!   vocabulary `hpack` maps its failures onto, not serving code.
//!   Self-contained by design (see its module doc on why the codes
//!   do not belong in `qqq-core`).
//! - `crate::tls` stays untouched: cipher policy, versions, ALPN,
//!   mTLS verification, and peer identity are transport-independent
//!   policy the hyper path itself uses (`serve_hyper_tls` builds
//!   on `TlsConfig::build`). Deleting it would drop policy, not
//!   dead code.
//! - In-house `http1` stays untouched: it is the differential
//!   oracle the migration gates still run against.
//!
//! If a future transport needs a second h2 codec, that is a new
//! decision with new evidence — not a revert. The deleted code is
//! in git history (`§O-732` names the commit).

pub mod error;
pub mod hpack;
