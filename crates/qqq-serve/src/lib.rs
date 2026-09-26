// SPDX-License-Identifier: Apache-2.0

//! # qqq-serve
//!
//! The HTTP and application server: routing, listener shards, HTTP/1.1, HTTP/2.
//!
//! Implements Proposal §6.4 and Checklist `SRV-001` … `SRV-020`.
//!
//! ## Scope, stated honestly
//!
//! | Area | State |
//! |---|---|
//! | Route table (radix trie) | **implemented** (`SRV-003`) |
//! | `OQ-007` — `wasi:http` vs custom | **resolved** (`SRV-006`) |
//! | HTTP/1.1 request-head parsing | **implemented** |
//! | Header-bomb and framing limits | **implemented** (`SRV-020`) |
//! | HTTP/1.1 responses, keep-alive, timeouts, connection limits | **implemented** (`SRV-001`) |
//! | Accept loop, per-tenant ledger, graceful drain | **implemented** (`SRV-001`, `SRV-011`, `SRV-012`) |
//! | HTTP/2 protocol: frames, HPACK, streams, flow control, multiplexing | **implemented** (`SRV-002`) |
//! | HTTP/2 on a listener (TLS/ALPN negotiation of `h2`) | **not implemented** |
//! | Streaming bodies, backpressure | **implemented** (`SRV-004`) |
//! | `max_request_bytes` enforced during streaming | **implemented** (`SRV-005`) |
//! | TLS, mTLS | **implemented** (`SRV-007`, `SRV-008`) |
//! | Per-route authentication policy (refuse-by-default) | **implemented** (`auth`) |
//! | Authenticators (`bearer-jwt`, `mtls`, `signed-request`) | **not implemented** — refused, never served |
//! | `WebSockets`, SSE | not implemented (`SRV-009`, `SRV-010`) |
//!
//! Each of those is named rather than silently absent. A listener that accepted
//! connections without the limits `SRV-005` and `SRV-011` require would be worse
//! than no listener: it would look like a server.
//!
//! ## Why this table is a snapshot and not a promise
//!
//! It drifted once, badly: every row below the accept loop said "not
//! implemented" while the code for it existed, because the entries were written
//! when the crate was created and not revisited as items landed. The worst case
//! was `h2`, which was **excluded from the module tree entirely** by a leftover
//! debugging line for long enough that nobody noticed 9,370 lines and 201 tests
//! were not being compiled (`§O-120`). A scope table that is not regenerated is
//! a claim about the past wearing the tense of the present.
//!
//! The rows here are now checked against the module tree by
//! `tools/check_scope_table.py`, which fails if a module listed as implemented is
//! not reachable from this file.
//!
//! ## The one place this crate deliberately closes a connection
//!
//! `server::drain_body` returns `false` for a `chunked` request body, ending the
//! connection. De-chunking is `SRV-004`'s job and does not exist yet, and
//! reading-and-discarding a chunked body without decoding it would leave the
//! connection at an offset only a decoder knows — a request-smuggling shape.
//! Closing is the honest answer until the decoder lands.
//!
//! ## Why the route table is first
//!
//! Proposal §6.4: *"A compile-time-known route table from `qqq.toml`, compiled
//! into a radix trie at load. No reflection, no runtime route registration, no
//! dynamic dispatch on the hot path."*
//!
//! That ordering is forced. Route matching happens once per request before
//! anything else, so its cost is a floor on every request's latency and a
//! ceiling on the whole server's throughput. Getting it right before writing the
//! I/O means the fast path is designed rather than discovered.
//!
//! ## Why a trie rather than a hash map
//!
//! A hash map answers "is this exact path registered?" in O(1). A router must
//! also answer "does any *pattern* match this path?", which requires walking
//! patterns. Doing that by iterating every route is O(routes) per request.
//!
//! A radix trie shares prefixes, so `/api/v1/orders` and `/api/v1/users` are
//! walked together and the answer is O(path length) regardless of how many
//! routes exist. That distinction is what separates a router that is fine at 10
//! routes from one that is still fine at 10,000.
//!
//! ## Resolved: `OQ-007`
//!
//! The open question was whether `wasi:http` is the foundation or whether a
//! custom interface is required. **Resolved: `wasi:http` is the foundation, and
//! `qqq:http` extends it.** The reasoning is recorded in `route`, where the
//! decision is implemented, because it constrains what a handler receives.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod access_log;
/// Per-route authentication policy: which routes may be served at all.
///
/// Not re-exported at the crate root, because its `Decision` would collide with
/// `cors::Decision` — two different questions ("may this origin read it?" and "may
/// this caller have it?") whose answers happen to share a name.
pub mod auth;
pub mod body;
pub mod body_bytes;
pub mod span;
pub mod trace_context;

pub use body_bytes::{BodyBytes, BodyHandler};
pub mod conn;
pub mod cors;
pub mod h2;
pub mod http1;
/// The fifteen-step request lifecycle of Proposal §4.4, with each step's measured
/// completeness (`ARCH-011`).
pub mod lifecycle;
/// Per-tenant request limits, and the accounting that enforces them.
pub mod limits;
/// The default metric set, per Proposal §10.2.
pub mod metrics;
pub mod response;
pub mod route;
pub mod server;
pub mod sse;
/// Streaming responses: writing a body in pieces, after the head.
pub mod stream;
pub mod tls;
/// The WebSocket opening handshake, per RFC 6455 §4.
pub mod ws;
/// A live WebSocket connection: the loop between the handshake and the guest.
pub mod ws_conn;
/// The WebSocket frame layer, per RFC 6455 §5.
pub mod ws_frame;
/// Message assembly: turning a sequence of frames into whole messages.
pub mod ws_message;

pub use conn::{Action, CloseReason, Connection, ConnectionConfig, ConnectionLedger};
pub use cors::{Cors, CorsError, Decision, Origin, Reason};
pub use http1::{
    head_end, is_valid_header_name, parse_head, ParseError, RequestHead, Version, MAX_HEADERS,
    MAX_HEADER_BYTES, MAX_HEAD_BYTES, MAX_REQUEST_BYTES, MAX_TARGET_BYTES,
};
pub use response::{
    error_response, forbids_body, from_error, method_not_allowed, not_found, parse_error_response,
    reason_phrase, retry_after_value, write_chunk, write_last_chunk, write_response,
    write_stream_head, ErrorResponse, Failure, Response, CHUNK_MAX,
};
pub use route::{
    Match, Method, Params, Route, RouteTable, RouterError, MAX_PARAMS, MAX_ROUTES, WILDCARD,
};
pub use server::{serve, Dispatch, Handler, RouteMatch, Served, ServerConfig};
pub use stream::{
    emit_stream_record, StreamError, StreamOutcome, StreamRecord, StreamWriter, StreamingHandler,
};
pub use ws::{accept_for, Handshake, HandshakeError};
