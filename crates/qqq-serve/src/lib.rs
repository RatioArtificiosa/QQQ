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
//! | HTTP/2, multiplexing, flow control | not implemented (`SRV-002`) |
//! | Streaming bodies, backpressure | not implemented (`SRV-004`) |
//! | `max_request_bytes` enforced during streaming | declared size checked; streaming is `SRV-005` |
//! | TLS, mTLS | not implemented (`SRV-007`, `SRV-008`) |
//! | `WebSockets`, SSE | not implemented (`SRV-009`, `SRV-010`) |
//!
//! Each of those is named rather than silently absent. A listener that accepted
//! connections without the limits `SRV-005` and `SRV-011` require would be worse
//! than no listener: it would look like a server.
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

pub mod body;
pub mod h2;
pub mod conn;
pub mod http1;
pub mod response;
pub mod route;
pub mod server;
pub mod tls;

pub use conn::{Action, CloseReason, Connection, ConnectionConfig, ConnectionLedger};
pub use http1::{
    head_end, is_valid_header_name, parse_head, ParseError, RequestHead, Version, MAX_HEADERS,
    MAX_HEADER_BYTES, MAX_HEAD_BYTES, MAX_REQUEST_BYTES, MAX_TARGET_BYTES,
};
pub use response::{
    error_response, forbids_body, from_error, method_not_allowed, not_found, parse_error_response,
    reason_phrase, retry_after_value, write_response, ErrorResponse, Failure, Response,
};
pub use route::{
    Match, Method, Params, Route, RouteTable, RouterError, MAX_PARAMS, MAX_ROUTES, WILDCARD,
};
pub use server::{serve, Handler, RouteMatch, Served, ServerConfig};
