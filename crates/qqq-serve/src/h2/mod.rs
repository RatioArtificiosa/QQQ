// SPDX-License-Identifier: Apache-2.0

//! HTTP/2: the frame layer, HPACK, stream state, flow control and multiplexing.
//!
//! Implements Checklist `SRV-002` — *"Implement HTTP/2 including multiplexing and
//! flow control"* — and Proposal §6.4, which lists HTTP/2 (complete) in V1's
//! scope.
//!
//! # Why this is built rather than depended on
//!
//! The `h2` crate exists and is good. It is deliberately not used here.
//!
//! Proposal §6.4 is a list of *commitments* about this server — backpressure
//! that propagates from the socket through the host to the guest's stream
//! (§6.4, "Body handling"), per-tenant connection limits (already built, in
//! `crate::conn`), and a route table compiled at load. Each of those is a place
//! where the protocol layer's flow-control and framing decisions are visible to
//! the layer above. A third-party HTTP/2 implementation exposes its own
//! vocabulary for those decisions, and the mapping between its vocabulary and
//! this project's is exactly where the guarantees get lost.
//!
//! That is not an argument against dependencies in general. It is the specific
//! argument that a transport protocol's *state* is not separable from the server
//! semantics built on it, and this crate's written standard is that every claim
//! is verified in source (see the Observations file's `§O-047` for how a claim
//! stated but not verified was treated).
//!
//! # The layers, bottom to top
//!
//! ```text
//!   bytes ──► frame      the 9-byte header and every frame type
//!               │
//!               ├──► hpack    header blocks: integer, Huffman, dynamic table
//!               │
//!               ├──► flow     connection and stream windows
//!               │
//!               └──► stream   per-stream state, and which frames are legal
//!                               │
//!                               ▼
//!                          conn        preface, dispatch, multiplexing
//! ```
//!
//! Each layer is independently testable, which is the property that makes the
//! whole verifiable: [`hpack`] has no idea a connection exists, [`flow`] has no
//! idea what a header is, and [`stream`] is a state machine with no I/O at all.
//! `SRV-001`'s accept loop was joined only after every piece existed separately,
//! and the defect that joining it found (`§O-047a`) was in the *handoff* — so the
//! seams here are named and tested rather than assumed.
//!
//! # What is implemented, and what is not
//!
//! | Area | State |
//! |---|---|
//! | Frame layer: header, SETTINGS, HEADERS, DATA, `WINDOW_UPDATE`, `RST_STREAM`, PING, GOAWAY, PRIORITY, CONTINUATION | **implemented** |
//! | HPACK: static table, dynamic table with eviction, integer, Huffman | **implemented** |
//! | Header validation: pseudo-header ordering, connection-specific headers | **implemented** |
//! | Stream states and frame legality | **implemented** |
//! | Flow control: both windows, `WINDOW_UPDATE`, `SETTINGS_INITIAL_WINDOW_SIZE` | **implemented** |
//! | Multiplexing, stream-id monotonicity, `MAX_CONCURRENT_STREAMS` | **implemented** |
//! | Preface and the initial SETTINGS exchange | **implemented** |
//! | Server push (`PUSH_PROMISE` sending) | **not implemented** — received frames are refused |
//! | Priority scheduling (RFC 9113 §5.3) | **parsed and ignored**, as §5.3.1 directs |
//! | TLS/ALPN negotiation, the socket accept loop for h2 | **not implemented** — `SRV-007`, and `crate::server` is HTTP/1.1 only |
//! | `CONTINUATION`-reassembly across reads | **implemented** in [`conn`], bounded by a limit |
//!
//! The last two rows are the honest gaps. This module is a complete HTTP/2
//! *protocol* implementation driven over a byte buffer; it is not yet wired to a
//! listener, and `crate::lib.rs` still reports `SRV-002` as not implemented
//! until that join is made. Naming the gap is the point — a protocol layer that
//! claimed to be a server would be worse than one that says where it stops.
//!
//! # Error model
//!
//! [`error::ErrorCode`] is the RFC's sixteen (fourteen defined) wire codes, local
//! to this module. It is deliberately **not** added to `qqq_core::ErrorCode`: an
//! HTTP/2 protocol error is a statement about the peer's bytes with a numeric
//! value that goes on the wire, not a `QQQ-XXXX` condition with a remediation.
//! The reasoning is in [`error`]'s module documentation, including why wiring
//! them into `qqq-core` would need a code outside this module rather than a
//! guess inside it.

pub mod conn;
pub mod error;
pub mod flow;
pub mod frame;
pub mod hpack;
pub mod settings;
pub mod stream;

pub use conn::{Connection, Event, State, MAX_CONTINUATIONS, MAX_HEADER_BLOCK_BYTES};
pub use error::{ConnectionError, ErrorCode, StreamError};
pub use flow::{FlowControl, FlowError};
pub use frame::{
    parse_frame, to_bytes, write_frame, Flags, Frame, FrameError, FrameHeader, FrameType,
    PrioritySpec, SettingId, CLIENT_PREFACE, DEFAULT_MAX_FRAME_SIZE, FRAME_HEADER_LEN,
    MAX_FRAME_PAYLOAD,
};
pub use hpack::{
    Decoder, Encoder, HeaderField, HpackError, DEFAULT_HEADER_TABLE_SIZE, MAX_HEADER_LIST_SIZE,
};
pub use settings::{
    Settings, SettingsError, DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_CONCURRENT_STREAMS,
};
pub use stream::{FrameKind, Stream, StreamId, StreamState};
