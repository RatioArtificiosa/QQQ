//! Per-stream state and frame legality (RFC 9113 §5.1).
//!
//! Implements `SRV-002`; RFC 9113 §5.1 (stream states), §5.1.1 (stream
//! identifiers), §5.1.2 (concurrent streams).
//!
//! # Why the state machine is its own layer with no I/O
//!
//! §5.1's table answers one question — *"is this frame legal on this stream right
//! now?"* — and the answer depends on nothing but the stream's state and the
//! frame's category. Keeping that decision here, with no socket, no buffer and no
//! `Connection` in scope, is what makes it exhaustively testable: every cell of
//! the table can be driven directly, and a wrong cell fails a unit test rather
//! than a networked integration test that is hard to reproduce.
//!
//! It is also where the **error kind** is decided, and that is the part that
//! breaks multiplexing when it is wrong. §5.1 splits its own rules between
//! *connection* errors and *stream* errors:
//!
//! * `DATA` on an idle stream is a **connection** error — the peer has invented a
//!   stream id with no `HEADERS` to introduce it, which corrupts the id space for
//!   every later stream.
//! * `HEADERS` on a closed stream is a **stream** error (`STREAM_CLOSED`) — one
//!   request raced its own cancellation, which is routine.
//!
//! Promoting the second to the first drops every other multiplexed request on the
//! connection because one was cancelled. Demoting the first to the second lets a
//! peer desynchronise the stream-id space silently. [`Stream::accepts`] returns
//! [`StreamError`] for the recoverable case and the caller is responsible for the
//! fatal one — see [`StreamError`]'s own documentation and [`crate::h2::conn`].
//!
//! # Where the flow-control windows live
//!
//! They live in [`crate::h2::flow`], and [`Stream`] holds only its id, its state
//! and its **outstanding receive credit** — not a second copy of the window.
//!
//! The reason is that a window is not a per-stream fact. `available_send` is the
//! *minimum* of the connection window and the stream window (§5.2.1), so the two
//! must be read together or the minimum is computed against a stale connection
//! value. Two owners of the same number is the classic way that happens: the
//! stream decrements its copy, the connection decrements its own, and nothing
//! notices that `WINDOW_UPDATE` for the connection also has to be seen by the
//! stream. `flow` owns both and is the only writer.
//!
//! What `Stream` *does* hold is `recv_unacked`: how many received bytes this
//! stream has taken from the connection window but not yet returned with a
//! `WINDOW_UPDATE`. That is genuinely per-stream state (the connection layer
//! decides per stream when to replenish) and it is the counter that makes
//! backpressure real rather than a window that is instantly refilled.

use std::fmt;

use super::error::{ErrorCode, StreamError};

// ---------------------------------------------------------------------------
// Stream ids
// ---------------------------------------------------------------------------

/// A stream identifier (RFC 9113 §5.1.1).
///
/// # Why this is a newtype and not a bare `u32`
///
/// §5.1.1 makes the *parity* of an id carry the direction of the stream that owns
/// it: client-initiated streams are odd, server-initiated (push) streams are
/// even, and `0` is not a stream at all — it names the connection when it appears
/// in a frame's stream-id field.
///
/// Every one of those rules is invisible on a `u32`. A function taking `u32`
/// cannot state that it requires an odd id, and the caller cannot be told; the
/// mistake then shows up as a stream that is tracked under an id no frame will
/// ever name. The newtype puts the parity rule in the constructor
/// ([`StreamId::client`], [`StreamId::server`]) where it is checked once.
///
/// The raw `u32` is still reachable with [`StreamId::get`] because the frame
/// layer speaks `u32` and converting at every call site would be noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(u32);

impl StreamId {
    /// The reserved bit that must be masked off before an id is interpreted.
    ///
    /// RFC 9113 §4.1: the high bit of the stream-id field is reserved and *"MUST
    /// be ignored when receiving"*. `frame.rs` already masks it; this constant
    /// exists so the invariant is checkable here too, and so a future
    /// construction path that bypasses the frame layer cannot smuggle it in.
    pub const RESERVED_BIT: u32 = 0x8000_0000;

    /// The largest legal stream id: 2^31 - 1.
    ///
    /// The id space is 31 bits once the reserved bit is removed, so an id at or
    /// above the reserved bit is not a legal stream id at all.
    pub const MAX: u32 = 0x7FFF_FFFF;

    /// A client-initiated stream id, which §5.1.1 requires to be **odd**.
    ///
    /// # Errors
    ///
    /// [`StreamError::protocol`] with `PROTOCOL_ERROR` when `raw` is zero or
    /// even. It is reported as a *stream* error here because this constructor is
    /// called while reshaping a frame the peer sent — see
    /// [`StreamId::client_from_frame`] for the case where the RFC wants a
    /// connection error instead.
    pub fn client(raw: u32) -> Result<Self, StreamError> {
        if raw == 0 {
            return Err(StreamError::protocol(
                ErrorCode::ProtocolError,
                "stream 0 is the connection, not a stream",
            ));
        }
        if raw & 1 == 0 {
            return Err(StreamError::protocol(
                ErrorCode::ProtocolError,
                format!(
                    "stream {raw} is even; a client-initiated stream id must be odd \
                     (RFC 9113 §5.1.1) — an even id from a client is push, which a \
                     server must never receive"
                ),
            ));
        }
        Ok(Self(raw))
    }

    /// A server-initiated stream id, which §5.1.1 requires to be **even**.
    ///
    /// Server-initiated ids exist for push. Push is **not implemented** in this
    /// module (see [`crate::h2`]'s table), so nothing in this crate calls this
    /// with a value it did not receive from a peer — it is here so the parity
    /// rule is stated in both directions and so a reverse proxy built on this
    /// layer is not forced to hand-roll it.
    ///
    /// # Errors
    ///
    /// [`StreamError::protocol`] with `PROTOCOL_ERROR` when `raw` is zero or odd.
    pub fn server(raw: u32) -> Result<Self, StreamError> {
        if raw == 0 {
            return Err(StreamError::protocol(
                ErrorCode::ProtocolError,
                "stream 0 is the connection, not a stream",
            ));
        }
        if raw & 1 == 1 {
            return Err(StreamError::protocol(
                ErrorCode::ProtocolError,
                format!("stream {raw} is odd; a server-initiated stream id must be even"),
            ));
        }
        Ok(Self(raw))
    }

    /// A client-initiated id as it arrived in a frame.
    ///
    /// # Why this is separate from [`StreamId::client`]
    ///
    /// RFC 9113 §5.1.1 is explicit that the parity violation is **fatal**:
    /// *"An endpoint that receives an unexpected stream identifier MUST respond
    /// with a connection error of type PROTOCOL_ERROR."* The rule cannot be
    /// enforced as a stream error, because a stream error is reported with a
    /// `RST_STREAM` **on the stream** — and the id that needs resetting is
    /// exactly the id that is not a legal stream. So a frame carrying an even id
    /// from a client must reach the connection layer, which returns
    /// [`ConnectionError`](super::error::ConnectionError) instead.
    ///
    /// # Errors
    ///
    /// [`StreamError::protocol`] with `PROTOCOL_ERROR` for a zero or even id;
    /// the caller promotes it to a connection error.
    pub fn client_from_frame(raw: u32) -> Result<Self, StreamError> {
        Self::client(raw)
    }

    /// The raw id.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Whether this is a client-initiated stream, i.e. odd.
    #[must_use]
    pub const fn is_client_initiated(self) -> bool {
        self.0 & 1 == 1
    }

    /// Whether this is a server-initiated stream, i.e. even.
    #[must_use]
    pub const fn is_server_initiated(self) -> bool {
        self.0 & 1 == 0
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Frame kinds
// ---------------------------------------------------------------------------

/// The category a frame belongs to, for stream-legality purposes.
///
/// # Why this is not [`FrameType`](super::frame::FrameType)
///
/// §5.1's table is written in terms of *categories*, not raw frame types, and the
/// mapping is many-to-one in one place that matters: a `SETTINGS` frame with the
/// `ACK` flag and one without are the same type but different rows of the table
/// (`Settings` is legal in every state; `SettingsAck` is too, but the connection
/// layer must not answer it). More importantly, `FrameType::Unknown` carries a
/// number this layer must not interpret, and matching on it here would put the
/// extension rule (§4.1: ignore unknown types) in the wrong module.
///
/// So this enum is the *interface* between the frame layer and the state machine,
/// and it is deliberately smaller than [`FrameType`](super::frame::FrameType):
/// `Unknown` is one variant regardless of the number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FrameKind {
    /// `DATA` (RFC 9113 §6.1).
    Data,
    /// `HEADERS` (RFC 9113 §6.2).
    Headers,
    /// `PRIORITY` (RFC 9113 §6.3, deprecated).
    Priority,
    /// `RST_STREAM` (RFC 9113 §6.4).
    RstStream,
    /// `SETTINGS` (RFC 9113 §6.5).
    Settings,
    /// `PUSH_PROMISE` (RFC 9113 §6.6).
    PushPromise,
    /// `PING` (RFC 9113 §6.7).
    Ping,
    /// `GOAWAY` (RFC 9113 §6.8).
    GoAway,
    /// `WINDOW_UPDATE` (RFC 9113 §6.9).
    WindowUpdate,
    /// `CONTINUATION` (RFC 9113 §6.10).
    Continuation,
    /// Any frame type this implementation does not recognise (§4.1).
    Unknown,
}

impl FrameKind {
    /// Map a frame type from the frame layer.
    #[must_use]
    pub const fn of(frame_type: super::frame::FrameType) -> Self {
        use super::frame::FrameType;
        match frame_type {
            FrameType::Data => Self::Data,
            FrameType::Headers => Self::Headers,
            FrameType::Priority => Self::Priority,
            FrameType::RstStream => Self::RstStream,
            FrameType::Settings => Self::Settings,
            FrameType::PushPromise => Self::PushPromise,
            FrameType::Ping => Self::Ping,
            FrameType::GoAway => Self::GoAway,
            FrameType::WindowUpdate => Self::WindowUpdate,
            FrameType::Continuation => Self::Continuation,
            // Deliberately collapsed: the *number* is not this layer's business,
            // and §4.1's ignore rule is the same for every unrecognised type.
            FrameType::Unknown(_) => Self::Unknown,
        }
    }

    /// Whether the frame names a stream at all.
    ///
    /// `SETTINGS`, `PING` and `GOAWAY` are connection-scoped; `WINDOW_UPDATE` may
    /// be either and the caller decides from the id. Used by the connection layer
    /// to decide whether stream-state checks apply — applying them to a `PING`
    /// would look up a stream that does not exist.
    #[must_use]
    pub const fn is_stream_scoped(self) -> bool {
        matches!(
            self,
            Self::Data
                | Self::Headers
                | Self::Priority
                | Self::RstStream
                | Self::PushPromise
                | Self::WindowUpdate
                | Self::Continuation
        )
    }

    /// The RFC's name, for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Data => "DATA",
            Self::Headers => "HEADERS",
            Self::Priority => "PRIORITY",
            Self::RstStream => "RST_STREAM",
            Self::Settings => "SETTINGS",
            Self::PushPromise => "PUSH_PROMISE",
            Self::Ping => "PING",
            Self::GoAway => "GOAWAY",
            Self::WindowUpdate => "WINDOW_UPDATE",
            Self::Continuation => "CONTINUATION",
            Self::Unknown => "UNKNOWN",
        }
    }
}

impl fmt::Display for FrameKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Stream states
// ---------------------------------------------------------------------------

/// A stream's state (RFC 9113 §5.1).
///
/// The seven states and their transitions are the RFC's Figure 2 exactly; the
/// names are §5.1's own so a log line can be matched against the specification.
///
/// # `ReservedLocal` / `ReservedRemote` and push
///
/// Server push is not implemented here, so neither reserved state is *entered* by
/// this crate. They are modelled anyway for one concrete reason: §5.1 permits a
/// `PRIORITY` frame on a reserved stream, and §5.1.2's concurrency counting
/// **excludes** reserved streams. An enum that omitted them would have to answer
/// "what state is this?" for a pushed stream with something wrong — and a wrong
/// answer there silently changes the concurrency count for every other stream.
/// Modelling all seven is cheaper than special-casing two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StreamState {
    /// No frame has been sent or received that names this stream.
    ///
    /// §5.1: *"This is the initial state of all streams."* Note that an id
    /// becomes *used* the moment any frame names it, so a `HEADERS` on an idle
    /// stream opens it, and a `DATA` on an idle stream is a connection error.
    Idle,
    /// A push stream promised by us but not yet used (server side of push).
    ReservedLocal,
    /// A push stream promised by the peer (client side of push).
    ReservedRemote,
    /// Both endpoints may send.
    Open,
    /// We have sent `END_STREAM`; the peer may still send.
    HalfClosedLocal,
    /// The peer has sent `END_STREAM`; we may still send.
    ///
    /// This is the state a normal request sits in while the server builds its
    /// response, and it is the one most easily got wrong: a server that treated
    /// half-closed (remote) as closed would refuse to send its own response on
    /// every request that carries a body end.
    HalfClosedRemote,
    /// The stream is finished. A frame for it is legal only for the small set of
    /// types §5.1 exempts.
    Closed,
}

impl StreamState {
    /// Whether the stream counts toward `SETTINGS_MAX_CONCURRENT_STREAMS`.
    ///
    /// RFC 9113 §5.1.2 counts streams in `Open` and in **either** half-closed
    /// state, and explicitly excludes `Idle`, the reserved states and `Closed`.
    /// Counting a closed stream would make a server refuse new streams forever —
    /// the ceiling would fill with history and never drain, which is a stall that
    /// looks exactly like the peer being slow.
    #[must_use]
    pub const fn counts_toward_concurrency(self) -> bool {
        matches!(
            self,
            Self::Open | Self::HalfClosedLocal | Self::HalfClosedRemote
        )
    }

    /// Whether the stream can never do anything again.
    #[must_use]
    pub const fn is_closed(self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Whether the stream is idle.
    #[must_use]
    pub const fn is_idle(self) -> bool {
        matches!(self, Self::Idle)
    }

    /// The RFC's name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::ReservedLocal => "reserved (local)",
            Self::ReservedRemote => "reserved (remote)",
            Self::Open => "open",
            Self::HalfClosedLocal => "half-closed (local)",
            Self::HalfClosedRemote => "half-closed (remote)",
            Self::Closed => "closed",
        }
    }
}

impl fmt::Display for StreamState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// The per-stream record
// ---------------------------------------------------------------------------

/// One stream: its id, its state, and the receive credit it owes back.
///
/// # What it deliberately does not hold
///
/// The flow-control windows. See this module's header for why; in one line, the
/// send decision needs the *minimum* of two windows and one owner is what keeps
/// that minimum honest. `recv_unacked` below is not a window — it is the
/// per-stream ledger the connection layer uses to decide when to send
/// `WINDOW_UPDATE`, and it is the only counter here that a window's value could
/// be confused with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    id: StreamId,
    state: StreamState,
    /// Bytes received on this stream and not yet returned with a
    /// `WINDOW_UPDATE`.
    ///
    /// RFC 9113 §6.9.1 lets a receiver replenish *less* than it received, and
    /// that is the entire mechanism of receive-side backpressure: a server that
    /// immediately returns every byte's worth of window is telling the client "I
    /// can take it faster than I can use it". Holding this counter here rather
    /// than in `flow` keeps the *policy* (when to replenish) separable from the
    /// *accounting* (what the window is).
    recv_unacked: u32,
    /// Bytes sent on this stream that have not been acknowledged, for
    /// diagnostics.
    ///
    /// Not used for admission — the window in `flow` is — but a stream's own
    /// count is what a stall investigation needs, and reconstructing it from the
    /// connection window is impossible once other streams have interleaved.
    send_unacked: u64,
}

impl Stream {
    /// A stream in a given state.
    #[must_use]
    pub const fn new(id: StreamId, state: StreamState) -> Self {
        Self {
            id,
            state,
            recv_unacked: 0,
            send_unacked: 0,
        }
    }

    /// A newly opened client request stream.
    ///
    /// §5.1: a `HEADERS` frame with no `END_STREAM` moves a stream from `idle` to
    /// `open`; with `END_STREAM` it moves straight to `half-closed (remote)`.
    /// Both are what a server sees for a request, so the caller names which.
    #[must_use]
    pub const fn opening(id: StreamId, end_stream: bool) -> Self {
        Self::new(
            id,
            if end_stream {
                StreamState::HalfClosedRemote
            } else {
                StreamState::Open
            },
        )
    }

    /// The id.
    #[must_use]
    pub const fn id(&self) -> StreamId {
        self.id
    }

    /// The state.
    #[must_use]
    pub const fn state(&self) -> StreamState {
        self.state
    }

    /// Bytes received and not yet replenished.
    #[must_use]
    pub const fn recv_unacked(&self) -> u32 {
        self.recv_unacked
    }

    /// Bytes sent and not yet acknowledged by a `WINDOW_UPDATE`.
    #[must_use]
    pub const fn send_unacked(&self) -> u64 {
        self.send_unacked
    }

    /// Whether both directions are finished, so the stream can be forgotten.
    ///
    /// A stream in this state is still **remembered** by the registry — §5.1.1
    /// requires monotonicity, which is unknowable without the history — but it no
    /// longer counts toward concurrency and no frame other than the exempt set is
    /// legal on it.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.state.is_closed()
    }

    /// Record received bytes against this stream's unreplenished credit.
    ///
    /// # Errors
    ///
    /// [`StreamError::protocol`] with `FLOW_CONTROL_ERROR` when the counter would
    /// leave the range of a 32-bit window. The counter is bounded by the window
    /// itself, so this cannot fire while flow control is enforced — it exists so
    /// the arithmetic is total rather than wrapping. A wrapping window counter is
    /// a **silent** window enlargement, which is the one flow-control failure
    /// that produces no error at all.
    pub fn note_received(&mut self, n: u32) -> Result<(), StreamError> {
        self.recv_unacked = self.recv_unacked.checked_add(n).ok_or_else(|| {
            StreamError::protocol(
                ErrorCode::FlowControlError,
                format!(
                    "stream {} received {n} bytes on top of {} unreplenished bytes, \
                     which overflows the window counter",
                    self.id, self.recv_unacked
                ),
            )
        })?;
        Ok(())
    }

    /// Take the accumulated credit, for a `WINDOW_UPDATE`.
    ///
    /// Returns how many bytes to advertise and resets the counter. Returning the
    /// whole amount is deliberate at this layer: the *decision* to return less is
    /// [`Stream::replenish`], and keeping the two apart means a backpressure
    /// policy is a call site rather than a rewrite.
    pub fn take_replenishable(&mut self) -> u32 {
        core::mem::take(&mut self.recv_unacked)
    }

    /// Note a `WINDOW_UPDATE` was sent for `n` bytes, cancelling that credit.
    ///
    /// # Errors
    ///
    /// [`StreamError::protocol`] with `INTERNAL_ERROR` when `n` exceeds the credit
    /// actually owed. That is our bug, not the peer's — and it is worth catching
    /// loudly, because returning credit that was never taken inflates the peer's
    /// window beyond what this endpoint can absorb.
    pub fn replenish(&mut self, n: u32) -> Result<(), StreamError> {
        if n > self.recv_unacked {
            return Err(StreamError::protocol(
                ErrorCode::InternalError,
                format!(
                    "stream {} tries to return {n} bytes of window but owes only {}",
                    self.id, self.recv_unacked
                ),
            ));
        }
        self.recv_unacked -= n;
        Ok(())
    }

    /// Note that `n` payload bytes were sent.
    ///
    /// Saturating rather than checked: this counter is diagnostic only, and a
    /// diagnostic counter that can fail an otherwise-valid send is worse than one
    /// that stops counting. The authoritative accounting is in `flow`, where the
    /// error is real.
    pub fn note_sent(&mut self, n: u32) {
        self.send_unacked = self.send_unacked.saturating_add(u64::from(n));
    }

    /// Note that a `WINDOW_UPDATE` acknowledged `n` sent bytes.
    pub fn note_acknowledged(&mut self, n: u32) {
        self.send_unacked = self.send_unacked.saturating_sub(u64::from(n));
    }

    // -- Legality (RFC 9113 §5.1) -------------------------------------------

    /// Whether a frame of `kind` is legal in this stream's current state.
    ///
    /// # The table, and the two rules that are easy to get backwards
    ///
    /// RFC 9113 §5.1 gives a table of states against frame types. Reduced to the
    /// frame categories this module models, and with the RFC's own error kinds:
    ///
    /// | state | legal | refused as |
    /// |---|---|---|
    /// | `idle` | `HEADERS`, `PRIORITY` | anything else: **connection** `PROTOCOL_ERROR` |
    /// | `reserved(local)` | `HEADERS`, `RST_STREAM`, `PRIORITY` | DATA etc.: **connection** `PROTOCOL_ERROR` |
    /// | `reserved(remote)` | `RST_STREAM`, `PRIORITY`, `WINDOW_UPDATE` | DATA etc.: **connection** `PROTOCOL_ERROR` |
    /// | `open` | everything | — |
    /// | `half-closed(local)` | `WINDOW_UPDATE`, `PRIORITY`, `RST_STREAM` | `DATA`/`HEADERS`: **stream** `STREAM_CLOSED` |
    /// | `half-closed(remote)` | `DATA`/`HEADERS`/`CONTINUATION` refused as stream error; rest legal | **stream** `STREAM_CLOSED` |
    /// | `closed` | `PRIORITY`, `WINDOW_UPDATE`, `RST_STREAM` | `HEADERS`: **stream** `STREAM_CLOSED`; other stream frames: **connection** `STREAM_CLOSED` |
    ///
    /// Two rules in that table are the ones implementations get wrong, and both
    /// are called out by the RFC in prose rather than in the table:
    ///
    /// 1. **`PRIORITY`, `WINDOW_UPDATE` and `RST_STREAM` are legal almost
    ///    everywhere** — including on idle streams and closed ones. §5.1 says of
    ///    `PRIORITY` that it *"can be sent … for a stream in any state"*, and of
    ///    `WINDOW_UPDATE` and `RST_STREAM` that they are permitted on a closed
    ///    stream. Treating a closed stream as "no frames at all" makes a client's
    ///    late `RST_STREAM` a connection error, which kills the whole connection
    ///    because one request was cancelled.
    /// 2. **`DATA` in `idle` is a *connection* error** (§5.1: *"Receiving any
    ///    frame other than HEADERS or PRIORITY on a stream in this state MUST be
    ///    treated as a connection error of type PROTOCOL_ERROR"*), while
    ///    **`HEADERS` on a closed stream is a *stream* error** (`STREAM_CLOSED`).
    ///    Swapping the two is the failure this function is tested against, in
    ///    both directions.
    ///
    /// `PushPromise` is refused everywhere: a server must never receive one
    /// (§8.4), and the refusal is a connection error because it is a statement
    /// about the peer's role, not about one stream.
    ///
    /// # Errors
    ///
    /// [`StreamError`] naming the reason. `StreamError::Closed` means
    /// `STREAM_CLOSED`; `StreamError::Protocol` carries the RFC code. The caller
    /// — [`crate::h2::conn`] — is responsible for promoting the cases §5.1 calls
    /// connection errors; the two are distinguished by
    /// [`StreamError::rule_scope`].
    pub fn accepts(&self, kind: FrameKind) -> Result<(), StreamError> {
        // -- Frames legal in nearly every state, checked first --------------
        //
        // PRIORITY, WINDOW_UPDATE and RST_STREAM are the three §5.1 exempts for
        // most states. Handling them here rather than in each arm is what keeps
        // the per-state arms about the frames that *are* state-sensitive, and it
        // makes "a late RST_STREAM on a closed stream is fine" a single fact
        // instead of seven.
        match kind {
            // §5.3.1 deprecates priority signalling, and §5.1 permits the frame in
            // every state including idle and closed. Ignoring it is the RFC's own
            // guidance, so it never changes state and never fails.
            FrameKind::Priority => return Ok(()),
            // §5.1: legal on a closed stream, and legal on an idle one — a
            // WINDOW_UPDATE for a stream the peer has not opened yet is not the
            // peer's error to make, it is our bookkeeping to fix.
            FrameKind::WindowUpdate => return Ok(()),
            // §5.1: *"RST_STREAM … can be sent on a stream in any state."* An
            // idle stream is the exception the RFC names — but only because a
            // RST_STREAM naming an idle stream is itself a connection error
            // (§4.2 precludes creating a stream with RST_STREAM). Refusing it
            // here as a stream error would let a peer reset a stream it never
            // opened and leave us believing it was once real.
            FrameKind::RstStream => {
                return if self.state.is_idle() {
                    Err(StreamError::protocol(
                        ErrorCode::ProtocolError,
                        format!(
                            "RST_STREAM on idle stream {}: a stream must be opened by \
                             HEADERS before it can be reset (RFC 9113 §5.1)",
                            self.id
                        ),
                    ))
                } else {
                    Ok(())
                };
            }
            _ => {}
        }

        // -- SETTINGS, PING, GOAWAY -----------------------------------------
        //
        // Connection-scoped frames name stream 0 and never reach a stream's
        // legality check through the connection layer. If one does arrive here
        // with a non-zero id, that is the frame layer's `BadStreamId` business,
        // not this function's — so the honest answer is "legal", and the caller
        // has already decided. Returning an error here would double-report and
        // mask the real fault.
        if !kind.is_stream_scoped() {
            return Ok(());
        }

        match self.state {
            // §5.1, `idle`: *"Receiving any frame other than HEADERS or PRIORITY
            // on a stream in this state MUST be treated as a connection error of
            // type PROTOCOL_ERROR."* That is `DATA`, `CONTINUATION` and
            // `PUSH_PROMISE` — the three that remain after the exempts above.
            StreamState::Idle => Err(StreamError::protocol(
                ErrorCode::ProtocolError,
                format!(
                    "{kind} on idle stream {}: the stream was never opened, so this \
                     frame invents an id with no HEADERS to introduce it \
                     (RFC 9113 §5.1) — a connection error",
                    self.id
                ),
            )),

            // §5.1, `reserved (local)`: we promised this stream. `HEADERS` (the
            // response) and `RST_STREAM` are ours to send; `DATA` is not, because
            // the promise is not a response yet.
            StreamState::ReservedLocal => Err(StreamError::protocol(
                ErrorCode::ProtocolError,
                format!(
                    "{kind} on stream {}: the stream is reserved by us and no response \
                     has been sent (RFC 9113 §5.1)",
                    self.id
                ),
            )),

            // §5.1, `reserved (remote)`: the peer promised this stream. `DATA` and
            // `HEADERS` are illegal from the peer; `WINDOW_UPDATE` and
            // `RST_STREAM` were already handled above.
            StreamState::ReservedRemote => Err(StreamError::protocol(
                ErrorCode::ProtocolError,
                format!(
                    "{kind} on stream {}: the stream is reserved by the peer and only \
                     WINDOW_UPDATE or RST_STREAM are legal (RFC 9113 §5.1)",
                    self.id
                ),
            )),

            // §5.1, `open`: *"Any type of frame can be sent"*, so nothing is
            // refused. This is the state the bulk of a request lives in, and an
            // over-eager check here is how a valid request body gets rejected.
            StreamState::Open => Ok(()),

            // §5.1, `half-closed (local)`: we have sent END_STREAM, so the peer
            // must not send DATA or HEADERS — that is a **stream** error,
            // `STREAM_CLOSED`, not a connection error, because it means one
            // request raced our response rather than that the connection is
            // corrupt. CONTINUATION is in the same clause: it continues a HEADERS
            // frame the peer sent before it learned we were done.
            StreamState::HalfClosedLocal => Err(StreamError::Closed),

            // §5.1, `half-closed (remote)`: the peer has sent END_STREAM, so it
            // may not send more DATA or HEADERS. A stream error, for the same
            // reason — and this is the *normal* request state, so getting it wrong
            // means every request with a body fails.
            StreamState::HalfClosedRemote => Err(StreamError::Closed),

            // §5.1, `closed`: this is the row with two different error kinds in
            // it, and the RFC states both explicitly.
            //
            // * HEADERS on a closed stream is a **stream** error of type
            //   `STREAM_CLOSED` — a request that raced its own cancellation is
            //   routine.
            // * Any other frame (here: DATA and CONTINUATION, the remaining
            //   stream-scoped kinds) is a **connection** error of type
            //   `STREAM_CLOSED`. The reason for the asymmetry is timing: a
            //   HEADERS arriving after we closed is explainable by
            //   request/response overlap, while DATA arriving after is evidence
            //   the peer is writing into a stream it should have finished.
            StreamState::Closed => match kind {
                FrameKind::Headers => Err(StreamError::Closed),
                _ => Err(StreamError::protocol(
                    ErrorCode::StreamClosed,
                    format!(
                        "{kind} on closed stream {}: only HEADERS is a stream error here; \
                         any other frame is a connection error of type STREAM_CLOSED \
                         (RFC 9113 §5.1)",
                        self.id
                    ),
                )),
            },
        }
    }

    /// Whether `kind` in the current state is illegal in a way that kills the
    /// **connection** rather than the stream.
    ///
    /// # Why the connection layer needs this and cannot infer it
    ///
    /// [`Stream::accepts`] returns a [`StreamError`] for both kinds of failure,
    /// because that is the type the state machine has. But §5.1 makes several of
    /// them connection errors, and the caller must know which. Inferring it from
    /// the *code* is wrong: `PROTOCOL_ERROR` is a connection error for DATA on
    /// idle and a stream error for a bad pseudo-header, so the code cannot decide.
    /// Inferring it from the state alone would duplicate the table.
    ///
    /// So the rule is recomputed here, from the same two inputs, and the two
    /// functions are tested against each other: any state/kind pair where
    /// `accepts` is `Ok` must be `false` here, and the pairs that `accepts`
    /// refuses must partition cleanly. That mutual test is what stops the two from
    /// drifting.
    #[must_use]
    pub fn refusal_is_fatal(&self, kind: FrameKind) -> bool {
        if self.accepts(kind).is_ok() {
            return false;
        }
        match self.state {
            // Idle: every refusal is the §5.1 connection error, except the
            // RST_STREAM case, which is also a connection-level rule (the peer is
            // resetting a stream it never opened).
            StreamState::Idle => true,
            // The reserved states' refusals are §5.1 connection errors.
            StreamState::ReservedLocal | StreamState::ReservedRemote => true,
            // The half-closed states refuse only as STREAM_CLOSED stream errors.
            StreamState::HalfClosedLocal | StreamState::HalfClosedRemote => false,
            // Closed: HEADERS is a stream error, everything else fatal.
            StreamState::Closed => !matches!(kind, FrameKind::Headers),
            // Open refuses nothing, so this arm is unreachable; returning `false`
            // states the safe default rather than panicking on an invariant the
            // caller cannot have broken.
            StreamState::Open => false,
        }
    }

    // -- Transitions ---------------------------------------------------------

    /// Apply the state change for a frame **we send**.
    ///
    /// # Errors
    ///
    /// [`StreamError`] when the frame is not legal in the current state, by
    /// [`Stream::accepts`]. Checked rather than assumed: a server that sends
    /// `HEADERS` on a stream it already answered produces a protocol violation
    /// the peer will report as *our* fault, and it is far cheaper to catch here.
    pub fn on_send(&mut self, kind: FrameKind, end_stream: bool) -> Result<(), StreamError> {
        self.accepts(kind)?;
        match (self.state, kind, end_stream) {
            // Opening: only HEADERS can move `idle` on the send side, and only
            // from `reserved (local)` in practice (a server does not open a
            // client's stream). Both land in a half-closed state when the sender
            // is done immediately.
            (StreamState::Idle, FrameKind::Headers, true) => {
                self.state = StreamState::HalfClosedLocal;
            }
            (StreamState::Idle, FrameKind::Headers, false) => {
                self.state = StreamState::Open;
            }
            // §5.1's Figure 2: from `open`, END_STREAM on either side gives the
            // corresponding half-closed state, not `closed` — the other direction
            // is still live, and collapsing to `closed` would refuse the peer's
            // own END_STREAM.
            (StreamState::Open, _, true) => {
                self.state = StreamState::HalfClosedLocal;
            }
            // §5.1: the *second* END_STREAM closes the stream, because now neither
            // direction can carry anything.
            (StreamState::HalfClosedRemote, _, true) => {
                self.state = StreamState::Closed;
            }
            // A RST_STREAM we send closes the stream immediately from any state.
            // §5.1 lists no half-closed intermediate for a reset: a reset stream
            // is finished in both directions.
            (_, FrameKind::RstStream, _) => {
                self.state = StreamState::Closed;
            }
            _ => {}
        }
        Ok(())
    }

    /// Apply the state change for a frame the **peer sent**.
    ///
    /// # Errors
    ///
    /// [`StreamError`] when the frame is not legal in the current state.
    pub fn on_recv(&mut self, kind: FrameKind, end_stream: bool) -> Result<(), StreamError> {
        self.accepts(kind)?;
        match (self.state, kind, end_stream) {
            (StreamState::Idle, FrameKind::Headers, true) => {
                self.state = StreamState::HalfClosedRemote;
            }
            (StreamState::Idle, FrameKind::Headers, false) => {
                self.state = StreamState::Open;
            }
            // §5.1 Figure 2: from `open`, the peer's END_STREAM gives
            // `half-closed (remote)`. This is the state a normal GET sits in while
            // the response is built.
            (StreamState::Open, _, true) => {
                self.state = StreamState::HalfClosedRemote;
            }
            // The second END_STREAM — this time ours, arriving while the peer is
            // already done — closes the stream.
            (StreamState::HalfClosedLocal, _, true) => {
                self.state = StreamState::Closed;
            }
            // §5.1: a RST_STREAM from the peer closes the stream from any state.
            (_, FrameKind::RstStream, _) => {
                self.state = StreamState::Closed;
            }
            _ => {}
        }
        Ok(())
    }

    /// Close the stream unconditionally.
    ///
    /// Used for `RST_STREAM` and for the connection teardown path, where every
    /// open stream finishes because the connection did. Naming it separately from
    /// the transition functions keeps "the stream is over" from being spelled as
    /// a fake END_STREAM on one side, which would leave the wrong half-closed bit
    /// set for anything that observed the state.
    pub fn close(&mut self) {
        self.state = StreamState::Closed;
    }
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// Why a new stream could not be admitted.
///
/// A distinct type rather than a bare [`StreamError`] because the two §5.1.1
/// rules here are **connection** errors — the id space is corrupted or the peer
/// is ignoring the ceiling — while everything inside [`Stream`] is a stream
/// error. Collapsing them would let a peer that reuses an id be answered with a
/// `RST_STREAM` on the reused stream, which is exactly the case where the
/// connection's state is no longer trustworthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    /// A stream id that is not strictly greater than the last one seen.
    ///
    /// RFC 9113 §5.1.1: *"The identifier of a newly established stream MUST be
    /// numerically greater than all streams that the initiating endpoint has
    /// opened. … An endpoint that receives an unexpected stream identifier MUST
    /// respond with a connection error of type PROTOCOL_ERROR."*
    ///
    /// The rule is what makes a stream id a **cursor** rather than a key: a
    /// server can forget closed streams' payloads and still know that anything at
    /// or below the cursor is finished. A peer allowed to reuse an id could
    /// resurrect a stream the server already answered.
    NotMonotonic {
        /// The id the peer used.
        got: u32,
        /// The highest id already seen.
        last: u32,
    },
    /// The peer opened more streams than its own advertised ceiling allows.
    ///
    /// RFC 9113 §5.1.2: exceeding `SETTINGS_MAX_CONCURRENT_STREAMS` *"MUST be
    /// treated as a stream error of type PROTOCOL_ERROR or REFUSED_STREAM"*. It is
    /// REFUSED_STREAM here, and that choice is load-bearing: §8.7 says a client
    /// may retry a REFUSED_STREAM request elsewhere, while PROTOCOL_ERROR implies
    /// the request was malformed and must not be retried. Answering a load-shed
    /// with PROTOCOL_ERROR makes clients give up on requests that would have
    /// succeeded on another connection.
    TooManyStreams {
        /// The ceiling that was in force.
        limit: u32,
        /// How many streams were already open.
        open: u32,
    },
    /// The id was not a legal client-initiated id at all (even, or zero).
    BadId(StreamError),
}

impl AdmissionError {
    /// The RFC code to report.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // The id space is corrupted; only a connection error describes that.
            Self::NotMonotonic { .. } => ErrorCode::ProtocolError,
            // A load-shed, which the client may retry (§8.7).
            Self::TooManyStreams { .. } => ErrorCode::RefusedStream,
            Self::BadId(e) => e.code(),
        }
    }

    /// Whether the connection is unusable afterwards.
    ///
    /// `true` for the id-space violations, `false` for a load-shed: a refused
    /// stream leaves every other stream in the connection working, which is the
    /// whole point of having a ceiling rather than a hard cap.
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        match self {
            Self::NotMonotonic { .. } | Self::BadId(_) => true,
            Self::TooManyStreams { .. } => false,
        }
    }
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMonotonic { got, last } => write!(
                f,
                "stream id {got} is not greater than the highest already used, {last} \
                 (RFC 9113 §5.1.1)"
            ),
            Self::TooManyStreams { limit, open } => write!(
                f,
                "{open} streams are open, at the advertised ceiling of {limit} \
                 (RFC 9113 §5.1.2)"
            ),
            Self::BadId(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AdmissionError {}

/// The set of streams a connection is tracking, plus the id cursor.
///
/// # Why a registry and not a `HashMap` in the connection
///
/// Three rules — strict monotonicity, the concurrency ceiling, and "the highest
/// id we have seen" for `GOAWAY` — are properties of the *collection* rather than
/// of any stream, and §5.1.1's monotonicity rule in particular cannot be checked
/// from one stream because it is a comparison against history. Putting them in
/// one place means [`crate::h2::conn`] asks one object whether a stream may be
/// opened, instead of remembering three invariants at every call site.
///
/// # Bounded memory
///
/// Closed streams are **retained** rather than evicted. That is deliberate: the
/// monotonicity rule is exactly "nothing at or below the cursor", so evicting a
/// closed stream and then accepting its id back would be the bug the rule exists
/// to prevent. The cost is bounded by the peer's stream rate rather than by
/// anything the peer can inflate — ids are strictly increasing 31-bit integers,
/// so a connection can hold at most one entry per stream it ever saw. A server
/// that needs to bound this further should bound *connections*, which
/// [`crate::conn`] already does per tenant.
#[derive(Debug, Clone, Default)]
pub struct StreamRegistry {
    streams: Vec<Stream>,
    /// The highest client-initiated stream id seen, or `0` for none.
    ///
    /// This is `GOAWAY`'s `last_stream_id`: the highest stream the server might
    /// have processed. Keeping it as a cursor rather than recomputing it from
    /// `streams` is what makes it correct after a stream is forgotten.
    last_client_id: u32,
    /// The ceiling in force, from `SETTINGS_MAX_CONCURRENT_STREAMS`.
    ///
    /// `None` is §6.5.2's "unlimited", which is *not* the same as zero — reading
    /// an unadvertised limit as zero refuses every stream.
    limit: Option<u32>,
}

impl StreamRegistry {
    /// An empty registry with no advertised ceiling.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty registry with a ceiling.
    #[must_use]
    pub fn with_limit(limit: Option<u32>) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    /// The ceiling in force.
    #[must_use]
    pub const fn limit(&self) -> Option<u32> {
        self.limit
    }

    /// Change the ceiling, as a `SETTINGS_MAX_CONCURRENT_STREAMS` requires.
    ///
    /// RFC 9113 §6.5.3: a reduction takes effect immediately and applies to
    /// streams already open — the new value is a ceiling on *how many may be
    /// open*, so a connection already past the new value must drain rather than
    /// have its streams reset. This only stores the number; enforcement is at the
    /// next admission, which is what "drain" means in practice.
    pub fn set_limit(&mut self, limit: Option<u32>) {
        self.limit = limit;
    }

    /// How many streams count toward the ceiling (§5.1.2).
    ///
    /// Reserved and closed streams are excluded; see
    /// [`StreamState::counts_toward_concurrency`].
    #[must_use]
    pub fn open_count(&self) -> u32 {
        self.streams
            .iter()
            .filter(|s| s.state().counts_toward_concurrency())
            .count()
            .try_into()
            .unwrap_or(u32::MAX)
    }

    /// The highest client-initiated id seen.
    #[must_use]
    pub const fn last_client_id(&self) -> u32 {
        self.last_client_id
    }

    /// Every stream, in id order of insertion.
    #[must_use]
    pub fn streams(&self) -> &[Stream] {
        &self.streams
    }

    /// A stream by id.
    #[must_use]
    pub fn get(&self, id: StreamId) -> Option<&Stream> {
        self.streams.iter().find(|s| s.id() == id)
    }

    /// A mutable stream by id.
    pub fn get_mut(&mut self, id: StreamId) -> Option<&mut Stream> {
        self.streams.iter_mut().find(|s| s.id() == id)
    }

    /// Whether an id has been used.
    #[must_use]
    pub fn contains(&self, id: StreamId) -> bool {
        self.get(id).is_some()
    }

    /// Admit a newly opened client stream.
    ///
    /// Enforces, in this order:
    ///
    /// 1. §5.1.1 parity — an even or zero id from a client is fatal.
    /// 2. §5.1.1 monotonicity — the id must exceed every id seen before,
    ///    **including closed ones**.
    /// 3. §5.1.2 concurrency — the ceiling applies only to streams that count,
    ///    so a connection whose streams have all finished is never refused.
    ///
    /// # Errors
    ///
    /// [`AdmissionError`], whose [`AdmissionError::is_fatal`] says whether the
    /// connection survives. The order matters: monotonicity is checked before the
    /// ceiling because a reused id is a corruption the ceiling would hide — a
    /// full connection would report REFUSED_STREAM for an id the peer already
    /// finished, and the peer would retry it on a *new* connection where it
    /// succeeds, masking a real violation.
    pub fn admit(&mut self, raw_id: u32, end_stream: bool) -> Result<StreamId, AdmissionError> {
        let id = StreamId::client_from_frame(raw_id).map_err(AdmissionError::BadId)?;

        if id.get() <= self.last_client_id {
            return Err(AdmissionError::NotMonotonic {
                got: id.get(),
                last: self.last_client_id,
            });
        }

        if let Some(limit) = self.limit {
            let open = self.open_count();
            if open >= limit {
                return Err(AdmissionError::TooManyStreams { limit, open });
            }
        }

        // The cursor advances **before** the stream is pushed, so a failure below
        // cannot leave an id that was used unrecorded. Nothing below can fail, but
        // ordering it this way keeps the invariant local rather than relying on
        // that.
        self.last_client_id = id.get();
        self.streams.push(Stream::opening(id, end_stream));
        Ok(id)
    }

    /// Apply a transition to a stream we sent a frame on.
    ///
    /// # Errors
    ///
    /// [`StreamError::protocol`] with `INTERNAL_ERROR` when the id is not
    /// registered — we sent a frame on a stream we never opened, which is our
    /// bug and would produce a wire violation the peer reports as ours. Otherwise
    /// [`Stream::on_send`]'s error.
    pub fn on_send(
        &mut self,
        id: StreamId,
        kind: FrameKind,
        end_stream: bool,
    ) -> Result<(), StreamError> {
        let stream = self.get_mut(id).ok_or_else(|| {
            StreamError::protocol(
                ErrorCode::InternalError,
                format!("no stream {id} is registered, so we cannot have sent on it"),
            )
        })?;
        stream.on_send(kind, end_stream)
    }

    /// Apply a transition to a stream the peer sent a frame on, admitting it if
    /// it is new.
    ///
    /// # Errors
    ///
    /// [`AdmissionError`] for a new stream, [`StreamError`] for an existing one.
    pub fn on_recv(
        &mut self,
        raw_id: u32,
        kind: FrameKind,
        end_stream: bool,
    ) -> Result<StreamId, RecvAdmissionError> {
        let id = StreamId::client_from_frame(raw_id).map_err(RecvAdmissionError::Fatal)?;
        if self.contains(id) {
            let stream = self
                .get_mut(id)
                .ok_or(RecvAdmissionError::Fatal(StreamError::protocol(
                    ErrorCode::InternalError,
                    "stream vanished between contains() and get_mut()",
                )))?;
            stream.on_recv(kind, end_stream)?;
            return Ok(id);
        }
        let id = if kind == FrameKind::Headers {
            self.admit(raw_id, end_stream)?
        } else {
            // Any frame other than HEADERS or PRIORITY on an unopened stream is
            // §5.1's connection error. It cannot be admitted, because admitting it
            // would give an illegal id an entry and make a later HEADERS on the
            // *real* stream look like a reuse.
            return Err(RecvAdmissionError::Fatal(StreamError::protocol(
                ErrorCode::ProtocolError,
                format!(
                    "{kind} on idle stream {raw_id}: only HEADERS may open a stream \
                     (RFC 9113 §5.1)"
                ),
            )));
        };
        Ok(id)
    }

    /// Close a stream because a `RST_STREAM` arrived.
    ///
    /// # Errors
    ///
    /// [`StreamError`] when the id is unregistered or idle; see
    /// [`StreamRegistry::on_recv`] for why an unopened stream cannot be reset.
    pub fn on_reset(&mut self, raw_id: u32) -> Result<StreamId, StreamError> {
        self.on_recv(raw_id, FrameKind::RstStream, false)
            .map_err(RecvAdmissionError::into_stream)
    }

    /// Close every stream, as a connection teardown does.
    pub fn close_all(&mut self) {
        for stream in &mut self.streams {
            stream.close();
        }
    }
}

/// Why [`StreamRegistry::on_recv`] failed.
///
/// Two error types in one result because the caller needs both: an existing
/// stream's failure is a `RST_STREAM`, while a new stream's admission failure may
/// end the connection. Returning a single rewritten [`StreamError`] would lose the
/// `REFUSED_STREAM` distinction that §8.7 depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecvAdmissionError {
    /// A condition that ends the connection.
    Fatal(StreamError),
    /// The stream was refused, and the connection continues.
    Admission(AdmissionError),
}

impl RecvAdmissionError {
    /// The RFC code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Fatal(e) => e.code(),
            Self::Admission(a) => a.code(),
        }
    }

    /// Whether the connection dies.
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        match self {
            Self::Fatal(_) => true,
            Self::Admission(a) => a.is_fatal(),
        }
    }

    /// The stream-level view, for the cases that terminate one stream.
    #[must_use]
    pub fn into_stream(self) -> StreamError {
        match self {
            Self::Fatal(e) => e,
            Self::Admission(a) => match a {
                AdmissionError::BadId(e) => e,
                other => StreamError::protocol(other.code(), other.to_string()),
            },
        }
    }
}

impl From<AdmissionError> for RecvAdmissionError {
    fn from(value: AdmissionError) -> Self {
        Self::Admission(value)
    }
}

impl From<StreamError> for RecvAdmissionError {
    fn from(value: StreamError) -> Self {
        Self::Fatal(value)
    }
}

impl fmt::Display for RecvAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fatal(e) => write!(f, "{e}"),
            Self::Admission(a) => write!(f, "{a}"),
        }
    }
}

impl std::error::Error for RecvAdmissionError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(n: u32) -> StreamId {
        StreamId::client(n).expect("a test id must be a legal client id")
    }

    // -- Ids ---------------------------------------------------------------

    /// §5.1.1: client streams are odd, server streams are even, and zero is
    /// never a stream. Getting this wrong tracks a stream under an id no frame
    /// will name.
    #[test]
    fn stream_ids_enforce_parity() {
        assert!(StreamId::client(0).is_err());
        assert!(StreamId::client(2).is_err());
        assert!(StreamId::client(1).is_ok());
        assert!(StreamId::client(3).is_ok());
        assert!(StreamId::client(StreamId::MAX).is_ok());

        assert!(StreamId::server(0).is_err());
        assert!(StreamId::server(1).is_err());
        assert!(StreamId::server(2).is_ok());

        assert!(sid(7).is_client_initiated());
        assert!(StreamId::server(8).unwrap().is_server_initiated());
    }

    /// An even id from a client is the push-parity violation. `frame.rs` refuses
    /// it too; this pins that the *reason* survives to here.
    #[test]
    fn an_even_id_from_a_client_is_refused() {
        let e = StreamId::client_from_frame(4).expect_err("4 is even");
        assert_eq!(e.code(), ErrorCode::ProtocolError);
        assert!(
            e.to_string().contains("even"),
            "the message must name the parity rule: {e}"
        );
    }

    #[test]
    fn a_stream_id_renders_as_its_number() {
        assert_eq!(sid(5).to_string(), "5");
    }

    // -- Frame kinds -------------------------------------------------------

    /// The category mapping, including the collapse of every unknown type to one
    /// variant — §4.1's ignore rule is the same for all of them.
    #[test]
    fn frame_kinds_map_from_frame_types() {
        use super::super::frame::FrameType;
        assert_eq!(FrameKind::of(FrameType::Data), FrameKind::Data);
        assert_eq!(FrameKind::of(FrameType::Headers), FrameKind::Headers);
        assert_eq!(FrameKind::of(FrameType::WindowUpdate), FrameKind::WindowUpdate);
        assert_eq!(FrameKind::of(FrameType::Continuation), FrameKind::Continuation);
        assert_eq!(FrameKind::of(FrameType::Unknown(0x2f)), FrameKind::Unknown);
        assert_eq!(FrameKind::of(FrameType::Unknown(0xff)), FrameKind::Unknown);
        assert_eq!(FrameKind::of(FrameType::Ping), FrameKind::Ping);
    }

    /// Connection-scoped frames do not name a stream. A state machine that
    /// treated `PING` as stream-scoped would look up stream 0.
    #[test]
    fn only_stream_scoped_kinds_name_a_stream() {
        assert!(!FrameKind::Settings.is_stream_scoped());
        assert!(!FrameKind::Ping.is_stream_scoped());
        assert!(!FrameKind::GoAway.is_stream_scoped());
        assert!(!FrameKind::Unknown.is_stream_scoped());
        assert!(FrameKind::Data.is_stream_scoped());
        assert!(FrameKind::Headers.is_stream_scoped());
        assert!(FrameKind::WindowUpdate.is_stream_scoped());
    }

    // -- §5.1 legality table ----------------------------------------------

    /// Every frame kind on an `idle` stream: HEADERS and PRIORITY open it; the
    /// rest are refused. §5.1's own list.
    #[test]
    fn idle_accepts_only_headers_and_priority() {
        let s = Stream::new(sid(1), StreamState::Idle);
        assert!(s.accepts(FrameKind::Headers).is_ok());
        assert!(s.accepts(FrameKind::Priority).is_ok());
        // §5.1 permits WINDOW_UPDATE and RST_STREAM on an idle stream as *frames*;
        // the RST_STREAM refusal below is the §4.2 "may not create a stream with
        // RST_STREAM" rule, which is a connection error.
        assert!(s.accepts(FrameKind::WindowUpdate).is_ok());
        assert!(s.accepts(FrameKind::RstStream).is_err());
        assert!(s.accepts(FrameKind::Data).is_err());
        assert!(s.accepts(FrameKind::Continuation).is_err());
    }

    /// **The headline rule of §5.1.** `DATA` on an idle stream is a *connection*
    /// error; `HEADERS` on a closed stream is a *stream* error. Swapping them
    /// either kills the connection for one cancelled request or lets a peer
    /// corrupt the id space in silence.
    #[test]
    fn data_on_an_idle_stream_is_fatal_but_headers_on_closed_is_not() {
        let idle = Stream::new(sid(1), StreamState::Idle);
        let e = idle.accepts(FrameKind::Data).expect_err("DATA on idle");
        assert_eq!(e.code(), ErrorCode::ProtocolError);
        assert!(
            idle.refusal_is_fatal(FrameKind::Data),
            "RFC 9113 §5.1 makes DATA on an idle stream a CONNECTION error"
        );

        let closed = Stream::new(sid(1), StreamState::Closed);
        let e = closed.accepts(FrameKind::Headers).expect_err("HEADERS on closed");
        assert_eq!(e.code(), ErrorCode::StreamClosed);
        assert!(
            !closed.refusal_is_fatal(FrameKind::Headers),
            "HEADERS on a closed stream is a STREAM error: one request raced its \
             own cancellation, and killing the connection would drop every other \
             multiplexed request"
        );
    }

    /// §5.1: `PRIORITY`, `WINDOW_UPDATE` and `RST_STREAM` are legal on a
    /// **closed** stream. Treating "closed" as "no frames at all" turns a late
    /// `RST_STREAM` into a connection error.
    #[test]
    fn closed_streams_still_accept_priority_window_update_and_reset() {
        let closed = Stream::new(sid(1), StreamState::Closed);
        assert!(closed.accepts(FrameKind::Priority).is_ok());
        assert!(closed.accepts(FrameKind::WindowUpdate).is_ok());
        assert!(closed.accepts(FrameKind::RstStream).is_ok());
    }

    /// §5.1 distinguishes the closed case for the remaining frames: DATA is a
    /// connection error, HEADERS is not. Both halves are asserted so a change to
    /// one cannot pass by breaking the other.
    #[test]
    fn data_on_a_closed_stream_is_fatal_and_headers_is_not() {
        let closed = Stream::new(sid(1), StreamState::Closed);
        assert!(closed.accepts(FrameKind::Data).is_err());
        assert!(closed.refusal_is_fatal(FrameKind::Data));
        assert!(!closed.refusal_is_fatal(FrameKind::Headers));
    }

    /// §5.1: `open` accepts everything, because both directions are live.
    #[test]
    fn open_accepts_every_stream_frame() {
        let s = Stream::new(sid(1), StreamState::Open);
        for kind in [
            FrameKind::Data,
            FrameKind::Headers,
            FrameKind::Priority,
            FrameKind::RstStream,
            FrameKind::WindowUpdate,
            FrameKind::Continuation,
        ] {
            assert!(s.accepts(kind).is_ok(), "open must accept {kind}");
        }
    }

    /// §5.1: both half-closed states refuse DATA and HEADERS as **stream**
    /// errors, and still accept the three exempts. `half-closed (remote)` is the
    /// normal request state, so a mistake here fails every request.
    #[test]
    fn half_closed_states_refuse_data_as_a_stream_error() {
        for state in [StreamState::HalfClosedLocal, StreamState::HalfClosedRemote] {
            let s = Stream::new(sid(1), state);
            assert_eq!(
                s.accepts(FrameKind::Data).expect_err("DATA").code(),
                ErrorCode::StreamClosed,
                "{state} must refuse DATA as STREAM_CLOSED"
            );
            assert!(
                !s.refusal_is_fatal(FrameKind::Data),
                "{state}: STREAM_CLOSED is a stream error, not a connection one"
            );
            assert!(s.accepts(FrameKind::RstStream).is_ok());
            assert!(s.accepts(FrameKind::WindowUpdate).is_ok());
            assert!(s.accepts(FrameKind::Priority).is_ok());
        }
    }

    /// The reserved states exist for push. Their refusals are connection errors
    /// because the peer has sent a frame for a stream that is not usable in that
    /// direction at all.
    #[test]
    fn reserved_states_refuse_data() {
        for state in [StreamState::ReservedLocal, StreamState::ReservedRemote] {
            let s = Stream::new(sid(1), state);
            assert!(s.accepts(FrameKind::Data).is_err(), "{state}");
            assert!(s.refusal_is_fatal(FrameKind::Data), "{state}");
        }
        // §5.1: RST_STREAM is permitted from both reserved states.
        assert!(Stream::new(sid(1), StreamState::ReservedLocal)
            .accepts(FrameKind::RstStream)
            .is_ok());
        assert!(Stream::new(sid(1), StreamState::ReservedRemote)
            .accepts(FrameKind::RstStream)
            .is_ok());
    }

    /// The two functions must agree: any pair `accepts` allows is not fatal, and
    /// any pair it refuses is classified by `refusal_is_fatal` without
    /// contradiction. This is what stops the table and the fatal-classifier from
    /// drifting apart, which is the failure mode that silently promotes a stream
    /// error to a connection error.
    #[test]
    fn the_fatal_classifier_agrees_with_the_legality_table() {
        let states = [
            StreamState::Idle,
            StreamState::ReservedLocal,
            StreamState::ReservedRemote,
            StreamState::Open,
            StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote,
            StreamState::Closed,
        ];
        let kinds = [
            FrameKind::Data,
            FrameKind::Headers,
            FrameKind::Priority,
            FrameKind::RstStream,
            FrameKind::PushPromise,
            FrameKind::WindowUpdate,
            FrameKind::Continuation,
        ];
        for state in states {
            let s = Stream::new(sid(1), state);
            for kind in kinds {
                let allowed = s.accepts(kind).is_ok();
                let fatal = s.refusal_is_fatal(kind);
                assert!(
                    !(allowed && fatal),
                    "{state} + {kind} is legal but classified fatal"
                );
                // Every refusal that is fatal must be a connection-level rule,
                // which for the states modelled here means a code that is not
                // STREAM_CLOSED from a half-closed state.
                if fatal {
                    assert!(
                        s.accepts(kind).is_err(),
                        "{state} + {kind}: fatal but legal"
                    );
                }
            }
        }
        // The closed/idle split, stated exhaustively rather than sampled.
        assert!(Stream::new(sid(1), StreamState::Idle).refusal_is_fatal(FrameKind::Data));
        assert!(!Stream::new(sid(1), StreamState::Closed).refusal_is_fatal(FrameKind::Headers));
        assert!(Stream::new(sid(1), StreamState::Closed).refusal_is_fatal(FrameKind::Data));
    }

    /// A server must never receive `PUSH_PROMISE` (§8.4). It is refused in every
    /// state.
    #[test]
    fn push_promise_is_refused_everywhere() {
        for state in [
            StreamState::Idle,
            StreamState::Open,
            StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote,
        ] {
            let s = Stream::new(sid(1), state);
            assert!(
                s.accepts(FrameKind::PushPromise).is_err(),
                "{state}: a server must never receive PUSH_PROMISE (RFC 9113 §8.4)"
            );
        }
    }

    // -- Transitions -------------------------------------------------------

    /// §5.1 Figure 2, receive side: a HEADERS with END_STREAM goes straight to
    /// `half-closed (remote)`, without ever being `open`.
    #[test]
    fn recv_headers_transitions_follow_figure_2() {
        let mut s = Stream::new(sid(1), StreamState::Idle);
        s.on_recv(FrameKind::Headers, false).unwrap();
        assert_eq!(s.state(), StreamState::Open);

        let mut s = Stream::new(sid(3), StreamState::Idle);
        s.on_recv(FrameKind::Headers, true).unwrap();
        assert_eq!(s.state(), StreamState::HalfClosedRemote);

        // The peer's END_STREAM on an open stream.
        let mut s = Stream::new(sid(5), StreamState::Open);
        s.on_recv(FrameKind::Data, true).unwrap();
        assert_eq!(s.state(), StreamState::HalfClosedRemote);
    }

    /// §5.1: the **second** END_STREAM closes the stream. Collapsing the first
    /// one to `closed` would refuse the peer's own end and the server's response.
    #[test]
    fn the_second_end_stream_closes_the_stream() {
        // Peer ends first, then we do.
        let mut s = Stream::new(sid(1), StreamState::Idle);
        s.on_recv(FrameKind::Headers, true).unwrap();
        assert_eq!(s.state(), StreamState::HalfClosedRemote);
        s.on_send(FrameKind::Headers, true).unwrap();
        assert_eq!(s.state(), StreamState::Closed);

        // We end first, then the peer does.
        let mut s = Stream::new(sid(3), StreamState::Idle);
        s.on_recv(FrameKind::Headers, false).unwrap();
        s.on_send(FrameKind::Headers, false).unwrap();
        assert_eq!(s.state(), StreamState::Open);
        s.on_send(FrameKind::Data, true).unwrap();
        assert_eq!(s.state(), StreamState::HalfClosedLocal);
        s.on_recv(FrameKind::Data, true).unwrap();
        assert_eq!(s.state(), StreamState::Closed);
    }

    /// A `RST_STREAM` closes from any state in either direction.
    #[test]
    fn reset_closes_from_any_state() {
        for state in [
            StreamState::Idle,
            StreamState::Open,
            StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote,
            StreamState::ReservedLocal,
            StreamState::ReservedRemote,
        ] {
            let mut s = Stream::new(sid(1), state);
            s.on_recv(FrameKind::RstStream, false).unwrap();
            assert_eq!(s.state(), StreamState::Closed, "recv reset from {state}");

            let mut s = Stream::new(sid(1), state);
            s.on_send(FrameKind::RstStream, false).unwrap();
            assert_eq!(s.state(), StreamState::Closed, "send reset from {state}");
        }
    }

    /// A transition attempted on an illegal frame fails **before** mutating, so a
    /// refused frame cannot leave the state half-advanced.
    #[test]
    fn an_illegal_transition_leaves_the_state_untouched() {
        let mut s = Stream::new(sid(1), StreamState::Idle);
        assert!(s.on_recv(FrameKind::Data, true).is_err());
        assert_eq!(s.state(), StreamState::Idle, "the state must not advance");

        let mut s = Stream::new(sid(3), StreamState::HalfClosedRemote);
        assert!(s.on_recv(FrameKind::Headers, false).is_err());
        assert_eq!(s.state(), StreamState::HalfClosedRemote);
    }

    /// §5.1.2's counting rule: open and both half-closed states count; idle,
    /// reserved and closed do not.
    #[test]
    fn concurrency_counts_only_live_streams() {
        assert!(StreamState::Open.counts_toward_concurrency());
        assert!(StreamState::HalfClosedLocal.counts_toward_concurrency());
        assert!(StreamState::HalfClosedRemote.counts_toward_concurrency());
        assert!(!StreamState::Idle.counts_toward_concurrency());
        assert!(!StreamState::ReservedLocal.counts_toward_concurrency());
        assert!(!StreamState::ReservedRemote.counts_toward_concurrency());
        assert!(!StreamState::Closed.counts_toward_concurrency());
    }

    // -- Registry ----------------------------------------------------------

    /// §5.1.1: ids must strictly increase. A reused id would resurrect a stream
    /// the server already answered.
    #[test]
    fn stream_ids_must_strictly_increase() {
        let mut r = StreamRegistry::new();
        assert_eq!(r.admit(1, true).unwrap(), sid(1));
        assert_eq!(r.admit(3, true).unwrap(), sid(3));
        assert_eq!(r.admit(5, true).unwrap(), sid(5));

        // Going back is a connection error.
        let e = r.admit(3, true).expect_err("3 was already used");
        assert!(
            matches!(e, AdmissionError::NotMonotonic { got: 3, last: 5 }),
            "got {e:?}"
        );
        assert!(e.is_fatal(), "an id-space violation ends the connection");
        assert_eq!(e.code(), ErrorCode::ProtocolError);

        // So is reusing the most recent id.
        assert!(r.admit(5, true).is_err());

        // And ids **below one already closed** are still refused: the cursor is
        // history, not a live set.
        r.get_mut(sid(1)).unwrap().close();
        assert!(
            r.admit(1, true).is_err(),
            "a closed id must not be reusable — the monotonicity rule is a cursor, \
             not a live set"
        );

        // The next odd id above the cursor is fine.
        assert!(r.admit(7, true).is_ok());
        assert_eq!(r.last_client_id(), 7);
    }

    /// An even id from a client is a push-parity violation and is fatal.
    #[test]
    fn the_registry_refuses_an_even_id() {
        let mut r = StreamRegistry::new();
        let e = r.admit(2, true).expect_err("2 is even");
        assert!(e.is_fatal());
        assert_eq!(e.code(), ErrorCode::ProtocolError);
        assert!(r.admit(0, true).is_err(), "0 is not a stream");
    }

    /// §5.1.2: the ceiling is enforced, and the refusal is `REFUSED_STREAM`
    /// rather than `PROTOCOL_ERROR` so the client may retry it (§8.7).
    #[test]
    fn the_concurrency_ceiling_is_enforced_as_refused_stream() {
        let mut r = StreamRegistry::with_limit(Some(2));
        r.admit(1, false).unwrap();
        r.admit(3, false).unwrap();
        assert_eq!(r.open_count(), 2);

        let e = r.admit(5, false).expect_err("the ceiling is 2");
        assert!(
            matches!(e, AdmissionError::TooManyStreams { limit: 2, open: 2 }),
            "got {e:?}"
        );
        assert_eq!(
            e.code(),
            ErrorCode::RefusedStream,
            "§8.7 lets a client retry a REFUSED_STREAM elsewhere; PROTOCOL_ERROR \
             would make it give up on a request that was merely load-shed"
        );
        assert!(!e.is_fatal(), "a load-shed leaves the connection usable");
    }

    /// §5.1.2: closed streams do not count, so a connection that has finished
    /// its work is never refused — a ceiling that never drains is a stall that
    /// looks exactly like a slow peer.
    #[test]
    fn finished_streams_free_the_ceiling() {
        let mut r = StreamRegistry::with_limit(Some(1));
        let a = r.admit(1, false).unwrap();
        assert!(r.admit(3, false).is_err());
        r.get_mut(a).unwrap().close();
        assert_eq!(r.open_count(), 0);
        assert!(
            r.admit(3, false).is_ok(),
            "closing a stream must free its slot, or the ceiling never drains"
        );
    }

    /// §6.5.2: `None` is "unlimited", which is **not** zero. Reading it as zero
    /// refuses every stream.
    #[test]
    fn no_advertised_ceiling_means_unlimited_not_zero() {
        let mut r = StreamRegistry::new();
        assert_eq!(r.limit(), None);
        for i in 0..50u32 {
            r.admit(2 * i + 1, false).unwrap();
        }
        assert_eq!(r.open_count(), 50);
    }

    /// A `SETTINGS_MAX_CONCURRENT_STREAMS: 0` is legal and means "no streams".
    /// Treating it as unset inverts the peer's intent.
    #[test]
    fn a_zero_ceiling_refuses_every_new_stream() {
        let mut r = StreamRegistry::with_limit(Some(0));
        let e = r.admit(1, false).expect_err("the ceiling is zero");
        assert_eq!(e.code(), ErrorCode::RefusedStream);
    }

    /// The ceiling can be changed and enforcement follows the new value.
    #[test]
    fn the_ceiling_can_be_reduced_at_runtime() {
        let mut r = StreamRegistry::with_limit(Some(10));
        r.admit(1, false).unwrap();
        r.admit(3, false).unwrap();
        r.set_limit(Some(2));
        assert!(r.admit(5, false).is_err(), "the new ceiling applies at once");
        r.set_limit(None);
        assert!(r.admit(5, false).is_ok(), "clearing the ceiling reopens it");
    }

    /// A frame other than HEADERS cannot open a stream: §5.1's connection error.
    /// Admitting it would give an illegal id an entry and make a later HEADERS on
    /// the real stream look like a reuse.
    #[test]
    fn only_headers_opens_a_stream() {
        let mut r = StreamRegistry::new();
        let e = r
            .on_recv(1, FrameKind::Data, false)
            .expect_err("DATA cannot open a stream");
        assert!(e.is_fatal());
        assert_eq!(e.code(), ErrorCode::ProtocolError);
        assert!(
            !r.contains(sid(1)),
            "a refused frame must not register a stream"
        );

        // A HEADERS on the same id now works, because nothing was registered.
        assert!(r.on_recv(1, FrameKind::Headers, true).is_ok());
        assert_eq!(r.get(sid(1)).unwrap().state(), StreamState::HalfClosedRemote);
    }

    /// The registry's receive path applies the state machine for an existing
    /// stream, including the stream-vs-connection distinction.
    #[test]
    fn the_registry_applies_recv_transitions() {
        let mut r = StreamRegistry::new();
        r.on_recv(1, FrameKind::Headers, true).unwrap();
        // The stream is half-closed (remote); more DATA is a stream error.
        let e = r.on_recv(1, FrameKind::Data, false).expect_err("DATA after END");
        assert!(!e.is_fatal(), "STREAM_CLOSED is a stream error");
        assert_eq!(e.code(), ErrorCode::StreamClosed);
    }

    /// A reset on a stream that was never opened cannot be honoured — the id
    /// would be recorded as used, which is what §5.1.1's cursor forbids.
    #[test]
    fn resetting_an_unopened_stream_fails() {
        let mut r = StreamRegistry::new();
        assert!(r.on_reset(1).is_err());
        assert!(!r.contains(sid(1)));
    }

    /// A reset on an open stream closes it and records the id.
    #[test]
    fn resetting_an_open_stream_closes_it() {
        let mut r = StreamRegistry::new();
        r.on_recv(1, FrameKind::Headers, false).unwrap();
        r.on_reset(1).unwrap();
        assert_eq!(r.get(sid(1)).unwrap().state(), StreamState::Closed);
        assert!(r.on_reset(3).is_err(), "3 was never opened");
    }

    /// The send path refuses to act on a stream we never opened: sending on an
    /// unregistered stream is our bug, and the peer would report it as ours.
    #[test]
    fn sending_on_an_unregistered_stream_is_an_internal_error() {
        let mut r = StreamRegistry::new();
        let e = r
            .on_send(sid(1), FrameKind::Headers, true)
            .expect_err("stream 1 is not registered");
        assert_eq!(
            e.code(),
            ErrorCode::InternalError,
            "our bug, not the peer's — mislabelling it as PROTOCOL_ERROR sends the \
             peer looking for a defect that is not there"
        );
    }

    /// `close_all` finishes every stream, as a connection teardown does.
    #[test]
    fn close_all_finishes_every_stream() {
        let mut r = StreamRegistry::new();
        r.admit(1, false).unwrap();
        r.admit(3, false).unwrap();
        r.close_all();
        assert!(r.streams().iter().all(Stream::is_finished));
        assert_eq!(r.open_count(), 0);
        assert_eq!(
            r.last_client_id(),
            3,
            "the cursor must survive the teardown — a GOAWAY after it reports this"
        );
    }

    // -- Receive credit ----------------------------------------------------

    /// The receive counter accumulates and can be returned, and returning more
    /// than is owed is our bug rather than the peer's.
    #[test]
    fn receive_credit_accumulates_and_is_returned() {
        let mut s = Stream::new(sid(1), StreamState::Open);
        s.note_received(100).unwrap();
        s.note_received(50).unwrap();
        assert_eq!(s.recv_unacked(), 150);

        assert_eq!(s.take_replenishable(), 150);
        assert_eq!(s.recv_unacked(), 0);

        s.note_received(10).unwrap();
        let e = s.replenish(11).expect_err("only 10 is owed");
        assert_eq!(e.code(), ErrorCode::InternalError);
        s.replenish(10).unwrap();
        assert_eq!(s.recv_unacked(), 0);
    }

    /// The receive counter is bounded by the window, and overflowing it is a
    /// `FLOW_CONTROL_ERROR` rather than a silent wrap — a wrapping window counter
    /// is a window enlargement that produces no error at all.
    #[test]
    fn the_receive_counter_refuses_to_wrap() {
        let mut s = Stream::new(sid(1), StreamState::Open);
        s.note_received(u32::MAX).unwrap();
        let e = s.note_received(1).expect_err("the counter would wrap");
        assert_eq!(e.code(), ErrorCode::FlowControlError);
    }

    /// The send-side counters are diagnostic and saturate rather than failing a
    /// valid send.
    #[test]
    fn send_counters_are_diagnostic_and_saturating() {
        let mut s = Stream::new(sid(1), StreamState::Open);
        s.note_sent(100);
        s.note_sent(50);
        assert_eq!(s.send_unacked(), 150);
        s.note_acknowledged(60);
        assert_eq!(s.send_unacked(), 90);
        // Over-acknowledging must not wrap to a huge number.
        s.note_acknowledged(1000);
        assert_eq!(s.send_unacked(), 0);
    }

    /// `opening` picks the state a request starts in, which is the difference
    /// between a GET and a GET with a body.
    #[test]
    fn opening_picks_the_initial_state() {
        assert_eq!(
            Stream::opening(sid(1), true).state(),
            StreamState::HalfClosedRemote
        );
        assert_eq!(Stream::opening(sid(3), false).state(), StreamState::Open);
        assert!(!Stream::opening(sid(5), false).is_finished());
    }

    /// Every state and kind renders something an operator can read.
    #[test]
    fn states_and_kinds_render() {
        for state in [
            StreamState::Idle,
            StreamState::ReservedLocal,
            StreamState::ReservedRemote,
            StreamState::Open,
            StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote,
            StreamState::Closed,
        ] {
            assert!(!state.to_string().is_empty());
            assert!(!state.as_str().contains('\n'));
        }
        for kind in [
            FrameKind::Data,
            FrameKind::Headers,
            FrameKind::Priority,
            FrameKind::RstStream,
            FrameKind::Settings,
            FrameKind::PushPromise,
            FrameKind::Ping,
            FrameKind::GoAway,
            FrameKind::WindowUpdate,
            FrameKind::Continuation,
            FrameKind::Unknown,
        ] {
            assert!(!kind.to_string().is_empty());
        }
        assert!(!AdmissionError::NotMonotonic { got: 1, last: 3 }
            .to_string()
            .is_empty());
        assert!(!AdmissionError::TooManyStreams { limit: 1, open: 1 }
            .to_string()
            .is_empty());
    }
}
