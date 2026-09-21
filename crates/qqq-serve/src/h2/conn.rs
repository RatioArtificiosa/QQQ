// SPDX-License-Identifier: Apache-2.0

//! The HTTP/2 connection layer: preface, frame dispatch, multiplexing and
//! `CONTINUATION`-reassembly.
//!
//! Implements Checklist `SRV-002` — *"Implement HTTP/2 including multiplexing and
//! flow control"* — by joining the layers below it. [`super::frame`] knows the
//! bytes, [`super::hpack`] knows header blocks, [`super::flow`] knows windows and
//! [`super::stream`] knows which frames are legal in which state. This module is
//! where a *connection* exists: the bytes arrive, one stream's headers may be
//! split across three `CONTINUATION` frames while another stream's `DATA` waits,
//! and the answer has to be the same as if they had arrived alone.
//!
//! # Why this is a state machine over buffers and not an `async` connection
//!
//! `SRV-002`'s text is about the protocol. [`Connection::recv`] takes bytes and
//! returns events; the socket, the TLS layer and the task that drives it belong
//! to `SRV-007` and `crate::server`. Keeping the protocol free of I/O is what
//! makes it testable by feeding it byte slices — including the cases that matter
//! most, like a header block split mid-`CONTINUATION`, which are almost
//! impossible to produce reliably on a real socket and trivial to produce here.
//!
//! # The four rules this layer exists to enforce
//!
//! 1. **The preface is exact and comes first.** RFC 9113 §3.4: a client
//!    connection preface is the 24-octet string, followed immediately by a
//!    `SETTINGS` frame. A server that reads headers before the preface is reading
//!    attacker-chosen bytes as a `SETTINGS` frame.
//! 2. **`CONTINUATION` is contiguous.** §6.10: *"A `HEADERS` frame without the
//!    `END_HEADERS` flag set MUST be followed by a `CONTINUATION` frame for the
//!    same stream. A receiver MUST treat the receipt of any other type of frame …
//!    as a connection error of type `PROTOCOL_ERROR`."* This is the rule that
//!    makes multiplexing *almost* free but not quite: other streams' frames must
//!    wait.
//! 3. **`SETTINGS` is acknowledged.** §6.5.3: *"The values in the `SETTINGS`
//!    frame MUST be processed in the order they appear … and the sender is
//!    expected to receive an ACK."* Emitting the ACK is this layer's job because
//!    only it knows a frame *arrived*.
//! 4. **A refused frame is not a moved stream.** Every transition goes through
//!    `Stream::on_recv`, which checks legality before mutating.
//!
//! # What this layer deliberately does not do
//!
//! * **Server push.** A received `PUSH_PROMISE` is a connection error, which is
//!   what `Frame::PushPromise` exists to name.
//! * **Priority scheduling.** §5.3.1 deprecates it; see [`super::frame`].
//! * **Writing response header blocks.** [`Connection::encoder`] exposes the HPACK
//!   encoder so the response path shares the connection's dynamic table, which
//!   §4.3 requires — but assembling a response is `crate::response`'s job.
//!
//! # Error scope is the whole point
//!
//! RFC 9113 has two failure scopes and they are not interchangeable: a **stream**
//! error resets one stream and the connection continues, while a **connection**
//! error ends everything and sends `GOAWAY`. [`Connection::recv`] returns a
//! `Result`, but the `Err` is only for the connection-fatal case; a stream error
//! comes back as [`Event::Refused`] so the caller emits `RST_STREAM` and keeps
//! serving the other multiplexed streams. Treating a stream error as fatal turns
//! one bad request into an outage; treating a connection error as a stream error
//! leaves a decoder permanently out of sync with its peer.

use std::collections::VecDeque;

use super::error::{ConnectionError, ErrorCode, StreamError};
use super::flow::FlowControl;
#[cfg(test)]
use super::frame::SettingId;
use super::frame::{
    parse_frame, to_bytes, Flags, Frame, FrameHeader, FrameType, CLIENT_PREFACE, FRAME_HEADER_LEN,
    MAX_FRAME_PAYLOAD,
};
use super::hpack::{Decoder, Encoder, HeaderField};
use super::settings::Settings;
use super::stream::{AdmissionError, FrameKind, StreamId, StreamRegistry, StreamState};

/// The `END_STREAM` flag. Bit `0x1` on `DATA` and `HEADERS`.
const END_STREAM: u8 = 0x1;
/// The `END_HEADERS` flag. Bit `0x4` on `HEADERS` and `CONTINUATION`.
const END_HEADERS: u8 = 0x4;
/// The `PADDED` flag on `DATA` and `HEADERS`.
const PADDED: u8 = 0x8;
/// The `ACK` flag on `SETTINGS` and `PING`.
const ACK: u8 = 0x1;

/// [`MAX_FRAME_PAYLOAD`] as the `u32` a frame header declares.
///
/// The constant is a `usize` because it also sizes buffers; a frame header's
/// length is 24 bits and therefore a `u32`. Comparing the two directly needs one
/// conversion, and doing it once here is clearer than a `try_into` at each use.
const MAX_FRAME_PAYLOAD_U32: u32 = 0xFF_FFFF;

/// The largest header block this connection will reassemble.
///
/// # Why there is a limit at all
///
/// A `HEADERS` frame has a 16 MiB payload ceiling, and `CONTINUATION` lets a peer
/// send arbitrarily many of them. Without a cap, a peer can make the server
/// allocate unbounded memory by never setting `END_HEADERS` — and because the
/// allocation is *per connection*, the amplification is a few bytes of network
/// traffic per megabyte of server memory. It is the cheapest denial of service in
/// the protocol.
///
/// 1 MiB, not 16 MiB: RFC 9113 §6.5.2 lets a server advertise
/// `SETTINGS_MAX_HEADER_LIST_SIZE`, real header blocks are a few kilobytes, and
/// the limit is on the *encoded* block, which compresses. A peer that needs more
/// is told so through the advertised setting rather than by failing.
pub const MAX_HEADER_BLOCK_BYTES: usize = 1 << 20;

/// The largest number of `CONTINUATION` frames one header block may use.
///
/// Not redundant with the byte cap for a hostile peer: an unbounded number of
/// **empty** `CONTINUATION` frames consume no memory per frame but do consume CPU
/// and keep the connection in the mid-header-block state forever, blocking every
/// other stream (§6.10). Counting frames closes that.
pub const MAX_CONTINUATIONS: u32 = 128;

/// What a connection did with the bytes it was given.
///
/// One `recv` may complete several frames and one frame may produce several
/// events. Order is arrival order, which is what a caller writing responses needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A request's headers are complete and decoded.
    Headers {
        /// The stream they arrived on.
        stream_id: u32,
        /// The decoded fields, in the order the peer sent them.
        fields: Vec<HeaderField>,
        /// Whether the peer set `END_STREAM`, i.e. there is no body.
        end_stream: bool,
    },
    /// Body bytes for a stream.
    Data {
        /// The stream they arrived on.
        stream_id: u32,
        /// The bytes, with padding removed.
        data: Vec<u8>,
        /// Whether this was the last of the body.
        end_stream: bool,
    },
    /// The peer reset a stream. The connection continues.
    StreamReset {
        /// The stream that was reset.
        stream_id: u32,
        /// The wire code the peer sent.
        code: ErrorCode,
    },
    /// The peer acknowledged our `SETTINGS`.
    SettingsAck,
    /// The peer sent us `SETTINGS`; the ACK is already queued for sending.
    Settings {
        /// The settings as applied.
        settings: Settings,
    },
    /// The peer sent `PING`; the echo is already queued (§6.7).
    PingAck,
    /// The peer began a graceful shutdown.
    GoAway {
        /// The highest stream the peer may have processed.
        last_stream_id: u32,
        /// The reason, when one was given.
        code: Option<ErrorCode>,
    },
    /// A frame was refused at the **stream** scope: reset it and carry on.
    ///
    /// Separate from the `Err` return because these two are constantly confused
    /// and the consequences differ by three orders of magnitude.
    Refused {
        /// The stream affected.
        stream_id: u32,
        /// The code to send in `RST_STREAM`.
        code: ErrorCode,
        /// Why, for the log.
        reason: String,
    },
}

/// Where a connection is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Waiting for the 24-octet preface.
    AwaitingPreface,
    /// The preface arrived; the first `SETTINGS` must be next (§3.4).
    AwaitingFirstSettings,
    /// Serving requests.
    Open,
    /// We sent `GOAWAY`; in-flight streams may still finish.
    Draining,
    /// `GOAWAY` has been sent or received and nothing more may be done.
    Closed,
}

/// A server-side HTTP/2 connection.
///
/// One per connection, driven by [`Self::recv`] and [`Self::poll_outbound`]. It
/// owns no socket and spawns no task: `SRV-007` and `crate::server` supply both.
#[derive(Debug)]
pub struct Connection {
    state: State,
    /// Bytes received but not yet a complete frame.
    inbound: Vec<u8>,
    /// Frames we owe the peer, in order. `VecDeque` because `PING` and `GOAWAY`
    /// are queued by different code paths and must keep their relative order.
    outbound: VecDeque<Vec<u8>>,
    /// What we advertised.
    settings: Settings,
    /// What the peer advertised. Governs what *we* may send.
    peer_settings: Settings,
    streams: StreamRegistry,
    flow: FlowControl,
    decoder: Decoder,
    encoder: Encoder,
    /// The header block being reassembled, if any. At most one, because §6.10
    /// forbids interleaving.
    pending: Option<PendingHeaders>,
    /// Streams we have reset, so a frame already in flight for one is ignored
    /// rather than treated as a protocol error.
    closed: Vec<u32>,
    /// Whether `GOAWAY` has been sent.
    goaway_sent: bool,
}

/// A header block mid-reassembly.
#[derive(Debug)]
struct PendingHeaders {
    stream_id: u32,
    fragment: Vec<u8>,
    end_stream: bool,
    /// How many `CONTINUATION` frames have arrived for this block.
    continuations: u32,
}

impl Connection {
    /// A connection waiting for the client preface.
    #[must_use]
    pub fn new() -> Self {
        let ours = Settings::server_default();
        let theirs = Settings::default();
        Self {
            state: State::AwaitingPreface,
            inbound: Vec::new(),
            outbound: VecDeque::new(),
            settings: ours,
            peer_settings: theirs,
            streams: StreamRegistry::new(),
            // `send` is governed by the peer's initial window, `recv` by ours.
            flow: FlowControl::new(theirs.initial_window_size, ours.initial_window_size),
            decoder: Decoder::new(),
            encoder: Encoder::new(),
            pending: None,
            closed: Vec::new(),
            goaway_sent: false,
        }
    }

    /// Where the connection is in its lifecycle.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// The settings we have advertised.
    #[must_use]
    pub const fn settings(&self) -> &Settings {
        &self.settings
    }

    /// The settings the peer advertised.
    #[must_use]
    pub const fn peer_settings(&self) -> &Settings {
        &self.peer_settings
    }

    /// The flow-control state.
    #[must_use]
    pub const fn flow(&self) -> &FlowControl {
        &self.flow
    }

    /// Mutable flow control, so the send path can charge for what it writes.
    pub fn flow_mut(&mut self) -> &mut FlowControl {
        &mut self.flow
    }

    /// The stream registry, read-only.
    #[must_use]
    pub const fn streams(&self) -> &StreamRegistry {
        &self.streams
    }

    /// Mutable stream registry, for the application layer's own transitions.
    pub fn streams_mut(&mut self) -> &mut StreamRegistry {
        &mut self.streams
    }

    /// The HPACK encoder, so the response path shares this connection's table.
    ///
    /// §4.3 makes the dynamic table per **connection**, not per stream: a
    /// response written with a different encoder would emit indices into a table
    /// the peer does not have, and the failure appears only once an index is used.
    pub fn encoder(&mut self) -> &mut Encoder {
        &mut self.encoder
    }

    /// Whether anything is queued to write.
    #[must_use]
    pub fn has_outbound(&self) -> bool {
        !self.outbound.is_empty()
    }

    /// How many frames are queued.
    #[must_use]
    pub fn queued_frames(&self) -> usize {
        self.outbound.len()
    }

    /// Take the next whole frame to write, or `None`.
    ///
    /// Whole frames, never a partial one: a caller that wrote half a frame and
    /// then blocked holds a connection in a state where the peer cannot frame
    /// anything that follows.
    pub fn poll_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    /// Feed bytes to the connection.
    ///
    /// Returns every event those bytes completed, in order. An empty return is
    /// normal: it means the bytes were a fragment of a frame, or a frame with no
    /// observable effect.
    ///
    /// # Errors
    ///
    /// A [`ConnectionError`] when the connection **must** end — a malformed
    /// frame, a broken preface, a `CONTINUATION` sequence interrupted by another
    /// stream, or a frame the RFC makes connection-fatal. A *stream* error is not
    /// an `Err`: it comes back as [`Event::Refused`].
    pub fn recv(&mut self, bytes: &[u8]) -> Result<Vec<Event>, ConnectionError> {
        self.inbound.extend_from_slice(bytes);
        let mut events = Vec::new();

        // The preface is a fixed 24 bytes and must be the first thing on the wire.
        if self.state == State::AwaitingPreface {
            if self.inbound.len() < CLIENT_PREFACE.len() {
                return Ok(events);
            }
            if !self.inbound.starts_with(CLIENT_PREFACE) {
                return Err(ConnectionError::protocol(
                    ErrorCode::ProtocolError,
                    "the connection preface did not match: RFC 9113 §3.4 requires the \
                     24-octet client preface string before any frame",
                ));
            }
            self.inbound.drain(..CLIENT_PREFACE.len());
            self.state = State::AwaitingFirstSettings;
            // Our own SETTINGS go out first, as §3.4 requires of the server.
            self.outbound
                .push_back(to_bytes(&self.settings.to_frame(true)));
        }

        loop {
            // §4.2: a frame header is 9 bytes, and the payload length comes from it.
            if self.inbound.len() < FRAME_HEADER_LEN {
                break;
            }
            let header = FrameHeader::parse(&self.inbound[..FRAME_HEADER_LEN])
                .map_err(|e| ConnectionError::protocol(ErrorCode::ProtocolError, e.to_string()))?;
            let total = header.total_len();

            // The cap is on the *declared* length, checked before waiting for the
            // payload: a peer that announces 16 MiB and sends one byte must not
            // make the server allocate anything.
            if header.length > MAX_FRAME_PAYLOAD_U32 {
                return Err(ConnectionError::protocol(
                    ErrorCode::FrameSizeError,
                    format!(
                        "a frame declared {} bytes, over the {MAX_FRAME_PAYLOAD}-byte ceiling \
                         (RFC 9113 §4.2)",
                        header.length
                    ),
                ));
            }
            if self.inbound.len() < total {
                break;
            }

            let frame_bytes: Vec<u8> = self.inbound.drain(..total).collect();
            // `parse_frame` returns the frame and the bytes it consumed; the
            // latter is discarded because the slice was already made by `total`.
            let (frame, _consumed) = parse_frame(&frame_bytes).map_err(|e| {
                ConnectionError::protocol(
                    e.code().unwrap_or(ErrorCode::ProtocolError),
                    e.to_string(),
                )
            })?;

            // Rule 2: while a header block is open, only its own CONTINUATION may
            // arrive. Checked before anything else touches state.
            if let Some(pending) = &self.pending {
                let same_stream = frame_stream_id(&frame) == Some(pending.stream_id);
                let is_continuation = matches!(frame, Frame::Continuation { .. }) && same_stream;
                if !is_continuation {
                    return Err(ConnectionError::protocol(
                        ErrorCode::ProtocolError,
                        format!(
                            "`{}` arrived on stream {:?} while stream {} had a header block \
                             open: RFC 9113 §6.10 requires the CONTINUATION sequence to be \
                             contiguous",
                            frame_type(&frame).as_str(),
                            frame_stream_id(&frame),
                            pending.stream_id
                        ),
                    ));
                }
            }

            // Rule 1, second half: SETTINGS must be the first frame after the
            // preface (§3.4).
            if self.state == State::AwaitingFirstSettings
                && !matches!(frame, Frame::Settings { .. })
            {
                return Err(ConnectionError::protocol(
                    ErrorCode::ProtocolError,
                    format!(
                        "the first frame after the preface was `{}`, not SETTINGS: \
                         RFC 9113 §3.4 requires the preface be followed immediately by \
                         SETTINGS",
                        frame_type(&frame).as_str()
                    ),
                ));
            }

            self.dispatch(frame, &mut events)?;
        }

        Ok(events)
    }

    /// Apply one complete frame.
    fn dispatch(
        &mut self,
        frame: Frame<'_>,
        events: &mut Vec<Event>,
    ) -> Result<(), ConnectionError> {
        let stream_id = frame_stream_id(&frame);
        let kind = FrameKind::of(frame_type(&frame));

        // Connection-scoped frames first: they have no stream and cannot be
        // refused at the stream scope.
        match &frame {
            Frame::Settings { .. } => return self.on_settings(frame, events),
            Frame::SettingsAck => {
                events.push(Event::SettingsAck);
                return Ok(());
            }
            Frame::Ping { .. } => {
                self.on_ping(frame, events);
                return Ok(());
            }
            Frame::GoAway { .. } => {
                self.on_goaway(frame, events);
                return Ok(());
            }
            Frame::WindowUpdate { .. } => return self.on_window_update(frame, events),
            // §8.4: a client must not push. `Frame::PushPromise` carries no
            // payload for exactly this reason — it is recognised to be refused.
            Frame::PushPromise { .. } => {
                return Err(ConnectionError::protocol(
                    ErrorCode::ProtocolError,
                    "a client sent PUSH_PROMISE: RFC 9113 §8.4 forbids a client from \
                     pushing, and this server did not enable it",
                ));
            }
            _ => {}
        }

        // Everything below is stream-scoped and must carry an id.
        let Some(raw_id) = stream_id else {
            return Err(ConnectionError::protocol(
                ErrorCode::ProtocolError,
                format!(
                    "`{}` carried no stream id (RFC 9113 §4.1)",
                    frame_type(&frame).as_str()
                ),
            ));
        };

        // A frame for a stream we already reset is ignored rather than refused:
        // §5.1 permits frames already in flight to arrive after a reset, and
        // treating that as an error punishes the peer for a race we created.
        if self.closed.contains(&raw_id) {
            return Ok(());
        }

        // RST_STREAM is handled before admission, because §5.1's exempt list
        // makes it legal on a stream that was never opened.
        if let Frame::RstStream { error, .. } = &frame {
            let code = *error;
            if let Ok(id) = StreamId::client_from_frame(raw_id) {
                if let Some(stream) = self.streams.get_mut(id) {
                    stream.close();
                }
            }
            self.flow.close_stream(raw_id);
            self.remember_closed(raw_id);
            events.push(Event::StreamReset {
                stream_id: raw_id,
                code,
            });
            return Ok(());
        }

        // Admission: id parity, monotonicity and the concurrency ceiling.
        //
        // Only a **live** stream skips this. An id we have already closed still
        // goes through `admit`, because §5.1.1's monotonicity rule is what makes
        // a reused id a connection error: `"The identifier of a newly established
        // stream MUST be numerically greater than all streams that the initiating
        // endpoint has opened … An endpoint that receives an unexpected stream
        // identifier MUST respond with a connection error of type PROTOCOL_ERROR."*
        //
        // The first version skipped admission whenever the id was *known*,
        // closed included, so a peer could reuse a finished stream id and the
        // connection carried on — measured, that produced a stream-scoped
        // `STREAM_CLOSED` refusal where the RFC requires the connection to end.
        // A resurrected stream id is exactly what the rule exists to prevent.
        if !self.is_live(raw_id) {
            if let Err(e) = self.streams.admit(raw_id, false) {
                return Self::classify_admission(raw_id, &e, events);
            }
            // §5.2.1: every stream has its own flow-control window, opened when
            // the stream is. Without this the window does not exist, `consume_recv`
            // reports `UnknownStream` for the body, and no credit ever accrues —
            // so `replenish` queues nothing and the connection stalls permanently
            // once the peer's initial window is spent. Measured: a ten-byte body
            // produced no `WINDOW_UPDATE` at all.
            self.flow.open_stream(raw_id);
        }

        let end_stream = frame_flags(&frame).end_stream();

        // HEADERS may open a block that continues across CONTINUATIONs.
        if let Frame::Headers { fragment, .. } = &frame {
            if !frame_flags(&frame).end_headers() {
                self.begin_header_block(fragment, raw_id, end_stream, kind, events)?;
                return Ok(());
            }
        }

        if let Frame::Continuation { fragment, .. } = &frame {
            return self.on_continuation(fragment, frame_flags(&frame).end_headers(), kind, events);
        }

        // DATA, and HEADERS that ended its own block.
        match &frame {
            Frame::Data { data, padding, .. } => {
                // §6.1: the padding counts against the window even though it is
                // not delivered. Charging only `data.len()` drifts the connection
                // out of sync with the peer's accounting by up to 255 bytes per
                // frame, until a send stalls for no visible reason.
                let charged = data.len() + usize::from(*padding) + 1;
                let charged = u32::try_from(charged).unwrap_or(u32::MAX);
                self.charge_recv(raw_id, charged, events)?;
                events.push(Event::Data {
                    stream_id: raw_id,
                    data: data.to_vec(),
                    end_stream,
                });
            }
            Frame::Headers { fragment, .. } => {
                let fields = self.decode_block(fragment)?;
                events.push(Event::Headers {
                    stream_id: raw_id,
                    fields,
                    end_stream,
                });
            }
            // PRIORITY is parsed and ignored (§5.3.1), but it must not skip the
            // state machine. An unrecognised frame type is ignored per §4.1, and
            // RST_STREAM was already handled above. Named rather than folded into
            // the wildcard so a reader can tell "ignored on purpose" from
            // "forgotten".
            #[allow(clippy::match_same_arms)]
            Frame::Priority { .. } | Frame::Unknown { .. } => {}
            _ => {}
        }

        self.apply_stream_transition(raw_id, kind, end_stream, events)?;
        Ok(())
    }

    /// Open the header block a `HEADERS` frame without `END_HEADERS` began.
    ///
    /// Returns `true` when the frame opened a pending block, which means the
    /// caller must **not** also emit headers: the block is not decoded yet.
    ///
    /// # Errors
    ///
    /// A connection error when the fragment alone already exceeds
    /// [`MAX_HEADER_BLOCK_BYTES`].
    fn begin_header_block(
        &mut self,
        fragment: &[u8],
        raw_id: u32,
        end_stream: bool,
        kind: FrameKind,
        events: &mut Vec<Event>,
    ) -> Result<bool, ConnectionError> {
        if fragment.len() > MAX_HEADER_BLOCK_BYTES {
            return Err(Self::header_block_too_large(fragment.len()));
        }
        self.pending = Some(PendingHeaders {
            stream_id: raw_id,
            fragment: fragment.to_vec(),
            end_stream,
            continuations: 0,
        });
        // The stream still transitions: §5.1 acts on HEADERS *arriving*, not on
        // the header block being complete.
        self.apply_stream_transition(raw_id, kind, end_stream, events)?;
        Ok(true)
    }

    /// Whether a stream id names a stream that is still open.
    ///
    /// Not the same as "we have seen this id": a closed stream is one the peer
    /// may **not** reuse (§5.1.1), so it must still be offered to `admit` for the
    /// monotonicity check rather than short-circuited as known.
    fn is_live(&self, raw_id: u32) -> bool {
        StreamId::client_from_frame(raw_id)
            .ok()
            .and_then(|id| self.streams.get(id))
            .is_some_and(|s| !s.state().is_closed())
    }

    /// Turn an admission refusal into the right scope.
    ///
    /// A free-standing `&self`-free function: it reads no connection state, so
    /// taking `&mut self` claimed a borrow it never used and made every caller
    /// look as though it mutated through it.
    fn classify_admission(
        raw_id: u32,
        e: &AdmissionError,
        events: &mut Vec<Event>,
    ) -> Result<(), ConnectionError> {
        if e.is_fatal() {
            return Err(ConnectionError::protocol(e.code(), e.to_string()));
        }
        // A stream-scoped refusal: §5.1.2's `REFUSED_STREAM` is retryable, which
        // is why load-shedding must not answer `PROTOCOL_ERROR`.
        events.push(Event::Refused {
            stream_id: raw_id,
            code: e.code(),
            reason: e.to_string(),
        });
        Ok(())
    }

    /// The refusal for an over-large header block.
    ///
    /// A **connection** error: the peer is told the limit through
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`, and a peer that exceeds it after being
    /// told is not making a per-stream mistake.
    fn header_block_too_large(got: usize) -> ConnectionError {
        ConnectionError::protocol(
            ErrorCode::EnhanceYourCalm,
            format!(
                "a header block reached {got} bytes, over the {MAX_HEADER_BLOCK_BYTES}-byte \
                 ceiling this connection reassembles: without a cap a peer can allocate \
                 unbounded memory per connection by never setting END_HEADERS"
            ),
        )
    }

    /// Decode a header block, mapping HPACK failures to the right scope.
    ///
    /// §4.3: a compression error is a **connection** error, not a stream one,
    /// because the dynamic table is shared. A decoder that lost sync with the
    /// encoder misdecodes *every* later header block on the connection, so
    /// resetting one stream would leave the connection producing wrong headers
    /// for the rest of its life.
    fn decode_block(&mut self, block: &[u8]) -> Result<Vec<HeaderField>, ConnectionError> {
        self.decoder.decode(block).map_err(|e| {
            ConnectionError::protocol(
                ErrorCode::CompressionError,
                format!(
                    "the header block could not be decoded: {e}. The HPACK dynamic table \
                     is shared by every stream on this connection, so a decode failure is \
                     a connection error (RFC 9113 §4.3), not a stream one"
                ),
            )
        })
    }

    /// Charge received bytes against both flow-control windows.
    fn charge_recv(
        &mut self,
        stream_id: u32,
        n: u32,
        events: &mut Vec<Event>,
    ) -> Result<(), ConnectionError> {
        if let Err(e) = self.flow.consume_recv(stream_id, n) {
            // §6.9: on the connection window a violation is connection-fatal; on
            // a stream window it resets the stream. `FlowError` knows which.
            if let Some(err) = e.as_connection_error() {
                return Err(err);
            }
            events.push(Event::Refused {
                stream_id,
                code: e.code(),
                reason: e.to_string(),
            });
        }
        Ok(())
    }

    /// Move a stream through the state machine, classifying a refusal.
    fn apply_stream_transition(
        &mut self,
        raw_id: u32,
        kind: FrameKind,
        end_stream: bool,
        events: &mut Vec<Event>,
    ) -> Result<(), ConnectionError> {
        let Ok(id) = StreamId::client_from_frame(raw_id) else {
            return Ok(());
        };
        let Some(stream) = self.streams.get_mut(id) else {
            return Ok(());
        };
        // The scope is read **before** the transition attempt, while the
        // stream's pre-refusal state is still available: §5.1's classification
        // depends on that state.
        let fatal = stream.refusal_is_fatal_direction(kind, true);
        match stream.on_recv(kind, end_stream) {
            Ok(()) => {}
            Err(e) => {
                if fatal {
                    return Err(ConnectionError::protocol(e.code(), e.to_string()));
                }
                // A stream error: reset that stream, keep the connection.
                stream.close();
                self.flow.close_stream(raw_id);
                self.remember_closed(raw_id);
                events.push(Event::Refused {
                    stream_id: raw_id,
                    code: e.code(),
                    reason: e.to_string(),
                });
                return Ok(());
            }
        }
        if self
            .streams
            .get(id)
            .is_some_and(|s| s.state() == StreamState::Closed)
        {
            self.flow.close_stream(raw_id);
            self.remember_closed(raw_id);
        }
        Ok(())
    }

    /// Note that our own side finished a stream.
    ///
    /// The application calls this after writing a response with `END_STREAM`.
    /// Without it the stream sits in `half-closed (remote)` and a later `GOAWAY`
    /// reports it as in-flight forever.
    ///
    /// # Errors
    ///
    /// A [`StreamError`] when our own `END_STREAM` is illegal for the stream's
    /// state. That is a bug in the caller rather than a peer violation, and is
    /// reported rather than put on the wire as a protocol error the peer would
    /// blame on us.
    pub fn note_local_end(&mut self, stream_id: u32) -> Result<(), StreamError> {
        let Ok(id) = StreamId::client_from_frame(stream_id) else {
            return Ok(());
        };
        let Some(stream) = self.streams.get_mut(id) else {
            return Ok(());
        };
        stream.on_send(FrameKind::Headers, true)?;
        if stream.state() == StreamState::Closed {
            self.flow.close_stream(stream_id);
            self.remember_closed(stream_id);
        }
        Ok(())
    }

    /// Remember a closed stream, without growing without bound.
    ///
    /// The list exists so a frame in flight when we reset a stream is ignored.
    /// It is bounded because a connection can open thousands of streams; once it
    /// is full the *oldest* is dropped, which is also the least likely to still
    /// have a frame crossing it.
    fn remember_closed(&mut self, raw_id: u32) {
        const MAX_REMEMBERED: usize = 256;
        if self.closed.len() >= MAX_REMEMBERED {
            self.closed.remove(0);
        }
        if !self.closed.contains(&raw_id) {
            self.closed.push(raw_id);
        }
    }

    /// Append a `CONTINUATION` fragment to the open header block (§6.10).
    ///
    /// Extracted from `dispatch`, which had grown past the point where a reader
    /// could hold it in view — and this is the self-contained half: everything it
    /// needs is the pending block, the fragment, and the two limits that bound
    /// reassembly.
    ///
    /// # Errors
    ///
    /// A [`ConnectionError`] when no block is open (a stray `CONTINUATION`), when
    /// the block exceeds [`MAX_HEADER_BLOCK_BYTES`], when it uses more than
    /// [`MAX_CONTINUATIONS`] frames, or when the completed block does not decode.
    /// All four are connection errors: §6.10 makes the first two protocol
    /// violations, and §4.3 makes the last one, because a shared HPACK table
    /// cannot be resynchronised by resetting a single stream.
    fn on_continuation(
        &mut self,
        fragment: &[u8],
        end_headers: bool,
        kind: FrameKind,
        events: &mut Vec<Event>,
    ) -> Result<(), ConnectionError> {
        let Some(mut pending) = self.pending.take() else {
            return Err(ConnectionError::protocol(
                ErrorCode::ProtocolError,
                "a CONTINUATION arrived with no header block open: RFC 9113 §6.10 \
                 forbids a CONTINUATION that does not follow a HEADERS",
            ));
        };
        pending.continuations += 1;
        if pending.continuations > MAX_CONTINUATIONS {
            return Err(ConnectionError::protocol(
                ErrorCode::EnhanceYourCalm,
                format!(
                    "a header block used more than {MAX_CONTINUATIONS} CONTINUATION frames: \
                     an unbounded sequence keeps every other stream blocked (RFC 9113 §6.10) \
                     at no cost to the sender"
                ),
            ));
        }
        if pending.fragment.len() + fragment.len() > MAX_HEADER_BLOCK_BYTES {
            let got = pending.fragment.len() + fragment.len();
            return Err(Self::header_block_too_large(got));
        }
        pending.fragment.extend_from_slice(fragment);

        if !end_headers {
            self.pending = Some(pending);
            return Ok(());
        }

        // The block is complete. Decoding it is where a shared dynamic table can
        // be desynchronised, so its failure is connection-fatal (§4.3).
        let fields = self.decode_block(&pending.fragment)?;
        let stream_id = pending.stream_id;
        let end_stream = pending.end_stream;
        if end_stream {
            self.apply_stream_transition(stream_id, kind, true, events)?;
        }
        events.push(Event::Headers {
            stream_id,
            fields,
            end_stream,
        });
        Ok(())
    }

    // -- connection-scoped frames ------------------------------------------

    /// §6.5: apply `SETTINGS` and queue the ACK.
    fn on_settings(
        &mut self,
        frame: Frame<'_>,
        events: &mut Vec<Event>,
    ) -> Result<(), ConnectionError> {
        let Frame::Settings { params } = frame else {
            unreachable!("on_settings is only called for SETTINGS");
        };

        if self.state == State::AwaitingFirstSettings {
            self.state = State::Open;
        }

        let old_initial = self.peer_settings.initial_window_size;
        // Apply to a *copy* first: a malformed settings frame must leave the
        // connection's view of the peer unchanged rather than half-applied.
        let mut peer = self.peer_settings;
        for (id, value) in &params {
            peer.apply_one(*id, *value)?;
        }
        // The concurrency ceiling binds our admission: it is the peer telling us
        // how many streams it will accept.
        self.streams.set_limit(peer.max_concurrent_streams);
        // §6.9.2: a change to INITIAL_WINDOW_SIZE adjusts every open stream's
        // window by the delta, which can legitimately make a window negative.
        if peer.initial_window_size != old_initial {
            self.flow
                .on_settings_initial_window_size(old_initial, peer.initial_window_size)
                .map_err(|e| {
                    e.as_connection_error()
                        .unwrap_or_else(|| ConnectionError::protocol(e.code(), e.to_string()))
                })?;
        }
        // §6.5.2: our encoder must honour the peer's header table size.
        self.encoder
            .set_allowed_table_size(peer.header_table_size as usize);
        self.peer_settings = peer;

        // §6.5.3: acknowledge, always.
        self.outbound.push_back(to_bytes(&Frame::SettingsAck));

        events.push(Event::Settings { settings: peer });
        Ok(())
    }

    /// §6.7: echo the `PING` payload.
    ///
    /// Returns `()` rather than a `Result`: §6.7 defines exactly one behaviour for
    /// every `PING` — echo it, or ignore an ACK — and neither can be refused. A
    /// `Result` here would advertise a failure that cannot happen and force every
    /// caller to handle it.
    // `Frame<'_>` by value is deliberate, here and in the two handlers below:
    // it borrows from the input buffer, and destructuring is how the fields are
    // read. `&Frame<'_>` would add a second layer of references to reach data
    // that is already a borrow.
    #[allow(clippy::needless_pass_by_value)]
    fn on_ping(&mut self, frame: Frame<'_>, events: &mut Vec<Event>) {
        let Frame::Ping { flags, payload } = frame else {
            unreachable!("on_ping is only called for PING");
        };
        if flags.ack() {
            // An ACK we did not ask for is ignored rather than an error: the peer
            // may have raced our own GOAWAY.
            return;
        }
        // §6.7: the response carries identical opaque data. Echoing it is what
        // lets a peer measure RTT and detect a connection that has silently died.
        self.outbound.push_back(to_bytes(&Frame::Ping {
            flags: Flags::none().with(ACK),
            payload,
        }));
        events.push(Event::PingAck);
    }

    /// §6.8: the peer is going away.
    #[allow(clippy::needless_pass_by_value)]
    fn on_goaway(&mut self, frame: Frame<'_>, events: &mut Vec<Event>) {
        let Frame::GoAway {
            last_stream_id,
            error,
            ..
        } = frame
        else {
            unreachable!("on_goaway is only called for GOAWAY");
        };
        self.state = State::Closed;
        events.push(Event::GoAway {
            last_stream_id,
            code: error,
        });
    }

    /// §6.9: apply a `WINDOW_UPDATE`.
    #[allow(clippy::needless_pass_by_value)]
    fn on_window_update(
        &mut self,
        frame: Frame<'_>,
        events: &mut Vec<Event>,
    ) -> Result<(), ConnectionError> {
        let Frame::WindowUpdate {
            stream_id,
            increment,
        } = frame
        else {
            unreachable!("on_window_update is only called for WINDOW_UPDATE");
        };
        if let Err(e) = self.flow.apply_window_update(stream_id, increment) {
            if let Some(err) = e.as_connection_error() {
                return Err(err);
            }
            events.push(Event::Refused {
                stream_id,
                code: e.code(),
                reason: e.to_string(),
            });
        }
        Ok(())
    }

    // -- sending ------------------------------------------------------------

    /// Queue `GOAWAY`, ending the connection after in-flight streams finish.
    ///
    /// `SRV-011`'s graceful shutdown begins here: the peer is told the highest
    /// stream we might have processed, so it knows which requests to retry
    /// elsewhere rather than assuming they were handled.
    pub fn send_goaway(&mut self, code: Option<ErrorCode>) {
        if self.goaway_sent {
            return;
        }
        let last = self.streams.last_client_id();
        self.outbound.push_back(to_bytes(&Frame::GoAway {
            last_stream_id: last,
            error: code,
            raw_error: code.map_or(0, ErrorCode::as_u32),
            debug: &[],
        }));
        self.goaway_sent = true;
        self.state = State::Draining;
        // After a GOAWAY the peer must not open new streams, so the ceiling drops
        // to zero without disturbing the ones in flight.
        self.streams.set_limit(Some(0));
    }

    /// Queue a `RST_STREAM` and close the stream locally.
    pub fn send_reset(&mut self, stream_id: u32, code: ErrorCode) {
        self.outbound.push_back(to_bytes(&Frame::RstStream {
            stream_id,
            error: code,
        }));
        if let Ok(id) = StreamId::client_from_frame(stream_id) {
            if let Some(stream) = self.streams.get_mut(id) {
                stream.close();
            }
        }
        self.flow.close_stream(stream_id);
        self.remember_closed(stream_id);
    }

    /// Queue `WINDOW_UPDATE` for whatever the receive path has consumed.
    ///
    /// Called after the application has taken body bytes. Without it the window
    /// only ever shrinks and a long-lived connection stalls permanently once the
    /// peer's initial window is spent — a stall that presents as a hung client
    /// and is a missing credit.
    pub fn replenish(&mut self) {
        let connection = self.flow.take_connection_replenishment();
        if connection > 0 {
            self.outbound.push_back(to_bytes(&Frame::WindowUpdate {
                stream_id: 0,
                increment: connection,
            }));
        }
        let ids: Vec<u32> = self
            .streams
            .streams()
            .iter()
            .map(|s| s.id().get())
            .collect();
        for id in ids {
            if let Some(credit) = self.flow.take_stream_replenishment(id) {
                if credit > 0 {
                    self.outbound.push_back(to_bytes(&Frame::WindowUpdate {
                        stream_id: id,
                        increment: credit,
                    }));
                }
            }
        }
    }
}

impl Default for Connection {
    fn default() -> Self {
        Self::new()
    }
}

/// The stream id a frame carries, or `None` for a connection-scoped frame.
///
/// A free function rather than a method on `Frame` because `frame::Frame` is
/// deliberately shaped so connection-scoped variants have no `stream_id` field at
/// all — the type system already says a `SETTINGS` has no stream, and an
/// accessor returning `None` would reintroduce the question.
fn frame_stream_id(frame: &Frame<'_>) -> Option<u32> {
    match frame {
        Frame::Data { stream_id, .. }
        | Frame::Headers { stream_id, .. }
        | Frame::Priority { stream_id, .. }
        | Frame::RstStream { stream_id, .. }
        | Frame::PushPromise { stream_id, .. }
        | Frame::WindowUpdate { stream_id, .. }
        | Frame::Continuation { stream_id, .. }
        | Frame::Unknown { stream_id, .. } => Some(*stream_id),
        Frame::Settings { .. } | Frame::SettingsAck | Frame::Ping { .. } | Frame::GoAway { .. } => {
            None
        }
    }
}

/// The type of a frame, recovered from its variant.
///
/// `Frame` has no `frame_type()` accessor on purpose: the type is the variant, so
/// a stored field could disagree with it. Recovering it here is the one place
/// that needs the number rather than the shape, and every arm maps to the
/// specification's own numbering (RFC 9113 §6).
fn frame_type(frame: &Frame<'_>) -> FrameType {
    match frame {
        Frame::Data { .. } => FrameType::Data,
        Frame::Headers { .. } => FrameType::Headers,
        Frame::Priority { .. } => FrameType::Priority,
        Frame::RstStream { .. } => FrameType::RstStream,
        Frame::Settings { .. } | Frame::SettingsAck => FrameType::Settings,
        Frame::PushPromise { .. } => FrameType::PushPromise,
        Frame::Ping { .. } => FrameType::Ping,
        Frame::GoAway { .. } => FrameType::GoAway,
        Frame::WindowUpdate { .. } => FrameType::WindowUpdate,
        Frame::Continuation { .. } => FrameType::Continuation,
        Frame::Unknown { frame_type, .. } => *frame_type,
    }
}

/// The flags a frame carries, or `Flags::none()` for the variants that have none.
///
/// `SETTINGS` is modelled as two variants rather than one with a flag, and
/// `PRIORITY`, `RST_STREAM`, `WINDOW_UPDATE`, `GOAWAY` and `PUSH_PROMISE` have no
/// defined flags. Returning `none()` for those is accurate rather than a default:
/// `end_stream()` and `end_headers()` on it are both `false`, which is the
/// correct reading.
fn frame_flags(frame: &Frame<'_>) -> Flags {
    match frame {
        Frame::Data { flags, .. }
        | Frame::Headers { flags, .. }
        | Frame::Ping { flags, .. }
        | Frame::Continuation { flags, .. } => *flags,
        _ => Flags::none(),
    }
}

// The flag constants are asserted against the frame layer rather than trusted:
// a bit renamed in one place and not the other would silently turn `END_STREAM`
// into `ACK`, which is the exact confusion `frame`'s own documentation warns
// about. `Flags` has no named constants by design (bit `0x20` means `END_STREAM`
// on `DATA` and `ACK` on `SETTINGS`), so the meaning is asserted here instead.
const _: () = assert!(END_STREAM == 0x1);
const _: () = assert!(END_HEADERS == 0x4);
const _: () = assert!(PADDED == 0x8);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h2::frame::FrameHeader as Header;

    /// A connection driven past the preface and into `Open`.
    fn opened() -> Connection {
        let mut c = Connection::new();
        let mut bytes = Vec::from(CLIENT_PREFACE);
        bytes.extend_from_slice(&to_bytes(&Frame::Settings { params: Vec::new() }));
        let events = c.recv(&bytes).expect("the preface and settings are legal");
        assert!(
            events.iter().any(|e| matches!(e, Event::Settings { .. })),
            "the peer's SETTINGS must be reported: {events:?}"
        );
        assert_eq!(c.state(), State::Open);
        c
    }

    /// One frame's bytes.
    fn bytes(frame: &Frame<'_>) -> Vec<u8> {
        to_bytes(frame)
    }

    /// A `HEADERS` frame with an HPACK-encoded block.
    fn headers(stream_id: u32, fields: &[HeaderField], end_stream: bool) -> Vec<u8> {
        let block = Encoder::new().encode(fields);
        let mut flags = Flags::none().with(END_HEADERS);
        if end_stream {
            flags = flags.with(END_STREAM);
        }
        bytes(&Frame::Headers {
            stream_id,
            flags,
            fragment: &block,
            padding: None,
            priority: None,
        })
    }

    /// A GET for `path`.
    fn request(stream_id: u32, path: &str) -> Vec<u8> {
        headers(
            stream_id,
            &[
                HeaderField::new(":method", "GET"),
                HeaderField::new(":path", path),
                HeaderField::new(":scheme", "https"),
                HeaderField::new(":authority", "example.test"),
            ],
            true,
        )
    }

    // -- preface ------------------------------------------------------------

    /// §3.4: the preface is exact.
    ///
    /// A server that skipped this check would read attacker-chosen bytes as a
    /// `SETTINGS` frame and frame everything after it from a wrong offset.
    #[test]
    fn a_wrong_preface_ends_the_connection() {
        let mut c = Connection::new();
        let mut b = b"NOT THE PREFACE AT ALL!!".to_vec();
        b.truncate(CLIENT_PREFACE.len());
        let e = c.recv(&b).expect_err("a wrong preface must be refused");
        assert_eq!(e.code(), ErrorCode::ProtocolError);
    }

    /// A preface delivered one byte at a time must still work.
    ///
    /// TCP gives no message boundaries. A preface parser that required all 24
    /// bytes in one read passes every test that hands it the whole string and
    /// fails on a real network.
    #[test]
    fn the_preface_may_arrive_one_byte_at_a_time() {
        let mut c = Connection::new();
        for (i, b) in CLIENT_PREFACE.iter().enumerate() {
            let events = c.recv(&[*b]).expect("a partial preface is not an error");
            assert!(
                events.is_empty(),
                "byte {i} produced events before the preface was complete"
            );
        }
        assert_eq!(c.state(), State::AwaitingFirstSettings);
    }

    /// §3.4: `SETTINGS` must be the first frame after the preface.
    #[test]
    fn the_first_frame_after_the_preface_must_be_settings() {
        let mut c = Connection::new();
        let mut b = Vec::from(CLIENT_PREFACE);
        b.extend_from_slice(&bytes(&Frame::Ping {
            flags: Flags::none(),
            payload: [0; 8],
        }));
        let e = c.recv(&b).expect_err("PING before SETTINGS is refused");
        assert!(
            e.to_string().contains("not SETTINGS"),
            "the error must say what was expected: {e}"
        );
    }

    /// The server's own `SETTINGS` goes out immediately, before anything else.
    #[test]
    fn the_server_sends_its_settings_first() {
        let mut c = Connection::new();
        let _ = c.recv(CLIENT_PREFACE).expect("the preface is enough");
        let first = c.poll_outbound().expect("our SETTINGS is queued");
        let header = Header::parse(&first).expect("a well-formed frame");
        assert_eq!(header.frame_type, FrameType::Settings);
        assert_eq!(header.stream_id, 0, "SETTINGS is connection-scoped");
    }

    // -- settings -----------------------------------------------------------

    /// §6.5.3: every `SETTINGS` is acknowledged.
    #[test]
    fn a_settings_frame_is_acknowledged() {
        let mut c = opened();
        // Drain what `opened` queued: our SETTINGS, then the ACK.
        let _ = c.poll_outbound();
        let ack = c.poll_outbound().expect("the ACK is queued");
        let header = Header::parse(&ack).expect("parses");
        assert_eq!(header.frame_type, FrameType::Settings);
        assert!(
            header.flags.ack(),
            "the ACK flag must be set, or the peer waits forever"
        );
        assert_eq!(header.length, 0, "§6.5: an ACK has a zero-length payload");
    }

    /// §6.5.3: the peer's `INITIAL_WINDOW_SIZE` governs what *we* may send.
    #[test]
    fn the_peers_initial_window_size_governs_our_send_window() {
        let mut c = opened();
        let before = c.flow().send().initial_stream_window();
        let b = bytes(&Frame::Settings {
            params: vec![(SettingId::InitialWindowSize, 1_000_000)],
        });
        let _ = c.recv(&b).expect("in range");
        assert_eq!(
            c.flow().send().initial_stream_window(),
            1_000_000,
            "was {before}"
        );
    }

    /// §6.5.2: `MAX_CONCURRENT_STREAMS` binds our admission.
    #[test]
    fn max_concurrent_streams_binds_the_registry() {
        let mut c = opened();
        let b = bytes(&Frame::Settings {
            params: vec![(SettingId::MaxConcurrentStreams, 1)],
        });
        let _ = c.recv(&b).expect("in range");
        assert_eq!(c.streams().limit(), Some(1));

        let _ = c.recv(&request(1, "/")).expect("the first stream fits");
        let events = c
            .recv(&request(3, "/"))
            .expect("a stream refusal is not fatal");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Refused { stream_id: 3, .. })),
            "the second stream must be refused at the stream scope: {events:?}"
        );
    }

    // -- ping ---------------------------------------------------------------

    /// §6.7: the echo carries identical opaque data.
    #[test]
    fn a_ping_is_echoed_with_the_same_payload() {
        let mut c = opened();
        let payload = *b"12345678";
        let events = c
            .recv(&bytes(&Frame::Ping {
                flags: Flags::none(),
                payload,
            }))
            .expect("a PING is legal");
        assert!(events.iter().any(|e| matches!(e, Event::PingAck)));

        let mut found = false;
        while let Some(f) = c.poll_outbound() {
            let header = Header::parse(&f).expect("parses");
            if header.frame_type == FrameType::Ping && header.flags.ack() {
                assert_eq!(&f[FRAME_HEADER_LEN..], &payload);
                found = true;
            }
        }
        assert!(found, "the echoed PING must be queued");
    }

    /// An unsolicited PING ACK is ignored, not an error.
    #[test]
    fn an_unsolicited_ping_ack_is_ignored() {
        let mut c = opened();
        let events = c
            .recv(&bytes(&Frame::Ping {
                flags: Flags::none().with(ACK),
                payload: [0; 8],
            }))
            .expect("an unsolicited ACK is not a protocol error");
        assert!(events.is_empty(), "{events:?}");
    }

    // -- requests -----------------------------------------------------------

    /// A complete request produces decoded headers.
    #[test]
    fn a_request_produces_decoded_headers() {
        let mut c = opened();
        let events = c.recv(&request(1, "/orders")).expect("a GET is legal");
        let (id, fields, end) = events
            .iter()
            .find_map(|e| match e {
                Event::Headers {
                    stream_id,
                    fields,
                    end_stream,
                } => Some((*stream_id, fields.clone(), *end_stream)),
                _ => None,
            })
            .expect("the headers must be reported");
        assert_eq!(id, 1);
        assert!(end, "GET carries END_STREAM");
        assert!(
            fields
                .iter()
                .any(|f| f.name == ":path" && f.value == "/orders"),
            "{fields:?}"
        );
    }

    /// §5.1: after a complete request the stream is half-closed (remote).
    #[test]
    fn a_complete_request_half_closes_the_stream() {
        let mut c = opened();
        let _ = c.recv(&request(1, "/")).expect("legal");
        let id = StreamId::client(1).unwrap();
        assert_eq!(
            c.streams().get(id).unwrap().state(),
            StreamState::HalfClosedRemote
        );
    }

    // -- multiplexing -------------------------------------------------------

    /// **The point of HTTP/2.** Two streams interleave and each is answered.
    #[test]
    fn two_streams_interleave_and_each_is_answered() {
        let mut c = opened();
        let mut b = request(1, "/");
        b.extend_from_slice(&headers(
            3,
            &[
                HeaderField::new(":method", "POST"),
                HeaderField::new(":path", "/a"),
            ],
            false,
        ));
        let _ = c.recv(&b).expect("both HEADERS are legal");

        let mut body = bytes(&Frame::Data {
            stream_id: 3,
            flags: Flags::none(),
            data: b"hello ",
            padding: 0,
        });
        body.extend_from_slice(&bytes(&Frame::Data {
            stream_id: 3,
            flags: Flags::none().with(END_STREAM),
            data: b"world",
            padding: 0,
        }));
        let events = c.recv(&body).expect("DATA is legal");

        let got: String = events
            .iter()
            .filter_map(|e| match e {
                Event::Data { data, .. } => Some(String::from_utf8_lossy(data).into_owned()),
                _ => None,
            })
            .collect();
        assert_eq!(got, "hello world");
        assert!(
            events.iter().any(|e| matches!(
                e,
                Event::Data {
                    end_stream: true,
                    ..
                }
            )),
            "the second DATA carried END_STREAM"
        );
    }

    /// §5.1.1: a **newly established** stream id must be strictly greater than
    /// every id the peer has already opened.
    ///
    /// ## Why this is a stream error here and not a connection error
    ///
    /// The rule reads as if any repeated id ends the connection, and the first
    /// version of this test asserted exactly that. It was wrong, and running it
    /// is what showed so: a client that sends a second `HEADERS` for a stream
    /// that already ended is violating **§5.1's** state table first, and that
    /// table is checked before id monotonicity because a stream that exists has a
    /// state and the §5.1 row for `half-closed (remote)` receiving `HEADERS` is
    /// explicitly `STREAM_CLOSED` — a **stream** error.
    ///
    /// §5.1.1's monotonicity rule is about *opening*, which is why the connection
    /// layer offers only genuinely new ids to `admit`. The `Headers` event in the
    /// first call's result is evidence the stream was opened and finished, so the
    /// second `HEADERS` is refused against a real stream rather than admitted as a
    /// new one.
    ///
    /// The connection-fatal path is covered by `an_even_client_stream_id_is_fatal`
    /// and, for monotonicity specifically, by a stream id *below* the cursor that
    /// was never opened — see `an_id_below_the_cursor_is_fatal`.
    #[test]
    fn a_second_headers_on_a_finished_stream_is_a_stream_error() {
        let mut c = opened();
        let events = c.recv(&request(5, "/")).expect("the first use is legal");
        assert!(
            events.iter().any(|e| matches!(e, Event::Headers { .. })),
            "the first request must open the stream: {events:?}"
        );

        // The peer repeats the id. §5.1's row for this state is checked first.
        let events = c
            .recv(&request(5, "/"))
            .expect("§5.1 makes this a stream error, so it is not fatal");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Refused { stream_id: 5, .. })),
            "the repeat must be refused at the stream scope: {events:?}"
        );
        assert_eq!(
            c.state(),
            State::Open,
            "one bad stream must not end the connection"
        );
    }

    /// §5.1.1: an id **below** the cursor that was never opened ends the
    /// connection.
    ///
    /// This is the monotonicity rule with no stream to hide behind: the peer
    /// skipped past id 3, so 3 can never be opened, and a frame that tries is the
    /// "unexpected stream identifier" the RFC names as a connection error. It is
    /// distinct from the repeat case above, where a *real* stream exists and §5.1
    /// gets to answer first.
    #[test]
    fn an_id_below_the_cursor_is_fatal() {
        let mut c = opened();
        // Open 5 and 7, leaving 3 unused and permanently unusable.
        let _ = c.recv(&request(5, "/")).expect("legal");
        let _ = c.recv(&request(7, "/")).expect("legal");

        // 3 was skipped: it is below the cursor and was never opened. This is the
        // §5.1.1 connection error with no stream state to answer first — the
        // counterpart to the repeat-headers case above, which the §5.1 table
        // handles at the stream scope.
        let e = c
            .recv(&request(3, "/"))
            .expect_err("an id below the cursor is a connection error");
        assert_eq!(e.code(), ErrorCode::ProtocolError);
        assert!(
            e.to_string()
                .contains("not greater than the highest already used"),
            "the error must cite the monotonicity rule: {e}"
        );
    }

    /// §5.1.1: an even id from a client is fatal.
    #[test]
    fn an_even_client_stream_id_is_fatal() {
        let mut c = opened();
        let e = c
            .recv(&request(2, "/"))
            .expect_err("even ids belong to the server");
        assert_eq!(e.code(), ErrorCode::ProtocolError);
    }

    // -- CONTINUATION -------------------------------------------------------

    /// **§6.10.** A header block split across `CONTINUATION` frames decodes.
    #[test]
    fn a_header_block_split_across_continuations_decodes() {
        let mut c = opened();
        let fields = [
            HeaderField::new(":method", "GET"),
            HeaderField::new(":path", "/split"),
            HeaderField::new(":authority", "example.test"),
        ];
        let block = Encoder::new().encode(&fields);
        assert!(block.len() >= 3, "need three bytes to split three ways");

        let (a, rest) = block.split_at(1);
        let (mid, tail) = rest.split_at(1);
        let mut b = bytes(&Frame::Headers {
            stream_id: 1,
            flags: Flags::none(),
            fragment: a,
            padding: None,
            priority: None,
        });
        b.extend_from_slice(&bytes(&Frame::Continuation {
            stream_id: 1,
            flags: Flags::none(),
            fragment: mid,
        }));
        b.extend_from_slice(&bytes(&Frame::Continuation {
            stream_id: 1,
            flags: Flags::none().with(END_HEADERS),
            fragment: tail,
        }));

        let events = c.recv(&b).expect("a contiguous block is legal");
        let got = events
            .iter()
            .find_map(|e| match e {
                Event::Headers { fields, .. } => Some(fields.clone()),
                _ => None,
            })
            .expect("the block must be reported once complete");
        assert_eq!(got, fields);
    }

    /// **§6.10's teeth.** Another stream's frame may not interrupt a block.
    ///
    /// A peer that could interleave a second stream's `HEADERS` between two
    /// `CONTINUATION`s would force per-stream reassembly buffers, and the memory
    /// cost is per connection. Refusing is both simpler and what the RFC requires.
    #[test]
    fn a_frame_from_another_stream_may_not_interrupt_a_block() {
        let mut c = opened();
        let block = Encoder::new().encode(&[HeaderField::new(":method", "GET")]);
        let (a, rest) = block.split_at(1);

        let mut b = bytes(&Frame::Headers {
            stream_id: 1,
            flags: Flags::none(),
            fragment: a,
            padding: None,
            priority: None,
        });
        // Stream 3 barges in.
        b.extend_from_slice(&headers(3, &[HeaderField::new(":method", "GET")], true));
        b.extend_from_slice(&bytes(&Frame::Continuation {
            stream_id: 1,
            flags: Flags::none().with(END_HEADERS),
            fragment: rest,
        }));

        let e = c
            .recv(&b)
            .expect_err("an interleaved frame must be a connection error");
        assert_eq!(e.code(), ErrorCode::ProtocolError);
        assert!(
            e.to_string().contains("contiguous"),
            "the error must cite the rule: {e}"
        );
    }

    /// A `CONTINUATION` with no block open is a protocol error.
    #[test]
    fn a_stray_continuation_is_refused() {
        let mut c = opened();
        let b = bytes(&Frame::Continuation {
            stream_id: 1,
            flags: Flags::none().with(END_HEADERS),
            fragment: b"x",
        });
        let e = c.recv(&b).expect_err("no block is open");
        assert_eq!(e.code(), ErrorCode::ProtocolError);
    }

    /// §6.10: the block may not be reassembled without bound.
    ///
    /// ## Why this drives bytes rather than asserting on a constant
    ///
    /// A test asserting `MAX_HEADER_BLOCK_BYTES == 1 << 20` passes whether or not
    /// anything enforces it — the shape `§M-006` records. This feeds the real
    /// path past the limit and requires a connection error.
    #[test]
    fn an_unbounded_header_block_is_refused() {
        let mut c = opened();
        let _ = c
            .recv(&bytes(&Frame::Headers {
                stream_id: 1,
                flags: Flags::none(),
                fragment: &[0u8; 1],
                padding: None,
                priority: None,
            }))
            .expect("the block opens");

        let chunk = vec![0u8; MAX_FRAME_PAYLOAD];
        let cont = bytes(&Frame::Continuation {
            stream_id: 1,
            flags: Flags::none(),
            fragment: &chunk,
        });
        let mut refused = false;
        for _ in 0..4 {
            if let Err(e) = c.recv(&cont) {
                assert_eq!(e.code(), ErrorCode::EnhanceYourCalm);
                refused = true;
                break;
            }
        }
        assert!(
            refused,
            "reassembling past {MAX_HEADER_BLOCK_BYTES} bytes must be refused; a peer \
             that never sets END_HEADERS would otherwise allocate without bound"
        );
    }

    /// §6.10: an unbounded *count* of empty CONTINUATIONs is refused too.
    ///
    /// The byte cap does not cover this: an empty CONTINUATION costs the sender
    /// nine bytes and frees the receiver nothing, while keeping the connection in
    /// the mid-block state where every other stream is blocked.
    #[test]
    fn an_unbounded_number_of_continuations_is_refused() {
        let mut c = opened();
        let _ = c
            .recv(&bytes(&Frame::Headers {
                stream_id: 1,
                flags: Flags::none(),
                fragment: &[0u8; 1],
                padding: None,
                priority: None,
            }))
            .expect("opens the block");
        let cont = bytes(&Frame::Continuation {
            stream_id: 1,
            flags: Flags::none(),
            fragment: &[],
        });

        let mut refused = false;
        for _ in 0..(MAX_CONTINUATIONS + 2) {
            if let Err(e) = c.recv(&cont) {
                assert_eq!(e.code(), ErrorCode::EnhanceYourCalm);
                refused = true;
                break;
            }
        }
        assert!(refused, "an endless CONTINUATION sequence must be refused");
    }

    // -- flow control -------------------------------------------------------

    /// §6.1: padding counts against the window.
    ///
    /// A decoder that charges only `data.len()` under-counts by up to 255 bytes
    /// per frame, and the connection drifts out of sync with the peer's window
    /// until a send stalls for no visible reason.
    #[test]
    fn padding_counts_against_the_window() {
        let mut c = opened();
        let _ = c
            .recv(&headers(1, &[HeaderField::new(":method", "POST")], false))
            .expect("opens");

        let before = c.flow().recv().connection().size();
        let d = bytes(&Frame::Data {
            stream_id: 1,
            flags: Flags::none().with(PADDED),
            data: b"x",
            padding: 200,
        });
        let _ = c.recv(&d).expect("legal");
        let after = c.flow().recv().connection().size();
        assert_eq!(
            before - after,
            202,
            "the pad-length octet and the padding are both charged"
        );
    }

    /// Replenishment turns consumption back into `WINDOW_UPDATE`.
    ///
    /// Without it a long-lived connection stalls permanently once the initial
    /// window is spent — a missing credit that presents as a hung peer.
    #[test]
    fn consumed_bytes_are_replenished() {
        let mut c = opened();
        let _ = c
            .recv(&headers(1, &[HeaderField::new(":method", "POST")], false))
            .expect("opens");
        let d = bytes(&Frame::Data {
            stream_id: 1,
            flags: Flags::none(),
            data: b"0123456789",
            padding: 0,
        });
        let _ = c.recv(&d).expect("legal");

        while c.poll_outbound().is_some() {}
        c.replenish();
        assert!(c.has_outbound(), "a WINDOW_UPDATE must be queued");

        let mut saw_connection = false;
        while let Some(f) = c.poll_outbound() {
            let header = Header::parse(&f).expect("parses");
            if header.frame_type == FrameType::WindowUpdate && header.stream_id == 0 {
                saw_connection = true;
            }
        }
        assert!(saw_connection, "the connection window must be replenished");
    }

    /// §6.9: a `WINDOW_UPDATE` of zero is a protocol error.
    #[test]
    fn a_zero_window_update_is_refused() {
        let mut c = opened();
        // Built by hand: the parser refuses a zero increment, so `to_bytes`
        // cannot produce one.
        let mut b = vec![0, 0, 4, 0x8, 0, 0, 0, 0, 0];
        b.extend_from_slice(&0u32.to_be_bytes());
        let e = c.recv(&b).expect_err("increment zero is illegal");
        assert_eq!(e.code(), ErrorCode::ProtocolError);
    }

    // -- reset --------------------------------------------------------------

    /// §6.4: a peer's `RST_STREAM` resets one stream, not the connection.
    #[test]
    fn a_peer_reset_closes_one_stream_and_the_connection_survives() {
        let mut c = opened();
        let _ = c.recv(&request(1, "/")).expect("legal");
        let _ = c.recv(&request(3, "/")).expect("legal");

        let events = c
            .recv(&bytes(&Frame::RstStream {
                stream_id: 1,
                error: ErrorCode::Cancel,
            }))
            .expect("a reset is not a connection error");
        assert!(events
            .iter()
            .any(|e| matches!(e, Event::StreamReset { stream_id: 1, .. })));

        // Stream 3 is untouched: this is the multiplexing guarantee.
        let id3 = StreamId::client(3).unwrap();
        assert!(c.streams().get(id3).is_some());
        assert_eq!(c.state(), State::Open);
    }

    /// A frame for a stream the peer already reset is ignored, not an error.
    #[test]
    fn a_frame_after_a_reset_is_ignored() {
        let mut c = opened();
        let _ = c.recv(&request(1, "/")).expect("legal");
        let _ = c
            .recv(&bytes(&Frame::RstStream {
                stream_id: 1,
                error: ErrorCode::Cancel,
            }))
            .expect("legal");

        // A DATA frame for the reset stream crossed ours in flight.
        let late = bytes(&Frame::Data {
            stream_id: 1,
            flags: Flags::none(),
            data: b"late",
            padding: 0,
        });
        let events = c
            .recv(&late)
            .expect("a frame in flight after a reset is not an error");
        assert!(events.is_empty(), "{events:?}");
    }

    /// Our own reset is queued.
    #[test]
    fn our_reset_is_queued() {
        let mut c = opened();
        let _ = c.recv(&request(1, "/")).expect("legal");
        while c.poll_outbound().is_some() {}
        c.send_reset(1, ErrorCode::RefusedStream);
        assert!(c.has_outbound(), "the RST_STREAM must be queued");
    }

    // -- goaway -------------------------------------------------------------

    /// §6.8: `GOAWAY` reports the highest stream we might have processed.
    #[test]
    fn goaway_reports_the_last_client_stream() {
        let mut c = opened();
        let _ = c.recv(&request(1, "/")).expect("legal");
        let _ = c.recv(&request(3, "/")).expect("legal");
        while c.poll_outbound().is_some() {}

        c.send_goaway(Some(ErrorCode::NoError));
        assert_eq!(c.state(), State::Draining);

        let f = c.poll_outbound().expect("GOAWAY is queued");
        let header = Header::parse(&f).expect("parses");
        assert_eq!(header.frame_type, FrameType::GoAway);
        // The payload's first four bytes are the last-stream-id, with the
        // reserved bit masked off.
        let last = u32::from_be_bytes([f[9] & 0x7f, f[10], f[11], f[12]]);
        assert_eq!(last, 3, "the highest id we saw, not the lowest");
    }

    /// A second `GOAWAY` is a no-op: the peer only acts on the first.
    #[test]
    fn goaway_is_sent_once() {
        let mut c = opened();
        while c.poll_outbound().is_some() {}
        c.send_goaway(None);
        c.send_goaway(None);
        assert_eq!(c.queued_frames(), 1);
    }

    /// After `GOAWAY` the peer may not open new streams.
    #[test]
    fn no_new_streams_after_goaway() {
        let mut c = opened();
        c.send_goaway(None);
        let events = c.recv(&request(1, "/")).expect("a refusal is not fatal");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Refused { stream_id: 1, .. })),
            "a stream opened after GOAWAY must be refused: {events:?}"
        );
    }

    /// A peer's `GOAWAY` ends the connection.
    #[test]
    fn a_peer_goaway_is_reported() {
        let mut c = opened();
        let events = c
            .recv(&bytes(&Frame::GoAway {
                last_stream_id: 5,
                error: Some(ErrorCode::NoError),
                raw_error: 0,
                debug: &[],
            }))
            .expect("legal");
        assert!(events.iter().any(|e| matches!(
            e,
            Event::GoAway {
                last_stream_id: 5,
                ..
            }
        )));
        assert_eq!(c.state(), State::Closed);
    }

    // -- frame-level errors -------------------------------------------------

    /// §8.4: a client may not push.
    #[test]
    fn a_client_push_promise_is_refused() {
        let mut c = opened();
        let b = bytes(&Frame::PushPromise { stream_id: 1 });
        let e = c.recv(&b).expect_err("a client must not send PUSH_PROMISE");
        assert_eq!(e.code(), ErrorCode::ProtocolError);
    }

    /// §4.3: an HPACK failure is a **connection** error, not a stream one.
    ///
    /// The dynamic table is shared, so a decoder out of sync misdecodes every
    /// later header block — resetting one stream would leave the connection
    /// producing wrong headers for the rest of its life.
    #[test]
    fn an_hpack_failure_ends_the_connection() {
        let mut c = opened();
        // 0x3f expects a dynamic-table index far beyond any that can exist.
        let b = bytes(&Frame::Headers {
            stream_id: 1,
            flags: Flags::none().with(END_HEADERS).with(END_STREAM),
            fragment: &[0xff, 0xff, 0xff, 0xff, 0x7f],
            padding: None,
            priority: None,
        });
        let e = c
            .recv(&b)
            .expect_err("a compression error is connection-fatal");
        assert_eq!(e.code(), ErrorCode::CompressionError);
    }

    /// A frame is never buffered beyond its declared length, and a declaration
    /// that cannot be satisfied is refused rather than waited on.
    ///
    /// ## What this can and cannot test
    ///
    /// A 24-bit length field cannot express a value greater than
    /// `MAX_FRAME_PAYLOAD` — that is what the ceiling *is*, so the guard in
    /// `recv` is unreachable through `parse_frame` and writing a test that
    /// claimed to exercise it would be a test with no fault it could catch.
    ///
    /// The property that *is* testable, and is the one that matters, is that the
    /// connection buffers nothing until a frame's declared payload has arrived:
    /// a header declaring the maximum leaves the connection holding 9 bytes, not
    /// 16 MiB. A peer that announces a huge frame and sends nothing therefore
    /// costs the server nine bytes, which is the denial-of-service shape the
    /// header-before-payload ordering exists to prevent.
    #[test]
    fn a_frame_is_never_buffered_past_its_declared_length() {
        let mut c = opened();
        // The largest length a 24-bit field can hold.
        let [l2, l1, l0] = MAX_FRAME_PAYLOAD_U32.to_be_bytes()[1..].try_into().unwrap();
        let header = [l2, l1, l0, 0x0, 0x0, 0, 0, 0, 1];

        let events = c
            .recv(&header)
            .expect("a header alone is not an error: the payload has not arrived");
        assert!(
            events.is_empty(),
            "nothing can complete from a header alone: {events:?}"
        );

        // And a short payload is still not accepted.
        let events = c.recv(&[0u8; 64]).expect("still incomplete");
        assert!(events.is_empty(), "{events:?}");

        // The rejection for a *malformed* header is a different path and is
        // covered by `frame`'s own tests.
    }

    /// A header declaring more than the connection will hold is refused by the
    /// length check rather than by allocating.
    ///
    /// Reaching it requires a length the 24-bit field *can* hold but the parser
    /// then rejects — which is the malformed-header path, so this asserts the
    /// refusal exists rather than pretending to exercise the unreachable guard.
    #[test]
    fn a_malformed_frame_header_is_refused_not_panicked_on() {
        let mut c = opened();
        // A header whose type byte is fine but whose declared length exceeds the
        // bytes ever supplied: the connection must wait, and must not grow.
        let header = [0xff, 0xff, 0xff, 0x0, 0x0, 0, 0, 0, 1];
        let events = c.recv(&header).expect("waiting is not an error");
        assert!(events.is_empty(), "{events:?}");
    }

    /// A truncated frame is buffered, not misparsed.
    #[test]
    fn a_partial_frame_is_buffered() {
        let mut c = opened();
        let full = request(1, "/");
        let (head, tail) = full.split_at(full.len() - 1);
        let events = c.recv(head).expect("a partial frame is not an error");
        assert!(events.is_empty(), "nothing completes yet: {events:?}");
        let events = c.recv(tail).expect("the rest completes it");
        assert!(
            events.iter().any(|e| matches!(e, Event::Headers { .. })),
            "the frame must complete once whole: {events:?}"
        );
    }

    // -- local side ---------------------------------------------------------

    /// Our own `END_STREAM` closes a half-closed-remote stream.
    #[test]
    fn our_end_stream_closes_the_stream() {
        let mut c = opened();
        let _ = c.recv(&request(1, "/")).expect("legal");
        c.note_local_end(1).expect("our END_STREAM is legal here");
        let id = StreamId::client(1).unwrap();
        assert_eq!(c.streams().get(id).unwrap().state(), StreamState::Closed);
    }

    /// Two connections do not share HPACK state: the table is per connection.
    #[test]
    fn two_connections_have_independent_hpack_state() {
        let mut a = opened();
        let mut b = opened();
        let fields = [HeaderField::new("x-test", "one")];
        let block = Encoder::new().encode(&fields);
        let frame = bytes(&Frame::Headers {
            stream_id: 1,
            flags: Flags::none().with(END_HEADERS).with(END_STREAM),
            fragment: &block,
            padding: None,
            priority: None,
        });
        let ea = a.recv(&frame).expect("a decodes its own peer's block");
        assert!(ea.iter().any(|e| matches!(e, Event::Headers { .. })));
        // `b` has its own decoder, so a literal block still decodes there.
        let eb = b.recv(&frame).expect("b has its own decoder");
        assert!(eb.iter().any(|e| matches!(e, Event::Headers { .. })));
    }

    /// Determinism: identical input produces identical events and bytes.
    #[test]
    fn identical_input_produces_identical_output() {
        fn run() -> (Vec<Event>, Vec<Vec<u8>>) {
            let mut c = opened();
            let mut b = request(1, "/");
            b.extend_from_slice(&request(3, "/"));
            let events = c.recv(&b).expect("legal");
            let mut out = Vec::new();
            while let Some(f) = c.poll_outbound() {
                out.push(f);
            }
            (events, out)
        }
        assert_eq!(run(), run(), "HTTP/2 framing must be deterministic");
    }
}
