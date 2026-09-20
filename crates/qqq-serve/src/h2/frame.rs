//! The HTTP/2 frame layer: the 9-byte header, and every frame type `SRV-002`
//! requires.
//!
//! Implements `SRV-002`; RFC 9113 §4 (framing), §6 (frame definitions).
//!
//! # The one shape every frame shares
//!
//! ```text
//! +-----------------------------------------------+
//! |                 Length (24)                   |
//! +---------------+---------------+---------------+
//! |   Type (8)    |   Flags (8)   |
//! +-+-------------+---------------+-------------------------------+
//! |R|                 Stream Identifier (31)                      |
//! +=+=============================================================+
//! |                   Frame Payload (0...)                      ...
//! +---------------------------------------------------------------+
//! ```
//!
//! Three properties of that header are load-bearing, and each is a place where
//! an implementation goes silently wrong:
//!
//! 1. **`R` is reserved and must be ignored.** Reading it as part of the stream
//!    id gives an id of 2^31 or more, which then fails every "is this stream id
//!    ours" check for a reason nobody can see. This module masks it off on read
//!    and writes a zero on the wire.
//! 2. **`Length` is the payload length only.** It does not include the 9-byte
//!    header. An off-by-nine here desynchronises the entire connection from the
//!    first frame onwards, and the symptom appears thousands of bytes later.
//! 3. **Flags are per-frame-type.** Bit 0x20 means `END_STREAM` on `DATA` and
//!    `ACK` on `SETTINGS`. A shared "flag" enum with shared semantics is how a
//!    `SETTINGS` ack is read as an end-of-stream.
//!
//! # Parsing is total on length, and refuses to interpret a short body
//!
//! [`Frame::parse`] takes exactly one frame's bytes: a 9-byte header plus its
//! declared payload. It returns a [`FrameError::Truncated`] when fewer bytes are
//! present rather than reading into whatever follows — a decoder that
//! over-reads turns a truncated frame into a misparse, and a misparse is a
//! framing desync.
//!
//! # What is parsed and deliberately ignored
//!
//! `PRIORITY` (type `0x2`) and the priority fields carried in `HEADERS`
//! (`PRIORITY` flag, `0x20`) are **parsed, validated and discarded**. RFC 9113
//! §5.3.1 deprecates the priority scheme: *"This document deprecates the
//! priority signaling scheme … an endpoint MAY ignore … A client SHOULD NOT send
//! the PRIORITY flag"*. Ignoring it is the specification's own guidance, not a
//! shortcut — but the *fields* are still length-checked, because a `HEADERS`
//! frame with the `PRIORITY` flag set is five bytes longer and skipping that
//! check shifts the header block by five bytes.
//!
//! The RFC does *not* permit ignoring a `PRIORITY` frame for an illegal stream
//! id whose stream is not idle (§5.1), so the state machine still sees it.

use std::fmt;

use super::error::ErrorCode;

// ---------------------------------------------------------------------------
// Limits and constants
// ---------------------------------------------------------------------------

/// The size of the fixed frame header, in bytes.
pub const FRAME_HEADER_LEN: usize = 9;

/// The largest payload any frame may carry: 2^24 - 1.
///
/// A hard limit of the format, not a policy choice: the length field is 24 bits,
/// so a payload of 2^24 is unrepresentable and an encoder that tried would
/// truncate silently. `SETTINGS_MAX_FRAME_SIZE` (RFC 9113 §6.5.2) defaults to
/// 16384 and may not exceed this value.
pub const MAX_FRAME_PAYLOAD: usize = 0xFF_FFFF;

/// The default `SETTINGS_MAX_FRAME_SIZE` (RFC 9113 §6.5.2).
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;

/// The connection preface (RFC 9113 §3.4).
///
/// Note the spelling: `PRI * HTTP/2.0` — **not** as a valid HTTP/1.1 request
/// line. The `*` target and `HTTP/2.0` version are both invalid in HTTP/1.1, so
/// an HTTP/1.1 server receiving one is guaranteed to reject it rather than
/// treating it as a request for `*`.
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// ---------------------------------------------------------------------------
// Frame types
// ---------------------------------------------------------------------------

/// A frame type code (RFC 9113 §6).
///
/// The numeric values are wire values and are pinned by test. `Unknown` carries
/// the raw number because the type space is extensible: RFC 9113 §4.1 requires
/// an endpoint to **ignore** a frame whose type it does not recognise, and
/// dropping such a frame is a rule that can only be implemented if the type is
/// representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FrameType {
    /// `0x0` — `DATA`.
    Data,
    /// `0x1` — `HEADERS`.
    Headers,
    /// `0x2` — `PRIORITY` (deprecated, parsed and ignored).
    Priority,
    /// `0x3` — `RST_STREAM`.
    RstStream,
    /// `0x4` — `SETTINGS`.
    Settings,
    /// `0x5` — `PUSH_PROMISE`.
    ///
    /// Recognised so it can be **refused**: this is a server, and RFC 9113 §8.4
    /// forbids a server from sending `PUSH_PROMISE`; a client that sends one is
    /// violating the protocol. The type exists here to produce a precise error
    /// rather than "unknown frame type".
    PushPromise,
    /// `0x6` — `PING`.
    Ping,
    /// `0x7` — `GOAWAY`.
    GoAway,
    /// `0x8` — `WINDOW_UPDATE`.
    WindowUpdate,
    /// `0x9` — `CONTINUATION`.
    Continuation,
    /// Any other type, which RFC 9113 §4.1 requires to be ignored.
    Unknown(u8),
}

impl FrameType {
    /// The wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Data => 0x0,
            Self::Headers => 0x1,
            Self::Priority => 0x2,
            Self::RstStream => 0x3,
            Self::Settings => 0x4,
            Self::PushPromise => 0x5,
            Self::Ping => 0x6,
            Self::GoAway => 0x7,
            Self::WindowUpdate => 0x8,
            Self::Continuation => 0x9,
            Self::Unknown(n) => n,
        }
    }

    /// Decode a wire value.
    #[must_use]
    pub const fn from_u8(n: u8) -> Self {
        match n {
            0x0 => Self::Data,
            0x1 => Self::Headers,
            0x2 => Self::Priority,
            0x3 => Self::RstStream,
            0x4 => Self::Settings,
            0x5 => Self::PushPromise,
            0x6 => Self::Ping,
            0x7 => Self::GoAway,
            0x8 => Self::WindowUpdate,
            0x9 => Self::Continuation,
            other => Self::Unknown(other),
        }
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
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    /// Whether this type is recognised by this implementation.
    #[must_use]
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(n) => write!(f, "UNKNOWN(0x{n:02x})"),
            known => f.write_str(known.as_str()),
        }
    }
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// A frame's flag octet, kept as a bit set.
///
/// # Why this is not an enum
///
/// The same bit means different things on different frame types: `0x1` is
/// `END_STREAM` on `DATA`/`HEADERS` and `ACK` on `SETTINGS`/`PING`; `0x20` is
/// `PADDED` on `DATA`/`HEADERS` and `PRIORITY` on `HEADERS`. A `Flags` enum with
/// one name per bit would have to pick one meaning and would then read a
/// `SETTINGS` acknowledgement as an end-of-stream.
///
/// So the raw octet is kept, and the named accessors are per-type:
/// [`Flags::end_stream`] is meaningful for `DATA` and `HEADERS`;
/// [`Flags::ack`] for `SETTINGS` and `PING`. Each names the frame types it
/// applies to in its own documentation, which is where the RFC states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Flags(u8);

impl Flags {
    /// `END_STREAM` (0x1) — on `DATA` and `HEADERS`.
    pub const END_STREAM: u8 = 0x1;
    /// `ACK` (0x1) — on `SETTINGS` and `PING`.
    pub const ACK: u8 = 0x1;
    /// `END_HEADERS` (0x4) — on `HEADERS`, `PUSH_PROMISE`, `CONTINUATION`.
    pub const END_HEADERS: u8 = 0x4;
    /// `PADDED` (0x8) — on `DATA` and `HEADERS`.
    pub const PADDED: u8 = 0x8;
    /// `PRIORITY` (0x20) — on `HEADERS`.
    pub const PRIORITY: u8 = 0x20;

    /// No flags.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// Flags from a raw octet.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// The raw octet.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether every bit in `mask` is set.
    #[must_use]
    pub const fn contains(self, mask: u8) -> bool {
        self.0 & mask == mask
    }

    /// Whether any bit in `mask` is set.
    #[must_use]
    pub const fn intersects(self, mask: u8) -> bool {
        self.0 & mask != 0
    }

    /// Set a bit.
    #[must_use]
    pub const fn with(self, mask: u8) -> Self {
        Self(self.0 | mask)
    }

    /// `END_STREAM`, on `DATA` and `HEADERS`.
    #[must_use]
    pub const fn end_stream(self) -> bool {
        self.contains(Self::END_STREAM)
    }

    /// `ACK`, on `SETTINGS` and `PING`.
    #[must_use]
    pub const fn ack(self) -> bool {
        self.contains(Self::ACK)
    }

    /// `END_HEADERS`, on `HEADERS`, `PUSH_PROMISE` and `CONTINUATION`.
    #[must_use]
    pub const fn end_headers(self) -> bool {
        self.contains(Self::END_HEADERS)
    }

    /// `PADDED`, on `DATA` and `HEADERS`.
    #[must_use]
    pub const fn padded(self) -> bool {
        self.contains(Self::PADDED)
    }

    /// `PRIORITY`, on `HEADERS`.
    #[must_use]
    pub const fn has_priority(self) -> bool {
        self.contains(Self::PRIORITY)
    }

    /// The flags, described for a log line.
    ///
    /// Interpreted for the frame type, because that is the only context in which
    /// a bit has a name.
    #[must_use]
    pub fn describe(self, frame_type: FrameType) -> String {
        let mut names: Vec<&str> = Vec::new();
        match frame_type {
            FrameType::Data => {
                if self.end_stream() {
                    names.push("END_STREAM");
                }
                if self.padded() {
                    names.push("PADDED");
                }
            }
            FrameType::Headers => {
                if self.end_stream() {
                    names.push("END_STREAM");
                }
                if self.end_headers() {
                    names.push("END_HEADERS");
                }
                if self.padded() {
                    names.push("PADDED");
                }
                if self.has_priority() {
                    names.push("PRIORITY");
                }
            }
            FrameType::Settings | FrameType::Ping => {
                if self.ack() {
                    names.push("ACK");
                }
            }
            FrameType::Continuation | FrameType::PushPromise => {
                if self.end_headers() {
                    names.push("END_HEADERS");
                }
                if frame_type == FrameType::PushPromise && self.padded() {
                    names.push("PADDED");
                }
            }
            _ => {}
        }
        if names.is_empty() {
            return "-".to_owned();
        }
        names.join("|")
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:02x}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Frame header
// ---------------------------------------------------------------------------

/// The 9-byte prefix of every frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Payload length, **excluding** this header.
    pub length: u32,
    /// The frame type.
    pub frame_type: FrameType,
    /// The flag octet.
    pub flags: Flags,
    /// The stream id, with the reserved bit already masked off.
    pub stream_id: u32,
}

impl FrameHeader {
    /// Parse a 9-byte header.
    ///
    /// # Errors
    ///
    /// [`FrameError::Truncated`] if fewer than [`FRAME_HEADER_LEN`] bytes are
    /// given. A short header is a transport condition, never a peer's protocol
    /// violation — the peer cannot send three bytes of a nine-byte field.
    pub fn parse(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < FRAME_HEADER_LEN {
            return Err(FrameError::Truncated {
                need: FRAME_HEADER_LEN,
                got: bytes.len(),
            });
        }
        let length = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
        // The reserved bit is masked, not rejected. RFC 9113 §4.1: "The
        // semantics of this bit are undefined, and the bit MUST remain unset
        // (0x0) when sending and MUST be ignored when receiving." Rejecting it
        // would break a peer using it for an extension this endpoint has not
        // agreed to.
        let stream_id = u32::from_be_bytes([bytes[5] & 0x7f, bytes[6], bytes[7], bytes[8]]);
        Ok(Self {
            length,
            frame_type: FrameType::from_u8(bytes[3]),
            flags: Flags::from_bits(bytes[4]),
            stream_id,
        })
    }

    /// Serialise the header.
    ///
    /// The reserved bit is written as zero, as RFC 9113 §4.1 requires.
    #[must_use]
    pub fn write(&self) -> [u8; FRAME_HEADER_LEN] {
        let len = self.length;
        let id = self.stream_id;
        [
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
            self.frame_type.as_u8(),
            self.flags.bits(),
            // 0x7f, not 0xff: the top bit is the reserved bit.
            ((id >> 24) & 0x7f) as u8,
            (id >> 16) as u8,
            (id >> 8) as u8,
            id as u8,
        ]
    }

    /// The total bytes this frame occupies, header included.
    #[must_use]
    pub const fn total_len(&self) -> usize {
        FRAME_HEADER_LEN + self.length as usize
    }
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

/// A parsed frame.
///
/// The payload of `Data` and of the header-block-carrying frames is borrowed
/// from the caller's buffer rather than copied: a `DATA` frame on a fast path is
/// the hot allocation of an HTTP/2 server, and copying it would double the
/// per-request memory traffic for no gain. Every other frame is small and owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    /// `DATA` (RFC 9113 §6.1).
    Data {
        /// The stream id, always non-zero.
        stream_id: u32,
        /// Flags.
        flags: Flags,
        /// The payload with padding and the pad-length octet already removed.
        data: &'a [u8],
        /// How many padding bytes were present.
        ///
        /// Kept rather than discarded because padding participates in
        /// **flow control**: RFC 9113 §6.1 says the length field of a `DATA`
        /// frame counts the pad length and the padding, so a peer sending one
        /// byte of payload in a 255-byte frame consumes 255 bytes of window. A
        /// decoder that returns only the payload and lets flow control read
        /// `data.len()` under-counts by up to 255 bytes per frame, and the
        /// connection drifts out of sync with the peer's window.
        padding: u8,
    },
    /// `HEADERS` (RFC 9113 §6.2).
    Headers {
        /// The stream id, always non-zero.
        stream_id: u32,
        /// Flags.
        flags: Flags,
        /// The header block fragment.
        fragment: &'a [u8],
        /// The pad length, when `PADDED` was set.
        padding: Option<u8>,
        /// The priority fields, present when the `PRIORITY` flag is set.
        ///
        /// Parsed for its length and discarded per RFC 9113 §5.3.1.
        priority: Option<PrioritySpec>,
    },
    /// `PRIORITY` (RFC 9113 §6.3, deprecated).
    ///
    /// Carried rather than dropped at the decoder because the *frame* still has
    /// state-machine consequences: RFC 9113 §5.1 makes a `PRIORITY` frame sent on
    /// a stream with an id not greater than the last client-initiated id a
    /// **connection** error, and a decoder that discarded the frame would lose
    /// the only evidence that the rule was broken.
    Priority {
        /// The stream id, always non-zero.
        stream_id: u32,
        /// The priority specification.
        spec: PrioritySpec,
    },
    /// `RST_STREAM` (RFC 9113 §6.4).
    RstStream {
        /// The stream id, always non-zero.
        stream_id: u32,
        /// Why the sender is terminating the stream.
        error: ErrorCode,
    },
    /// `SETTINGS` (RFC 9113 §6.5).
    Settings {
        /// The parameters, in the order received.
        ///
        /// A `Vec` and not a map: a repeated parameter is legal (the last wins,
        /// §6.5.3) and keeping the order makes that determinable, and an
        /// unknown identifier must be ignored rather than dropped from a map
        /// that the caller then cannot distinguish from "not sent".
        params: Vec<(SettingId, u32)>,
    },
    /// A `SETTINGS` acknowledgement, which carries no payload.
    SettingsAck,
    /// `PUSH_PROMISE`. Recognised in order to be refused.
    ///
    /// A **server** must never receive one: RFC 9113 §8.4 permits only a server
    /// to push, so a client that sends this frame is violating the protocol. The
    /// variant exists so the refusal names the frame rather than reporting an
    /// unknown type.
    PushPromise {
        /// The stream id the promise was sent on, always non-zero.
        stream_id: u32,
    },
    /// `PING` (RFC 9113 §6.7).
    Ping {
        /// Flags; `ACK` distinguishes a response from a request.
        flags: Flags,
        /// The eight opaque octets.
        payload: [u8; 8],
    },
    /// `GOAWAY` (RFC 9113 §6.8).
    GoAway {
        /// The highest stream id the sender might have processed.
        last_stream_id: u32,
        /// Why, or `None` when the code on the wire was unassigned.
        error: Option<ErrorCode>,
        /// The raw code, retained when it was unassigned.
        raw_error: u32,
        /// Debug data, which may be empty.
        debug: &'a [u8],
    },
    /// `WINDOW_UPDATE` (RFC 9113 §6.9).
    WindowUpdate {
        /// The stream id, or `0` for the connection window.
        stream_id: u32,
        /// The increment. Always 1..=2^31-1; a zero increment is a protocol
        /// error and is rejected during parsing rather than represented.
        increment: u32,
    },
    /// `CONTINUATION` (RFC 9113 §6.10).
    Continuation {
        /// The stream id, always non-zero.
        stream_id: u32,
        /// Flags.
        flags: Flags,
        /// The next fragment of the header block.
        fragment: &'a [u8],
    },
    /// A frame whose type this implementation does not recognise.
    ///
    /// RFC 9113 §4.1 requires it to be ignored. The payload is **not** retained:
    /// an unknown frame has no semantics here, and keeping a peer-controlled
    /// buffer alive for one is a memory-growth channel.
    Unknown {
        /// The type as received.
        frame_type: FrameType,
        /// The declared payload length, so flow accounting and logs can see it.
        length: u32,
        /// The stream id as received.
        stream_id: u32,
    },
}

/// A stream's priority specification (RFC 9113 §6.3), parsed and discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrioritySpec {
    /// Whether the stream depends on another.
    pub exclusive: bool,
    /// The stream this one depends on.
    ///
    /// `0` means the root of the dependency tree. A stream depending on itself
    /// is a stream error, not a connection error (§5.3.1), so the value is kept
    /// rather than corrected.
    pub depends_on: u32,
    /// The weight, `1..=256` on the wire as `0..=255`.
    pub weight: u8,
}

impl PrioritySpec {
    /// The five bytes a priority specification occupies.
    pub const LEN: usize = 5;

    /// Parse five bytes.
    ///
    /// # Errors
    ///
    /// [`FrameError::Truncated`] when fewer than [`PrioritySpec::LEN`] bytes are
    /// available.
    pub fn parse(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < Self::LEN {
            return Err(FrameError::Truncated {
                need: Self::LEN,
                got: bytes.len(),
            });
        }
        Ok(Self {
            exclusive: bytes[0] & 0x80 != 0,
            depends_on: u32::from_be_bytes([bytes[0] & 0x7f, bytes[1], bytes[2], bytes[3]]),
            weight: bytes[4],
        })
    }

    /// Serialise.
    #[must_use]
    pub fn write(self) -> [u8; Self::LEN] {
        let d = self.depends_on;
        [
            ((d >> 24) & 0x7f) as u8 | if self.exclusive { 0x80 } else { 0 },
            (d >> 16) as u8,
            (d >> 8) as u8,
            d as u8,
            self.weight,
        ]
    }

    /// Whether the specification is self-referential.
    ///
    /// RFC 9113 §5.3.1: *"A stream cannot depend on itself. An endpoint MUST
    /// treat this as a stream error of type PROTOCOL_ERROR."* A **stream** error,
    /// not a connection error — the distinction is why this is a predicate on
    /// the stream's own frame rather than a connection-level check.
    #[must_use]
    pub const fn is_self_dependent(&self, stream_id: u32) -> bool {
        self.depends_on == stream_id
    }
}

/// A `SETTINGS` identifier (RFC 9113 §6.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SettingId {
    /// `0x1` — `SETTINGS_HEADER_TABLE_SIZE`.
    HeaderTableSize,
    /// `0x2` — `SETTINGS_ENABLE_PUSH`.
    EnablePush,
    /// `0x3` — `SETTINGS_MAX_CONCURRENT_STREAMS`.
    MaxConcurrentStreams,
    /// `0x4` — `SETTINGS_INITIAL_WINDOW_SIZE`.
    InitialWindowSize,
    /// `0x5` — `SETTINGS_MAX_FRAME_SIZE`.
    MaxFrameSize,
    /// `0x6` — `SETTINGS_MAX_HEADER_LIST_SIZE`.
    MaxHeaderListSize,
    /// Any other identifier, which RFC 9113 §6.5.2 requires to be **ignored**.
    ///
    /// Retained rather than dropped so a log can say which identifier a peer
    /// sent, which is the only way to debug an extension negotiation that went
    /// wrong.
    Unknown(u16),
}

impl SettingId {
    /// The wire value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::HeaderTableSize => 0x1,
            Self::EnablePush => 0x2,
            Self::MaxConcurrentStreams => 0x3,
            Self::InitialWindowSize => 0x4,
            Self::MaxFrameSize => 0x5,
            Self::MaxHeaderListSize => 0x6,
            Self::Unknown(n) => n,
        }
    }

    /// Decode a wire value.
    #[must_use]
    pub const fn from_u16(n: u16) -> Self {
        match n {
            0x1 => Self::HeaderTableSize,
            0x2 => Self::EnablePush,
            0x3 => Self::MaxConcurrentStreams,
            0x4 => Self::InitialWindowSize,
            0x5 => Self::MaxFrameSize,
            0x6 => Self::MaxHeaderListSize,
            other => Self::Unknown(other),
        }
    }

    /// The RFC's name, for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HeaderTableSize => "SETTINGS_HEADER_TABLE_SIZE",
            Self::EnablePush => "SETTINGS_ENABLE_PUSH",
            Self::MaxConcurrentStreams => "SETTINGS_MAX_CONCURRENT_STREAMS",
            Self::InitialWindowSize => "SETTINGS_INITIAL_WINDOW_SIZE",
            Self::MaxFrameSize => "SETTINGS_MAX_FRAME_SIZE",
            Self::MaxHeaderListSize => "SETTINGS_MAX_HEADER_LIST_SIZE",
            Self::Unknown(_) => "SETTINGS_UNKNOWN",
        }
    }
}

impl fmt::Display for SettingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(n) => write!(f, "SETTINGS_UNKNOWN(0x{n:04x})"),
            known => f.write_str(known.as_str()),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a frame could not be decoded.
///
/// Split into *our* failures and *the peer's* violations, because the two
/// produce completely different responses: a truncated read is a transport
/// condition that a retry may fix, and a `FRAME_SIZE_ERROR` is the peer's bug
/// that a `GOAWAY` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer bytes were available than the frame declared.
    ///
    /// A transport condition, not a protocol violation: it means the caller
    /// handed over a partial frame, which is what happens at a read boundary.
    /// The caller's correct response is to read more, not to send a `GOAWAY`.
    Truncated {
        /// How many bytes the frame needs.
        need: usize,
        /// How many were available.
        got: usize,
    },
    /// The payload length was wrong for the frame type (RFC 9113 §6).
    ///
    /// A connection error of type `FRAME_SIZE_ERROR` for `SETTINGS`, `PING`,
    /// `GOAWAY` and `RST_STREAM`; a stream error for `WINDOW_UPDATE` and
    /// `HEADERS`. The distinction is the caller's, because it needs the stream
    /// id, which is on the header — so this error carries the type rather than
    /// deciding.
    BadLength {
        /// The frame type.
        frame_type: FrameType,
        /// The length that arrived.
        length: u32,
        /// The length the RFC requires, when it is a single value.
        expected: &'static str,
    },
    /// The stream id was illegal for the frame type.
    ///
    /// Only `DATA`, `HEADERS`, `PRIORITY`, `RST_STREAM`, `PUSH_PROMISE` and
    /// `CONTINUATION` require a non-zero id; `SETTINGS`, `PING` and `GOAWAY`
    /// require zero, and `WINDOW_UPDATE` permits both depending on its scope.
    BadStreamId {
        /// The frame type.
        frame_type: FrameType,
        /// The id that arrived.
        stream_id: u32,
        /// What the RFC requires.
        expected: &'static str,
    },
    /// Padding was longer than the payload.
    ///
    /// RFC 9113 §6.1: *"If the length of the padding is the length of the frame
    /// payload or greater, the recipient MUST treat this as a connection error of
    /// type PROTOCOL_ERROR."* The check exists because the alternative is a
    /// slice index computed by subtracting a peer-controlled number, which is a
    /// panic in safe code and a memory-safety bug anywhere else.
    BadPadding {
        /// The pad length octet.
        pad_len: u8,
        /// The payload length it was subtracted from.
        length: u32,
    },
    /// A `WINDOW_UPDATE` carried a zero increment.
    ///
    /// RFC 9113 §6.9: a zero increment *"MUST be treated as a stream error of
    /// type PROTOCOL_ERROR"* when the frame names a stream, and as a connection
    /// error when it names the connection. The distinction is the caller's, so
    /// the raw values are carried.
    ZeroWindowIncrement {
        /// The stream id the frame named; `0` is the connection.
        stream_id: u32,
    },
    /// A header block fragment arrived while another was still open.
    ///
    /// RFC 9113 §6.10: the frame sequence for a header block *"MUST NOT be
    /// interleaved with any other frames"*. The decoder cannot detect this — it
    /// sees one frame at a time — so this variant exists for the connection
    /// layer, which is where the rule is enforceable.
    InterleavedHeaderBlock {
        /// The stream whose header block is still open.
        open_stream_id: u32,
        /// The frame that interrupted it.
        frame_type: FrameType,
    },
}

impl FrameError {
    /// The RFC code the peer's violation calls for.
    ///
    /// [`FrameError::Truncated`] has no code: it is not the peer's violation.
    /// Returning one anyway would send a `GOAWAY` for a partial read.
    #[must_use]
    pub const fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Truncated { .. } => None,
            Self::BadLength { .. }
            | Self::BadStreamId { .. }
            | Self::BadPadding { .. }
            | Self::InterleavedHeaderBlock { .. } => Some(ErrorCode::ProtocolError),
            // §6.9 makes a zero increment a PROTOCOL_ERROR, not a
            // FLOW_CONTROL_ERROR. The clipped spelling is deliberate: the errata
            // and several implementations disagree, and the RFC text wins.
            Self::ZeroWindowIncrement { .. } => Some(ErrorCode::ProtocolError),
        }
    }

    /// Whether this is a transport condition rather than a protocol violation.
    #[must_use]
    pub const fn is_transport(&self) -> bool {
        matches!(self, Self::Truncated { .. })
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { need, got } => {
                write!(f, "truncated frame: need {need} bytes, have {got}")
            }
            Self::BadLength {
                frame_type,
                length,
                expected,
            } => write!(
                f,
                "{frame_type} payload of {length} bytes is wrong: expected {expected}"
            ),
            Self::BadStreamId {
                frame_type,
                stream_id,
                expected,
            } => write!(f, "{frame_type} on stream {stream_id}: expected {expected}"),
            Self::BadPadding { pad_len, length } => write!(
                f,
                "pad length {pad_len} is not less than the {length}-byte payload"
            ),
            Self::ZeroWindowIncrement { stream_id } => {
                write!(f, "WINDOW_UPDATE increment is zero on stream {stream_id}")
            }
            Self::InterleavedHeaderBlock {
                open_stream_id,
                frame_type,
            } => write!(
                f,
                "{frame_type} arrived while stream {open_stream_id}'s header block was open"
            ),
        }
    }
}

impl std::error::Error for FrameError {}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse one frame from the front of `bytes`.
///
/// Returns the frame and how many bytes it consumed, so a caller reading a
/// stream can advance without guessing.
///
/// # Errors
///
/// * [`FrameError::Truncated`] when `bytes` holds less than the frame declares.
///   The caller reads more and calls again — this is the read-boundary case, not
///   a violation.
/// * Any other [`FrameError`] for a frame the RFC does not permit.
pub fn parse_frame(bytes: &[u8]) -> Result<(Frame<'_>, usize), FrameError> {
    let header = FrameHeader::parse(bytes)?;
    let total = header.total_len();
    if bytes.len() < total {
        return Err(FrameError::Truncated {
            need: total,
            got: bytes.len(),
        });
    }
    let payload = &bytes[FRAME_HEADER_LEN..total];
    let frame = decode(header, payload)?;
    Ok((frame, total))
}

/// Decode a frame given its already-parsed header and exact payload.
///
/// # Errors
///
/// Any [`FrameError`], as [`parse_frame`].
pub fn decode(header: FrameHeader, payload: &[u8]) -> Result<Frame<'_>, FrameError> {
    let FrameHeader {
        length,
        frame_type,
        flags,
        stream_id,
    } = header;
    // The invariant the rest of this function relies on. It cannot fail when
    // reached from `parse_frame`, and it is the only way to call `decode`
    // directly with a mismatched pair.
    if payload.len() != length as usize {
        return Err(FrameError::Truncated {
            need: length as usize,
            got: payload.len(),
        });
    }

    match frame_type {
        FrameType::Data => {
            require_nonzero(frame_type, stream_id)?;
            let (data, padding) = strip_padding(frame_type, flags, payload)?;
            Ok(Frame::Data {
                stream_id,
                flags,
                data,
                padding,
            })
        }
        FrameType::Headers => {
            require_nonzero(frame_type, stream_id)?;
            let mut rest = payload;
            let mut padding = None;
            if flags.padded() {
                let (pad, after) = take_pad_len(payload, length)?;
                padding = Some(pad);
                rest = after;
            }
            let mut priority = None;
            if flags.has_priority() {
                priority = Some(PrioritySpec::parse(rest)?);
                rest = &rest[PrioritySpec::LEN..];
            }
            // The priority field is not padding and must not be trimmed by the
            // pad length: RFC 9113 §6.2 orders the payload as pad-length,
            // priority, fragment, padding, so the trim applies to the fragment
            // only. Applying it to the whole remainder (priority included) would
            // be wrong by exactly five bytes on a frame that sets both flags.
            let fragment = strip_trailing_padding(rest, padding.unwrap_or(0), length)?;
            Ok(Frame::Headers {
                stream_id,
                flags,
                fragment,
                padding,
                priority,
            })
        }
        FrameType::Priority => {
            require_nonzero(frame_type, stream_id)?;
            if length != PrioritySpec::LEN as u32 {
                return Err(FrameError::BadLength {
                    frame_type,
                    length,
                    expected: "exactly 5 bytes",
                });
            }
            Ok(Frame::Priority {
                stream_id,
                spec: PrioritySpec::parse(payload)?,
            })
        }
        FrameType::RstStream => {
            require_nonzero(frame_type, stream_id)?;
            if length != 4 {
                return Err(FrameError::BadLength {
                    frame_type,
                    length,
                    expected: "exactly 4 bytes",
                });
            }
            let raw = u32::from_be_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]);
            // An unassigned code is not a violation (RFC 9113 §7). A `RST_STREAM`
            // carrying one is still a reset, so it must not be dropped.
            Ok(Frame::RstStream {
                stream_id,
                error: ErrorCode::from_u32(raw).unwrap_or(ErrorCode::InternalError),
            })
        }
        FrameType::Settings => {
            require_zero(frame_type, stream_id)?;
            if flags.ack() {
                // An ACK carries no payload. RFC 9113 §6.5: a non-empty ACK is a
                // FRAME_SIZE_ERROR, not something to read parameters from.
                if length != 0 {
                    return Err(FrameError::BadLength {
                        frame_type,
                        length,
                        expected: "0 bytes on an ACK",
                    });
                }
                return Ok(Frame::SettingsAck);
            }
            if length % 6 != 0 {
                return Err(FrameError::BadLength {
                    frame_type,
                    length,
                    expected: "a multiple of 6 bytes",
                });
            }
            let mut params = Vec::with_capacity(length as usize / 6);
            for chunk in payload.chunks_exact(6) {
                let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                params.push((SettingId::from_u16(id), value));
            }
            Ok(Frame::Settings { params })
        }
        FrameType::PushPromise => {
            require_nonzero(frame_type, stream_id)?;
            Ok(Frame::PushPromise { stream_id })
        }
        FrameType::Ping => {
            require_zero(frame_type, stream_id)?;
            if length != 8 {
                return Err(FrameError::BadLength {
                    frame_type,
                    length,
                    expected: "exactly 8 bytes",
                });
            }
            let mut payload8 = [0u8; 8];
            payload8.copy_from_slice(payload);
            Ok(Frame::Ping {
                flags,
                payload: payload8,
            })
        }
        FrameType::GoAway => {
            require_zero(frame_type, stream_id)?;
            if length < 8 {
                return Err(FrameError::BadLength {
                    frame_type,
                    length,
                    expected: "at least 8 bytes",
                });
            }
            let last_stream_id =
                u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
            let raw_error = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            Ok(Frame::GoAway {
                last_stream_id,
                error: ErrorCode::from_u32(raw_error),
                raw_error,
                debug: &payload[8..],
            })
        }
        FrameType::WindowUpdate => {
            if length != 4 {
                return Err(FrameError::BadLength {
                    frame_type,
                    length,
                    expected: "exactly 4 bytes",
                });
            }
            let increment = u32::from_be_bytes([
                payload[0] & 0x7f,
                payload[1],
                payload[2],
                payload[3],
            ]);
            if increment == 0 {
                return Err(FrameError::ZeroWindowIncrement { stream_id });
            }
            Ok(Frame::WindowUpdate {
                stream_id,
                increment,
            })
        }
        FrameType::Continuation => {
            require_nonzero(frame_type, stream_id)?;
            Ok(Frame::Continuation {
                stream_id,
                flags,
                fragment: payload,
            })
        }
        FrameType::Unknown(_) => Ok(Frame::Unknown {
            frame_type,
            length,
            stream_id,
        }),
    }
}

/// Require a non-zero stream id.
fn require_nonzero(frame_type: FrameType, stream_id: u32) -> Result<(), FrameError> {
    if stream_id == 0 {
        return Err(FrameError::BadStreamId {
            frame_type,
            stream_id,
            expected: "a non-zero stream id",
        });
    }
    Ok(())
}

/// Require a zero stream id.
fn require_zero(frame_type: FrameType, stream_id: u32) -> Result<(), FrameError> {
    if stream_id != 0 {
        return Err(FrameError::BadStreamId {
            frame_type,
            stream_id,
            expected: "stream id 0",
        });
    }
    Ok(())
}

/// Read the pad-length octet, validating it (RFC 9113 §6.1).
fn take_pad_len(payload: &[u8], length: u32) -> Result<(u8, &[u8]), FrameError> {
    let Some((&pad_len, rest)) = payload.split_first() else {
        return Err(FrameError::Truncated {
            need: 1,
            got: 0,
        });
    };
    // The comparison is against the *whole* payload length, not the remainder:
    // RFC 9113 §6.1 requires the pad length to be strictly less than the frame
    // payload length, and the pad-length octet is itself part of the payload. A
    // check against the remainder would accept `pad_len == length - 1` here and
    // then subtract to an empty slice, which is subtly different from what the
    // RFC permits.
    if u32::from(pad_len) >= length {
        return Err(FrameError::BadPadding { pad_len, length });
    }
    Ok((pad_len, rest))
}

/// Remove a leading pad-length octet and trailing padding from a `DATA` payload.
fn strip_padding(
    frame_type: FrameType,
    flags: Flags,
    payload: &[u8],
) -> Result<(&[u8], u8), FrameError> {
    if !flags.padded() {
        return Ok((payload, 0));
    }
    let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let (pad_len, rest) = take_pad_len(payload, length)?;
    let data = strip_trailing_padding(rest, pad_len, length)?;
    Ok((data, pad_len))
}

/// Trim `pad_len` bytes from the end.
fn strip_trailing_padding(
    rest: &[u8],
    pad_len: u8,
    length: u32,
) -> Result<&[u8], FrameError> {
    let pad = usize::from(pad_len);
    if rest.len() < pad {
        return Err(FrameError::BadPadding { pad_len, length });
    }
    Ok(&rest[..rest.len() - pad])
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

/// Serialise a frame into `out`.
///
/// # Panics
///
/// Not in practice: the only panic path is a payload longer than
/// [`MAX_FRAME_PAYLOAD`], which is unreachable in a debug build because the
/// length check below is a `debug_assert` and in a release build because
/// [`header_for`] clamps. The assertion is kept rather than replaced by silent
/// truncation, because a truncated length field desynchronises the connection
/// and a debug assertion names the bug at its source.
pub fn write_frame(frame: &Frame<'_>, out: &mut Vec<u8>) {
    match frame {
        Frame::Data {
            stream_id,
            flags,
            data,
            padding,
        } => {
            let pad = usize::from(*padding);
            // The pad-length octet is present **iff** PADDED was set, not iff
            // the padding is non-zero: `PADDED` with a zero pad length is legal
            // and still costs one byte in the payload.
            let mut payload =
                Vec::with_capacity(data.len() + pad + usize::from(flags.padded()));
            if flags.padded() {
                payload.push(*padding);
            }
            payload.extend_from_slice(data);
            payload.resize(payload.len() + pad, 0);
            push(
                header_for(payload.len(), FrameType::Data, *flags, *stream_id),
                &payload,
                out,
            );
        }
        Frame::Headers {
            stream_id,
            flags,
            fragment,
            padding,
            priority,
        } => {
            let pad = padding.map_or(0, usize::from);
            let mut payload =
                Vec::with_capacity(fragment.len() + PrioritySpec::LEN + usize::from(flags.padded()));
            if flags.padded() {
                payload.push(padding.unwrap_or(0));
            }
            if let Some(spec) = priority {
                payload.extend_from_slice(&spec.write());
            }
            payload.extend_from_slice(fragment);
            payload.resize(payload.len() + pad, 0);
            push(
                header_for(payload.len(), FrameType::Headers, *flags, *stream_id),
                &payload,
                out,
            );
        }
        Frame::Priority { stream_id, spec } => {
            push(
                header_for(
                    PrioritySpec::LEN,
                    FrameType::Priority,
                    Flags::none(),
                    *stream_id,
                ),
                &spec.write(),
                out,
            );
        }
        Frame::RstStream { stream_id, error } => {
            push(
                header_for(4, FrameType::RstStream, Flags::none(), *stream_id),
                &error.as_u32().to_be_bytes(),
                out,
            );
        }
        Frame::Settings { params } => {
            let mut payload = Vec::with_capacity(params.len() * 6);
            for (id, value) in params {
                payload.extend_from_slice(&id.as_u16().to_be_bytes());
                payload.extend_from_slice(&value.to_be_bytes());
            }
            push(
                header_for(payload.len(), FrameType::Settings, Flags::none(), 0),
                &payload,
                out,
            );
        }
        Frame::SettingsAck => {
            push(
                header_for(0, FrameType::Settings, Flags::from_bits(Flags::ACK), 0),
                &[],
                out,
            );
        }
        Frame::PushPromise { stream_id } => {
            // Deliberately written as an empty frame rather than refusing: this
            // encoder is used by tests as well as by the server, and a test that
            // wants to prove the *decoder* refuses a PUSH_PROMISE needs to be
            // able to send one.
            push(
                header_for(0, FrameType::PushPromise, Flags::none(), *stream_id),
                &[],
                out,
            );
        }
        Frame::Ping { flags, payload } => {
            push(header_for(8, FrameType::Ping, *flags, 0), &payload[..], out);
        }
        Frame::GoAway {
            last_stream_id,
            error,
            raw_error,
            debug,
        } => {
            let code = error.map_or(*raw_error, ErrorCode::as_u32);
            let mut payload = Vec::with_capacity(8 + debug.len());
            payload.extend_from_slice(&(last_stream_id & 0x7fff_ffff).to_be_bytes());
            payload.extend_from_slice(&code.to_be_bytes());
            payload.extend_from_slice(debug);
            push(
                header_for(payload.len(), FrameType::GoAway, Flags::none(), 0),
                &payload,
                out,
            );
        }
        Frame::WindowUpdate {
            stream_id,
            increment,
        } => {
            push(
                header_for(4, FrameType::WindowUpdate, Flags::none(), *stream_id),
                &(increment & 0x7fff_ffff).to_be_bytes(),
                out,
            );
        }
        Frame::Continuation {
            stream_id,
            flags,
            fragment,
        } => {
            push(
                header_for(fragment.len(), FrameType::Continuation, *flags, *stream_id),
                fragment,
                out,
            );
        }
        Frame::Unknown {
            frame_type,
            length,
            stream_id,
        } => {
            // A decoder never retains an unknown frame's payload (it has no
            // meaning here, and holding a peer-controlled buffer alive is a
            // memory-growth channel), so the encoder emits an **empty** frame of
            // the same type. Writing a header claiming `length` bytes without
            // the bytes is a framing desync; `length` is therefore reported
            // rather than trusted.
            debug_assert_eq!(
                *length, 0,
                "an unknown frame reached the encoder with a declared payload it does not carry"
            );
            push(
                header_for(0, *frame_type, Flags::none(), *stream_id),
                &[],
                out,
            );
        }
    }
}

/// Build a header, asserting the payload fits the 24-bit length field.
fn header_for(length: usize, frame_type: FrameType, flags: Flags, stream_id: u32) -> FrameHeader {
    debug_assert!(
        length <= MAX_FRAME_PAYLOAD,
        "a {length}-byte {frame_type} payload exceeds the 24-bit length field"
    );
    // `u32::try_from` rather than `as u32`: a truncating cast here would emit a
    // length that disagrees with the payload, which desynchronises the whole
    // connection. The fallback is unreachable outside a release build with an
    // oversized payload, and on that path the frame is better refused than
    // truncated — `MAX_FRAME_PAYLOAD` is what the format permits.
    let length = u32::try_from(length).unwrap_or(u32::MAX);
    FrameHeader {
        length: length.min(MAX_FRAME_PAYLOAD as u32),
        frame_type,
        flags,
        stream_id,
    }
}

/// Append a header and payload.
fn push(header: FrameHeader, payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&header.write());
    out.extend_from_slice(payload);
}

/// Serialise a frame into a fresh buffer.
#[must_use]
pub fn to_bytes(frame: &Frame<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + 64);
    write_frame(frame, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The header's three field positions, checked against the diagram in
    /// RFC 9113 §4.1 rather than against this implementation's own writer.
    #[test]
    fn a_frame_header_parses_the_rfc_layout() {
        // length = 0x000102 (258), type = HEADERS (0x1), flags = END_HEADERS,
        // stream = 0x00000005
        let bytes = [0x00, 0x01, 0x02, 0x01, 0x04, 0x00, 0x00, 0x00, 0x05];
        let h = FrameHeader::parse(&bytes).expect("parses");
        assert_eq!(h.length, 258);
        assert_eq!(h.frame_type, FrameType::Headers);
        assert_eq!(h.flags, Flags::from_bits(0x04));
        assert_eq!(h.stream_id, 5);
        assert_eq!(h.total_len(), 267, "length excludes the 9-byte header");
    }

    /// **The reserved bit must be ignored.** Reading it as part of the stream id
    /// gives an id of 2^31 or more, which then fails every "is this stream ours"
    /// check for a reason nobody can see. RFC 9113 §4.1.
    #[test]
    fn the_reserved_bit_is_masked_off_the_stream_id() {
        let bytes = [0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x01];
        let h = FrameHeader::parse(&bytes).expect("parses");
        assert_eq!(
            h.stream_id, 1,
            "the reserved bit must not reach the stream id"
        );

        // And the writer never sets it.
        let written = FrameHeader {
            length: 0,
            frame_type: FrameType::Ping,
            flags: Flags::none(),
            stream_id: u32::MAX,
        }
        .write();
        assert_eq!(written[5] & 0x80, 0, "the reserved bit must be sent as zero");
        assert_eq!(
            FrameHeader::parse(&written).expect("parses").stream_id,
            0x7fff_ffff,
            "the 31-bit id round-trips"
        );
    }

    #[test]
    fn a_truncated_header_is_reported_as_transport_not_protocol() {
        let e = FrameHeader::parse(&[0, 0, 0]).unwrap_err();
        assert!(matches!(e, FrameError::Truncated { need: 9, got: 3 }));
        assert!(e.is_transport(), "a short read is not the peer's violation");
        assert_eq!(
            e.code(),
            None,
            "a partial read must not produce a GOAWAY code"
        );
    }

    /// The wire values of the frame types, from RFC 9113 §6's table.
    #[test]
    fn frame_type_values_match_rfc_9113_section_6() {
        for (t, v) in [
            (FrameType::Data, 0x0u8),
            (FrameType::Headers, 0x1),
            (FrameType::Priority, 0x2),
            (FrameType::RstStream, 0x3),
            (FrameType::Settings, 0x4),
            (FrameType::PushPromise, 0x5),
            (FrameType::Ping, 0x6),
            (FrameType::GoAway, 0x7),
            (FrameType::WindowUpdate, 0x8),
            (FrameType::Continuation, 0x9),
        ] {
            assert_eq!(t.as_u8(), v);
            assert_eq!(FrameType::from_u8(v), t);
            assert!(t.is_known());
        }
        assert_eq!(FrameType::from_u8(0x0a), FrameType::Unknown(0x0a));
        assert!(!FrameType::Unknown(0x0a).is_known());
    }

    // -- round trips --------------------------------------------------------

    /// Serialise `frame`, parse it back, and assert the round trip is exact.
    ///
    /// # Why this asserts inside rather than returning the parsed frame
    ///
    /// `Frame<'a>` borrows the bytes it was parsed from — frame payloads are
    /// slices, not copies, so a DATA frame does not allocate. A helper returning
    /// `Frame<'_>` would return a value borrowing its own local buffer, which the
    /// borrow checker rejected, correctly.
    ///
    /// Copying every payload into an owned frame would sidestep that and would
    /// also stop testing the property that matters: that the payload is a *slice
    /// of the input* at the right offset. So the assertion happens here, where
    /// both the buffer and the parse are alive.
    fn assert_round_trips(original: &Frame<'_>) {
        let bytes = to_bytes(original);
        let (parsed, used) = parse_frame(&bytes).expect("must parse what we wrote");
        assert_eq!(used, bytes.len(), "the whole frame must be consumed");
        assert_eq!(&parsed, original, "the frame must round-trip exactly");
    }

    #[test]
    fn a_data_frame_round_trips() {
        let original = Frame::Data {
            stream_id: 1,
            flags: Flags::from_bits(Flags::END_STREAM),
            data: b"hello",
            padding: 0,
        };
        assert_round_trips(&original.clone());
    }

    /// Padding participates in **flow control**: the `DATA` length field counts
    /// the pad-length octet and the padding, so a decoder that returns only the
    /// payload makes the connection drift out of sync with the peer's window.
    /// RFC 9113 §6.1, §5.2.2.
    #[test]
    fn a_padded_data_frame_reports_its_padding_and_hides_it() {
        let original = Frame::Data {
            stream_id: 1,
            flags: Flags::from_bits(Flags::PADDED | Flags::END_STREAM),
            data: b"abc",
            padding: 4,
        };
        let bytes = to_bytes(&original);
        // 9 header + 1 pad-length + 3 data + 4 padding.
        assert_eq!(bytes.len(), 17);
        assert_eq!(
            bytes[0..3],
            [0, 0, 8],
            "the length counts the pad octet and the padding"
        );

        // The payload is inspected from a fresh parse, because a `Frame` borrows
        // the bytes it came from and cannot outlive this function's buffer.
        let bytes = to_bytes(&original);
        let (parsed, _) = parse_frame(&bytes).expect("must parse what we wrote");
        match parsed {
            Frame::Data { data, padding, .. } => {
                assert_eq!(data, b"abc", "padding must not appear as data");
                assert_eq!(padding, 4);
            }
            other => panic!("expected DATA, got {other:?}"),
        }
    }

    /// The padding check is a security check: the alternative is a slice index
    /// computed by subtracting a peer-controlled number.
    #[test]
    fn padding_longer_than_the_payload_is_refused() {
        // pad length 5, payload length 5: not strictly less, so refused.
        let bytes = [0, 0, 5, 0x0, 0x8, 0, 0, 0, 1, 5, 0, 0, 0, 0];
        let e = parse_frame(&bytes).unwrap_err();
        assert_eq!(e, FrameError::BadPadding { pad_len: 5, length: 5 });
        assert_eq!(e.code(), Some(ErrorCode::ProtocolError));

        // And exactly one less is accepted.
        let ok = [0, 0, 5, 0x0, 0x8, 0, 0, 0, 1, 4, 0, 0, 0, 0];
        assert!(parse_frame(&ok).is_ok());
    }

    #[test]
    fn a_headers_frame_round_trips() {
        let original = Frame::Headers {
            stream_id: 3,
            flags: Flags::from_bits(Flags::END_HEADERS | Flags::END_STREAM),
            fragment: b"\x82\x86",
            padding: None,
            priority: None,
        };
        assert_round_trips(&original.clone());
    }

    /// `HEADERS` with the `PRIORITY` flag is five bytes longer; skipping that
    /// check shifts the header block by five bytes and every subsequent field is
    /// garbage. RFC 9113 §6.2.
    #[test]
    fn a_headers_frame_with_priority_round_trips_and_splits_correctly() {
        let original = Frame::Headers {
            stream_id: 5,
            flags: Flags::from_bits(Flags::END_HEADERS | Flags::PRIORITY),
            fragment: b"\x82",
            padding: None,
            priority: Some(PrioritySpec {
                exclusive: true,
                depends_on: 3,
                weight: 200,
            }),
        };
        // The priority block sits between the 9-byte header and the fragment, so
        // the fragment's offset is what proves it was skipped rather than
        // swallowed. Parsed here, from a buffer that is still alive.
        let bytes = to_bytes(&original);
        let (parsed, used) = parse_frame(&bytes).expect("must parse what we wrote");
        assert_eq!(used, bytes.len(), "the whole frame must be consumed");
        match parsed {
            Frame::Headers {
                fragment, priority, ..
            } => {
                assert_eq!(fragment, b"\x82", "the fragment must start after the 5 bytes");
                assert_eq!(priority.expect("present").depends_on, 3);
            }
            other => panic!("expected HEADERS, got {other:?}"),
        }
    }

    #[test]
    fn a_padded_headers_frame_round_trips() {
        let original = Frame::Headers {
            stream_id: 7,
            flags: Flags::from_bits(Flags::END_HEADERS | Flags::PADDED),
            fragment: b"\x82\x86\x84",
            padding: Some(2),
            priority: None,
        };
        assert_round_trips(&original.clone());
    }

    #[test]
    fn a_priority_frame_round_trips() {
        let original = Frame::Priority {
            stream_id: 9,
            spec: PrioritySpec {
                exclusive: false,
                depends_on: 1,
                weight: 15,
            },
        };
        assert_round_trips(&original.clone());
    }

    /// RFC 9113 §5.3.1: *"A stream cannot depend on itself"* — and it is a
    /// **stream** error, not a connection error.
    #[test]
    fn a_self_dependent_priority_is_detected() {
        let spec = PrioritySpec {
            exclusive: false,
            depends_on: 9,
            weight: 1,
        };
        assert!(spec.is_self_dependent(9));
        assert!(!spec.is_self_dependent(11));
    }

    #[test]
    fn an_rst_stream_frame_round_trips() {
        let original = Frame::RstStream {
            stream_id: 1,
            error: ErrorCode::EnhanceYourCalm,
        };
        assert_round_trips(&original.clone());
    }

    #[test]
    fn a_settings_frame_round_trips() {
        let original = Frame::Settings {
            params: vec![
                (SettingId::MaxConcurrentStreams, 100),
                (SettingId::InitialWindowSize, 65_535),
                (SettingId::Unknown(0xbeef), 1),
            ],
        };
        assert_round_trips(&original.clone());
    }

    #[test]
    fn a_settings_ack_round_trips() {
        assert_round_trips(&Frame::SettingsAck);
    }

    #[test]
    fn a_ping_round_trips() {
        let original = Frame::Ping {
            flags: Flags::none(),
            payload: *b"12345678",
        };
        assert_round_trips(&original.clone());

        let ack = Frame::Ping {
            flags: Flags::from_bits(Flags::ACK),
            payload: [0; 8],
        };
        assert_round_trips(&ack.clone());
    }

    #[test]
    fn a_goaway_frame_round_trips() {
        let original = Frame::GoAway {
            last_stream_id: 5,
            error: Some(ErrorCode::ProtocolError),
            raw_error: 1,
            debug: b"because",
        };
        assert_round_trips(&original.clone());
    }

    /// An unassigned code is retained rather than dropped: RFC 9113 §7 says it
    /// must not be treated as an error in itself, so the frame is still a
    /// `GOAWAY` and the number is still visible in the log.
    #[test]
    fn a_goaway_with_an_unassigned_code_is_not_dropped() {
        let bytes = {
            let mut v = Vec::new();
            v.extend_from_slice(&[0, 0, 8, 0x7, 0x0, 0, 0, 0, 0]);
            v.extend_from_slice(&3u32.to_be_bytes());
            v.extend_from_slice(&0xfeed_u32.to_be_bytes());
            v
        };
        let (frame, _) = parse_frame(&bytes).expect("parses");
        match frame {
            Frame::GoAway {
                last_stream_id,
                error,
                raw_error,
                ..
            } => {
                assert_eq!(last_stream_id, 3);
                assert_eq!(error, None);
                assert_eq!(raw_error, 0xfeed);
            }
            other => panic!("expected GOAWAY, got {other:?}"),
        }
    }

    #[test]
    fn a_window_update_frame_round_trips() {
        let original = Frame::WindowUpdate {
            stream_id: 0,
            increment: 65_535,
        };
        assert_round_trips(&original.clone());

        let stream = Frame::WindowUpdate {
            stream_id: 1,
            increment: 1,
        };
        assert_round_trips(&stream.clone());
    }

    /// RFC 9113 §6.9: a zero increment is a `PROTOCOL_ERROR`. Representing it
    /// would let it reach the flow-control layer, which would then add nothing
    /// and silently report success.
    #[test]
    fn a_zero_window_increment_is_refused() {
        let bytes = [0, 0, 4, 0x8, 0x0, 0, 0, 0, 1, 0, 0, 0, 0];
        let e = parse_frame(&bytes).unwrap_err();
        assert_eq!(e, FrameError::ZeroWindowIncrement { stream_id: 1 });
        assert_eq!(e.code(), Some(ErrorCode::ProtocolError));
    }

    #[test]
    fn a_continuation_frame_round_trips() {
        let original = Frame::Continuation {
            stream_id: 1,
            flags: Flags::from_bits(Flags::END_HEADERS),
            fragment: b"\x00\x01\x02",
        };
        assert_round_trips(&original.clone());
    }

    /// RFC 9113 §4.1: an unrecognised frame type must be **ignored**, which
    /// requires it to be representable rather than rejected by the decoder.
    #[test]
    fn an_unknown_frame_type_is_returned_rather_than_refused() {
        let bytes = [0, 0, 3, 0xab, 0x0, 0, 0, 0, 0, 1, 2, 3];
        let (frame, used) = parse_frame(&bytes).expect("an unknown type is not an error");
        assert_eq!(used, 12);
        assert_eq!(
            frame,
            Frame::Unknown {
                frame_type: FrameType::Unknown(0xab),
                length: 3,
                stream_id: 0,
            }
        );
    }

    // -- malformed inputs ---------------------------------------------------

    #[test]
    fn a_truncated_payload_is_reported_with_the_size_needed() {
        // A PING declaring 8 bytes with only 3 present.
        let bytes = [0, 0, 8, 0x6, 0x0, 0, 0, 0, 0, 1, 2, 3];
        let e = parse_frame(&bytes).unwrap_err();
        assert_eq!(e, FrameError::Truncated { need: 17, got: 12 });
        assert!(e.is_transport());
    }

    /// Each fixed-length frame type, checked against RFC 9113 §6.
    ///
    /// # Why each case carries its own stream id
    ///
    /// This test used `bytes[8] = 1` for every case, and PING failed with
    /// `BadStreamId` rather than `BadLength` — correctly: PING, SETTINGS and
    /// GOAWAY are connection-level and must carry stream id 0, and the parser
    /// checks that before the length. The test was asserting one error while
    /// triggering a different, earlier one, which is a test that cannot fail for
    /// its own reason. The stream id is now a per-case field so the length is the
    /// only thing wrong.
    ///
    /// Only `WINDOW_UPDATE` is stream-scoped, and its wrong-length form is a
    /// 4-byte payload rather than the required 4 + 1.
    #[test]
    fn a_wrong_length_is_refused_for_every_fixed_size_frame() {
        // (type, wrong length, name, stream id)
        let cases: [(u8, u32, &str, u32); 4] = [
            (0x3, 3, "RST_STREAM", 1),
            (0x6, 7, "PING", 0),
            (0x7, 7, "GOAWAY", 0),
            (0x8, 5, "WINDOW_UPDATE", 1),
        ];
        for (type_byte, length, name, stream_id) in cases {
            let mut bytes = vec![0u8; 9 + length as usize];
            bytes[0] = (length >> 16) as u8;
            bytes[1] = (length >> 8) as u8;
            bytes[2] = length as u8;
            bytes[3] = type_byte;
            bytes[4..8].copy_from_slice(&stream_id.to_be_bytes());
            let e = parse_frame(&bytes).unwrap_err();
            assert!(
                matches!(e, FrameError::BadLength { .. }),
                "{name} with {length} bytes should be a length error, got {e:?}"
            );
            assert_eq!(e.code(), Some(ErrorCode::ProtocolError));
        }
    }

    /// `SETTINGS` is a list of 6-byte entries; a payload that is not a multiple
    /// of six cannot be decoded, and guessing at its boundary is how a parameter
    /// is read from the wrong offset. RFC 9113 §6.5.
    #[test]
    fn a_settings_payload_not_a_multiple_of_six_is_refused() {
        let bytes = [0, 0, 5, 0x4, 0x0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
        let e = parse_frame(&bytes).unwrap_err();
        assert!(matches!(e, FrameError::BadLength { length: 5, .. }));
    }

    /// RFC 9113 §6.5: a `SETTINGS` ACK with a payload is a `FRAME_SIZE_ERROR`.
    /// Reading parameters from it would treat an acknowledgement as new settings.
    #[test]
    fn a_settings_ack_with_a_payload_is_refused() {
        let bytes = [0, 0, 6, 0x4, 0x1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1];
        let e = parse_frame(&bytes).unwrap_err();
        assert!(matches!(e, FrameError::BadLength { length: 6, .. }));
    }

    /// `SETTINGS`, `PING` and `GOAWAY` are connection-scoped and carry stream id
    /// zero; a non-zero id means the sender believes they are stream frames.
    /// RFC 9113 §6.5, §6.7, §6.8.
    #[test]
    fn a_connection_frame_with_a_stream_id_is_refused() {
        for (type_byte, length) in [(0x4u8, 0u32), (0x6, 8), (0x7, 8)] {
            let mut bytes = vec![0u8; 9 + length as usize];
            bytes[2] = length as u8;
            bytes[3] = type_byte;
            bytes[8] = 1; // non-zero stream id
            let e = parse_frame(&bytes).unwrap_err();
            assert!(
                matches!(e, FrameError::BadStreamId { stream_id: 1, .. }),
                "type 0x{type_byte:x} should refuse a stream id, got {e:?}"
            );
        }
    }

    /// `DATA` on stream 0 is a connection error: there is no stream for the
    /// bytes to belong to. RFC 9113 §6.1.
    #[test]
    fn a_stream_frame_with_stream_id_zero_is_refused() {
        for type_byte in [0x0u8, 0x1, 0x2, 0x3, 0x9] {
            let mut bytes = vec![0u8; 9];
            bytes[3] = type_byte;
            bytes[8] = 0;
            let e = parse_frame(&bytes).unwrap_err();
            assert!(
                matches!(e, FrameError::BadStreamId { stream_id: 0, .. }),
                "type 0x{type_byte:x} should refuse stream 0, got {e:?}"
            );
        }
    }

    /// A `PRIORITY` frame is exactly five bytes of payload. §6.3.
    #[test]
    fn a_priority_frame_of_the_wrong_length_is_refused() {
        let bytes = [0, 0, 4, 0x2, 0x0, 0, 0, 0, 1, 0, 0, 0, 0];
        let e = parse_frame(&bytes).unwrap_err();
        assert!(matches!(e, FrameError::BadLength { length: 4, .. }));
    }

    // -- flags --------------------------------------------------------------

    /// **The same bit means different things on different frames.** A shared
    /// flag enum would read a `SETTINGS` acknowledgement as an end-of-stream.
    /// RFC 9113 §6.1, §6.5, §6.7.
    #[test]
    fn the_same_bit_is_named_per_frame_type() {
        let one = Flags::from_bits(0x1);
        assert!(one.end_stream(), "on DATA and HEADERS it is END_STREAM");
        assert!(one.ack(), "on SETTINGS and PING it is ACK");

        let twenty = Flags::from_bits(0x20);
        assert!(twenty.has_priority(), "on HEADERS it is PRIORITY");
        assert!(
            !twenty.padded(),
            "0x20 is not PADDED; that is 0x8 and conflating them shifts the fragment"
        );

        assert_eq!(Flags::from_bits(0x1).describe(FrameType::Settings), "ACK");
        assert_eq!(
            Flags::from_bits(0x1).describe(FrameType::Data),
            "END_STREAM"
        );
        assert_eq!(Flags::none().describe(FrameType::Data), "-");
        // A bit with no meaning on this frame type is not named.
        assert_eq!(Flags::from_bits(0x80).describe(FrameType::Ping), "-");
    }

    // -- headers and limits -------------------------------------------------

    #[test]
    fn the_client_preface_is_the_rfc_bytes() {
        assert_eq!(CLIENT_PREFACE, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        assert_eq!(CLIENT_PREFACE.len(), 24, "RFC 9113 §3.4 specifies 24 bytes");
    }

    /// The length field is 24 bits, so the format itself caps a payload at
    /// 2^24 - 1, and `SETTINGS_MAX_FRAME_SIZE`'s ceiling is that value.
    #[test]
    fn the_payload_limit_is_the_24_bit_maximum() {
        assert_eq!(MAX_FRAME_PAYLOAD, 16_777_215);
        assert_eq!(MAX_FRAME_PAYLOAD, (1 << 24) - 1);
        assert!(DEFAULT_MAX_FRAME_SIZE < MAX_FRAME_PAYLOAD as u32);
    }

    /// A large frame round-trips through the three length octets.
    #[test]
    fn a_frame_near_the_length_limit_round_trips() {
        let data = vec![0x5au8; 70_000];
        let original = Frame::Data {
            stream_id: 1,
            flags: Flags::none(),
            data: &data,
            padding: 0,
        };
        let bytes = to_bytes(&original);
        assert_eq!(bytes.len(), 9 + 70_000);
        assert_eq!(&bytes[0..3], &[0x01, 0x11, 0x70], "70000 = 0x011170");
        let (parsed, used) = parse_frame(&bytes).expect("parses");
        assert_eq!(used, bytes.len());
        assert_eq!(parsed, original);
    }

    /// `SETTINGS` identifiers, from RFC 9113 §6.5.2.
    #[test]
    fn setting_ids_match_rfc_9113_section_6_5_2() {
        for (id, v) in [
            (SettingId::HeaderTableSize, 0x1u16),
            (SettingId::EnablePush, 0x2),
            (SettingId::MaxConcurrentStreams, 0x3),
            (SettingId::InitialWindowSize, 0x4),
            (SettingId::MaxFrameSize, 0x5),
            (SettingId::MaxHeaderListSize, 0x6),
        ] {
            assert_eq!(id.as_u16(), v);
            assert_eq!(SettingId::from_u16(v), id);
        }
        assert_eq!(SettingId::from_u16(0x7), SettingId::Unknown(0x7));
    }

    /// Every error renders something an operator can act on.
    #[test]
    fn every_frame_error_renders() {
        let errors = [
            FrameError::Truncated { need: 9, got: 1 },
            FrameError::BadLength {
                frame_type: FrameType::Ping,
                length: 3,
                expected: "8",
            },
            FrameError::BadStreamId {
                frame_type: FrameType::Data,
                stream_id: 0,
                expected: "non-zero",
            },
            FrameError::BadPadding {
                pad_len: 9,
                length: 4,
            },
            FrameError::ZeroWindowIncrement { stream_id: 0 },
            FrameError::InterleavedHeaderBlock {
                open_stream_id: 1,
                frame_type: FrameType::Data,
            },
        ];
        for e in errors {
            let s = e.to_string();
            assert!(!s.is_empty());
            assert!(!s.contains('\n'));
        }
    }
}
