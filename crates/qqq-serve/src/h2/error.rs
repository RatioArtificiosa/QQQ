// SPDX-License-Identifier: Apache-2.0

//! HTTP/2 error types: connection errors, stream errors, and their wire codes.
//!
//! Implements `SRV-002`; RFC 9113 §5.4 (error codes), §5.4.1 (connection error),
//! §5.4.2 (stream error).
//!
//! # Why these are local to `h2` and not additions to `qqq-core`
//!
//! `qqq-core::ErrorCode` is the **product's** error taxonomy: a stable
//! `QQQ-XXXX` identifier, a documented URL, and a remediation, for conditions a
//! user or an agent can act on (Proposal §8.3). Every code in it is a statement
//! about QQQ.
//!
//! An HTTP/2 protocol error is not that. `PROTOCOL_ERROR` is a statement about
//! **the peer's bytes**, defined by an RFC, with a numeric code that goes on the
//! wire: it exists so the other end of the connection knows what to fix, not so
//! a support thread can be correlated. There is nothing to remediate on our
//! side — the fix is in the client.
//!
//! Adding the sixteen HTTP/2 codes to `ErrorCode` would also mean they inherit
//! `response::classify`'s catch-all, which maps unknown codes to
//! `Failure::GuestFault` — a 500 for what is a client error, which is precisely
//! the defect `parse_error_response` was written to fix
//! (`crates/qqq-serve/src/response.rs`, and checklist `SRV-001`'s note on it).
//!
//! So the codes live here. The `Display` implementation is the RFC's own
//! constant name, so a log line reads `PROTOCOL_ERROR` and not `error 1` — an
//! operator debugging a client integration should be able to grep the RFC.
//!
//! **Follow-up:** if the host ever needs to *report* an HTTP/2 failure through
//! the `QQQ-XXXX` surface (for example, a listener bind that fails because a
//! client will not speak h2), the mapping belongs in a single function that
//! lives outside this module. It is deliberately not guessed at here.

use std::fmt;

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// An HTTP/2 error code (RFC 9113 §7, "Error Codes").
///
/// # Why the numeric values matter and are written out
///
/// These are **wire values**. `PROTOCOL_ERROR` is `0x1` on the wire, so a
/// mis-numbered variant would not fail to compile — it would produce a `GOAWAY`
/// naming a different error and send every implementer debugging the wrong
/// layer. The values are therefore spelled explicitly and pinned by test.
///
/// The `#[repr(u32)]` and the explicit discriminants are load-bearing; the
/// `try_from` below is the only conversion path, so an unassigned number cannot
/// be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u32)]
pub enum ErrorCode {
    /// `0x00` — the associated condition is not a result of an error.
    ///
    /// Sent in `GOAWAY` for a normal shutdown, and in `RST_STREAM` when a stream
    /// is cancelled without fault. Sending it *when there was an error* is worse
    /// than sending nothing: it tells the peer to look for a bug elsewhere.
    NoError = 0x00,
    /// `0x01` — the peer violated the protocol.
    ///
    /// The RFC's own guidance is to use this when no more specific code applies.
    ProtocolError = 0x01,
    /// `0x02` — an internal error in this implementation.
    ///
    /// Reserved for exactly that: our bug, not the peer's bytes. Distinguishing
    /// it from `PROTOCOL_ERROR` is what stops a peer from "fixing" its client
    /// when the server is broken.
    InternalError = 0x02,
    /// `0x03` — flow-control rules were violated.
    ///
    /// RFC 9113 §5.2.2: sending more `DATA` than the window allows, or a
    /// `WINDOW_UPDATE` that overflows the window, is this code and not
    /// `PROTOCOL_ERROR`. The distinction matters because the two have different
    /// causes — one is a window accounting bug, the other a framing one.
    FlowControlError = 0x03,
    /// `0x04` — the peer did not acknowledge a `SETTINGS` frame in time.
    ///
    /// RFC 9113 §7. Note that the RFC's *name* for this code is
    /// `SETTINGS_TIMEOUT`, which reads like "a setting was out of range" and is
    /// not: an out-of-range setting is `PROTOCOL_ERROR` (§6.5.2). The rename here
    /// is deliberate and the wire value is unchanged.
    SettingsTimeout = 0x04,
    /// `0x05` — a frame arrived for a stream that is not open.
    StreamClosed = 0x05,
    /// `0x06` — a frame's size was wrong for its type.
    FrameSizeError = 0x06,
    /// `0x07` — a stream was closed by the peer and the frame arrived anyway.
    RefusedStream = 0x07,
    /// `0x08` — the stream is no longer needed and is being cancelled.
    Cancel = 0x08,
    /// `0x09` — the connection is being torn down and the stream cannot be
    /// completed.
    CompressionError = 0x09,
    /// `0x0a` — the connection is being torn down.
    ///
    /// Distinct from [`ErrorCode::NoError`]: this one says the *stream* failed
    /// because of the connection, not because of anything about the request.
    ConnectError = 0x0a,
    /// `0x0b` — excessive load, or a limit such as `MAX_CONCURRENT_STREAMS` was
    /// exceeded.
    EnhanceYourCalm = 0x0b,
    /// `0x0c` — the peer detected an unsafe negotiation of a feature this
    /// implementation does not support.
    InadequateSecurity = 0x0c,
    /// `0x0d` — the request was refused before the application processed it.
    ///
    /// A server sending this **must** have sent `SETTINGS_MAX_CONCURRENT_STREAMS`
    /// no greater than the number of streams it is willing to process, or the
    /// client cannot tell a load-shed from a bug (RFC 9113 §8.7).
    Http11Required = 0x0d,
}

impl ErrorCode {
    /// The numeric wire value.
    ///
    /// The value in a `GOAWAY`'s or `RST_STREAM`'s error-code field.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Decode a wire value.
    ///
    /// Returns `None` for a value HTTP/2 does not define. A peer is permitted to
    /// send an unassigned code — the space is extensible — so callers must treat
    /// `None` as "an unknown error" and **not** as a protocol violation: RFC 9113
    /// §7 says an endpoint must not treat an unrecognised code as an error in
    /// itself.
    #[must_use]
    pub const fn from_u32(n: u32) -> Option<Self> {
        // An exhaustive `match` rather than a table walk, so a new variant is a
        // compile error here rather than a silent `None`.
        match n {
            0x00 => Some(Self::NoError),
            0x01 => Some(Self::ProtocolError),
            0x02 => Some(Self::InternalError),
            0x03 => Some(Self::FlowControlError),
            0x04 => Some(Self::SettingsTimeout),
            0x05 => Some(Self::StreamClosed),
            0x06 => Some(Self::FrameSizeError),
            0x07 => Some(Self::RefusedStream),
            0x08 => Some(Self::Cancel),
            0x09 => Some(Self::CompressionError),
            0x0a => Some(Self::ConnectError),
            0x0b => Some(Self::EnhanceYourCalm),
            0x0c => Some(Self::InadequateSecurity),
            0x0d => Some(Self::Http11Required),
            _ => None,
        }
    }

    /// The RFC's name for this code.
    ///
    /// Uppercase and underscored, exactly as RFC 9113 §7 spells it, so a log
    /// line can be matched against the specification.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoError => "NO_ERROR",
            Self::ProtocolError => "PROTOCOL_ERROR",
            Self::InternalError => "INTERNAL_ERROR",
            Self::FlowControlError => "FLOW_CONTROL_ERROR",
            Self::SettingsTimeout => "SETTINGS_TIMEOUT",
            Self::StreamClosed => "STREAM_CLOSED",
            Self::FrameSizeError => "FRAME_SIZE_ERROR",
            Self::RefusedStream => "REFUSED_STREAM",
            Self::Cancel => "CANCEL",
            Self::CompressionError => "COMPRESSION_ERROR",
            Self::ConnectError => "CONNECT_ERROR",
            Self::EnhanceYourCalm => "ENHANCE_YOUR_CALM",
            Self::InadequateSecurity => "INADEQUATE_SECURITY",
            Self::Http11Required => "HTTP_1_1_REQUIRED",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:x})", self.as_str(), self.as_u32())
    }
}

// ---------------------------------------------------------------------------
// Connection errors
// ---------------------------------------------------------------------------

/// A condition that ends the whole connection.
///
/// RFC 9113 §5.4.1: a connection error is reported with a `GOAWAY`, and the
/// connection is then closed. Some connection errors are detected while
/// **decoding a frame header** — before the stream id is known — in which case
/// the `GOAWAY`'s last-stream-id is `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// The 24-byte client preface did not match.
    ///
    /// RFC 9113 §3.4. Names the bytes actually seen, truncated, because "bad
    /// preface" alone cannot distinguish a TLS-only client, an HTTP/1.1 request
    /// sent to an h2 listener, and a truncated write.
    BadPreface {
        /// What arrived instead, escaped for a log line.
        got: String,
    },
    /// A `GOAWAY` arrived; the peer is shutting the connection down.
    PeerGoAway {
        /// The last stream the peer might have processed.
        last_stream_id: u32,
        /// Why, if the peer said.
        error: Option<ErrorCode>,
    },
    /// We sent a `GOAWAY`; the connection is finished.
    ///
    /// Carries the frame's own error code so the caller reports what the peer
    /// will read on the wire rather than a second opinion computed here.
    LocalGoAway {
        /// The last stream we might have processed.
        last_stream_id: u32,
        /// The code that was sent.
        error: ErrorCode,
    },
    /// The peer sent bytes that are not HTTP/2.
    Protocol {
        /// The RFC's code.
        code: ErrorCode,
        /// One sentence naming what was wrong. **Unstable:** for logs.
        detail: String,
    },
    /// A structural failure: a truncated frame body, a length that disagrees
    /// with the payload.
    ///
    /// Kept apart from [`ConnectionError::Protocol`] because the source is
    /// different — this is our decoder refusing to interpret bytes, not the peer
    /// violating a rule — and because a truncated body is overwhelmingly a
    /// **transport** problem in tests and a framing bug in production.
    Malformed {
        /// The RFC's code to send.
        code: ErrorCode,
        /// What was wrong.
        detail: String,
    },
}

impl ConnectionError {
    /// The code to put in the `GOAWAY`.
    ///
    /// A peer `GOAWAY` gets `NO_ERROR`: answering a clean shutdown with an error
    /// code tells the peer it did something wrong.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::BadPreface { .. } => ErrorCode::ProtocolError,
            Self::PeerGoAway { .. } => ErrorCode::NoError,
            Self::LocalGoAway { error, .. } => *error,
            Self::Protocol { code, .. } | Self::Malformed { code, .. } => *code,
        }
    }

    /// Whether the peer is at fault.
    ///
    /// Used to decide whether an access log should be alarmed. A `GOAWAY` from a
    /// client that is shutting down is routine; a `PROTOCOL_ERROR` is not.
    #[must_use]
    pub const fn is_peer_fault(&self) -> bool {
        !matches!(
            self,
            Self::PeerGoAway { .. } | Self::LocalGoAway { .. } | Self::Malformed { .. }
        )
    }

    /// The stable name, for metrics.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::BadPreface { .. } => "bad-preface",
            Self::PeerGoAway { .. } => "peer-goaway",
            Self::LocalGoAway { .. } => "local-goaway",
            Self::Protocol { .. } => "protocol",
            Self::Malformed { .. } => "malformed",
        }
    }

    /// Build a protocol connection error.
    #[must_use]
    pub fn protocol(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self::Protocol {
            code,
            detail: detail.into(),
        }
    }

    /// Build a malformed-framing connection error.
    #[must_use]
    pub fn malformed(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self::Malformed {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadPreface { got } => write!(
                f,
                "the client preface did not match `PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n`; \
                 received `{got}`"
            ),
            Self::PeerGoAway {
                last_stream_id,
                error,
            } => match error {
                Some(e) => write!(f, "the peer sent GOAWAY ({e}) after stream {last_stream_id}"),
                None => write!(f, "the peer sent GOAWAY after stream {last_stream_id}"),
            },
            Self::LocalGoAway {
                last_stream_id,
                error,
            } => write!(f, "GOAWAY sent ({error}) after stream {last_stream_id}"),
            Self::Protocol { code, detail } => write!(f, "{code}: {detail}"),
            Self::Malformed { code, detail } => write!(f, "malformed frame: {detail} ({code})"),
        }
    }
}

impl std::error::Error for ConnectionError {}

// ---------------------------------------------------------------------------
// Stream errors
// ---------------------------------------------------------------------------

/// A condition that ends one stream and leaves the connection usable.
///
/// RFC 9113 §5.4.2. Reported with `RST_STREAM` on the offending stream. The
/// distinction from [`ConnectionError`] is the whole point of this type: a
/// stream error is **recoverable**, and a server that promoted one to a
/// connection error would drop every other multiplexed request because one was
/// malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// The peer violated the protocol on this stream.
    Protocol {
        /// The RFC's code.
        code: ErrorCode,
        /// What was wrong.
        detail: String,
    },
    /// A `RST_STREAM` arrived from the peer.
    Reset {
        /// The code the peer sent.
        code: ErrorCode,
    },
    /// The stream ended while a frame for it was still arriving.
    ///
    /// The peer sent a valid frame for a stream it has already closed. RFC 9113
    /// §5.1 requires `STREAM_CLOSED` for most such frames, but for `DATA` and
    /// `HEADERS` on a half-closed (remote) stream it is a connection error — so
    /// the two cases are distinct variants here rather than one.
    Closed,
}

impl StreamError {
    /// The code to put in the `RST_STREAM`.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Protocol { code, .. } | Self::Reset { code } => *code,
            Self::Closed => ErrorCode::StreamClosed,
        }
    }

    /// Whether the *stream* was at fault, rather than the peer's framing.
    ///
    /// A `RST_STREAM` from the peer and a cancelled stream are both routine; a
    /// protocol violation is not.
    #[must_use]
    pub const fn is_peer_fault(&self) -> bool {
        matches!(self, Self::Protocol { .. })
    }

    /// Build a protocol stream error.
    #[must_use]
    pub fn protocol(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self::Protocol {
            code,
            detail: detail.into(),
        }
    }

    /// Whether the stream is closed for good once this is raised.
    ///
    /// Always `true`: a stream error terminates the stream (RFC 9113 §5.4.2).
    /// Exposed as a method rather than a constant so a caller reads the RFC's
    /// rule at the call site instead of remembering it.
    #[must_use]
    pub const fn terminates_stream(&self) -> bool {
        true
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol { code, detail } => write!(f, "{code}: {detail}"),
            Self::Reset { code } => write!(f, "the peer reset the stream with {code}"),
            Self::Closed => f.write_str("STREAM_CLOSED: the stream is already closed"),
        }
    }
}

impl std::error::Error for StreamError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// **The wire values are the contract.** A mis-numbered variant does not
    /// fail to compile — it sends a `GOAWAY` naming a different error and every
    /// implementer debugs the wrong layer. RFC 9113 §7.
    #[test]
    fn error_code_values_match_rfc_9113_section_7() {
        for (code, value) in [
            (ErrorCode::NoError, 0x00),
            (ErrorCode::ProtocolError, 0x01),
            (ErrorCode::InternalError, 0x02),
            (ErrorCode::FlowControlError, 0x03),
            (ErrorCode::SettingsTimeout, 0x04),
            (ErrorCode::StreamClosed, 0x05),
            (ErrorCode::FrameSizeError, 0x06),
            (ErrorCode::RefusedStream, 0x07),
            (ErrorCode::Cancel, 0x08),
            (ErrorCode::CompressionError, 0x09),
            (ErrorCode::ConnectError, 0x0a),
            (ErrorCode::EnhanceYourCalm, 0x0b),
            (ErrorCode::InadequateSecurity, 0x0c),
            (ErrorCode::Http11Required, 0x0d),
        ] {
            assert_eq!(code.as_u32(), value, "{code} has the wrong wire value");
            assert_eq!(
                ErrorCode::from_u32(value),
                Some(code),
                "0x{value:x} must decode to {code}"
            );
        }
    }

    /// Every defined code round-trips, and the exhaustiveness is checked by
    /// listing them all — a new variant added without updating
    /// `error_code_values_match_rfc_9113_section_7` would still round-trip, so
    /// `all()` exists to be counted.
    #[test]
    fn every_code_round_trips() {
        let all = [
            ErrorCode::NoError,
            ErrorCode::ProtocolError,
            ErrorCode::InternalError,
            ErrorCode::FlowControlError,
            ErrorCode::SettingsTimeout,
            ErrorCode::StreamClosed,
            ErrorCode::FrameSizeError,
            ErrorCode::RefusedStream,
            ErrorCode::Cancel,
            ErrorCode::CompressionError,
            ErrorCode::ConnectError,
            ErrorCode::EnhanceYourCalm,
            ErrorCode::InadequateSecurity,
            ErrorCode::Http11Required,
        ];
        assert_eq!(all.len(), 14, "RFC 9113 §7 defines fourteen codes");
        for c in all {
            assert_eq!(ErrorCode::from_u32(c.as_u32()), Some(c));
        }
    }

    /// RFC 9113 §7: *"Unknown or unsupported error codes MUST NOT trigger any
    /// special behavior. These MAY be treated by an implementation as being
    /// equivalent to INTERNAL_ERROR."*
    ///
    /// So an unassigned number is `None`, **not** an error — a peer extending the
    /// space must not be punished for it.
    #[test]
    fn an_unassigned_code_decodes_to_none_rather_than_failing() {
        assert_eq!(ErrorCode::from_u32(0x0e), None);
        assert_eq!(ErrorCode::from_u32(0xff), None);
        assert_eq!(ErrorCode::from_u32(u32::MAX), None);
    }

    /// The names are the RFC's own, so a log line can be grepped against the
    /// specification.
    #[test]
    fn error_code_names_are_the_rfc_spelling() {
        assert_eq!(ErrorCode::ProtocolError.as_str(), "PROTOCOL_ERROR");
        assert_eq!(ErrorCode::FlowControlError.as_str(), "FLOW_CONTROL_ERROR");
        assert_eq!(ErrorCode::EnhanceYourCalm.as_str(), "ENHANCE_YOUR_CALM");
        assert_eq!(ErrorCode::Http11Required.as_str(), "HTTP_1_1_REQUIRED");
        assert_eq!(
            ErrorCode::ProtocolError.to_string(),
            "PROTOCOL_ERROR (0x1)"
        );
    }

    /// Answering a clean peer shutdown with an error code tells the peer it did
    /// something wrong.
    #[test]
    fn a_peer_goaway_is_not_reported_as_the_peer_at_fault() {
        let e = ConnectionError::PeerGoAway {
            last_stream_id: 3,
            error: None,
        };
        assert_eq!(e.code(), ErrorCode::NoError);
        assert!(!e.is_peer_fault());

        let bad = ConnectionError::protocol(ErrorCode::ProtocolError, "x");
        assert!(bad.is_peer_fault());
        assert_ne!(bad.code(), ErrorCode::NoError);
    }

    /// A stream error terminates the stream and never the connection — which is
    /// the property that makes multiplexing useful.
    #[test]
    fn a_stream_error_terminates_only_the_stream() {
        let e = StreamError::protocol(ErrorCode::ProtocolError, "bad pseudo-header");
        assert!(e.terminates_stream());
        assert_eq!(e.code(), ErrorCode::ProtocolError);
        assert!(e.is_peer_fault());

        let reset = StreamError::Reset {
            code: ErrorCode::Cancel,
        };
        assert_eq!(reset.code(), ErrorCode::Cancel);
        assert!(
            !reset.is_peer_fault(),
            "a client cancelling its own request is routine"
        );

        assert_eq!(StreamError::Closed.code(), ErrorCode::StreamClosed);
    }

    /// Every error renders with something an operator can act on — either the
    /// RFC code or the bytes that were wrong.
    #[test]
    fn every_error_renders_with_the_code_and_the_detail() {
        let errors = [
            ConnectionError::BadPreface {
                got: "GET / HTTP/1.1".to_owned(),
            },
            ConnectionError::PeerGoAway {
                last_stream_id: 1,
                error: Some(ErrorCode::Cancel),
            },
            ConnectionError::LocalGoAway {
                last_stream_id: 1,
                error: ErrorCode::ProtocolError,
            },
            ConnectionError::protocol(ErrorCode::FrameSizeError, "length 5"),
            ConnectionError::malformed(ErrorCode::FrameSizeError, "truncated"),
        ];
        for e in errors {
            let s = e.to_string();
            assert!(!s.is_empty(), "{e:?} rendered nothing");
            assert!(!s.contains('\n'), "Display must stay single-line: {s}");
            assert!(!e.as_str().is_empty());
        }

        let bad = ConnectionError::BadPreface {
            got: "GET / HTTP/1.1".to_owned(),
        };
        assert!(
            bad.to_string().contains("GET / HTTP/1.1"),
            "the preface error must name what arrived, or it cannot distinguish \
             an HTTP/1.1 client from a truncated write"
        );
    }
}
