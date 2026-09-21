// SPDX-License-Identifier: Apache-2.0

//! The WebSocket frame layer, per RFC 6455 §5.
//!
//! The companion to [`crate::ws`]'s handshake: once the connection has been upgraded,
//! every byte on it is a frame. This module decodes and encodes them.
//!
//! # The nine rules that decide whether an implementation interoperates
//!
//! §5 is short and every clause is load-bearing. Each of these is a real
//! interoperability or security failure, not a style preference:
//!
//! | Rule | §  | What breaks without it |
//! |---|---|---|
//! | A client **must** mask; a server **must not** | 5.1 | An unmasked client frame is a protocol error. A server that masked would be rejected by browsers. |
//! | A server **must close** on an unmasked client frame | 5.1 | Accepting it lets a cache-poisoning attack through: a client that can make a proxy see a valid HTTP request inside a WebSocket frame can poison the proxy's cache for every user. |
//! | Masking is **4 bytes XOR'd by index**, resetting per frame | 5.3 | A naive running-XOR across frames corrupts everything after the first. |
//! | Control frames **must not** be fragmented | 5.4 | A `Close` split across frames has no defined meaning. |
//! | A control frame payload is **≤ 125** bytes | 5.5 | The length field is reused for a reason; a larger one is a protocol error. |
//! | A `Close` payload, if present, is **≥ 2** bytes and valid UTF-8 after it | 5.5.1 | The first two bytes are a status code; a one-byte payload has no defined reading. |
//! | **Only `text` and `binary` may start a fragmented message**, and continuation frames must follow | 5.4 | A `Ping` between fragments is legal **only** because control frames may interleave. |
//! | `text` payloads are **UTF-8**, and validity must be checked even across fragments | 8.1 | A split multi-byte sequence is only valid as a whole; validating per fragment rejects correct senders. |
//! | The length field is **7 / 7+16 / 7+64** bits, and the 16- and 64-bit forms are **minimal** | 5.2 | A payload of 10 bytes encoded in the 64-bit form is a protocol error, and accepting it is a smuggling primitive. |
//!
//! # Why decoding and encoding are separate functions on separate types
//!
//! A [`Frame`] is what arrived; [`encode`] writes what is sent. They are not inverses:
//! a server **never** masks its output and **always** rejects unmasked input, so the two
//! directions have different rules. A single `fn decode/encode` pair sharing a mask
//! parameter would make it possible to write a server that masks — which is the bug the
//! asymmetry exists to prevent.

use crate::ws::HandshakeError;

/// The opcode, from §5.2's table.
///
/// A closed set. The four non-control opcodes and three control opcodes are everything
/// §5.2 defines; a reserved opcode is a protocol error, not an extension point — §5.2
/// says extensions use the reserved *bits* with a negotiated extension, and an
/// unrecognised opcode must fail the connection rather than being ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    /// `0x0` — a continuation of a fragmented message.
    Continuation,
    /// `0x1` — UTF-8 text.
    Text,
    /// `0x2` — binary.
    Binary,
    /// `0x8` — close.
    Close,
    /// `0x9` — ping.
    Ping,
    /// `0xA` — pong.
    Pong,
}

impl Opcode {
    /// The four-bit value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }

    /// The opcode for a four-bit value, or `None` for a reserved one.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }

    /// Whether this is a control frame.
    ///
    /// §5.5: the high bit of the opcode is the control bit, which is why the test is a
    /// bit and not a list. Stated as a method so the rule has a name — three separate
    /// restrictions depend on it.
    #[must_use]
    pub const fn is_control(self) -> bool {
        self.as_u8() & 0x8 != 0
    }
}

/// Why a frame was refused.
///
/// Every variant maps to a `Close` code as well as a message, because §7.4.1 requires the
/// server to say *why* it is closing: a client that receives `1002` knows it sent
/// something malformed, while a silent close is indistinguishable from a network fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The frame is shorter than its own header claims.
    Truncated {
        /// How many bytes were needed.
        needed: usize,
        /// How many were present.
        got: usize,
    },
    /// The opcode is one of the reserved values.
    ReservedOpcode {
        /// The value received.
        opcode: u8,
    },
    /// A client frame was not masked. §5.1.
    UnmaskedClientFrame,
    /// A control frame was fragmented, or exceeded 125 bytes. §5.4, §5.5.
    InvalidControlFrame {
        /// Which rule was broken.
        reason: String,
    },
    /// The length was encoded non-minimally. §5.2.
    NonMinimalLength {
        /// The length encoded.
        length: u64,
    },
    /// A continuation arrived with no message in progress, or a data frame arrived
    /// mid-message. §5.4.
    UnexpectedContinuation {
        /// What was expected.
        expected: String,
    },
    /// A close payload was one byte, or its reason was not UTF-8. §5.5.1.
    InvalidClosePayload {
        /// Why it was refused.
        reason: String,
    },
}

impl FrameError {
    /// The close code §7.4.1 requires for this failure.
    ///
    /// `1002` (protocol error) for a malformed frame, `1007` (invalid payload data) for a
    /// text or close reason that is not UTF-8. The distinction matters to a client: 1002
    /// means "your framing is wrong", 1007 means "your content is wrong", and a client
    /// that retries after 1007 with a corrected payload succeeds where it would loop on
    /// 1002.
    #[must_use]
    pub const fn close_code(&self) -> u16 {
        match self {
            Self::InvalidClosePayload { .. } => 1007,
            _ => 1002,
        }
    }
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { needed, got } => {
                write!(
                    f,
                    "the frame needs {needed} bytes but only {got} are present"
                )
            }
            Self::ReservedOpcode { opcode } => {
                write!(f, "opcode 0x{opcode:X} is reserved")
            }
            Self::UnmaskedClientFrame => f.write_str(
                "a client frame must be masked; an unmasked one is a protocol error and \
                 accepting it enables a cache-poisoning attack",
            ),
            Self::InvalidControlFrame { reason } => write!(f, "invalid control frame: {reason}"),
            Self::NonMinimalLength { length } => write!(
                f,
                "a {length}-byte payload was encoded in a wider length form than \
                 necessary, which §5.2 forbids"
            ),
            Self::UnexpectedContinuation { expected } => {
                write!(f, "unexpected continuation: {expected}")
            }
            Self::InvalidClosePayload { reason } => write!(f, "invalid close payload: {reason}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// The largest single frame this crate will buffer.
///
/// A 64-bit length field can claim 2^63 bytes, and `Vec::with_capacity` on such a value
/// **aborts the process** rather than returning an error — so the ceiling is checked
/// *before* the allocation, not after it. This is a memory-safety-adjacent limit, not a
/// performance one: an unauthenticated peer chooses the number.
///
/// A caller wanting larger messages streams them across frames, which is what §5.4's
/// fragmentation exists for.
pub const MAX_FRAME_BYTES: u64 = 16 * 1024 * 1024;

/// A decoded frame.
///
/// The payload is owned and unmasked, so a caller never sees the mask or has to remember
/// it was applied. That is deliberate: a decoded frame that still carried its mask would
/// be a value every consumer has to know how to interpret, and one of them would forget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The frame's kind.
    pub opcode: Opcode,
    /// Whether this frame ends the message.
    pub fin: bool,
    /// The payload, unmasked.
    pub payload: Vec<u8>,
}

impl Frame {
    /// A close frame with a status code and reason.
    ///
    /// The reason is truncated to fit §5.5's 125-byte ceiling rather than being rejected:
    /// a server closing with an over-long reason has already decided to close, so failing
    /// to *compose* the frame would leave the connection in limbo. Truncation is on a
    /// character boundary, because the reason must remain valid UTF-8 (§5.5.1).
    #[must_use]
    pub fn close(code: u16, reason: &str) -> Self {
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        // 125 total, minus the two code bytes.
        let mut budget = 123;
        for ch in reason.chars() {
            let n = ch.len_utf8();
            if n > budget {
                break;
            }
            payload.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
            budget -= n;
        }
        Self {
            opcode: Opcode::Close,
            fin: true,
            payload,
        }
    }

    /// A pong echoing a ping's payload, as §5.5.3 requires.
    #[must_use]
    pub fn pong(payload: Vec<u8>) -> Self {
        Self {
            opcode: Opcode::Pong,
            fin: true,
            payload,
        }
    }

    /// The close code, when this is a close frame carrying one.
    #[must_use]
    pub fn close_code(&self) -> Option<u16> {
        if self.opcode != Opcode::Close || self.payload.len() < 2 {
            return None;
        }
        Some(u16::from_be_bytes([self.payload[0], self.payload[1]]))
    }
}

/// Decode one server-side frame from `bytes`.
///
/// Returns the frame and how many bytes it consumed, so a caller reading from a socket
/// can keep the remainder. `None` means "not enough bytes yet" — which is not an error:
/// framing over TCP arrives in arbitrary pieces, and treating a partial frame as
/// malformed is how a decoder fails on a split packet.
///
/// # Errors
///
/// Any [`FrameError`]. Note that a server **must** fail on an unmasked client frame
/// (§5.1) — see [`FrameError::UnmaskedClientFrame`] for why accepting one is a security
/// failure and not merely a leniency.
pub fn decode_server_frame(bytes: &[u8]) -> Result<Option<(Frame, usize)>, FrameError> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let b0 = bytes[0];
    let b1 = bytes[1];

    let fin = b0 & 0x80 != 0;
    let rsv = b0 & 0x70;
    let opcode_raw = b0 & 0x0F;
    let masked = b1 & 0x80 != 0;
    let short_len = b1 & 0x7F;

    // No extension is negotiated, so any reserved bit is a protocol error. §5.2 requires
    // failing the connection rather than ignoring them: a peer that set one expects a
    // meaning this server did not agree to, so continuing would misinterpret its frames.
    if rsv != 0 {
        return Err(FrameError::ReservedOpcode { opcode: opcode_raw });
    }

    let Some(opcode) = Opcode::from_u8(opcode_raw) else {
        return Err(FrameError::ReservedOpcode { opcode: opcode_raw });
    };

    // §5.1: a server MUST fail the connection on an unmasked client frame.
    if !masked {
        return Err(FrameError::UnmaskedClientFrame);
    }

    if opcode.is_control() {
        if !fin {
            return Err(FrameError::InvalidControlFrame {
                reason: "a control frame must not be fragmented (§5.4)".to_owned(),
            });
        }
        if short_len > 125 {
            return Err(FrameError::InvalidControlFrame {
                reason: "a control frame payload may not exceed 125 bytes (§5.5)".to_owned(),
            });
        }
    }

    let mut offset = 2;
    let payload_len: u64 = match short_len {
        126 => {
            if bytes.len() < offset + 2 {
                return Ok(None);
            }
            let v = u64::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
            offset += 2;
            // §5.2: the 16-bit form is only for lengths that do not fit in 7 bits. A
            // smaller value here is a protocol error, and accepting it is a smuggling
            // primitive — two encodings of one payload mean two peers can disagree about
            // what was sent.
            if v < 126 {
                return Err(FrameError::NonMinimalLength { length: v });
            }
            v
        }
        127 => {
            if bytes.len() < offset + 8 {
                return Ok(None);
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes[offset..offset + 8]);
            let v = u64::from_be_bytes(arr);
            offset += 8;
            if v < 65_536 {
                return Err(FrameError::NonMinimalLength { length: v });
            }
            v
        }
        n => u64::from(n),
    };

    if payload_len > MAX_FRAME_BYTES {
        // `needed` is only for the message, so a saturating conversion is right: the
        // value is already known to exceed the ceiling, and the exact figure a 32-bit
        // target cannot represent is not worth failing over.
        #[allow(clippy::cast_possible_truncation)]
        let needed = payload_len.min(usize::MAX as u64) as usize;
        return Err(FrameError::Truncated {
            needed,
            got: bytes.len(),
        });
    }
    // Safe on every target: `payload_len` is at most `MAX_FRAME` (16 MiB), which fits a
    // 32-bit `usize` with room to spare. The `u64` field is why it is written this way —
    // the wire format is 64-bit and the in-memory one need not be.
    #[allow(clippy::cast_possible_truncation)]
    let payload_len = payload_len as usize;

    let mask_end = offset + 4;
    if bytes.len() < mask_end {
        return Ok(None);
    }
    let mask = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ];
    offset = mask_end;

    let end = offset + payload_len;
    if bytes.len() < end {
        return Ok(None);
    }

    // §5.3: the mask is XOR'd **by index**, starting at zero for each frame. A running
    // XOR carried across frames corrupts everything after the first — and it is the kind
    // of bug that appears only with a payload longer than one mask period, which a test
    // with a short fixture would not catch.
    let mut payload = bytes[offset..end].to_vec();
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }

    if opcode == Opcode::Close {
        validate_close_payload(&payload)?;
    }

    Ok(Some((
        Frame {
            opcode,
            fin,
            payload,
        },
        end,
    )))
}

/// §5.5.1: a close payload, if present, is a 2-byte code followed by UTF-8.
fn validate_close_payload(payload: &[u8]) -> Result<(), FrameError> {
    if payload.is_empty() {
        // A close with no payload is valid: it means "no status", which §7.1.5 permits.
        return Ok(());
    }
    if payload.len() == 1 {
        return Err(FrameError::InvalidClosePayload {
            reason: "a close payload is either empty or at least two bytes, because the \
                     first two are a status code (§5.5.1)"
                .to_owned(),
        });
    }
    if std::str::from_utf8(&payload[2..]).is_err() {
        return Err(FrameError::InvalidClosePayload {
            reason: "the close reason after the status code must be UTF-8".to_owned(),
        });
    }
    Ok(())
}

/// Encode a server frame.
///
/// # A server never masks
///
/// §5.1: "A server MUST NOT mask any frames that it sends to the client." The signature
/// reflects that — there is no mask parameter and no `mask: bool` — so a caller cannot
/// produce a masked server frame even by mistake. A browser that receives one closes the
/// connection with `1002`, and the failure looks like a broken server rather than a
/// protocol violation in the encoder.
#[must_use]
// Every cast in this function is guarded by the branch it sits in and documented there:
// `< 126` fits a `u8` by the comparison, `<= u16::MAX` fits a `u16` by the comparison, and
// the final arm widens a `usize` to `u64`, which cannot lose anything on any target this
// crate builds for. A `try_into` per arm would state the same thing less clearly.
#[allow(clippy::cast_possible_truncation)]
pub fn encode(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.payload.len() + 10);
    let b0 = (if frame.fin { 0x80 } else { 0 }) | frame.opcode.as_u8();
    out.push(b0);

    let len = frame.payload.len();
    // # The boundary is `u16::MAX`, not `u32::MAX`
    //
    // §5.2 defines three length forms: 7 bits (0..=125), 7+16 (126..=65535), and 7+64
    // (65536 and above). A first version of this function tested `len <= u32::MAX` for the
    // 16-bit form, which is four orders of magnitude too wide: a 70,000-byte payload wrote
    // the marker `126` and then **`(len as u16)`**, silently truncating 70,000 to 4,464.
    //
    // The frame was well-formed and the payload was gone. A test that encoded and decoded
    // a 70,000-byte payload caught it -- and it is exactly the case a short fixture misses,
    // because every length below 65,536 takes the branch that works.
    // Each arm's conversion is guarded by the branch it is in:
    //
    // - `< 126` fits a `u8` by the comparison itself.
    // - `<= u16::MAX` fits a `u16` by the comparison itself.
    // - the last arm takes a `usize`, which is at most 64 bits on every target this crate
    //   builds for, so widening to `u64` cannot lose anything.
    if len < 126 {
        out.push(len as u8);
    } else if u16::try_from(len).is_ok() {
        out.push(0x7E);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&frame.payload);
    out
}

/// The text of a `Text` frame, validating §8.1's UTF-8 requirement.
///
/// # Why validation is here and not at decode
///
/// Because a text message may be **fragmented**, and a multi-byte character split across
/// two frames is only valid as a whole. Validating each fragment would reject correct
/// senders; validating nothing would let invalid UTF-8 reach a guest. So the check
/// belongs at message assembly, on the completed payload.
///
/// The failure is `1007` (invalid payload data), not `1002`: the framing was fine and the
/// content was not, and a client that retries with corrected content succeeds.
///
/// # Errors
///
/// [`FrameError::InvalidClosePayload`] is not used here — this returns the same error type
/// so a caller has one thing to handle, with the reason naming the actual problem.
pub fn text_of(frame: &Frame) -> Result<&str, FrameError> {
    std::str::from_utf8(&frame.payload).map_err(|e| FrameError::InvalidClosePayload {
        reason: format!("a text payload must be UTF-8 (§8.1): {e}"),
    })
}

/// Reject a handshake-shaped problem at the frame layer.
///
/// An alias so a caller that speaks both layers has one error type for "the peer is not
/// speaking this protocol".
pub type ProtocolError = HandshakeError;

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a **client** frame: masked, as §5.1 requires.
    fn client_frame(opcode: Opcode, fin: bool, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push((if fin { 0x80 } else { 0 }) | opcode.as_u8());
        let len = payload.len();
        // Same guarded casts as `encode`, mirrored so the helper produces the *masked*
        // client form a server must accept. Each is guarded by its branch.
        #[allow(clippy::cast_possible_truncation)]
        if len < 126 {
            #[allow(clippy::cast_possible_truncation)]
            out.push(0x80 | len as u8);
        } else if u16::try_from(len).is_ok() {
            out.push(0x80 | 0x7E);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(0x80 | 0x7F);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        out.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            out.push(b ^ mask[i % 4]);
        }
        out
    }

    // -- the opcode set ----------------------------------------------------

    /// Every defined opcode round-trips, and the reserved ones do not.
    #[test]
    fn opcodes_round_trip_and_reserved_ones_are_refused() {
        for op in [
            Opcode::Continuation,
            Opcode::Text,
            Opcode::Binary,
            Opcode::Close,
            Opcode::Ping,
            Opcode::Pong,
        ] {
            assert_eq!(Opcode::from_u8(op.as_u8()), Some(op), "{op:?}");
        }
        for reserved in [0x3u8, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF] {
            assert_eq!(
                Opcode::from_u8(reserved),
                None,
                "0x{reserved:X} is reserved"
            );
        }
    }

    /// `is_control` follows §5.5's high bit, not a hand-written list.
    #[test]
    fn the_control_bit_decides_control_frames() {
        assert!(!Opcode::Continuation.is_control());
        assert!(!Opcode::Text.is_control());
        assert!(!Opcode::Binary.is_control());
        assert!(Opcode::Close.is_control());
        assert!(Opcode::Ping.is_control());
        assert!(Opcode::Pong.is_control());
    }

    // -- decoding ----------------------------------------------------------

    /// A masked text frame decodes to its payload.
    #[test]
    fn a_masked_text_frame_decodes() {
        let raw = client_frame(Opcode::Text, true, b"hello", [0x37, 0xfa, 0x21, 0x3d]);
        let (frame, used) = decode_server_frame(&raw).expect("valid").expect("complete");
        assert_eq!(frame.opcode, Opcode::Text);
        assert!(frame.fin);
        assert_eq!(frame.payload, b"hello");
        assert_eq!(used, raw.len());
    }

    /// **An unmasked client frame is refused.** §5.1.
    ///
    /// Not a leniency: a client that can make a proxy see a valid HTTP request inside a
    /// frame is the cache-poisoning attack §5.1's masking rule exists to prevent.
    #[test]
    fn an_unmasked_client_frame_is_refused() {
        // Hand-built: a text frame with the mask bit clear.
        let raw = [0x81u8, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let err = decode_server_frame(&raw).expect_err("must refuse");
        assert_eq!(err, FrameError::UnmaskedClientFrame);
        assert!(
            err.to_string().contains("cache-poisoning"),
            "the message must say why this is not merely strict: {err}"
        );
    }

    /// **The mask resets per frame.** §5.3.
    ///
    /// A running XOR across frames corrupts everything after the first. This decodes two
    /// frames in sequence with **different** masks and asserts both payloads survive — a
    /// decoder that carried the mask over would fail the second.
    #[test]
    fn the_mask_resets_for_each_frame() {
        let first = client_frame(Opcode::Text, true, b"first", [0x01, 0x02, 0x03, 0x04]);
        let second = client_frame(Opcode::Text, true, b"second!", [0xAA, 0xBB, 0xCC, 0xDD]);

        let (f1, n1) = decode_server_frame(&first)
            .expect("valid")
            .expect("complete");
        assert_eq!(f1.payload, b"first");
        let (f2, _) = decode_server_frame(&second)
            .expect("valid")
            .expect("complete");
        assert_eq!(
            f2.payload, b"second!",
            "the second frame's mask must be applied from index 0, not continued"
        );
        assert_eq!(n1, first.len());
    }

    /// A long payload is masked correctly past the 4-byte mask period.
    ///
    /// The case a short fixture cannot catch: with a 4-byte mask and a 5-byte payload, an
    /// implementation that XOR'd only the first four bytes would still pass a 4-byte test.
    #[test]
    fn a_payload_longer_than_the_mask_is_fully_unmasked() {
        let payload: Vec<u8> = (0..=255u8).collect();
        let mask = [0x11, 0x22, 0x33, 0x44];
        let raw = client_frame(Opcode::Binary, true, &payload, mask);
        let (frame, _) = decode_server_frame(&raw).expect("valid").expect("complete");
        assert_eq!(frame.payload, payload);
    }

    /// A partial frame returns `None` rather than an error.
    ///
    /// Framing over TCP arrives in arbitrary pieces. Treating a split packet as malformed
    /// is how a decoder works locally and fails in production.
    #[test]
    fn a_partial_frame_is_not_an_error() {
        let raw = client_frame(Opcode::Text, true, b"hello", [1, 2, 3, 4]);
        for n in 0..raw.len() {
            assert_eq!(
                decode_server_frame(&raw[..n]),
                Ok(None),
                "a {n}-byte prefix is incomplete, not malformed"
            );
        }
        assert!(decode_server_frame(&raw).expect("valid").is_some());
    }

    /// The decoder consumes exactly one frame, leaving the rest.
    #[test]
    fn only_one_frame_is_consumed() {
        let mut raw = client_frame(Opcode::Text, true, b"one", [1, 2, 3, 4]);
        let first_len = raw.len();
        raw.extend_from_slice(&client_frame(Opcode::Text, true, b"two", [5, 6, 7, 8]));

        let (f, used) = decode_server_frame(&raw).expect("valid").expect("complete");
        assert_eq!(f.payload, b"one");
        assert_eq!(used, first_len);

        let (f2, _) = decode_server_frame(&raw[used..])
            .expect("valid")
            .expect("complete");
        assert_eq!(f2.payload, b"two");
    }

    // -- length forms ------------------------------------------------------

    /// All three length forms encode and decode.
    #[test]
    fn all_three_length_forms_round_trip() {
        for len in [0usize, 1, 125, 126, 127, 1000, 65_535, 65_536, 70_000] {
            let payload = vec![0xABu8; len];
            let raw = client_frame(Opcode::Binary, true, &payload, [9, 8, 7, 6]);
            let (frame, used) = decode_server_frame(&raw)
                .unwrap_or_else(|e| panic!("{len} bytes: {e}"))
                .unwrap_or_else(|| panic!("{len} bytes: incomplete"));
            assert_eq!(frame.payload.len(), len, "{len} bytes");
            assert_eq!(used, raw.len());
        }
    }

    /// **A non-minimal length is refused.** §5.2.
    ///
    /// A 10-byte payload in the 64-bit form is a protocol error, and accepting it is a
    /// smuggling primitive: two encodings of one payload let two peers disagree about
    /// what was sent.
    #[test]
    fn a_non_minimal_length_is_refused() {
        // 10 bytes declared in the 16-bit form.
        let mut raw = vec![0x82u8, 0x80 | 0x7E, 0x00, 0x0A];
        raw.extend_from_slice(&[1, 2, 3, 4]);
        raw.extend_from_slice(&[0u8; 10]);
        let err = decode_server_frame(&raw).expect_err("must refuse");
        assert!(
            matches!(err, FrameError::NonMinimalLength { .. }),
            "{err:?}"
        );

        // 200 bytes declared in the 64-bit form.
        let mut raw = vec![0x82u8, 0x80 | 0x7F];
        raw.extend_from_slice(&200u64.to_be_bytes());
        raw.extend_from_slice(&[1, 2, 3, 4]);
        raw.extend_from_slice(&[0u8; 200]);
        let err = decode_server_frame(&raw).expect_err("must refuse");
        assert!(
            matches!(err, FrameError::NonMinimalLength { .. }),
            "{err:?}"
        );
    }

    // -- control frames ----------------------------------------------------

    /// **A fragmented control frame is refused.** §5.4.
    #[test]
    fn a_fragmented_control_frame_is_refused() {
        for opcode in [Opcode::Close, Opcode::Ping, Opcode::Pong] {
            let raw = client_frame(opcode, false, b"x", [1, 2, 3, 4]);
            let err = decode_server_frame(&raw).expect_err("must refuse");
            assert!(
                matches!(err, FrameError::InvalidControlFrame { .. }),
                "{opcode:?}: {err:?}"
            );
        }
    }

    /// **A control frame payload over 125 bytes is refused.** §5.5.
    ///
    /// The length field is reused for a reason, so 126 is the 16-bit marker — a control
    /// frame claiming it is a protocol error even before the payload is read.
    #[test]
    fn an_oversized_control_frame_is_refused() {
        let raw = client_frame(Opcode::Ping, true, &[0u8; 126], [1, 2, 3, 4]);
        let err = decode_server_frame(&raw).expect_err("must refuse");
        assert!(
            matches!(err, FrameError::InvalidControlFrame { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("125"), "{err}");
    }

    /// A control frame of exactly 125 bytes is accepted.
    ///
    /// The boundary control: `> 125` is the rule, so 125 must pass. An off-by-one here
    /// rejects a legal frame.
    #[test]
    fn a_control_frame_of_exactly_125_bytes_is_accepted() {
        let raw = client_frame(Opcode::Ping, true, &[7u8; 125], [1, 2, 3, 4]);
        let (frame, _) = decode_server_frame(&raw).expect("valid").expect("complete");
        assert_eq!(frame.payload.len(), 125);
    }

    // -- close payloads ----------------------------------------------------

    /// **A one-byte close payload is refused.** §5.5.1.
    #[test]
    fn a_one_byte_close_payload_is_refused() {
        let raw = client_frame(Opcode::Close, true, &[0x03], [1, 2, 3, 4]);
        let err = decode_server_frame(&raw).expect_err("must refuse");
        assert!(
            matches!(err, FrameError::InvalidClosePayload { .. }),
            "{err:?}"
        );
        assert_eq!(
            err.close_code(),
            1007,
            "invalid payload data, not a framing error"
        );
    }

    /// An empty close payload is valid — it means "no status".
    #[test]
    fn an_empty_close_payload_is_valid() {
        let raw = client_frame(Opcode::Close, true, &[], [1, 2, 3, 4]);
        let (frame, _) = decode_server_frame(&raw).expect("valid").expect("complete");
        assert_eq!(frame.opcode, Opcode::Close);
        assert_eq!(frame.close_code(), None);
    }

    /// A close with a valid code and reason decodes.
    #[test]
    fn a_close_with_a_code_and_reason_decodes() {
        let mut payload = 1000u16.to_be_bytes().to_vec();
        payload.extend_from_slice(b"bye");
        let raw = client_frame(Opcode::Close, true, &payload, [1, 2, 3, 4]);
        let (frame, _) = decode_server_frame(&raw).expect("valid").expect("complete");
        assert_eq!(frame.close_code(), Some(1000));
    }

    /// **A close reason that is not UTF-8 is refused.** §5.5.1.
    #[test]
    fn a_non_utf8_close_reason_is_refused() {
        let mut payload = 1000u16.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        let raw = client_frame(Opcode::Close, true, &payload, [1, 2, 3, 4]);
        let err = decode_server_frame(&raw).expect_err("must refuse");
        assert!(
            matches!(err, FrameError::InvalidClosePayload { .. }),
            "{err:?}"
        );
    }

    // -- encoding ----------------------------------------------------------

    /// **A server frame is never masked.** §5.1.
    ///
    /// The signature has no mask parameter for this reason: a browser receiving a masked
    /// server frame closes with 1002, and the failure looks like a broken server rather
    /// than a protocol violation in the encoder.
    #[test]
    fn a_server_frame_is_never_masked() {
        for opcode in [Opcode::Text, Opcode::Binary, Opcode::Ping, Opcode::Close] {
            let raw = encode(&Frame {
                opcode,
                fin: true,
                payload: b"x".to_vec(),
            });
            assert_eq!(raw[1] & 0x80, 0, "{opcode:?} must not set the mask bit");
        }
    }

    /// Server frames use the minimal length form.
    #[test]
    fn server_frames_use_the_minimal_length_form() {
        for (len, expect_marker) in [(125usize, 125u8), (126, 126), (70_000, 127)] {
            let raw = encode(&Frame {
                opcode: Opcode::Binary,
                fin: true,
                payload: vec![0u8; len],
            });
            assert_eq!(raw[1], expect_marker, "{len} bytes");
        }
    }

    /// **A server frame survives its own decoder at every length boundary.**
    ///
    /// The assertion above checks the *marker*; this checks the *payload*, and it is the
    /// one that caught a real bug: `encode` used `len <= u32::MAX` for the 16-bit form, so
    /// a 70,000-byte payload wrote the marker `126` and then `(len as u16)` — silently
    /// truncating 70,000 to 4,464. The frame was well-formed and the payload was gone.
    ///
    /// A decode-only fixture cannot see this, because the bug is in the encoder. A
    /// short-payload fixture cannot see it either, because every length below 65,536 takes
    /// the branch that works. Both halves matter: this is the encoder and the decoder
    /// compared against each other across the boundaries.
    #[test]
    fn a_server_frame_round_trips_at_every_length_boundary() {
        // 125/126 and 65535/65536 are the two boundaries §5.2 defines.
        for len in [0usize, 1, 125, 126, 127, 65_535, 65_536, 70_000] {
            // `% 251` keeps every value inside `u8`, so the cast cannot truncate.
            #[allow(clippy::cast_possible_truncation)]
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let raw = encode(&Frame {
                opcode: Opcode::Binary,
                fin: true,
                payload: payload.clone(),
            });

            // The decoder refuses unmasked client frames, so the round-trip is checked by
            // reading the length and payload back out of the bytes the encoder wrote —
            // which is what a client does.
            let declared = match raw[1] {
                126 => u64::from(u16::from_be_bytes([raw[2], raw[3]])),
                127 => {
                    let mut a = [0u8; 8];
                    a.copy_from_slice(&raw[2..10]);
                    u64::from_be_bytes(a)
                }
                n => u64::from(n),
            };
            assert_eq!(
                declared, len as u64,
                "a {len}-byte payload declared {declared} bytes"
            );

            let header = if raw[1] == 127 {
                10
            } else if raw[1] == 126 {
                4
            } else {
                2
            };
            assert_eq!(
                &raw[header..],
                payload.as_slice(),
                "a {len}-byte payload's bytes must survive encoding"
            );
        }
    }

    /// `fin` is written from the frame.
    #[test]
    fn fin_is_encoded() {
        let frag = encode(&Frame {
            opcode: Opcode::Text,
            fin: false,
            payload: b"a".to_vec(),
        });
        assert_eq!(frag[0] & 0x80, 0);
        let last = encode(&Frame {
            opcode: Opcode::Continuation,
            fin: true,
            payload: b"b".to_vec(),
        });
        assert_eq!(last[0] & 0x80, 0x80);
    }

    // -- close construction ------------------------------------------------

    /// A close frame carries the code and reason, and fits §5.5's ceiling.
    #[test]
    fn a_close_frame_is_built_within_the_ceiling() {
        let f = Frame::close(1000, "bye");
        assert_eq!(f.opcode, Opcode::Close);
        assert!(f.fin, "a control frame is always final");
        assert_eq!(f.close_code(), Some(1000));
        assert!(f.payload.len() <= 125, "{} bytes", f.payload.len());
        assert_eq!(&f.payload[2..], b"bye");
    }

    /// An over-long reason is truncated on a character boundary, not rejected.
    ///
    /// A server closing with a long reason has already decided to close; refusing to
    /// *compose* the frame would leave the connection in limbo. Truncation must respect
    /// UTF-8 or the reason is invalid and the peer rejects the close.
    #[test]
    fn an_over_long_close_reason_is_truncated_safely() {
        // Multi-byte characters, so a byte-indexed cut would split one.
        let reason = "é".repeat(200);
        let f = Frame::close(1000, &reason);
        assert!(f.payload.len() <= 125, "{} bytes", f.payload.len());
        assert!(
            std::str::from_utf8(&f.payload[2..]).is_ok(),
            "the truncated reason must remain valid UTF-8"
        );
    }

    /// A pong echoes its ping's payload, as §5.5.3 requires.
    #[test]
    fn a_pong_echoes_the_ping_payload() {
        let f = Frame::pong(b"ping-data".to_vec());
        assert_eq!(f.opcode, Opcode::Pong);
        assert_eq!(f.payload, b"ping-data");
        assert!(f.fin);
    }

    // -- text validation ---------------------------------------------------

    /// A valid UTF-8 text payload yields a `&str`.
    #[test]
    fn a_valid_text_payload_yields_a_str() {
        let f = Frame {
            opcode: Opcode::Text,
            fin: true,
            payload: "héllo 🎉".as_bytes().to_vec(),
        };
        assert_eq!(text_of(&f).expect("valid"), "héllo 🎉");
    }

    /// Invalid UTF-8 in a text frame is refused with `1007`.
    #[test]
    fn invalid_utf8_text_is_refused() {
        let f = Frame {
            opcode: Opcode::Text,
            fin: true,
            payload: vec![0xFF, 0xFE],
        };
        let err = text_of(&f).expect_err("must refuse");
        assert_eq!(
            err.close_code(),
            1007,
            "invalid payload data, not a framing error"
        );
    }

    /// **A fragmented text message validates as a whole, not per fragment.**
    ///
    /// §8.1: a multi-byte character split across two frames is valid only as a whole, so
    /// validating each fragment would reject a correct sender. This asserts the rule the
    /// design depends on — the fragments are individually invalid and jointly valid.
    #[test]
    fn a_split_multibyte_character_is_valid_as_a_whole() {
        let full = "é".as_bytes().to_vec();
        assert_eq!(full.len(), 2);
        let part1 = Frame {
            opcode: Opcode::Text,
            fin: false,
            payload: vec![full[0]],
        };
        let part2 = Frame {
            opcode: Opcode::Continuation,
            fin: true,
            payload: vec![full[1]],
        };

        assert!(
            text_of(&part1).is_err(),
            "the first fragment alone is invalid UTF-8 -- which is why per-fragment \
             validation would reject a correct sender"
        );

        let mut joined = part1.payload.clone();
        joined.extend_from_slice(&part2.payload);
        let whole = Frame {
            opcode: Opcode::Text,
            fin: true,
            payload: joined,
        };
        assert_eq!(text_of(&whole).expect("valid as a whole"), "é");
    }

    // -- reserved bits -----------------------------------------------------

    /// A frame with a reserved bit set is refused. §5.2.
    #[test]
    fn a_reserved_bit_is_refused() {
        let mut raw = client_frame(Opcode::Text, true, b"x", [1, 2, 3, 4]);
        raw[0] |= 0x40; // RSV1
        let err = decode_server_frame(&raw).expect_err("must refuse");
        assert!(matches!(err, FrameError::ReservedOpcode { .. }), "{err:?}");
    }

    /// A reserved opcode is refused rather than ignored.
    #[test]
    fn a_reserved_opcode_is_refused() {
        let mut raw = client_frame(Opcode::Text, true, b"x", [1, 2, 3, 4]);
        raw[0] = (raw[0] & 0xF0) | 0x3;
        let err = decode_server_frame(&raw).expect_err("must refuse");
        assert!(matches!(err, FrameError::ReservedOpcode { .. }), "{err:?}");
    }

    // -- determinism -------------------------------------------------------

    /// Encoding is deterministic. §10.5.
    #[test]
    fn encoding_is_deterministic() {
        let f = Frame {
            opcode: Opcode::Binary,
            fin: true,
            payload: (0..=255u8).collect(),
        };
        let first = encode(&f);
        for _ in 0..50 {
            assert_eq!(encode(&f), first);
        }
    }
}
