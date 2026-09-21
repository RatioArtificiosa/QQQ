// SPDX-License-Identifier: Apache-2.0

//! Message assembly: turning a sequence of frames into whole messages.
//!
//! RFC 6455 §5.4. The frame layer decodes *one frame*; a message may arrive as several.
//! This is the state machine between them, and it is where three rules that the frame
//! layer cannot enforce actually live.
//!
//! # The three rules, and why each needs state
//!
//! | Rule | §  | Why a single frame cannot be checked |
//! |---|---|---|
//! | A `Continuation` requires a message in progress | 5.4 | The frame is well-formed; it is its **arrival order** that is wrong. A decoder sees one frame and no history. |
//! | A data frame must not arrive mid-message | 5.4 | `Text` is a valid opcode whether it starts a message or illegally interrupts one. |
//! | A message's total length is bounded | — | Each frame is under the cap individually; a thousand of them are not. The frame layer's `MAX_FRAME_BYTES` says nothing about the sum. |
//!
//! # Control frames interleave, and that is not an exception
//!
//! §5.4: "Control frames MAY be injected in the middle of a fragmented message." So a
//! `Ping` between two fragments is legal — and this is the reason a `Ping` arriving
//! mid-message must **not** reset the accumulation. A state machine that treated any frame
//! as a potential restart would drop the first half of the message, and the failure would
//! appear only under a ping, which is rare in tests and constant in production behind a
//! load balancer.
//!
//! # Why text validation happens here rather than per frame
//!
//! A multi-byte character split across two fragments is valid only as a whole, so
//! validating each fragment would reject a correct sender. The check runs once, on the
//! assembled payload — which is why [`Assembler::push`] returns the message rather than
//! the frames.

use crate::ws_frame::{Frame, FrameError, Opcode};

/// A complete message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Whether the payload is text or binary.
    pub kind: Opcode,
    /// The assembled payload.
    pub payload: Vec<u8>,
}

impl Message {
    /// The message as text, validating UTF-8 (§8.1).
    ///
    /// # Errors
    ///
    /// [`FrameError::InvalidClosePayload`] with a reason naming the actual problem — the
    /// variant is reused so a caller has one error type for "the peer sent something we
    /// must close over", and its `close_code` is `1007`, which is right for bad UTF-8.
    pub fn as_text(&self) -> Result<&str, FrameError> {
        if self.kind != Opcode::Text {
            return Err(FrameError::InvalidClosePayload {
                reason: "this is a binary message, not text".to_owned(),
            });
        }
        std::str::from_utf8(&self.payload).map_err(|e| FrameError::InvalidClosePayload {
            reason: format!("a text message must be UTF-8 (§8.1): {e}"),
        })
    }
}

/// What a frame produced when it was pushed.
///
/// A three-way answer rather than `Option<Message>`, because "a control frame passed
/// through" and "a fragment was accumulated" are different facts and a caller acts
/// differently on each: a ping must be answered, a fragment must not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// The message is complete.
    Complete(Message),
    /// A fragment was accumulated; more frames are expected.
    Accumulating,
    /// A control frame, which the caller handles and which does **not** disturb any
    /// message in progress.
    Control(Frame),
}

/// The largest message this assembler will accumulate.
///
/// Larger than [`crate::ws_frame::MAX_FRAME_BYTES`] because a message may be many frames,
/// and smaller than any plausible memory ceiling because an unauthenticated peer chooses
/// how many fragments to send. The check is on the **running total**, which is the part the
/// frame layer cannot see: each frame is under its own cap and a thousand of them are not.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Assembles frames into messages.
///
/// One per connection. Holding the state is the point: whether a `Continuation` is legal
/// and whether a `Text` may arrive both depend on what came before, and a value that
/// forgot would have to be told.
#[derive(Debug, Default)]
pub struct Assembler {
    /// The message being accumulated, if any.
    in_progress: Option<InProgress>,
}

#[derive(Debug)]
struct InProgress {
    /// `Text` or `Binary` — the opcode of the frame that started it, which is what the
    /// completed message's `kind` must be. A `Continuation` carries no kind of its own,
    /// which is precisely why the state has to remember one.
    kind: Opcode,
    payload: Vec<u8>,
}

impl Assembler {
    /// A new assembler with no message in progress.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a message is partly accumulated.
    #[must_use]
    pub fn is_accumulating(&self) -> bool {
        self.in_progress.is_some()
    }

    /// How many bytes are currently held.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.in_progress.as_ref().map_or(0, |m| m.payload.len())
    }

    /// Push one frame.
    ///
    /// # Errors
    ///
    /// [`FrameError::UnexpectedContinuation`] when a `Continuation` arrives with nothing
    /// in progress, or a data frame arrives while a message is — both are §5.4 violations
    /// that only the arrival *sequence* can reveal.
    ///
    /// [`FrameError::Truncated`] when the accumulated total would exceed
    /// [`MAX_MESSAGE_BYTES`]. Checked **before** extending, so a peer cannot make the
    /// assembler allocate its way out of memory by sending many fragments.
    pub fn push(&mut self, frame: Frame) -> Result<Progress, FrameError> {
        // Control frames pass through and leave any message in progress **untouched**.
        // §5.4 allows them to interleave, so a ping is not a restart.
        if frame.opcode.is_control() {
            return Ok(Progress::Control(frame));
        }

        match frame.opcode {
            Opcode::Text | Opcode::Binary => {
                if self.in_progress.is_some() {
                    return Err(FrameError::UnexpectedContinuation {
                        expected: format!(
                            "a `Continuation` or a control frame, because a \
                             {} message is still being assembled (§5.4)",
                            self.in_progress.as_ref().map_or("data", |m| m.kind_name())
                        ),
                    });
                }
                if frame.fin {
                    // A single-frame message: no accumulation needed, but the **text
                    // check still runs**, because §8.1 applies to every text message and
                    // not only to fragmented ones.
                    let message = Message {
                        kind: frame.opcode,
                        payload: frame.payload,
                    };
                    if message.kind == Opcode::Text {
                        message.as_text()?;
                    }
                    return Ok(Progress::Complete(message));
                }
                // The first fragment of a fragmented message.
                if frame.payload.len() > MAX_MESSAGE_BYTES {
                    return Err(FrameError::Truncated {
                        needed: frame.payload.len(),
                        got: 0,
                    });
                }
                self.in_progress = Some(InProgress {
                    kind: frame.opcode,
                    payload: frame.payload,
                });
                Ok(Progress::Accumulating)
            }
            Opcode::Continuation => {
                let Some(mut in_progress) = self.in_progress.take() else {
                    return Err(FrameError::UnexpectedContinuation {
                        expected: "a `Text` or `Binary` frame to start a message, because \
                                   none is in progress (§5.4)"
                            .to_owned(),
                    });
                };

                // Bounded **before** the extend, not after: a peer sending a million
                // fragments would otherwise grow this vector until the allocator failed.
                let total = in_progress
                    .payload
                    .len()
                    .saturating_add(frame.payload.len());
                if total > MAX_MESSAGE_BYTES {
                    // The message is abandoned rather than left half-built. A caller that
                    // recovers must not be able to continue assembling a message that was
                    // already refused, or it would accept a payload it had rejected.
                    return Err(FrameError::Truncated {
                        needed: total,
                        got: in_progress.payload.len(),
                    });
                }

                in_progress.payload.extend_from_slice(&frame.payload);
                if !frame.fin {
                    self.in_progress = Some(in_progress);
                    return Ok(Progress::Accumulating);
                }

                let message = Message {
                    kind: in_progress.kind,
                    payload: in_progress.payload,
                };
                // §8.1 again: the check is on the assembled payload, because a multi-byte
                // character split across fragments is valid only as a whole.
                if message.kind == Opcode::Text {
                    message.as_text()?;
                }
                Ok(Progress::Complete(message))
            }
            // Control frames were handled above; this arm is unreachable and is written
            // out rather than silenced so adding an opcode is a compile error here.
            Opcode::Close | Opcode::Ping | Opcode::Pong => Ok(Progress::Control(frame)),
        }
    }
}

impl InProgress {
    /// A human name for the kind, for the error message.
    fn kind_name(&self) -> &'static str {
        if self.kind == Opcode::Text {
            "text"
        } else {
            "binary"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(fin: bool, payload: &[u8]) -> Frame {
        Frame {
            opcode: Opcode::Text,
            fin,
            payload: payload.to_vec(),
        }
    }

    fn cont(fin: bool, payload: &[u8]) -> Frame {
        Frame {
            opcode: Opcode::Continuation,
            fin,
            payload: payload.to_vec(),
        }
    }

    fn ping(payload: &[u8]) -> Frame {
        Frame {
            opcode: Opcode::Ping,
            fin: true,
            payload: payload.to_vec(),
        }
    }

    // -- single-frame messages ---------------------------------------------

    /// A complete text frame yields a message immediately.
    #[test]
    fn a_single_frame_message_is_complete() {
        let mut a = Assembler::new();
        let out = a.push(text(true, b"hello")).expect("valid");
        match out {
            Progress::Complete(m) => {
                assert_eq!(m.kind, Opcode::Text);
                assert_eq!(m.as_text().expect("utf8"), "hello");
            }
            other => panic!("expected a message, got {other:?}"),
        }
        assert!(!a.is_accumulating());
    }

    /// A complete binary frame keeps its kind.
    #[test]
    fn a_binary_message_keeps_its_kind() {
        let mut a = Assembler::new();
        let out = a
            .push(Frame {
                opcode: Opcode::Binary,
                fin: true,
                payload: vec![0, 1, 2],
            })
            .expect("valid");
        match out {
            Progress::Complete(m) => {
                assert_eq!(m.kind, Opcode::Binary);
                assert!(
                    m.as_text().is_err(),
                    "a binary message must not be readable as text"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    /// **A single-frame text message is validated too.**
    ///
    /// §8.1 applies to every text message, not only fragmented ones. A change that moved
    /// the check into the continuation path would leave one-frame messages unchecked —
    /// which is the common case.
    #[test]
    fn a_single_frame_text_message_is_validated() {
        let mut a = Assembler::new();
        let err = a
            .push(text(true, &[0xFF, 0xFE]))
            .expect_err("invalid UTF-8 must be refused");
        assert_eq!(err.close_code(), 1007);
    }

    // -- fragmentation -----------------------------------------------------

    /// A fragmented message assembles across frames.
    #[test]
    fn a_fragmented_message_assembles() {
        let mut a = Assembler::new();
        assert_eq!(
            a.push(text(false, b"Hel")).expect("valid"),
            Progress::Accumulating
        );
        assert!(a.is_accumulating());
        assert_eq!(
            a.push(cont(false, b"lo, ")).expect("valid"),
            Progress::Accumulating
        );
        // "Hel" (3) + "lo, " (4) = 7. A first version asserted 6 — my arithmetic, not the
        // assembler's. Counting the bytes is the whole point of this assertion, so getting
        // the expected sum wrong would have hidden a real off-by-one in `buffered`.
        assert_eq!(a.buffered(), 7);

        let out = a.push(cont(true, b"world")).expect("valid");
        match out {
            Progress::Complete(m) => {
                assert_eq!(m.as_text().expect("utf8"), "Hello, world");
                assert_eq!(m.kind, Opcode::Text, "the kind comes from the first frame");
            }
            other => panic!("{other:?}"),
        }
        assert!(!a.is_accumulating(), "the state must clear");
    }

    /// A binary message fragments the same way.
    #[test]
    fn a_fragmented_binary_message_assembles() {
        let mut a = Assembler::new();
        a.push(Frame {
            opcode: Opcode::Binary,
            fin: false,
            payload: vec![1, 2],
        })
        .expect("valid");
        let out = a.push(cont(true, &[3, 4])).expect("valid");
        match out {
            Progress::Complete(m) => {
                assert_eq!(m.kind, Opcode::Binary);
                assert_eq!(m.payload, vec![1, 2, 3, 4]);
            }
            other => panic!("{other:?}"),
        }
    }

    // -- the sequence rules ------------------------------------------------

    /// **A `Continuation` with nothing in progress is refused.** §5.4.
    ///
    /// The frame is well-formed, so only the arrival order can reveal this.
    #[test]
    fn a_continuation_with_nothing_in_progress_is_refused() {
        let mut a = Assembler::new();
        let err = a.push(cont(true, b"x")).expect_err("must refuse");
        assert!(
            matches!(err, FrameError::UnexpectedContinuation { .. }),
            "{err:?}"
        );
        assert!(
            err.to_string().contains("none is in progress"),
            "the message must say what was expected: {err}"
        );
    }

    /// **A data frame arriving mid-message is refused.** §5.4.
    ///
    /// A second `Text` while a message is being assembled is illegal: the sender meant to
    /// continue it and used the wrong opcode, and accepting it would silently start a new
    /// message with the old one's bytes lost.
    #[test]
    fn a_data_frame_mid_message_is_refused() {
        let mut a = Assembler::new();
        a.push(text(false, b"first")).expect("valid");
        let err = a.push(text(true, b"second")).expect_err("must refuse");
        assert!(
            matches!(err, FrameError::UnexpectedContinuation { .. }),
            "{err:?}"
        );
        assert!(
            err.to_string()
                .contains("text message is still being assembled"),
            "the message must name the kind in progress: {err}"
        );
    }

    /// A binary frame mid-text-message is refused too.
    #[test]
    fn a_binary_frame_mid_message_is_refused() {
        let mut a = Assembler::new();
        a.push(text(false, b"x")).expect("valid");
        let err = a
            .push(Frame {
                opcode: Opcode::Binary,
                fin: true,
                payload: vec![1],
            })
            .expect_err("must refuse");
        assert!(
            matches!(err, FrameError::UnexpectedContinuation { .. }),
            "{err:?}"
        );
    }

    // -- control frames interleave ----------------------------------------

    /// **A control frame mid-message passes through and does not reset the message.**
    ///
    /// §5.4 permits interleaving, and this is the rule a state machine is most likely to
    /// get wrong: treating the ping as a restart would drop the first half, and the
    /// failure appears only under a ping — rare in tests, constant in production behind a
    /// load balancer that keeps idle connections alive.
    #[test]
    fn a_control_frame_mid_message_does_not_reset_it() {
        let mut a = Assembler::new();
        a.push(text(false, b"first-")).expect("valid");

        let out = a.push(ping(b"keepalive")).expect("valid");
        match out {
            Progress::Control(f) => {
                assert_eq!(f.opcode, Opcode::Ping);
                assert_eq!(
                    f.payload, b"keepalive",
                    "the caller needs the payload to echo"
                );
            }
            other => panic!("expected a control frame, got {other:?}"),
        }

        assert!(a.is_accumulating(), "the message must survive the ping");
        assert_eq!(a.buffered(), 6, "and its bytes must be untouched");

        let out = a.push(cont(true, b"second")).expect("valid");
        match out {
            Progress::Complete(m) => {
                assert_eq!(
                    m.as_text().expect("utf8"),
                    "first-second",
                    "the message must join across the interleaved control frame"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    /// A close frame mid-message also passes through without resetting.
    #[test]
    fn a_close_frame_mid_message_passes_through() {
        let mut a = Assembler::new();
        a.push(text(false, b"partial")).expect("valid");
        let out = a.push(Frame::close(1000, "going away")).expect("valid");
        assert!(matches!(out, Progress::Control(_)), "{out:?}");
        assert!(a.is_accumulating());
    }

    /// Control frames pass through with no message in progress.
    #[test]
    fn a_control_frame_with_no_message_passes_through() {
        let mut a = Assembler::new();
        let out = a.push(ping(b"x")).expect("valid");
        assert!(matches!(out, Progress::Control(_)), "{out:?}");
        assert!(!a.is_accumulating());
    }

    // -- bounds ------------------------------------------------------------

    /// **A fragmented message is bounded by its running total.**
    ///
    /// The part the frame layer cannot see: each frame is under `MAX_FRAME_BYTES`
    /// individually, and a million of them are not. Checked before the extend, so a peer
    /// cannot make the assembler allocate its way out of memory.
    #[test]
    fn the_running_total_is_bounded() {
        let mut a = Assembler::new();
        // One fragment of just over half the ceiling, then another that would pass it.
        let half = MAX_MESSAGE_BYTES / 2 + 1;
        a.push(text(false, &vec![b'a'; half]))
            .expect("the first fits");

        let err = a
            .push(cont(true, &vec![b'b'; half]))
            .expect_err("the total must be bounded");
        assert!(matches!(err, FrameError::Truncated { .. }), "{err:?}");
        assert!(
            !a.is_accumulating(),
            "the abandoned message must not be resumable -- a caller that continued would \
             accept a payload that was already refused"
        );
    }

    /// A single oversized first fragment is refused.
    #[test]
    fn an_oversized_first_fragment_is_refused() {
        let mut a = Assembler::new();
        let err = a
            .push(text(false, &vec![b'a'; MAX_MESSAGE_BYTES + 1]))
            .expect_err("must refuse");
        assert!(matches!(err, FrameError::Truncated { .. }), "{err:?}");
        assert!(!a.is_accumulating());
    }

    // -- text across fragments --------------------------------------------

    /// **A multi-byte character split across fragments assembles and validates.**
    ///
    /// §8.1: valid only as a whole. This is why the check is here rather than in the frame
    /// layer, and why `Assembler` exists at all.
    #[test]
    fn a_split_multibyte_character_validates_as_a_whole() {
        let bytes = "é".as_bytes();
        let mut a = Assembler::new();
        a.push(text(false, &bytes[..1]))
            .expect("a fragment is not validated alone");
        let out = a.push(cont(true, &bytes[1..])).expect("valid");
        match out {
            Progress::Complete(m) => assert_eq!(m.as_text().expect("utf8"), "é"),
            other => panic!("{other:?}"),
        }
    }

    /// A fragmented message whose whole payload is invalid UTF-8 is refused at the end.
    #[test]
    fn an_invalid_assembled_message_is_refused() {
        let mut a = Assembler::new();
        a.push(text(false, &[0xFF]))
            .expect("a fragment is not validated alone");
        let err = a.push(cont(true, &[0xFE])).expect_err("must refuse");
        assert_eq!(err.close_code(), 1007);
    }

    // -- reuse across messages --------------------------------------------

    /// The assembler handles consecutive messages, and its state clears between them.
    #[test]
    fn consecutive_messages_are_independent() {
        let mut a = Assembler::new();
        for i in 0..5 {
            let out = a
                .push(text(true, format!("m{i}").as_bytes()))
                .expect("valid");
            match out {
                Progress::Complete(m) => assert_eq!(m.as_text().expect("utf8"), format!("m{i}")),
                other => panic!("{other:?}"),
            }
            assert!(!a.is_accumulating(), "state must clear after message {i}");
        }
    }

    /// A fragmented message followed by a single-frame one both work.
    #[test]
    fn fragmented_then_whole_messages_work() {
        let mut a = Assembler::new();
        a.push(text(false, b"a")).expect("valid");
        a.push(cont(true, b"b")).expect("valid");
        let out = a.push(text(true, b"c")).expect("valid");
        match out {
            Progress::Complete(m) => assert_eq!(m.as_text().expect("utf8"), "c"),
            other => panic!("{other:?}"),
        }
    }

    /// An empty message is a valid message.
    #[test]
    fn an_empty_message_is_valid() {
        let mut a = Assembler::new();
        let out = a.push(text(true, b"")).expect("valid");
        match out {
            Progress::Complete(m) => assert_eq!(m.as_text().expect("utf8"), ""),
            other => panic!("{other:?}"),
        }
    }

    /// An empty first fragment followed by content assembles.
    #[test]
    fn an_empty_first_fragment_is_valid() {
        let mut a = Assembler::new();
        assert_eq!(
            a.push(text(false, b"")).expect("valid"),
            Progress::Accumulating
        );
        let out = a.push(cont(true, b"body")).expect("valid");
        match out {
            Progress::Complete(m) => assert_eq!(m.as_text().expect("utf8"), "body"),
            other => panic!("{other:?}"),
        }
    }
}
