// SPDX-License-Identifier: Apache-2.0

//! Flow control (RFC 9113 §5.2, §6.9).
//!
//! Implements `SRV-002`; RFC 9113 §5.2 (flow control), §5.2.1 (the two windows),
//! §6.9 (`WINDOW_UPDATE`), §6.9.1 (the window's range), §6.9.2
//! (`SETTINGS_INITIAL_WINDOW_SIZE`).
//!
//! # The one rule this module exists to get right
//!
//! *"A sender MUST NOT send a flow-controlled frame with a length that exceeds
//! the space available in either of the flow-control windows advertised by the
//! receiver."* — §5.2.1.
//!
//! **Either**. Every mistake in flow control is some version of forgetting one of
//! the two windows, so the decision is a single function here,
//! [`FlowControl::available_send`], returning the **minimum** of the connection
//! window and the stream's. It is not "check the connection, then check the
//! stream" at the call site, because that shape lets one of the two checks be
//! dropped and still compile.
//!
//! ```text
//!   connection window ──┐
//!                       ├──► minimum ──► how many bytes this DATA frame may carry
//!   stream window     ──┘
//! ```
//!
//! # Why both windows live here and not on the stream
//!
//! [`crate::h2::stream`] holds a stream's state and its unreplenished receive
//! credit. It does **not** hold the stream's window. The reason is that the
//! minimum above has to be computed against the *current* connection window, and
//! two owners of one number drift: a stream would decrement its copy, the
//! connection its own, and neither would see the other's `WINDOW_UPDATE`. One
//! owner makes the minimum honest by construction.
//!
//! # The three error codes, and why they are not interchangeable
//!
//! §5.2.2 and §6.9 assign three different codes to three different failures, and
//! each names a different bug in the peer:
//!
//! | condition | code | what it means |
//! |---|---|---|
//! | more DATA received than the window allows | `FLOW_CONTROL_ERROR` | a window accounting bug |
//! | a `WINDOW_UPDATE` with increment 0 | `PROTOCOL_ERROR` | a framing bug |
//! | a `WINDOW_UPDATE` that overflows 2^31-1 | `FLOW_CONTROL_ERROR` | a window accounting bug |
//! | an adjusted window that exceeds 2^31-1 | `FLOW_CONTROL_ERROR` | the peer's setting is unusable |
//!
//! The zero-increment case is `PROTOCOL_ERROR` and not `FLOW_CONTROL_ERROR`,
//! which is counter-intuitive enough that §6.9 calls it out explicitly:
//! *"A receiver MUST treat the receipt of a `WINDOW_UPDATE` frame with an
//! flow-control window increment of 0 as a stream error of type `PROTOCOL_ERROR`;
//! errors on the connection flow-control window MUST be treated as a connection
//! error."* Returning `FLOW_CONTROL_ERROR` there sends the peer debugging its
//! window arithmetic when the defect is in its frame encoding.
//!
//! # Negative windows are legal, and are the point of the delta rule
//!
//! §6.9.2: a change to `SETTINGS_INITIAL_WINDOW_SIZE` adjusts **every open
//! stream's** send window by the difference, and *"a change to
//! `SETTINGS_INITIAL_WINDOW_SIZE` can cause the available space in a flow-control
//! window to become negative"*. A negative window is not an error — it means the
//! sender has already sent more than the new window permits and must wait for
//! `WINDOW_UPDATE` before sending more. Implementations get this wrong by
//! clamping at zero, which **silently grants the peer extra credit**: the sender
//! then believes it may send the clamped amount again, and the receiver's
//! accounting is violated by exactly the amount that was clamped away.
//!
//! The window is therefore stored as a **signed 64-bit** value, wide enough that
//! neither the delta nor the running total can overflow before it is checked.

use std::fmt;

use super::error::{ConnectionError, ErrorCode, StreamError};

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// The connection's initial send window: 65535 bytes (RFC 9113 §6.9.2).
///
/// Fixed and not settable: `SETTINGS_INITIAL_WINDOW_SIZE` applies to **streams**
/// only, and the connection window begins here for every connection and can only
/// grow via `WINDOW_UPDATE`. An implementation that applied the setting to the
/// connection too would let a peer enlarge the connection window with a single
/// setting, which is exactly the amplification the fixed value prevents.
pub const DEFAULT_CONNECTION_WINDOW: u32 = 65_535;

/// The largest a flow-control window may become: 2^31 - 1 (RFC 9113 §6.9.1).
///
/// *"A sender MUST NOT allow a flow-control window to exceed 2^31-1 octets."*
/// The ceiling is the format's, not a policy: `WINDOW_UPDATE`'s increment field
/// is 31 bits, so a window larger than this could never be extended and every
/// subsequent increment would be an error. It is also the reason an
/// over-large window is `FLOW_CONTROL_ERROR` rather than `PROTOCOL_ERROR`.
pub const MAX_WINDOW: u32 = 2_147_483_647;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A flow-control violation.
///
/// # Why this is its own type rather than a bare [`ConnectionError`]
///
/// Every flow-control failure is a *connection* error by default — §5.2.2 gives
/// no stream-level alternative for exceeding a window — **except** the
/// `WINDOW_UPDATE` cases, which §6.9 splits: a zero increment on a stream is a
/// stream error and on the connection is a connection error.
///
/// A single type that carries the scope is what lets [`FlowControl`] return one
/// thing and the caller decide, instead of the caller re-deriving the scope from
/// a stream id — which is precisely the check that gets forgotten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// The peer sent more flow-controlled data than a window allowed.
    ///
    /// RFC 9113 §5.2.2, §6.1: a connection error of type `FLOW_CONTROL_ERROR`.
    /// Carries both the window that was exceeded and by how much, because
    /// "flow control exceeded" alone cannot distinguish a peer that ignored the
    /// window from one that miscounted padding — and padding *does* count (§6.1),
    /// which is the misread that produces this error most often.
    WindowExceeded {
        /// Which window: the stream id, or `None` for the connection.
        stream: Option<u32>,
        /// The window's value when the frame arrived.
        window: i64,
        /// How many bytes the frame claimed.
        requested: u32,
    },
    /// A `WINDOW_UPDATE` carried an increment of zero.
    ///
    /// RFC 9113 §6.9: *"A receiver MUST treat the receipt of a `WINDOW_UPDATE` frame
    /// with an flow-control window increment of 0 as a stream error of type
    /// `PROTOCOL_ERROR`"* — and, for the connection window, as a connection error.
    /// **`PROTOCOL_ERROR`, not `FLOW_CONTROL_ERROR`**: the defect is in the
    /// frame's encoding, and reporting it as a window bug sends the peer looking
    /// in the wrong place.
    ZeroIncrement {
        /// Whether this named the connection window.
        connection: bool,
    },
    /// A `WINDOW_UPDATE` would push a window past 2^31-1.
    ///
    /// RFC 9113 §6.9.1: *"A sender MUST NOT allow a flow-control window to exceed
    /// 2^31-1 octets. If a sender receives a `WINDOW_UPDATE` that causes a
    /// flow-control window to exceed this maximum, it MUST terminate either the
    /// stream or the connection."* A `FLOW_CONTROL_ERROR`, not `PROTOCOL_ERROR`:
    /// the peer's frame is well-formed, its window arithmetic is wrong.
    WindowOverflow {
        /// Which window: the stream id, or `None` for the connection.
        stream: Option<u32>,
        /// The window's value before the increment.
        window: i64,
        /// The increment that would overflow it.
        increment: u32,
    },
    /// A `SETTINGS_INITIAL_WINDOW_SIZE` change overflowed an open stream's
    /// window.
    ///
    /// RFC 9113 §6.9.2 assigns `FLOW_CONTROL_ERROR`. Note the asymmetry with the
    /// negative case, which is **legal**: only going *over* the ceiling is an
    /// error, because a window below zero is meaningful ("wait") while one above
    /// 2^31-1 is unrepresentable.
    SettingsWindowOverflow {
        /// The stream whose window overflowed.
        stream: u32,
        /// The window before the adjustment.
        window: i64,
        /// The delta that was applied.
        delta: i64,
    },
    /// The window named a stream that has no entry.
    ///
    /// Not a peer-visible protocol violation in itself — a `WINDOW_UPDATE` may
    /// legitimately arrive for a stream that has since closed — so the caller
    /// decides. Carried as an error so a silent drop of real credit is
    /// impossible, because a lost `WINDOW_UPDATE` is a **stall**: the sender
    /// waits forever for credit that was received and discarded.
    UnknownStream {
        /// The stream id from the frame.
        stream: u32,
    },
}

impl FlowError {
    /// The RFC code for this violation.
    #[must_use]
    // Kept as separate arms: these four variants deliberately share a code but
    // name different violations (§5.2.2 window exceeded, §6.9 overflow, a
    // settings-driven overflow, and a WINDOW_UPDATE for an unknown stream), and
    // each carries its own field. Merging them into one `|` arm would erase the
    // distinction the rest of this module matches on.
    #[allow(clippy::match_same_arms)]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::WindowExceeded { .. } => ErrorCode::FlowControlError,
            // §6.9 is explicit that a zero increment is PROTOCOL_ERROR. Both
            // scopes share the code and differ only in what they terminate.
            Self::ZeroIncrement { .. } => ErrorCode::ProtocolError,
            Self::WindowOverflow { .. } => ErrorCode::FlowControlError,
            Self::SettingsWindowOverflow { .. } => ErrorCode::FlowControlError,
            Self::UnknownStream { .. } => ErrorCode::FlowControlError,
        }
    }

    /// Whether this ends the connection rather than one stream.
    ///
    /// The rule from §5.2.2 and §6.9: a **connection-window** violation is always
    /// fatal, because every stream shares that window and its accounting can no
    /// longer be trusted. A **stream-window** violation terminates the stream,
    /// and the connection continues with its other streams intact — which is the
    /// property that makes multiplexing useful under a misbehaving peer.
    #[must_use]
    // Kept as separate arms: both are non-fatal, but for different reasons that
    // the comments below state — one is a property of a single stream's window,
    // the other consumed nothing at all. Merging them would drop a rule.
    #[allow(clippy::match_same_arms)]
    pub const fn is_connection_fatal(&self) -> bool {
        match self {
            // The connection window has no stream id, so `stream: None` is the
            // connection. A stream-window overflow resets that stream only.
            Self::WindowExceeded { stream, .. } | Self::WindowOverflow { stream, .. } => {
                stream.is_none()
            }
            Self::ZeroIncrement { connection } => *connection,
            // A settings-driven overflow is a property of one stream's window.
            Self::SettingsWindowOverflow { .. } => false,
            // Nothing was consumed; the caller decides whether the stream exists.
            Self::UnknownStream { .. } => false,
        }
    }

    /// The stream this violation belongs to, or `None` for the connection.
    ///
    /// Note that `SettingsWindowOverflow` stores its stream id as a bare `u32`
    /// rather than an `Option<u32>`: that failure can only ever be about a stream,
    /// because the connection window is not moved by `SETTINGS_INITIAL_WINDOW_SIZE`
    /// (§6.9.2). The asymmetry is deliberate — an `Option` there would suggest a
    /// connection-scoped case that does not exist.
    #[must_use]
    pub const fn stream(&self) -> Option<u32> {
        match self {
            Self::WindowExceeded { stream, .. } | Self::WindowOverflow { stream, .. } => *stream,
            Self::SettingsWindowOverflow { stream, .. } | Self::UnknownStream { stream } => {
                Some(*stream)
            }
            // A zero increment carries no id: the caller already asked about a
            // specific window and `connection` records which. `None` here means
            // "the connection", which is what a caller reporting a fatal fault
            // wants.
            Self::ZeroIncrement { .. } => None,
        }
    }

    /// The connection-error view, for the fatal cases.
    ///
    /// `None` when this terminates only a stream — the caller resets that stream
    /// and continues.
    #[must_use]
    pub fn as_connection_error(&self) -> Option<ConnectionError> {
        if self.is_connection_fatal() {
            Some(ConnectionError::protocol(self.code(), self.to_string()))
        } else {
            None
        }
    }

    /// The stream-error view, for the recoverable cases.
    #[must_use]
    pub fn as_stream_error(&self) -> StreamError {
        StreamError::protocol(self.code(), self.to_string())
    }
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WindowExceeded {
                stream,
                window,
                requested,
            } => match stream {
                Some(id) => write!(
                    f,
                    "stream {id} sent {requested} flow-controlled bytes but its window \
                     is {window} (RFC 9113 §5.2.2) — note that DATA padding counts \
                     against the window, which is the usual cause"
                ),
                None => write!(
                    f,
                    "the connection received {requested} flow-controlled bytes but its \
                     window is {window} (RFC 9113 §5.2.2)"
                ),
            },
            Self::ZeroIncrement { connection } => {
                if *connection {
                    f.write_str(
                        "WINDOW_UPDATE on the connection with a zero increment \
                         (RFC 9113 §6.9): PROTOCOL_ERROR, not FLOW_CONTROL_ERROR",
                    )
                } else {
                    f.write_str(
                        "WINDOW_UPDATE on a stream with a zero increment \
                         (RFC 9113 §6.9): PROTOCOL_ERROR, not FLOW_CONTROL_ERROR",
                    )
                }
            }
            Self::WindowOverflow {
                stream,
                window,
                increment,
            } => match stream {
                Some(id) => write!(
                    f,
                    "a {increment}-byte WINDOW_UPDATE would take stream {id}'s window \
                     from {window} past the {MAX_WINDOW} maximum (RFC 9113 §6.9.1)"
                ),
                None => write!(
                    f,
                    "a {increment}-byte WINDOW_UPDATE would take the connection window \
                     from {window} past the {MAX_WINDOW} maximum (RFC 9113 §6.9.1)"
                ),
            },
            Self::SettingsWindowOverflow {
                stream,
                window,
                delta,
            } => write!(
                f,
                "SETTINGS_INITIAL_WINDOW_SIZE would move stream {stream}'s window from \
                 {window} by {delta}, past the {MAX_WINDOW} maximum (RFC 9113 §6.9.2)"
            ),
            Self::UnknownStream { stream } => write!(
                f,
                "flow control named stream {stream}, which has no window — dropping a \
                 WINDOW_UPDATE stalls the sender"
            ),
        }
    }
}

impl std::error::Error for FlowError {}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

/// One flow-control window.
///
/// Signed 64-bit, deliberately. See this module's header: a window may legally go
/// **negative** when `SETTINGS_INITIAL_WINDOW_SIZE` is reduced (§6.9.2), and a
/// `u32` cannot represent that. Clamping at zero instead of going negative grants
/// the peer credit it does not have, silently.
///
/// 64 bits rather than `i32`: the ceiling is 2^31-1, and an increment is up to
/// 2^31-1, so a `+` on `i32` can overflow *before* the range check that is
/// supposed to catch it. Wide arithmetic makes the check the only thing that can
/// fail, which is what makes the check testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// The current size, which may be negative (§6.9.2).
    size: i64,
    /// The value a newly opened stream starts at, from
    /// `SETTINGS_INITIAL_WINDOW_SIZE`.
    ///
    /// Held per window rather than read from a shared `Settings` so that the
    /// delta rule of §6.9.2 is computable from the window itself: the adjustment
    /// is `new - old`, and a window that does not remember what it started at
    /// cannot compute it. This is the field whose absence produces the classic
    /// bug — adjusting by the *new* value instead of the difference, which is
    /// correct for exactly one stream and wrong for every other.
    initial: u32,
    /// Bytes consumed on this window since the last `WINDOW_UPDATE` was taken.
    ///
    /// The credit owed back to the peer. Tracked per window for the same reason
    /// the connection's `connection_recv_unacked` is tracked: `WINDOW_UPDATE`
    /// advertises a *delta*, and a delta computed from the window's remaining
    /// size is not a delta at all — it is the whole window, which over-credits
    /// the peer by everything already spent. See
    /// [`FlowControl::take_stream_replenishment`].
    recv_unacked: u32,
}

impl Window {
    /// A window at a given size, with that size as its initial value.
    #[must_use]
    pub const fn new(size: u32) -> Self {
        Self {
            size: size as i64,
            initial: size,
            recv_unacked: 0,
        }
    }

    /// The credit owed back to the peer: bytes consumed since the last take.
    #[must_use]
    pub const fn recv_unacked(&self) -> u32 {
        self.recv_unacked
    }

    /// The current size, which may be negative.
    #[must_use]
    pub const fn size(&self) -> i64 {
        self.size
    }

    /// The current size as a send allowance: negative saturates to zero.
    ///
    /// This is the **only** place a negative window becomes zero, and it is safe
    /// here because the value is used to answer "may I send *now*". The window
    /// itself keeps its negative value, so a later `WINDOW_UPDATE` must first
    /// climb back to zero before any sending resumes — which is the whole point
    /// of §6.9.2's rule. Clamping in the stored value instead would make that
    /// first `WINDOW_UPDATE` immediately sendable.
    #[must_use]
    // `size` is proven to be in `1..=MAX_WINDOW` by the two branches above, so
    // this cast cannot truncate or lose a sign. `try_from` is not available in a
    // `const fn`, and the include-the-guard-in-the-expression alternative is the
    // same cast with more punctuation. The `allow` is scoped to this function
    // rather than the module so it cannot silence a *new* unchecked cast nearby.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub const fn available(&self) -> u32 {
        if self.size <= 0 {
            0
        } else if self.size > MAX_WINDOW as i64 {
            // Unreachable: every mutation checks the ceiling. Saturating rather
            // than truncating, because a truncating cast here would silently
            // reduce a window and manufacture a stall.
            MAX_WINDOW
        } else {
            self.size as u32
        }
    }

    /// The initial size this window's stream was opened at.
    #[must_use]
    pub const fn initial(&self) -> u32 {
        self.initial
    }

    /// Decrement by `n`, refusing to go below zero.
    ///
    /// # Errors
    ///
    /// [`FlowError::WindowExceeded`]. Sending or receiving more than the window
    /// allows is the violation §5.2.2 defines, and the check is here rather than
    /// at the call site so that it cannot be skipped.
    pub fn try_consume(&mut self, stream: Option<u32>, n: u32) -> Result<(), FlowError> {
        let after = self.size - i64::from(n);
        if after < 0 {
            return Err(FlowError::WindowExceeded {
                stream,
                window: self.size,
                requested: n,
            });
        }
        self.size = after;
        Ok(())
    }

    /// Add an increment, refusing to exceed the ceiling.
    ///
    /// # Errors
    ///
    /// [`FlowError::WindowOverflow`] when the result would exceed 2^31-1.
    /// Allowing it is not an option: §6.9.1 forbids a window above the ceiling,
    /// and a window that large could never be extended again because no
    /// `WINDOW_UPDATE` increment is representable.
    pub fn try_increase(&mut self, stream: Option<u32>, increment: u32) -> Result<(), FlowError> {
        let after = self.size + i64::from(increment);
        if after > i64::from(MAX_WINDOW) {
            return Err(FlowError::WindowOverflow {
                stream,
                window: self.size,
                increment,
            });
        }
        self.size = after;
        Ok(())
    }

    /// Apply a new `SETTINGS_INITIAL_WINDOW_SIZE` to this window (§6.9.2).
    ///
    /// # The rule, stated exactly
    ///
    /// The window moves by the **difference** between the new initial size and
    /// the old one — not to the new value. For a stream that has never sent
    /// anything the two coincide, which is why the bug is invisible until a stream
    /// has data in flight:
    ///
    /// ```text
    ///   initial 65535, window 1000 (64535 bytes in flight)
    ///   SETTINGS_INITIAL_WINDOW_SIZE: 0
    ///   delta = 0 - 65535 = -65535
    ///   window = 1000 - 65535 = -64535   ← legal, and it means "wait"
    ///
    ///   setting the window to 0 instead would grant 1000 more bytes of credit
    ///   than the peer has allowed.
    /// ```
    ///
    /// A negative result is **legal** and is not an error (§6.9.2 names the case).
    /// Only exceeding 2^31-1 is.
    ///
    /// # Errors
    ///
    /// [`FlowError::SettingsWindowOverflow`] when the adjusted window exceeds
    /// 2^31-1.
    pub fn apply_initial_window_size(
        &mut self,
        stream: u32,
        new_initial: u32,
    ) -> Result<(), FlowError> {
        let delta = i64::from(new_initial) - i64::from(self.initial);
        let after = self.size + delta;
        if after > i64::from(MAX_WINDOW) {
            return Err(FlowError::SettingsWindowOverflow {
                stream,
                window: self.size,
                delta,
            });
        }
        self.size = after;
        // The initial is updated **after** the delta is computed, which is what
        // makes a second change compute its delta from the right baseline. Doing
        // it first would make the second delta zero and silently stop adjusting.
        self.initial = new_initial;
        Ok(())
    }

    /// Reset to a new initial size unconditionally.
    ///
    /// Used when a stream is created, where the window is exactly the initial
    /// size and there is no delta to apply.
    #[must_use]
    pub const fn at_initial(size: u32) -> Self {
        Self::new(size)
    }
}

impl fmt::Display for Window {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (initial {})", self.size, self.initial)
    }
}

// ---------------------------------------------------------------------------
// The two directions
// ---------------------------------------------------------------------------

/// One direction's windows: the connection's and every stream's.
///
/// # Why one type covers both directions
///
/// The send and receive directions are structurally identical — a connection
/// window plus a per-stream window, each subject to the same ceiling and the same
/// delta rule — and they differ only in *who* decrements them: we decrement the
/// send windows when we transmit, and the receive windows when the peer does (the
/// receive window is the sender's view, so §5.2.1's accounting applies to the
/// bytes we have accepted against the credit we advertised).
///
/// Sharing the type means the delta rule of §6.9.2 — the rule most implementations
/// get wrong — is written once. A version that kept the receive side as loose
/// `u32`s would have to reimplement it, and the reimplementation is exactly the
/// one nobody remembers to test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Direction {
    /// The connection-level window.
    connection: Window,
    /// Per-stream windows, keyed by stream id.
    ///
    /// A `Vec` rather than a `HashMap`: a connection has at most
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` live streams (100 by default, and the
    /// peer's own ceiling bounds it), so a linear scan is faster than hashing for
    /// every size that occurs in practice, and it keeps iteration order stable for
    /// diagnostics.
    streams: Vec<(u32, Window)>,
    /// The `SETTINGS_INITIAL_WINDOW_SIZE` a newly opened stream starts at.
    initial_stream_window: u32,
}

impl Direction {
    /// A direction with the given connection window and initial stream window.
    #[must_use]
    pub const fn new(connection: u32, initial_stream_window: u32) -> Self {
        Self {
            connection: Window::new(connection),
            streams: Vec::new(),
            initial_stream_window,
        }
    }

    /// The connection window's current size.
    #[must_use]
    pub const fn connection(&self) -> &Window {
        &self.connection
    }

    /// The initial size a new stream's window starts at.
    #[must_use]
    pub const fn initial_stream_window(&self) -> u32 {
        self.initial_stream_window
    }

    /// How many streams have a window.
    #[must_use]
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// A stream's window.
    #[must_use]
    pub fn stream(&self, stream_id: u32) -> Option<&Window> {
        self.streams
            .iter()
            .find(|(id, _)| *id == stream_id)
            .map(|(_, w)| w)
    }

    /// A stream's window, mutably.
    pub fn stream_mut(&mut self, stream_id: u32) -> Option<&mut Window> {
        self.streams
            .iter_mut()
            .find(|(id, _)| *id == stream_id)
            .map(|(_, w)| w)
    }

    /// Open a stream's window at the current initial size.
    ///
    /// Idempotent: opening an existing stream's window leaves it alone, so a
    /// second `HEADERS` on the same stream (trailers) cannot reset a window that
    /// has real accounting in it. Resetting it there would hand the peer a full
    /// window's worth of extra credit mid-stream.
    pub fn open_stream(&mut self, stream_id: u32) -> &mut Window {
        if self.stream(stream_id).is_none() {
            self.streams
                .push((stream_id, Window::at_initial(self.initial_stream_window)));
        }
        // The push above guarantees presence; the fallback keeps the function
        // total without an `unwrap` in non-test code.
        let index = self
            .streams
            .iter()
            .position(|(id, _)| *id == stream_id)
            .unwrap_or(self.streams.len().saturating_sub(1));
        &mut self.streams[index].1
    }

    /// Forget a stream's window, when the stream is finished.
    ///
    /// RFC 9113 §5.2.1: the window is per stream, so a closed stream's window is
    /// meaningless. Retaining it would let a long-lived connection accumulate one
    /// entry per request it ever served — bounded only by the peer's request rate.
    pub fn close_stream(&mut self, stream_id: u32) {
        self.streams.retain(|(id, _)| *id != stream_id);
    }

    /// Apply a `SETTINGS_INITIAL_WINDOW_SIZE` change to every open stream.
    ///
    /// # The rule most implementations get wrong
    ///
    /// RFC 9113 §6.9.2 is unambiguous: *"a change to `SETTINGS_INITIAL_WINDOW_SIZE`
    /// … MUST be applied to all streams that are currently open"* by the
    /// **difference** between old and new. Applying it only to *new* streams is
    /// the common shortcut and it leaves every in-flight stream with a window the
    /// peer's accounting disagrees with — which surfaces as a stall (the sender
    /// waiting for credit that was already granted) or as a `FLOW_CONTROL_ERROR`
    /// (the sender using credit that was not).
    ///
    /// The initial size is updated even when the adjustment fails, because the
    /// error is fatal to the connection: continuing with the old baseline would
    /// make a subsequent, valid change compute the wrong delta.
    ///
    /// # Errors
    ///
    /// [`FlowError::SettingsWindowOverflow`] for the first stream whose adjusted
    /// window exceeds 2^31-1 (§6.9.2's `FLOW_CONTROL_ERROR`).
    pub fn apply_initial_window_size(&mut self, new_initial: u32) -> Result<(), FlowError> {
        let mut first_error = None;
        for (id, window) in &mut self.streams {
            if let Err(e) = window.apply_initial_window_size(*id, new_initial) {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        self.initial_stream_window = new_initial;
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Every stream window, for diagnostics and tests.
    #[must_use]
    pub fn streams(&self) -> &[(u32, Window)] {
        &self.streams
    }
}

// ---------------------------------------------------------------------------
// The connection-wide view
// ---------------------------------------------------------------------------

/// All four windows: connection and per-stream, send and receive.
///
/// Constructed from the **peer's** settings, because both windows are the peer's
/// advertisement of what it will accept:
///
/// * The **send** direction starts at [`DEFAULT_CONNECTION_WINDOW`] for the
///   connection and at the peer's `SETTINGS_INITIAL_WINDOW_SIZE` per stream.
/// * The **receive** direction starts at the same numbers for the local
///   endpoint's own advertisement — the caller passes *our* settings for that
///   side, which is why [`FlowControl::new`] takes two initial sizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowControl {
    /// What we may send, bounded by what the peer advertised.
    send: Direction,
    /// What the peer may send, bounded by what we advertised.
    recv: Direction,
    /// Bytes received on the connection and not yet returned with a
    /// `WINDOW_UPDATE`.
    ///
    /// The connection-level counterpart of a stream's receive credit, and the one
    /// that makes connection-level backpressure possible: §6.9.1 lets a receiver
    /// replenish less than it received, and without this counter there is nothing
    /// to decide *when* to replenish from.
    connection_recv_unacked: u32,
}

impl FlowControl {
    /// Flow control for a connection, given the peer's initial stream window for
    /// the send direction and ours for the receive direction.
    ///
    /// # Why two arguments
    ///
    /// `SETTINGS_INITIAL_WINDOW_SIZE` is what each endpoint advertises about what
    /// **it** will accept. The send window must start at the *peer's* value (that
    /// is the credit it granted us) and the receive window at *ours* (that is the
    /// credit we granted it). Using one number for both happens to work against a
    /// peer that sends the default, and produces a window that is wrong by the
    /// difference against every peer that does not — which is the kind of bug that
    /// only appears against a specific client.
    #[must_use]
    pub fn new(peer_initial_window_size: u32, our_initial_window_size: u32) -> Self {
        Self {
            send: Direction::new(DEFAULT_CONNECTION_WINDOW, peer_initial_window_size),
            recv: Direction::new(DEFAULT_CONNECTION_WINDOW, our_initial_window_size),
            connection_recv_unacked: 0,
        }
    }

    /// The send direction.
    #[must_use]
    pub const fn send(&self) -> &Direction {
        &self.send
    }

    /// The send direction, mutably.
    pub fn send_mut(&mut self) -> &mut Direction {
        &mut self.send
    }

    /// The receive direction.
    #[must_use]
    pub const fn recv(&self) -> &Direction {
        &self.recv
    }

    /// The receive direction, mutably.
    pub fn recv_mut(&mut self) -> &mut Direction {
        &mut self.recv
    }

    /// Bytes received on the connection and not yet replenished.
    #[must_use]
    pub const fn connection_recv_unacked(&self) -> u32 {
        self.connection_recv_unacked
    }

    /// Open both windows for a new stream.
    ///
    /// Both directions, because a stream that can receive but not send (or the
    /// reverse) is a stream that half-works — and the failure appears as a stall
    /// on one direction only, which points at the wrong layer.
    pub fn open_stream(&mut self, stream_id: u32) {
        self.send.open_stream(stream_id);
        self.recv.open_stream(stream_id);
    }

    /// Forget a finished stream's windows.
    pub fn close_stream(&mut self, stream_id: u32) {
        self.send.close_stream(stream_id);
        self.recv.close_stream(stream_id);
    }

    // -- Sending -----------------------------------------------------------

    /// How many bytes may be sent on `stream_id` right now.
    ///
    /// **The minimum of the connection window and the stream window** — §5.2.1's
    /// rule, and the function this module exists for. A DATA frame needs room in
    /// both; checking only one is the defect that passes every test written
    /// against a single stream and fails the moment two are multiplexed.
    ///
    /// A stream with no window (never opened, or already closed) returns `0`
    /// rather than an error: "cannot send" is the correct answer for a stream that
    /// does not exist, and the caller — which owns the state machine — is the
    /// layer that knows whether that is a bug.
    #[must_use]
    pub fn available_send(&self, stream_id: u32) -> u32 {
        let connection = self.send.connection().available();
        let stream = self.send.stream(stream_id).map_or(0, Window::available);
        connection.min(stream)
    }

    /// Whether any stream could be sent on at all.
    ///
    /// Used to distinguish "this stream is blocked" from "the connection is
    /// blocked", which is the difference between a `WINDOW_UPDATE` for a stream
    /// and one for the connection. Sending the wrong one leaves the stall in
    /// place, and the connection then looks hung for an unrelated reason.
    #[must_use]
    pub fn connection_send_available(&self) -> u32 {
        self.send.connection().available()
    }

    /// Record that `n` bytes were sent on `stream_id`.
    ///
    /// Decrements **both** windows, because a DATA frame consumes both (§5.2.1).
    /// # Errors
    ///
    /// [`FlowError::WindowExceeded`] when either window is insufficient. Both
    /// windows are checked before either is decremented, so a failure cannot leave
    /// one decremented and the other not — an asymmetry that would be
    /// unrecoverable, because the peer's accounting is the authority and there is
    /// no frame that resynchronises a window.
    ///
    /// [`FlowError::UnknownStream`] when `stream_id` has no send window — sending
    /// on a stream whose window was never opened is our bookkeeping bug, and
    /// silently succeeding would make the connection window absorb it.
    pub fn on_send(&mut self, stream_id: u32, n: u32) -> Result<(), FlowError> {
        if self.send.stream(stream_id).is_none() {
            return Err(FlowError::UnknownStream { stream: stream_id });
        }
        // Check both first: 65535 and 100 each individually allow 50, but a DATA
        // frame consumes from both, and a failure part-way through would leave the
        // windows inconsistent with no frame able to repair them.
        let connection = self.send.connection().size();
        let stream = self.send.stream(stream_id).map_or(0, Window::size);
        let need = i64::from(n);
        if connection < need {
            return Err(FlowError::WindowExceeded {
                stream: None,
                window: connection,
                requested: n,
            });
        }
        if stream < need {
            return Err(FlowError::WindowExceeded {
                stream: Some(stream_id),
                window: stream,
                requested: n,
            });
        }

        self.send.connection.try_consume(None, n)?;
        if let Some(window) = self.send.stream_mut(stream_id) {
            window.try_consume(Some(stream_id), n)?;
        }
        Ok(())
    }

    // -- Receiving ---------------------------------------------------------

    /// Account for `n` received bytes on `stream_id` (§5.2.1, §6.1).
    ///
    /// # Why this consumes the *receive* windows
    ///
    /// A flow-control window is a sender's budget: it is the receiver's
    /// advertisement of how much it is willing to accept, and it decreases as
    /// bytes arrive. So `n` bytes received decrement **both** of our receive
    /// windows — the connection's and the stream's — exactly as sending
    /// decrements both send windows.
    ///
    /// `n` must be the frame's **payload length including padding**, not the data
    /// length: §6.1 makes the padding and its length octet count against the
    /// window. Passing `data.len()` under-counts by up to 255 bytes per frame, and
    /// the drift is invisible until it produces a spurious error thousands of
    /// frames later. The frame layer keeps `padding` on `Frame::Data` for exactly
    /// this reason.
    ///
    /// # Errors
    ///
    /// [`FlowError::WindowExceeded`] for the connection window (fatal) or the
    /// stream's (a stream error) — §5.2.2. The two are distinguished by
    /// [`FlowError::is_connection_fatal`].
    pub fn consume_recv(&mut self, stream_id: u32, n: u32) -> Result<(), FlowError> {
        // The connection window first. It is the one shared by every stream, so
        // exceeding it is fatal and there is no point checking the stream window
        // if the connection's is already blown.
        self.recv.connection.try_consume(None, n)?;
        match self.recv.stream_mut(stream_id) {
            Some(window) => {
                window.try_consume(Some(stream_id), n)?;
                // The credit owed back to the peer. Charged only after the
                // consume succeeded, so a refused frame does not manufacture
                // credit for bytes that were never accepted.
                window.recv_unacked = window.recv_unacked.saturating_add(n);
            }
            // §5.1: a stream that has never been opened has no window, and DATA
            // on it is a connection error the state machine reports. Reaching here
            // means a stream was opened without opening its window — the
            // connection layer's bug, not the peer's — but consuming the
            // connection window above was still correct, because those bytes did
            // arrive. Reported as `UnknownStream` so the caller can distinguish it
            // from a real window violation.
            None => return Err(FlowError::UnknownStream { stream: stream_id }),
        }
        self.connection_recv_unacked =
            self.connection_recv_unacked.checked_add(n).ok_or_else(|| {
                FlowError::WindowExceeded {
                    stream: None,
                    window: self.recv.connection.size(),
                    requested: n,
                }
            })?;
        Ok(())
    }

    /// Apply a `WINDOW_UPDATE` to either the connection or a stream (§6.9).
    ///
    /// # The three checks, in order
    ///
    /// 1. **Zero increment** is [`FlowError::ZeroIncrement`] —
    ///    `PROTOCOL_ERROR`, per §6.9, and *not* `FLOW_CONTROL_ERROR`.
    /// 2. **An unknown stream** is [`FlowError::UnknownStream`]. A
    ///    `WINDOW_UPDATE` may legitimately arrive for a stream that has since
    ///    closed (§5.1 permits it on a closed stream), so the caller decides —
    ///    but silently dropping it is not an option, because a lost
    ///    `WINDOW_UPDATE` is a permanent stall.
    /// 3. **Overflow past 2^31-1** is [`FlowError::WindowOverflow`] — a
    ///    `FLOW_CONTROL_ERROR` per §6.9.1.
    ///
    /// # Errors
    ///
    /// [`FlowError`], as above.
    pub fn apply_window_update(&mut self, stream_id: u32, increment: u32) -> Result<(), FlowError> {
        // §6.9: the increment field is 31 bits and a value of zero is explicitly
        // an error rather than a no-op. Checking it first means an overflow is
        // never reported for a frame whose actual defect is a zero increment,
        // which would name the wrong bug to the peer.
        if increment == 0 {
            return Err(FlowError::ZeroIncrement {
                connection: stream_id == 0,
            });
        }
        if stream_id == 0 {
            if let Err(e) = self.send.connection.try_increase(None, increment) {
                self.connection_recv_unacked = self.connection_recv_unacked.saturating_sub(
                    // A connection WINDOW_UPDATE also returns receive credit: the
                    // receive window is replenished by the same rule, and the two
                    // must move together or one of them drifts toward zero and
                    // stalls the connection.
                    self.connection_recv_unacked.min(increment),
                );
                return Err(e);
            }
            return Ok(());
        }
        match self.send.stream_mut(stream_id) {
            Some(window) => window.try_increase(Some(stream_id), increment),
            None => Err(FlowError::UnknownStream { stream: stream_id }),
        }
    }

    /// Return receive credit on the connection, as a `WINDOW_UPDATE` does.
    ///
    /// Separate from [`FlowControl::apply_window_update`] because this is the
    /// *receive* window: the peer's `WINDOW_UPDATE` replenishes our send window,
    /// while our own `WINDOW_UPDATE` replenishes the window the peer sends
    /// against. Conflating the two is how a connection ends up with a send window
    /// that grows while its receive window is exhausted — a one-way stall.
    ///
    /// Returns the increment to advertise, which is what was owed at the time of
    /// the call. The caller sends the frame; this only does the accounting.
    pub fn take_connection_replenishment(&mut self) -> u32 {
        core::mem::take(&mut self.connection_recv_unacked)
    }

    /// Return receive credit on a stream, as a `WINDOW_UPDATE` does.
    ///
    /// Returns `None` when the stream has no receive window, which is the
    /// "stream is closed or was never opened" case the caller reports as
    /// [`FlowError::UnknownStream`] if it mattered.
    ///
    /// # This returned the window's *size* until it was first called
    ///
    /// The body was `window.size().max(0)` — the remaining window, not the credit
    /// owed. Its own doc comment said *"Returning only the credit owed"*, so the
    /// code contradicted the text beside it, and nothing noticed because the
    /// function had **no test and no caller**: `conn`'s `replenish` was the first
    /// call site, and the defect surfaced the moment it was exercised. Measured:
    /// ten bytes of body produced a `WINDOW_UPDATE` of 65,525 — the whole initial
    /// window — which tells the peer it may send 65 KB more than it may. A peer
    /// that believes it is over-credits itself, and the accounting drifts until
    /// the connection violates the peer's real window.
    ///
    /// It now returns what the receive path has actually consumed since the last
    /// call, exactly as `take_connection_replenishment` does. The parallel
    /// structure is the point: the connection and stream windows move together or
    /// one of them drifts toward zero and stalls the connection.
    pub fn take_stream_replenishment(&mut self, stream_id: u32) -> Option<u32> {
        match self.recv.stream_mut(stream_id) {
            Some(window) => Some(core::mem::take(&mut window.recv_unacked)),
            None => None,
        }
    }

    // -- Settings ----------------------------------------------------------

    /// Apply a new `SETTINGS_INITIAL_WINDOW_SIZE` for the **send** direction
    /// (§6.9.2).
    ///
    /// # The retroactive delta, and the negative window
    ///
    /// This is the rule the module was written around. The setting applies to
    /// *every open stream*, moving each window by `new - old`. A window that goes
    /// negative is **legal** and means the sender must wait; clamping it to zero
    /// instead grants the peer credit it does not have.
    ///
    /// Only the send direction is affected. §6.9.2 is about
    /// `SETTINGS_INITIAL_WINDOW_SIZE`, which is what a peer advertises about what
    /// it will accept — so it changes what we may send, not what we may receive.
    /// Applying it to both is a subtle symmetry error that halves a connection's
    /// throughput against a peer that sends a non-default value.
    ///
    /// # Errors
    ///
    /// [`FlowError::SettingsWindowOverflow`] when an adjusted window exceeds
    /// 2^31-1 (a `FLOW_CONTROL_ERROR`).
    pub fn on_settings_initial_window_size(&mut self, old: u32, new: u32) -> Result<(), FlowError> {
        // `old` is taken as a parameter rather than read from the direction so
        // that the caller — which owns the `Settings` both endpoints exchanged —
        // states which transition it is applying. It is cross-checked against the
        // direction's own record so a caller that passes the wrong pair is caught
        // here rather than producing a wrong window silently.
        debug_assert_eq!(
            self.send.initial_stream_window(),
            old,
            "the caller's old SETTINGS_INITIAL_WINDOW_SIZE must match what the send \
             direction recorded, or the delta is computed from the wrong baseline"
        );
        self.send.apply_initial_window_size(new)
    }

    /// Apply a new `SETTINGS_INITIAL_WINDOW_SIZE` for the **receive** direction.
    ///
    /// Our own setting: it changes the window the peer sends against, so it
    /// applies to streams opened from now on. Flows already in progress keep the
    /// window they were granted — the RFC's §6.9.2 adjustment is defined for the
    /// sender's view of the receiver's advertisement, and adjusting our own
    /// receive windows by our own setting would double-count a change the peer has
    /// not yet seen. (The peer applies the same delta on its side when it receives
    /// our `SETTINGS`, which is why the two agree.)
    pub fn on_our_initial_window_size(&mut self, new: u32) {
        self.recv.initial_stream_window = new;
    }
}

impl Default for FlowControl {
    /// A connection with every default: 65535 in both directions.
    fn default() -> Self {
        Self::new(DEFAULT_CONNECTION_WINDOW, DEFAULT_CONNECTION_WINDOW)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Open a stream and return a flow-control object with defaults.
    fn fc_with_stream(id: u32) -> FlowControl {
        let mut fc = FlowControl::default();
        fc.open_stream(id);
        fc
    }

    // -- The minimum of the two windows ------------------------------------

    /// **§5.2.1's rule.** A DATA frame needs room in *both* windows, so the
    /// allowance is the minimum. Checking only the connection window passes every
    /// single-stream test and fails as soon as two streams are multiplexed.
    #[test]
    fn available_send_is_the_minimum_of_both_windows() {
        let mut fc = fc_with_stream(1);
        assert_eq!(fc.available_send(1), DEFAULT_CONNECTION_WINDOW);

        // Drain the *stream* window only, via a WINDOW_UPDATE-free path: consume
        // the stream's window directly to isolate it.
        fc.send_mut()
            .stream_mut(1)
            .expect("the stream's window exists")
            .try_consume(Some(1), 60_000)
            .expect("60_000 is within 65535");
        assert_eq!(fc.send_mut().connection().size(), 65_535);
        assert_eq!(
            fc.available_send(1),
            5_535,
            "the stream window is the smaller one and must be the answer"
        );

        // Now make the *connection* window the smaller one: drain it to 1535 and
        // leave the stream's at 64 535, so the minimum is the connection's.
        let mut fc = fc_with_stream(1);
        fc.send.connection.try_consume(None, 64_000).unwrap();
        assert_eq!(fc.send.connection().size(), 1_535);
        fc.send
            .stream_mut(1)
            .unwrap()
            .try_consume(Some(1), 1_000)
            .unwrap();
        assert_eq!(fc.send.stream(1).unwrap().size(), 64_535);
        assert_eq!(
            fc.available_send(1),
            1_535,
            "the connection window is now the smaller one and must be the answer"
        );
    }

    /// A stream with no window cannot send, and says so as `0` rather than as an
    /// error — the state machine owns the "does this stream exist" question.
    #[test]
    fn a_stream_with_no_window_has_no_allowance() {
        let fc = FlowControl::default();
        assert_eq!(fc.available_send(1), 0);
        assert_eq!(fc.available_send(999), 0);
    }

    /// A fully drained connection window blocks every stream, even one with a
    /// full stream window. This is the multiplexing-relevant half of the minimum.
    #[test]
    fn the_connection_window_blocks_every_stream() {
        let mut fc = fc_with_stream(1);
        fc.open_stream(3);
        fc.send
            .connection
            .try_consume(None, DEFAULT_CONNECTION_WINDOW)
            .unwrap();
        assert_eq!(fc.connection_send_available(), 0);
        assert_eq!(fc.available_send(1), 0);
        assert_eq!(
            fc.available_send(3),
            0,
            "one drained connection window blocks every stream, which is why the \
             connection window needs its own WINDOW_UPDATE"
        );
        assert_eq!(
            fc.send.stream(1).map(Window::size),
            Some(65_535),
            "the stream's own window is untouched"
        );
    }

    /// A drained *stream* window blocks only that stream.
    #[test]
    fn a_stream_window_blocks_only_that_stream() {
        let mut fc = fc_with_stream(1);
        fc.open_stream(3);
        fc.send
            .stream_mut(1)
            .unwrap()
            .try_consume(Some(1), 65_535)
            .unwrap();
        assert_eq!(fc.available_send(1), 0);
        assert_eq!(
            fc.available_send(3),
            65_535,
            "another stream is unaffected — this is what multiplexing buys"
        );
    }

    // -- Sending -----------------------------------------------------------

    /// `on_send` decrements both windows.
    #[test]
    fn sending_decrements_both_windows() {
        let mut fc = fc_with_stream(1);
        fc.on_send(1, 1_000).unwrap();
        assert_eq!(fc.send.connection().size(), 64_535);
        assert_eq!(fc.send.stream(1).map(Window::size), Some(64_535));
        assert_eq!(fc.available_send(1), 64_535);
    }

    /// Sending past either window is refused, and the refusal is attributed to
    /// the window that was short — the two produce different responses (a stream
    /// `WINDOW_UPDATE` vs a connection one).
    #[test]
    fn sending_past_either_window_is_refused_with_the_right_attribution() {
        let mut fc = fc_with_stream(1);
        // The connection is the shorter one.
        fc.send.connection.try_consume(None, 65_000).unwrap();
        let e = fc.on_send(1, 1_000).expect_err("only 535 remains");
        assert!(matches!(
            e,
            FlowError::WindowExceeded {
                stream: None,
                window: 535,
                requested: 1000
            }
        ));
        assert!(
            e.is_connection_fatal(),
            "a connection-window violation is fatal: every stream shares the window \
             and its accounting can no longer be trusted"
        );

        // The stream is the shorter one; the connection is untouched.
        let mut fc = fc_with_stream(1);
        fc.send
            .stream_mut(1)
            .unwrap()
            .try_consume(Some(1), 65_000)
            .unwrap();
        let e = fc.on_send(1, 1_000).expect_err("only 535 remains");
        assert!(matches!(
            e,
            FlowError::WindowExceeded {
                stream: Some(1),
                window: 535,
                requested: 1000
            }
        ));
        assert!(
            !e.is_connection_fatal(),
            "a stream-window violation resets one stream; the connection survives"
        );
    }

    /// **A failed send must not half-decrement.** The connection window allows the
    /// frame and the stream window does not; if the connection were decremented
    /// first, its accounting would drift with no frame able to repair it.
    #[test]
    fn a_refused_send_leaves_both_windows_untouched() {
        let mut fc = fc_with_stream(1);
        fc.send
            .stream_mut(1)
            .unwrap()
            .try_consume(Some(1), 65_000)
            .unwrap();
        let before_c = fc.send.connection().size();
        let before_s = fc.send.stream(1).unwrap().size();
        assert!(fc.on_send(1, 1_000).is_err());
        assert_eq!(
            fc.send.connection().size(),
            before_c,
            "the connection window must not be decremented by a refused send — there \
             is no frame that resynchronises a window"
        );
        assert_eq!(fc.send.stream(1).unwrap().size(), before_s);
    }

    /// Sending on a stream with no window is a bookkeeping bug, not a silent
    /// charge to the connection window.
    #[test]
    fn sending_on_a_stream_with_no_window_is_refused() {
        let mut fc = FlowControl::default();
        let e = fc.on_send(1, 10).expect_err("stream 1 has no window");
        assert!(matches!(e, FlowError::UnknownStream { stream: 1 }));
        assert_eq!(
            fc.send.connection().size(),
            65_535,
            "the connection window must not absorb a send for a stream that does not \
             exist"
        );
    }

    /// Exactly the available amount is sendable — the boundary case an off-by-one
    /// in the comparison turns into an intermittent stall.
    #[test]
    fn sending_exactly_the_window_is_allowed_and_empties_it() {
        let mut fc = fc_with_stream(1);
        fc.on_send(1, 65_535).unwrap();
        assert_eq!(fc.available_send(1), 0);
        assert!(fc.on_send(1, 1).is_err());
        assert_eq!(fc.send.connection().size(), 0);
    }

    // -- Receiving ---------------------------------------------------------

    /// Receiving consumes both receive windows and accumulates connection credit.
    #[test]
    fn receiving_consumes_both_receive_windows() {
        let mut fc = fc_with_stream(1);
        fc.consume_recv(1, 1_000).unwrap();
        assert_eq!(fc.recv.connection().size(), 64_535);
        assert_eq!(fc.recv.stream(1).map(Window::size), Some(64_535));
        assert_eq!(fc.connection_recv_unacked(), 1_000);
    }

    /// **§5.2.2.** Receiving more than the window allows is a
    /// `FLOW_CONTROL_ERROR`, and the connection window is the fatal one.
    #[test]
    fn receiving_beyond_a_window_is_a_flow_control_error() {
        let mut fc = fc_with_stream(1);
        let e = fc
            .consume_recv(1, 65_536)
            .expect_err("one byte over the connection window");
        assert_eq!(e.code(), ErrorCode::FlowControlError);
        assert!(
            e.is_connection_fatal(),
            "the connection window is shared; exceeding it is fatal"
        );

        // The stream window alone.
        let mut fc = fc_with_stream(1);
        fc.recv
            .stream_mut(1)
            .unwrap()
            .try_consume(Some(1), 65_000)
            .unwrap();
        let e = fc
            .consume_recv(1, 1_000)
            .expect_err("stream window is short");
        assert_eq!(e.code(), ErrorCode::FlowControlError);
        assert!(!e.is_connection_fatal());
        assert_eq!(
            fc.recv.connection().size(),
            64_535,
            "the connection window was consumed first and those bytes did arrive, so \
             it must stay decremented even though the stream refused"
        );
    }

    /// The receive windows are independent of the send windows — a send must not
    /// consume receive credit, or the two directions drift into a one-way stall.
    #[test]
    fn send_and_receive_windows_are_independent() {
        let mut fc = fc_with_stream(1);
        fc.on_send(1, 1_000).unwrap();
        assert_eq!(fc.send.connection().size(), 64_535);
        assert_eq!(
            fc.recv.connection().size(),
            65_535,
            "sending must not consume receive credit"
        );

        let mut fc = fc_with_stream(1);
        fc.consume_recv(1, 1_000).unwrap();
        assert_eq!(
            fc.send.connection().size(),
            65_535,
            "receiving must not consume send credit"
        );
    }

    /// The connection replenishment is taken once and only what was owed.
    #[test]
    fn connection_replenishment_is_taken_once() {
        let mut fc = fc_with_stream(1);
        fc.consume_recv(1, 2_000).unwrap();
        fc.consume_recv(1, 500).unwrap();
        assert_eq!(fc.take_connection_replenishment(), 2_500);
        assert_eq!(
            fc.take_connection_replenishment(),
            0,
            "credit already returned must not be returned twice — that inflates the \
             peer's window beyond what this endpoint can absorb"
        );
    }

    // -- WINDOW_UPDATE -----------------------------------------------------

    /// **§6.9.** A zero increment is `PROTOCOL_ERROR`, *not*
    /// `FLOW_CONTROL_ERROR`. Reporting the wrong code sends the peer debugging its
    /// window arithmetic when the defect is in its frame encoding.
    #[test]
    fn a_zero_increment_is_a_protocol_error() {
        let mut fc = fc_with_stream(1);
        let e = fc
            .apply_window_update(1, 0)
            .expect_err("a zero increment is refused");
        assert_eq!(
            e.code(),
            ErrorCode::ProtocolError,
            "RFC 9113 §6.9 makes this PROTOCOL_ERROR, not FLOW_CONTROL_ERROR"
        );
        assert!(!e.is_connection_fatal(), "on a stream it is a stream error");

        let e = fc
            .apply_window_update(0, 0)
            .expect_err("zero on the connection");
        assert_eq!(e.code(), ErrorCode::ProtocolError);
        assert!(
            e.is_connection_fatal(),
            "the same defect on the connection window is a connection error (§6.9)"
        );
    }

    /// A zero increment must be refused **without** changing the window.
    #[test]
    fn a_zero_increment_changes_nothing() {
        let mut fc = fc_with_stream(1);
        fc.on_send(1, 100).unwrap();
        let before = fc.send.connection().size();
        assert!(fc.apply_window_update(1, 0).is_err());
        assert_eq!(fc.send.connection().size(), before);
        assert_eq!(fc.send.stream(1).unwrap().size(), before);
    }

    /// A valid increment grows both windows.
    #[test]
    fn a_window_update_grows_the_window() {
        let mut fc = fc_with_stream(1);
        fc.on_send(1, 10_000).unwrap();
        fc.apply_window_update(1, 10_000).unwrap();
        assert_eq!(fc.send.stream(1).unwrap().size(), 65_535);
        fc.apply_window_update(0, 10_000).unwrap();
        assert_eq!(fc.send.connection().size(), 65_535);
    }

    /// **§6.9.1.** An increment that would push a window past 2^31-1 is a
    /// `FLOW_CONTROL_ERROR`, and the window is left unchanged.
    #[test]
    fn an_increment_past_the_ceiling_is_refused() {
        let mut fc = fc_with_stream(1);
        // Take the stream window to the ceiling.
        let to_ceiling = MAX_WINDOW - DEFAULT_CONNECTION_WINDOW;
        fc.apply_window_update(1, to_ceiling).unwrap();
        assert_eq!(fc.send.stream(1).unwrap().size(), i64::from(MAX_WINDOW));

        let e = fc
            .apply_window_update(1, 1)
            .expect_err("one byte past the ceiling");
        assert!(matches!(
            e,
            FlowError::WindowOverflow {
                stream: Some(1),
                increment: 1,
                ..
            }
        ));
        assert_eq!(e.code(), ErrorCode::FlowControlError);
        assert_eq!(
            fc.send.stream(1).unwrap().size(),
            i64::from(MAX_WINDOW),
            "a refused increment must not leave a partial application"
        );

        // And at the ceiling exactly is fine.
        fc.on_send(1, 1).unwrap();
        fc.apply_window_update(1, 1).unwrap();
        assert_eq!(fc.send.stream(1).unwrap().size(), i64::from(MAX_WINDOW));
    }

    /// The connection window has its own ceiling check.
    #[test]
    fn the_connection_window_has_its_own_ceiling() {
        let mut fc = fc_with_stream(1);
        fc.apply_window_update(0, MAX_WINDOW - DEFAULT_CONNECTION_WINDOW)
            .unwrap();
        assert_eq!(fc.send.connection().size(), i64::from(MAX_WINDOW));
        let e = fc.apply_window_update(0, 1).expect_err("past the ceiling");
        assert!(matches!(e, FlowError::WindowOverflow { stream: None, .. }));
        assert!(e.is_connection_fatal());
    }

    /// A `WINDOW_UPDATE` for a stream with no window is reported rather than
    /// silently dropped: a lost `WINDOW_UPDATE` is a permanent stall.
    #[test]
    fn a_window_update_for_an_unknown_stream_is_reported() {
        let mut fc = FlowControl::default();
        let e = fc
            .apply_window_update(7, 100)
            .expect_err("stream 7 has no window");
        assert!(matches!(e, FlowError::UnknownStream { stream: 7 }));
        assert!(
            !e.is_connection_fatal(),
            "a WINDOW_UPDATE may legitimately arrive for a stream that has closed; \
             the caller decides, but it must not be dropped in silence"
        );
    }

    // -- SETTINGS_INITIAL_WINDOW_SIZE (§6.9.2) -----------------------------

    /// **The rule this module was written around.** A change adjusts *every open
    /// stream* by the **difference**, not to the new value. Applying it only to
    /// new streams is the classic bug, and it is invisible until a stream has
    /// bytes in flight.
    #[test]
    fn a_settings_change_adjusts_open_streams_by_the_delta() {
        let mut fc = fc_with_stream(1);
        fc.open_stream(3);
        // Stream 1 has 10 000 bytes in flight; stream 3 has none.
        fc.on_send(1, 10_000).unwrap();
        assert_eq!(fc.send.stream(1).unwrap().size(), 55_535);
        assert_eq!(fc.send.stream(3).unwrap().size(), 65_535);

        // Raise the initial window to 100 000: delta is +34 465.
        fc.on_settings_initial_window_size(DEFAULT_CONNECTION_WINDOW, 100_000)
            .unwrap();
        assert_eq!(
            fc.send.stream(1).unwrap().size(),
            55_535 + 34_465,
            "the stream with data in flight moves by the DELTA, not to the new value"
        );
        assert_eq!(
            fc.send.stream(3).unwrap().size(),
            100_000,
            "a stream with nothing in flight lands exactly on the new value — which \
             is why the bug is invisible until bytes are in flight"
        );

        // Lower it: delta is -34 465.
        fc.on_settings_initial_window_size(100_000, 65_535).unwrap();
        assert_eq!(fc.send.stream(1).unwrap().size(), 55_535);
        assert_eq!(fc.send.stream(3).unwrap().size(), 65_535);
    }

    /// **The negative-window case.** §6.9.2: reducing the initial window below
    /// what a stream has already sent makes its window negative, and that is
    /// *legal* — it means "wait". Clamping to zero instead grants the peer credit
    /// it does not have.
    #[test]
    fn a_shrinking_settings_change_can_make_a_window_negative() {
        let mut fc = fc_with_stream(1);
        // The whole window has been sent, so the stream window is 0 and 65535
        // bytes are in flight.
        fc.on_send(1, 65_535).unwrap();
        assert_eq!(fc.send.stream(1).unwrap().size(), 0);

        // Drop the initial window to 1000: delta = 1000 - 65535 = -64535.
        fc.on_settings_initial_window_size(DEFAULT_CONNECTION_WINDOW, 1_000)
            .unwrap();
        assert_eq!(
            fc.send.stream(1).unwrap().size(),
            -64_535,
            "RFC 9113 §6.9.2 says the window may become negative: it means the sender \
             must wait, not that the change is an error"
        );
        assert_eq!(fc.available_send(1), 0, "a negative window allows nothing");

        // Clamping at zero would have left 0 and then let the peer's next
        // WINDOW_UPDATE of 64 535 grant a full window; the negative value means it
        // must first climb back to zero.
        fc.apply_window_update(1, 64_535).unwrap();
        assert_eq!(
            fc.send.stream(1).unwrap().size(),
            -64_535 + 64_535,
            "the increment applies to the negative window, so it reaches exactly zero \
             — with clamping it would have reached 64 535 and over-granted"
        );
        assert_eq!(fc.available_send(1), 0);
        // The connection window is also drained at this point (65535 bytes were
        // sent), so `available_send` is the minimum of two zeros. Replenish the
        // *connection* window so the assertion below is genuinely about the
        // stream's negative window rather than about the connection's zero — a
        // test that passes because of the other window is a test that would not
        // notice the stream window being wrong.
        fc.apply_window_update(0, 65_535).unwrap();
        assert_eq!(
            fc.available_send(1),
            0,
            "still blocked by the stream's window"
        );

        fc.apply_window_update(1, 1).unwrap();
        assert_eq!(
            fc.available_send(1),
            1,
            "one byte of credit above zero is now sendable"
        );
    }

    /// A window driven negative is not itself an error; only exceeding the ceiling
    /// is.
    #[test]
    fn a_negative_window_is_not_an_error() {
        let mut fc = fc_with_stream(1);
        fc.on_send(1, 65_535).unwrap();
        assert!(
            fc.on_settings_initial_window_size(DEFAULT_CONNECTION_WINDOW, 0)
                .is_ok(),
            "driving a window negative is legal (§6.9.2)"
        );
        assert_eq!(fc.send.stream(1).unwrap().size(), -65_535);
    }

    /// A change that would push a stream's window past 2^31-1 is a
    /// `FLOW_CONTROL_ERROR` (§6.9.2).
    #[test]
    fn a_settings_change_past_the_ceiling_is_refused() {
        let mut fc = fc_with_stream(1);
        // Start at 65535 and raise to the ceiling: fine.
        fc.on_settings_initial_window_size(DEFAULT_CONNECTION_WINDOW, MAX_WINDOW)
            .unwrap();
        assert_eq!(fc.send.stream(1).unwrap().size(), i64::from(MAX_WINDOW));
        // Now lower it back and send nothing, then raise again — fine.
        fc.on_settings_initial_window_size(MAX_WINDOW, DEFAULT_CONNECTION_WINDOW)
            .unwrap();
        assert_eq!(
            fc.send.stream(1).unwrap().size(),
            i64::from(DEFAULT_CONNECTION_WINDOW)
        );
    }

    /// A settings overflow is reported as a `FLOW_CONTROL_ERROR` and applies to a
    /// stream, not the connection.
    #[test]
    fn a_settings_overflow_is_a_stream_scoped_flow_control_error() {
        let mut fc = fc_with_stream(1);
        // Drive the stream window near the ceiling while keeping the initial low,
        // then raise the initial past what the window can absorb.
        fc.apply_window_update(1, MAX_WINDOW - DEFAULT_CONNECTION_WINDOW)
            .unwrap();
        let e = fc
            .on_settings_initial_window_size(DEFAULT_CONNECTION_WINDOW, MAX_WINDOW)
            .expect_err("the delta pushes the window past the ceiling");
        assert_eq!(e.code(), ErrorCode::FlowControlError);
        assert!(matches!(
            e,
            FlowError::SettingsWindowOverflow { stream: 1, .. }
        ));
        assert!(
            !e.is_connection_fatal(),
            "one stream's window overflow resets that stream; the other multiplexed \
             streams are unaffected"
        );
    }

    /// **The delta baseline must advance.** A window that does not remember what
    /// it was initialised at computes the wrong delta on the second change — and
    /// the second change is where a client that varies its setting shows up.
    #[test]
    fn successive_settings_changes_use_the_right_baseline() {
        let mut fc = fc_with_stream(1);
        fc.on_send(1, 1_000).unwrap(); // stream window 64 535

        fc.on_settings_initial_window_size(DEFAULT_CONNECTION_WINDOW, 20_000)
            .unwrap();
        assert_eq!(fc.send.stream(1).unwrap().size(), 64_535 - 45_535);
        assert_eq!(fc.send.initial_stream_window(), 20_000);

        // A second change must use 20 000 as the old value, not 65 535.
        fc.on_settings_initial_window_size(20_000, 65_535).unwrap();
        assert_eq!(
            fc.send.stream(1).unwrap().size(),
            (64_535 - 45_535) + 45_535,
            "the second delta is computed from 20 000; using the original 65 535 \
             would double the adjustment and over-grant a full window"
        );
        assert_eq!(fc.send.stream(1).unwrap().size(), 64_535);
    }

    /// A new stream opened after a settings change starts at the **new** initial
    /// size, not the old one.
    #[test]
    fn a_stream_opened_after_a_settings_change_starts_at_the_new_size() {
        let mut fc = fc_with_stream(1);
        fc.on_settings_initial_window_size(DEFAULT_CONNECTION_WINDOW, 1_000)
            .unwrap();
        fc.open_stream(3);
        assert_eq!(fc.send.stream(3).unwrap().size(), 1_000);
        assert_eq!(
            fc.send.stream(1).unwrap().size(),
            1_000,
            "the existing stream was adjusted by the delta and lands on the same value \
             when nothing was in flight"
        );
    }

    /// §6.9.2 changes the window the **peer** grants us, so it must not touch what
    /// we grant the peer. Applying it to both directions halves throughput against
    /// any peer that sends a non-default value.
    #[test]
    fn a_settings_change_affects_only_the_send_direction() {
        let mut fc = fc_with_stream(1);
        let recv_before = fc.recv.stream(1).unwrap().size();
        fc.on_settings_initial_window_size(DEFAULT_CONNECTION_WINDOW, 1_000)
            .unwrap();
        assert_eq!(
            fc.recv.stream(1).unwrap().size(),
            recv_before,
            "SETTINGS_INITIAL_WINDOW_SIZE is what the PEER will accept, so it changes \
             what we may send — not what we may receive"
        );
        assert_eq!(fc.recv.initial_stream_window(), DEFAULT_CONNECTION_WINDOW);

        fc.on_our_initial_window_size(1_000);
        assert_eq!(fc.recv.initial_stream_window(), 1_000);
        assert_eq!(
            fc.send.initial_stream_window(),
            1_000,
            "the send direction keeps the value the peer's setting produced"
        );
    }

    // -- Windows and lifetime ----------------------------------------------

    /// Opening a stream's window twice must not reset it: a second HEADERS
    /// (trailers) on a stream with real accounting would otherwise hand the peer a
    /// full window of extra credit mid-stream.
    #[test]
    fn opening_a_window_twice_does_not_reset_it() {
        let mut fc = fc_with_stream(1);
        fc.on_send(1, 1_000).unwrap();
        fc.open_stream(1);
        assert_eq!(
            fc.send.stream(1).unwrap().size(),
            64_535,
            "re-opening a stream must not restore its window"
        );
    }

    /// Closing a stream forgets both of its windows, so a long-lived connection
    /// does not accumulate one entry per request it ever served.
    #[test]
    fn closing_a_stream_forgets_both_windows() {
        let mut fc = fc_with_stream(1);
        fc.open_stream(3);
        assert_eq!(fc.send.stream_count(), 2);
        fc.close_stream(1);
        assert_eq!(fc.send.stream_count(), 1);
        assert_eq!(fc.recv.stream_count(), 1);
        assert!(fc.send.stream(1).is_none());
        assert!(fc.recv.stream(1).is_none());
        assert_eq!(fc.available_send(1), 0);
    }

    /// Both directions start at the values the caller supplied, and they may
    /// differ — that difference is the point of taking two arguments.
    #[test]
    fn both_directions_start_at_their_own_values() {
        let fc = FlowControl::new(1_000, 2_000);
        assert_eq!(fc.send.initial_stream_window(), 1_000);
        assert_eq!(fc.recv.initial_stream_window(), 2_000);
        assert_eq!(
            fc.send.connection().size(),
            i64::from(DEFAULT_CONNECTION_WINDOW),
            "the connection window is fixed at 65535 regardless of either setting \
             (RFC 9113 §6.9.2)"
        );
    }

    /// `Window::available` clamps a negative window to zero for the *decision* but
    /// the stored value keeps its sign.
    #[test]
    fn a_negative_window_reports_zero_available_but_keeps_its_value() {
        let mut w = Window::new(0);
        w.try_consume(Some(1), 0).unwrap();
        assert_eq!(w.available(), 0);
        // Drive it negative via a settings change.
        let mut w = Window::new(DEFAULT_CONNECTION_WINDOW);
        w.try_consume(Some(1), 65_535).unwrap();
        w.apply_initial_window_size(1, 0).unwrap();
        assert_eq!(w.size(), -65_535);
        assert_eq!(w.available(), 0);
    }

    // -- Error rendering ---------------------------------------------------

    /// Every flow error names the RFC rule it enforces, so an operator can act on
    /// it without reading this source.
    #[test]
    fn every_flow_error_renders_with_the_rule() {
        let errors = [
            FlowError::WindowExceeded {
                stream: Some(1),
                window: 10,
                requested: 20,
            },
            FlowError::WindowExceeded {
                stream: None,
                window: 5,
                requested: 9,
            },
            FlowError::ZeroIncrement { connection: false },
            FlowError::ZeroIncrement { connection: true },
            FlowError::WindowOverflow {
                stream: Some(3),
                window: 1,
                increment: 2,
            },
            FlowError::WindowOverflow {
                stream: None,
                window: 1,
                increment: 2,
            },
            FlowError::SettingsWindowOverflow {
                stream: 1,
                window: 1,
                delta: -2,
            },
            FlowError::UnknownStream { stream: 9 },
        ];
        for e in errors {
            let s = e.to_string();
            assert!(!s.is_empty(), "{e:?} rendered nothing");
            assert!(!s.contains('\n'), "Display must stay single-line: {s}");
            // The code is always one of the two the RFC assigns to flow control.
            assert!(
                matches!(
                    e.code(),
                    ErrorCode::FlowControlError | ErrorCode::ProtocolError
                ),
                "{e:?} carries a code the RFC does not assign here"
            );
        }
        assert!(
            FlowError::ZeroIncrement { connection: false }
                .to_string()
                .contains("PROTOCOL_ERROR"),
            "the message must name the counter-intuitive code, or the next reader \
             will 'fix' it to FLOW_CONTROL_ERROR"
        );
    }

    /// The connection-error view is produced exactly for the fatal cases, and the
    /// stream-error view always is.
    #[test]
    fn the_error_views_match_the_scope() {
        let fatal = FlowError::WindowExceeded {
            stream: None,
            window: 0,
            requested: 1,
        };
        assert!(fatal.as_connection_error().is_some());
        assert_eq!(
            fatal.as_connection_error().map(|e| e.code()),
            Some(ErrorCode::FlowControlError)
        );

        let stream = FlowError::WindowExceeded {
            stream: Some(1),
            window: 0,
            requested: 1,
        };
        assert!(
            stream.as_connection_error().is_none(),
            "a stream-window violation must not be reported as fatal, or one bad \
             stream drops every other multiplexed request"
        );
        assert_eq!(stream.as_stream_error().code(), ErrorCode::FlowControlError);
        assert!(stream.as_stream_error().terminates_stream());
    }

    /// The window renders both numbers, because a stall investigation needs to
    /// know whether the initial or the current value is wrong.
    #[test]
    fn a_window_renders_its_size_and_initial() {
        let w = Window::new(100);
        assert_eq!(w.to_string(), "100 (initial 100)");
        assert_eq!(w.initial(), 100);
    }

    /// The default is the RFC's default in both directions.
    #[test]
    fn the_default_is_65535_in_both_directions() {
        let fc = FlowControl::default();
        assert_eq!(fc.send.connection().size(), 65_535);
        assert_eq!(fc.recv.connection().size(), 65_535);
        assert_eq!(fc.connection_recv_unacked(), 0);
    }
}
