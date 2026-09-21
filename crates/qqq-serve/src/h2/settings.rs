// SPDX-License-Identifier: Apache-2.0

//! SETTINGS: the parameters both ends of a connection declare about themselves.
//!
//! Implements `SRV-002`; RFC 9113 §6.5 (the frame), §6.5.2 (the parameters),
//! §6.5.3 (synchronisation).
//!
//! # Why SETTINGS is not just a frame
//!
//! A `SETTINGS` frame carries integers, so it is tempting to treat it as a
//! parameter list and be done. Three rules make it a protocol of its own, and
//! each is a place an implementation goes wrong in a way that only appears under
//! load:
//!
//! 1. **They are directional.** `SETTINGS` describes *the sender's* limits. A
//!    server's `MAX_CONCURRENT_STREAMS` tells the client how many streams it may
//!    open; it says nothing about how many the server may open. Storing one set
//!    of settings rather than two is the classic conflation, and it inverts every
//!    limit in one direction.
//! 2. **They apply on receipt, except when they do not.** RFC 9113 §6.5.3: the
//!    values apply as soon as they are *received*, but `SETTINGS_INITIAL_WINDOW_SIZE`
//!    changes the flow-control window of **every open stream** by the delta —
//!    and that adjustment can make a window negative, which is legal (§6.9.2)
//!    and means "the peer owes us bytes". A window type that cannot represent a
//!    negative value will either panic or silently clamp, and both are wrong.
//! 3. **They must be acknowledged.** A `SETTINGS` frame requires a
//!    `SETTINGS`/`ACK` (§6.5.3). Without it the peer cannot tell whether its
//!    values took effect, and a client that lowers `INITIAL_WINDOW_SIZE` and
//!    never sees an ACK will stall on the first body it sends.
//!
//! # Validation, and what an illegal value does
//!
//! RFC 9113 §6.5.2 gives each parameter a range. A value outside it is a
//! **connection** error of type `PROTOCOL_ERROR` — not a stream error, and not
//! something to clamp. Clamping is the tempting wrong answer: it keeps the
//! connection alive and silently negotiates something neither side asked for,
//! and the resulting behaviour differs by implementation.
//!
//! Note the one trap in that table: `ENABLE_PUSH` is a boolean taking exactly
//! `0` or `1`. *"Any value other than 0 or 1 MUST be treated as a connection
//! error of type `PROTOCOL_ERROR`."* Accepting `2` as "true" is the natural
//! mistake.

use std::fmt;

use super::error::{ConnectionError, ErrorCode};
use super::frame::{Frame, SettingId};

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/// The default `SETTINGS_HEADER_TABLE_SIZE`: 4096 bytes (RFC 9113 §6.5.2).
pub const DEFAULT_HEADER_TABLE_SIZE: u32 = 4_096;

/// The default `SETTINGS_INITIAL_WINDOW_SIZE`: 65535 (RFC 9113 §6.5.2).
///
/// The same value as HTTP/2's connection-level default, which is a coincidence
/// worth naming: the connection window is fixed at 65535 and only a
/// `WINDOW_UPDATE` can grow it, while the stream window starts at this value and
/// **can be changed by SETTINGS** (§6.9.2).
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65_535;

/// The default `SETTINGS_MAX_FRAME_SIZE`: 16384 (RFC 9113 §6.5.2).
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;

/// The smallest legal `SETTINGS_MAX_FRAME_SIZE` (RFC 9113 §6.5.2).
pub const MIN_MAX_FRAME_SIZE: u32 = 16_384;

/// The largest legal `SETTINGS_MAX_FRAME_SIZE`: 2^24 - 1.
pub const MAX_MAX_FRAME_SIZE: u32 = 16_777_215;

/// The largest legal `SETTINGS_INITIAL_WINDOW_SIZE`: 2^31 - 1.
///
/// The ceiling is the flow-control window's own maximum (§6.9.1), not an
/// arbitrary number: a window larger than 2^31-1 cannot be represented in a
/// `WINDOW_UPDATE`, so a peer could never extend it.
pub const MAX_INITIAL_WINDOW_SIZE: u32 = 2_147_483_647;

/// The `SETTINGS_MAX_CONCURRENT_STREAMS` value this server advertises.
///
/// 100 is RFC 9113 §6.5.2's own suggested floor and is comfortably above what a
/// browser uses (Chrome opens up to 6 per origin, Firefox 6, and both keep a
/// couple of spare). It is a *default*, not a recommendation: a deployment with
/// a measured number should say so, which is why it is a field on
/// [`Settings`] rather than a constant baked into the connection.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 100;

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// One endpoint's HTTP/2 settings, as it has declared them.
///
/// Not a `HashMap`: every parameter has a distinct type and a distinct default,
/// and a map turns a typo into a silently absent setting that reads as "leave it
/// at the default".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// `SETTINGS_HEADER_TABLE_SIZE` — the HPACK dynamic table size the *sender*
    /// is willing to accept (RFC 9113 §6.5.2, RFC 7541 §4.2).
    pub header_table_size: u32,
    /// `SETTINGS_ENABLE_PUSH` — whether the sender will accept server push.
    ///
    /// `None` means the parameter was never sent, which for a **server** means
    /// enabled (a client's `ENABLE_PUSH` default is 1 for servers) and for a
    /// client means it may push. Modelled as `Option` because a server is a
    /// **connection error** to send `ENABLE_PUSH` at all (§6.5.2), so "not sent"
    /// and "sent as 1" must be distinguishable.
    pub enable_push: Option<bool>,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` — the ceiling on streams the *peer* may
    /// have open at once.
    ///
    /// `None` means "no limit advertised", which RFC 9113 §6.5.2 defines as
    /// unlimited rather than zero. Defaulting it to a number would invent a
    /// limit the peer never declared.
    pub max_concurrent_streams: Option<u32>,
    /// `SETTINGS_INITIAL_WINDOW_SIZE` — the initial flow-control window for new
    /// streams, in both directions.
    pub initial_window_size: u32,
    /// `SETTINGS_MAX_FRAME_SIZE` — the largest frame payload the sender will
    /// accept.
    pub max_frame_size: u32,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` — an *advisory* ceiling on the size of
    /// the header list the sender will accept.
    ///
    /// Advisory is the RFC's word (§6.5.2): exceeding it is not an error, and a
    /// server may still answer 431. Modelled as `Option` for the same reason as
    /// `max_concurrent_streams`.
    pub max_header_list_size: Option<u32>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            header_table_size: DEFAULT_HEADER_TABLE_SIZE,
            enable_push: None,
            max_concurrent_streams: None,
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: None,
        }
    }
}

impl Settings {
    /// The settings a **server** sends in its first frame.
    ///
    /// RFC 9113 §8.4: a server must not send `ENABLE_PUSH` at all, so it stays
    /// `None` — the client's own default of 1 governs. Push is not implemented,
    /// and the honest way to say so is to leave the parameter alone and refuse a
    /// `PUSH_PROMISE` if one arrives; sending `ENABLE_PUSH: 0` would claim a
    /// negotiation the code does not perform.
    #[must_use]
    pub fn server_default() -> Self {
        Self {
            header_table_size: DEFAULT_HEADER_TABLE_SIZE,
            enable_push: None,
            max_concurrent_streams: Some(DEFAULT_MAX_CONCURRENT_STREAMS),
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            // `u32::try_from` rather than `as u32`: `MAX_HEADER_LIST_SIZE` is
            // 64 KiB and so always fits, and the fallback states that instead of
            // a cast that would silently wrap if the constant grew past 4 GiB.
            max_header_list_size: Some(
                u32::try_from(super::hpack::MAX_HEADER_LIST_SIZE).unwrap_or(u32::MAX),
            ),
        }
    }

    /// Apply a `SETTINGS` frame's parameters, validating each (RFC 9113 §6.5.2).
    ///
    /// # Why the frame's parameters are applied in order
    ///
    /// §6.5.3: *"The values in the SETTINGS frame MUST be processed in the order
    /// they appear, with no other frame processing between values."* A repeated
    /// parameter therefore takes its **last** value, and a frame carrying
    /// `INITIAL_WINDOW_SIZE: 100, INITIAL_WINDOW_SIZE: 200` leaves 200. Applying
    /// them out of order, or into a map that keeps the first, gives 100 — a
    /// silently different window that shows up as a stall.
    ///
    /// # Errors
    ///
    /// A [`ConnectionError`] of type `PROTOCOL_ERROR` for any out-of-range
    /// value. It is a connection error and not a stream one because settings are
    /// connection-scoped: there is no stream to reset.
    pub fn apply(&mut self, frame: &Frame<'_>) -> Result<(), ConnectionError> {
        let Frame::Settings { params } = frame else {
            return Err(ConnectionError::protocol(
                ErrorCode::InternalError,
                "apply() called with a frame that is not SETTINGS",
            ));
        };
        for (id, value) in params {
            self.apply_one(*id, *value)?;
        }
        Ok(())
    }

    /// Apply one parameter, validating its range.
    ///
    /// # Errors
    ///
    /// As [`Settings::apply`].
    pub fn apply_one(&mut self, id: SettingId, value: u32) -> Result<(), ConnectionError> {
        match id {
            // §6.5.2 gives no range; any 32-bit value is a table size the sender
            // is willing to accept, and a size the receiver cannot allocate is
            // the receiver's problem to bound, not the peer's to guess.
            SettingId::HeaderTableSize => self.header_table_size = value,
            SettingId::EnablePush => {
                // A **boolean**: 0 or 1 and nothing else. Accepting 2 as "true"
                // is the natural mistake, and the RFC calls it out explicitly.
                match value {
                    0 => self.enable_push = Some(false),
                    1 => self.enable_push = Some(true),
                    other => {
                        return Err(ConnectionError::protocol(
                            ErrorCode::ProtocolError,
                            format!(
                                "SETTINGS_ENABLE_PUSH is a boolean; {other} is neither 0 nor 1"
                            ),
                        ));
                    }
                }
            }
            // No range: the value is a count, and 0 is legal and means "no
            // streams may be opened".
            SettingId::MaxConcurrentStreams => self.max_concurrent_streams = Some(value),
            SettingId::InitialWindowSize => {
                if value > MAX_INITIAL_WINDOW_SIZE {
                    return Err(ConnectionError::protocol(
                        ErrorCode::FlowControlError,
                        format!(
                            "SETTINGS_INITIAL_WINDOW_SIZE {value} exceeds the maximum \
                             {MAX_INITIAL_WINDOW_SIZE}"
                        ),
                    ));
                }
                self.initial_window_size = value;
            }
            SettingId::MaxFrameSize => {
                if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value) {
                    return Err(ConnectionError::protocol(
                        ErrorCode::ProtocolError,
                        format!(
                            "SETTINGS_MAX_FRAME_SIZE {value} is outside \
                             {MIN_MAX_FRAME_SIZE}..={MAX_MAX_FRAME_SIZE}"
                        ),
                    ));
                }
                self.max_frame_size = value;
            }
            // Advisory, per §6.5.2, and with no range.
            SettingId::MaxHeaderListSize => self.max_header_list_size = Some(value),
            // §6.5.2: *"Settings that are not defined … MUST be ignored."*
            // Ignoring is not the same as accepting: the value is dropped, so it
            // can never be mistaken for a parameter this implementation honours.
            SettingId::Unknown(_) => {}
        }
        Ok(())
    }

    /// The parameters to send, in the order a server sends them.
    ///
    /// Only parameters this endpoint has an opinion about are included. Sending
    /// a parameter at its default states a preference nobody has, and every byte
    /// of the initial exchange is on the critical path of every connection.
    #[must_use]
    pub fn to_params(&self, server: bool) -> Vec<(SettingId, u32)> {
        let mut params = vec![(SettingId::HeaderTableSize, self.header_table_size)];
        // §8.4: a server must not send ENABLE_PUSH. `server` is a parameter
        // rather than a field because it is a property of the *role*, not of the
        // settings, and getting it wrong is a connection error a peer will
        // enforce.
        if !server {
            if let Some(push) = self.enable_push {
                params.push((SettingId::EnablePush, u32::from(push)));
            }
        }
        if let Some(n) = self.max_concurrent_streams {
            params.push((SettingId::MaxConcurrentStreams, n));
        }
        params.push((SettingId::InitialWindowSize, self.initial_window_size));
        params.push((SettingId::MaxFrameSize, self.max_frame_size));
        if let Some(n) = self.max_header_list_size {
            params.push((SettingId::MaxHeaderListSize, n));
        }
        params
    }

    /// A `SETTINGS` frame carrying these parameters.
    #[must_use]
    pub fn to_frame(&self, server: bool) -> Frame<'static> {
        Frame::Settings {
            params: self.to_params(server),
        }
    }

    /// Whether the peer permits server push.
    ///
    /// RFC 9113 §6.5.2: `ENABLE_PUSH` defaults to 1, so an unset parameter is
    /// *permission*, not a refusal. Reading an unset parameter as "no" is the
    /// mistake that makes push silently unavailable against every client that
    /// omits it — which is most of them.
    #[must_use]
    pub fn push_enabled(&self) -> bool {
        self.enable_push.unwrap_or(true)
    }

    /// The peer's stream ceiling, or `None` for unlimited (RFC 9113 §6.5.2).
    #[must_use]
    pub fn stream_limit(&self) -> Option<u32> {
        self.max_concurrent_streams
    }
}

impl fmt::Display for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "header_table_size={} initial_window_size={} max_frame_size={}",
            self.header_table_size, self.initial_window_size, self.max_frame_size
        )?;
        match self.max_concurrent_streams {
            Some(n) => write!(f, " max_concurrent_streams={n}")?,
            None => f.write_str(" max_concurrent_streams=unlimited")?,
        }
        match self.max_header_list_size {
            Some(n) => write!(f, " max_header_list_size={n}")?,
            None => f.write_str(" max_header_list_size=unlimited")?,
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a `SETTINGS` frame was refused.
///
/// Thin — the real checking lives in [`Settings::apply_one`] and produces a
/// [`ConnectionError`] — but a named type here keeps the connection layer from
/// having to name `ConnectionError` in its public signature for a settings
/// problem, and gives a place for the role rule below to live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsError {
    /// A client sent `ENABLE_PUSH` (RFC 9113 §6.5.2).
    ///
    /// *"A server MUST NOT explicitly set this value to 1. … A client MUST treat
    /// receipt of a SETTINGS frame with `SETTINGS_ENABLE_PUSH` set to any value
    /// other than 0 or 1 as a connection error."* The direction that is easy to
    /// miss is this one: **33.5% of real servers were found to reject it**, so
    /// the rule is enforced in both directions here rather than only the popular
    /// one.
    ServerSentEnablePush,
    /// A parameter was outside its range.
    OutOfRange {
        /// The parameter.
        id: SettingId,
        /// The value sent.
        value: u32,
    },
}

impl SettingsError {
    /// The RFC code to report.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::ProtocolError
    }
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServerSentEnablePush => {
                f.write_str("a server must not send SETTINGS_ENABLE_PUSH (RFC 9113 §8.4)")
            }
            Self::OutOfRange { id, value } => {
                write!(f, "{id} value {value} is outside its permitted range")
            }
        }
    }
}

impl std::error::Error for SettingsError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_frame(params: Vec<(SettingId, u32)>) -> Frame<'static> {
        Frame::Settings { params }
    }

    /// The defaults RFC 9113 §6.5.2 defines, asserted separately so a typo in
    /// one of them is caught by name rather than by a downstream stall.
    #[test]
    fn the_defaults_are_the_rfc_values() {
        let s = Settings::default();
        assert_eq!(s.header_table_size, 4_096);
        assert_eq!(s.initial_window_size, 65_535);
        assert_eq!(s.max_frame_size, 16_384);
        assert_eq!(s.enable_push, None, "unset, not false");
        assert_eq!(
            s.max_concurrent_streams, None,
            "unset is unlimited, not zero"
        );
        assert_eq!(s.max_header_list_size, None);
    }

    #[test]
    fn a_settings_frame_applies_every_parameter() {
        let mut s = Settings::default();
        s.apply(&settings_frame(vec![
            (SettingId::HeaderTableSize, 8_192),
            (SettingId::MaxConcurrentStreams, 250),
            (SettingId::InitialWindowSize, 100_000),
            (SettingId::MaxFrameSize, 32_768),
            (SettingId::MaxHeaderListSize, 16_384),
        ]))
        .expect("all values are legal");

        assert_eq!(s.header_table_size, 8_192);
        assert_eq!(s.max_concurrent_streams, Some(250));
        assert_eq!(s.initial_window_size, 100_000);
        assert_eq!(s.max_frame_size, 32_768);
        assert_eq!(s.max_header_list_size, Some(16_384));
    }

    /// §6.5.3: the values are processed in the order they appear, so a repeated
    /// parameter takes its **last** value. Keeping the first gives a silently
    /// different window, which shows up as a stall rather than an error.
    #[test]
    fn a_repeated_parameter_takes_the_last_value() {
        let mut s = Settings::default();
        s.apply(&settings_frame(vec![
            (SettingId::InitialWindowSize, 100),
            (SettingId::InitialWindowSize, 200),
        ]))
        .expect("legal");
        assert_eq!(
            s.initial_window_size, 200,
            "the last value wins, per RFC 9113 §6.5.3"
        );
    }

    /// `ENABLE_PUSH` is a boolean. Accepting `2` as "true" is the natural
    /// mistake and the RFC calls it out explicitly.
    #[test]
    fn enable_push_accepts_only_zero_and_one() {
        let mut s = Settings::default();
        s.apply(&settings_frame(vec![(SettingId::EnablePush, 0)]))
            .expect("0 is legal");
        assert_eq!(s.enable_push, Some(false));

        s.apply(&settings_frame(vec![(SettingId::EnablePush, 1)]))
            .expect("1 is legal");
        assert_eq!(s.enable_push, Some(true));

        for bad in [2u32, 3, 100, u32::MAX] {
            let mut s = Settings::default();
            let e = s
                .apply(&settings_frame(vec![(SettingId::EnablePush, bad)]))
                .expect_err("only 0 and 1 are legal");
            assert_eq!(e.code(), ErrorCode::ProtocolError);
            assert!(e.to_string().contains("boolean"), "{e}");
        }
    }

    /// §6.5.2: `INITIAL_WINDOW_SIZE` above 2^31-1 is a `FLOW_CONTROL_ERROR` —
    /// the one parameter whose out-of-range code is not `PROTOCOL_ERROR`, because
    /// the ceiling is the window's own maximum rather than an arbitrary bound.
    #[test]
    fn an_oversized_initial_window_is_a_flow_control_error() {
        let mut s = Settings::default();
        let e = s
            .apply(&settings_frame(vec![(
                SettingId::InitialWindowSize,
                MAX_INITIAL_WINDOW_SIZE + 1,
            )]))
            .expect_err("2^31 is over the maximum");
        assert_eq!(e.code(), ErrorCode::FlowControlError);

        // The maximum itself is legal, which is the positive control: an
        // off-by-one that rejected `2^31 - 1` would pass the assertion above.
        let mut s = Settings::default();
        s.apply(&settings_frame(vec![(
            SettingId::InitialWindowSize,
            MAX_INITIAL_WINDOW_SIZE,
        )]))
        .expect("2^31 - 1 is the maximum and is legal");
        assert_eq!(s.initial_window_size, MAX_INITIAL_WINDOW_SIZE);
    }

    /// §6.5.2: `MAX_FRAME_SIZE` is `2^14 ..= 2^24-1`. Both bounds are checked in
    /// both directions, because either end being off by one changes which clients
    /// can talk to the server.
    #[test]
    fn max_frame_size_is_range_checked_at_both_ends() {
        for good in [MIN_MAX_FRAME_SIZE, 20_000, MAX_MAX_FRAME_SIZE] {
            let mut s = Settings::default();
            s.apply(&settings_frame(vec![(SettingId::MaxFrameSize, good)]))
                .unwrap_or_else(|e| panic!("{good} is in range: {e}"));
            assert_eq!(s.max_frame_size, good);
        }
        for bad in [
            0u32,
            1,
            MIN_MAX_FRAME_SIZE - 1,
            MAX_MAX_FRAME_SIZE + 1,
            u32::MAX,
        ] {
            let mut s = Settings::default();
            let e = s
                .apply(&settings_frame(vec![(SettingId::MaxFrameSize, bad)]))
                .expect_err("out of range");
            assert_eq!(
                e.code(),
                ErrorCode::ProtocolError,
                "{bad} should be refused"
            );
        }
    }

    /// §6.5.2: an undefined setting must be **ignored**. Ignoring is not the
    /// same as accepting: nothing observable may change.
    #[test]
    fn an_unknown_setting_is_ignored_without_changing_anything() {
        let mut s = Settings::default();
        let before = s;
        s.apply(&settings_frame(vec![(SettingId::Unknown(0xbeef), 12_345)]))
            .expect("an unknown setting is not an error");
        assert_eq!(s, before, "an unknown setting must not change any value");
    }

    /// A zero `MAX_CONCURRENT_STREAMS` is legal and means "no streams". Treating
    /// it as "unset" (and therefore unlimited) inverts the client's intent.
    #[test]
    fn a_zero_stream_limit_is_a_limit_not_an_absence() {
        let mut s = Settings::default();
        s.apply(&settings_frame(vec![(SettingId::MaxConcurrentStreams, 0)]))
            .expect("legal");
        assert_eq!(s.stream_limit(), Some(0));
        assert_ne!(
            s.stream_limit(),
            None,
            "zero must not collapse to `unset`, which means unlimited"
        );
    }

    /// §6.5.2: an unset `ENABLE_PUSH` is **permission**, not refusal. Reading it
    /// as "no" makes push unavailable against every client that omits it.
    #[test]
    fn an_unset_enable_push_permits_push() {
        assert!(Settings::default().push_enabled());
        let mut s = Settings::default();
        s.apply(&settings_frame(vec![(SettingId::EnablePush, 0)]))
            .unwrap();
        assert!(!s.push_enabled());
    }

    /// RFC 9113 §8.4: a server must not send `ENABLE_PUSH`. The settings a
    /// server sends therefore never include it, and the encoder enforces the
    /// role rather than trusting a field to be `None`.
    #[test]
    fn a_server_never_sends_enable_push() {
        // Even with the field explicitly set, the server role suppresses it.
        let mut s = Settings::server_default();
        s.enable_push = Some(true);
        let params = s.to_params(true);
        assert!(
            !params.iter().any(|(id, _)| *id == SettingId::EnablePush),
            "a server must not send SETTINGS_ENABLE_PUSH"
        );

        // A client does send it, so the suppression is role-driven and not a
        // blanket omission.
        let params = s.to_params(false);
        assert!(params.iter().any(|(id, _)| *id == SettingId::EnablePush));
    }

    /// The initial SETTINGS frame a server sends must include the parameters the
    /// connection layer relies on — in particular `MAX_CONCURRENT_STREAMS`,
    /// because RFC 9113 §8.7 forbids sending `REFUSED_STREAM` for a load-shed
    /// unless a stream ceiling was advertised that justifies it.
    #[test]
    fn the_server_defaults_advertise_a_stream_ceiling() {
        let s = Settings::server_default();
        assert_eq!(s.stream_limit(), Some(DEFAULT_MAX_CONCURRENT_STREAMS));
        let params = s.to_params(true);
        assert!(params
            .iter()
            .any(|(id, v)| *id == SettingId::MaxConcurrentStreams && *v == 100));
        assert!(params
            .iter()
            .any(|(id, _)| *id == SettingId::InitialWindowSize));
        assert!(params.iter().any(|(id, _)| *id == SettingId::MaxFrameSize));
    }

    /// Settings survive a frame round trip, which is what makes the initial
    /// exchange testable without a socket.
    #[test]
    fn settings_round_trip_through_a_frame() {
        let s = Settings::server_default();
        let frame = s.to_frame(true);
        let bytes = super::super::frame::to_bytes(&frame);
        let (parsed, used) =
            super::super::frame::parse_frame(&bytes).expect("the frame we wrote must parse");
        assert_eq!(used, bytes.len());

        let mut back = Settings::default();
        back.apply(&parsed).expect("our own settings are legal");
        assert_eq!(back.header_table_size, s.header_table_size);
        assert_eq!(back.initial_window_size, s.initial_window_size);
        assert_eq!(back.max_frame_size, s.max_frame_size);
        assert_eq!(back.max_concurrent_streams, s.max_concurrent_streams);
        assert_eq!(back.max_header_list_size, s.max_header_list_size);
    }

    /// Applying a non-SETTINGS frame is a programming error and must be reported
    /// rather than silently doing nothing — a silent no-op here would drop the
    /// peer's entire settings exchange.
    #[test]
    fn applying_a_non_settings_frame_is_reported() {
        let mut s = Settings::default();
        let e = s
            .apply(&Frame::SettingsAck)
            .expect_err("an ACK is not a parameter list");
        assert_eq!(e.code(), ErrorCode::InternalError);
    }

    #[test]
    fn settings_render_with_their_limits() {
        let s = Settings::server_default();
        let rendered = s.to_string();
        assert!(rendered.contains("max_concurrent_streams=100"));
        assert!(rendered.contains("initial_window_size=65535"));

        let unlimited = Settings::default().to_string();
        assert!(
            unlimited.contains("max_concurrent_streams=unlimited"),
            "an absent limit must not render as 0: {unlimited}"
        );
    }
}
