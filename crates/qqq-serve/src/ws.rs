// SPDX-License-Identifier: Apache-2.0

//! The WebSocket opening handshake, per RFC 6455 §4.
//!
//! Implements the server side of `SRV-009`. Proposal §6.4 scopes WebSockets in V1:
//!
//! > **Scope in V1:** HTTP/1.1 (complete), HTTP/2 (complete), **WebSockets over both**,
//! > Server-Sent Events, [...]
//!
//! # What this module is, and what it is not
//!
//! It is the **handshake**: parsing the client's upgrade request, deciding whether to
//! accept it, and building the `101 Switching Protocols` response. It is not the frame
//! layer — opcodes, masking, fragmentation — which is a separate concern with its own
//! rules and is not built yet.
//!
//! Splitting them this way follows the specification's own structure (§4 versus §5), and
//! it means the handshake is testable without a socket or a frame codec. The frame layer
//! will arrive as its own module.
//!
//! # The five things a server must check, and what happens if it skips one
//!
//! | Check | Why it is not optional |
//! |---|---|
//! | `Upgrade: websocket` (case-insensitive) | A request without it is an ordinary `GET`. Accepting it would hijack a normal request. |
//! | `Connection` contains `Upgrade` (a **token list**) | `Connection` is a comma-separated list; `keep-alive, Upgrade` is valid and a naive equality test rejects it. |
//! | `Sec-WebSocket-Version: 13` | Version 13 is the only one RFC 6455 defines. A server that ignores this answers an older client with a key it cannot verify, and the failure surfaces as a broken connection with no diagnosis. |
//! | `Sec-WebSocket-Key` is 16 bytes, base64 | The key is what proves the server read the handshake. A malformed one means the client is not speaking the protocol. |
//! | The method is `GET` | §4.1 requires it. A `POST` with an upgrade header is not a handshake. |
//!
//! # Why the GUID is a constant and SHA-1 is correct here
//!
//! `Sec-WebSocket-Accept` is `base64(SHA-1(key ++ GUID))` where the GUID is fixed by the
//! specification. **This is not a security control.** It exists so a server that
//! understood the upgrade cannot be confused with a proxy that passed it through
//! blindly: only something that read the key can compute the accept value. An attacker
//! who can compute SHA-1 gains nothing, because the input is a key the client itself
//! chose — there is no secret to collide against. See the workspace manifest, where the
//! dependency's presence is explained for the same reason.

use std::fmt::Write as _;

use base64::Engine as _;
use sha1::{Digest as _, Sha1};

/// The GUID RFC 6455 §4.2.2 fixes for the accept computation.
///
/// A constant, not a secret. It appears in the specification verbatim and in every
/// WebSocket implementation ever written.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The only protocol version RFC 6455 defines.
pub const VERSION: &str = "13";

/// Why a handshake was refused.
///
/// A value rather than a bare `false`, because the reasons have different remedies: a
/// missing `Upgrade` means the caller should handle the request normally, while a wrong
/// *version* means the client is speaking an older protocol and the server should say
/// which versions it supports — which §4.4 requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// The method is not `GET`. §4.1 requires it.
    NotGet {
        /// What the request used.
        method: String,
    },
    /// `Upgrade` is absent or does not name `websocket`.
    NotAnUpgrade,
    /// `Connection` does not contain the `Upgrade` token.
    ConnectionNotUpgraded,
    /// `Sec-WebSocket-Version` is absent or is not `13`.
    ///
    /// The response must name the supported version, so a client speaking an older
    /// protocol can retry rather than fail opaquely.
    UnsupportedVersion {
        /// What the client asked for, or `None` when the header is absent.
        got: Option<String>,
    },
    /// `Sec-WebSocket-Key` is absent, or is not 16 base64-encoded bytes.
    BadKey {
        /// Why the value was rejected.
        reason: String,
    },
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotGet { method } => {
                write!(f, "a WebSocket handshake must be a GET, not `{method}`")
            }
            Self::NotAnUpgrade => f.write_str(
                "`Upgrade: websocket` is required; without it this is an ordinary request",
            ),
            Self::ConnectionNotUpgraded => {
                f.write_str("`Connection` must list the `Upgrade` token")
            }
            Self::UnsupportedVersion { got } => match got {
                Some(v) => write!(
                    f,
                    "`Sec-WebSocket-Version: {v}` is not supported; only {VERSION} is"
                ),
                None => write!(f, "`Sec-WebSocket-Version` is required; only {VERSION} is"),
            },
            Self::BadKey { reason } => write!(f, "`Sec-WebSocket-Key` is invalid: {reason}"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// A validated upgrade request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    /// The client's key, echoed into the accept value.
    key: String,
    /// The subprotocols the client offered, in preference order.
    protocols: Vec<String>,
    /// The extensions the client offered, verbatim.
    ///
    /// Retained rather than parsed: this crate negotiates none, and §4.1 says a server
    /// that does not understand an extension must ignore it. Keeping the list lets a
    /// caller log what was offered without this module pretending to understand it.
    extensions: Vec<String>,
}

impl Handshake {
    /// Parse and validate a client's upgrade request.
    ///
    /// `method` is the request method, and `header` looks a header up case-insensitively.
    ///
    /// # Errors
    ///
    /// Any [`HandshakeError`]. The checks run in the order §4.2.1 lists the fields, so the
    /// first failure names the first thing that was wrong rather than a later symptom.
    pub fn parse<F>(method: &str, header: F) -> Result<Self, HandshakeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if method != "GET" {
            return Err(HandshakeError::NotGet {
                method: method.to_owned(),
            });
        }

        // `Upgrade` is a token and must name websocket. Matched case-insensitively
        // because the field is a token list and case-insensitive by HTTP's rules.
        match header("upgrade") {
            Some(v)
                if v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("websocket")) => {}
            _ => return Err(HandshakeError::NotAnUpgrade),
        }

        // **`Connection` is a list, not a value.** `Connection: keep-alive, Upgrade` is
        // valid and common — it is what a browser sends on a connection it also wants
        // kept alive — so an equality test against "upgrade" rejects a correct client.
        match header("connection") {
            Some(v)
                if v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade")) => {}
            _ => return Err(HandshakeError::ConnectionNotUpgraded),
        }

        let version = header("sec-websocket-version");
        match version.as_deref() {
            Some(v) if v.trim() == VERSION => {}
            other => {
                return Err(HandshakeError::UnsupportedVersion {
                    got: other.map(str::to_owned),
                })
            }
        }

        let raw_key = header("sec-websocket-key").ok_or_else(|| HandshakeError::BadKey {
            reason: "the header is absent".to_owned(),
        })?;
        let key = validate_key(&raw_key)?;

        let protocols = header("sec-websocket-protocol")
            .map(|v| {
                v.split(',')
                    .map(|p| p.trim().to_owned())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let extensions = header("sec-websocket-extensions")
            .map(|v| {
                v.split(',')
                    .map(|e| e.trim().to_owned())
                    .filter(|e| !e.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            key,
            protocols,
            extensions,
        })
    }

    /// The client's key, as received.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The subprotocols the client offered, in its own preference order.
    #[must_use]
    pub fn protocols(&self) -> &[String] {
        &self.protocols
    }

    /// The extensions the client offered, verbatim and uninterpreted.
    #[must_use]
    pub fn extensions(&self) -> &[String] {
        &self.extensions
    }

    /// The value for `Sec-WebSocket-Accept`.
    ///
    /// `base64(SHA-1(key ++ GUID))`, per §4.2.2.
    #[must_use]
    pub fn accept(&self) -> String {
        accept_for(&self.key)
    }

    /// Select a subprotocol from the client's offer, or decline to.
    ///
    /// `supported` is the server's list, in its own preference order; the **server's**
    /// order decides, which is what §4.1 means by "the server selects the first one it
    /// supports" over its own list rather than the client's. Returning `None` is a
    /// complete answer — §4.1 says a server may decline all of them — and means the
    /// response omits `Sec-WebSocket-Protocol` entirely.
    #[must_use]
    pub fn select_protocol(&self, supported: &[&str]) -> Option<String> {
        supported
            .iter()
            .find(|s| self.protocols.iter().any(|p| p == *s))
            .map(|s| (*s).to_owned())
    }
}

/// Validate a `Sec-WebSocket-Key`.
///
/// §4.1 requires 16 bytes, base64-encoded. Checked because the key is the *evidence* the
/// client is speaking the protocol: a value of the wrong length means either a different
/// protocol or a broken client, and computing an accept for it would produce a handshake
/// the client cannot verify — a failure that surfaces much later as a dropped
/// connection.
fn validate_key(raw: &str) -> Result<String, HandshakeError> {
    let trimmed = raw.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|e| HandshakeError::BadKey {
            reason: format!("not valid base64: {e}"),
        })?;
    if decoded.len() != 16 {
        return Err(HandshakeError::BadKey {
            reason: format!("decoded to {} bytes, expected 16", decoded.len()),
        });
    }
    // The **decoded** length is what the specification constrains, and the encoded form
    // is echoed verbatim into the accept computation — so the original string is kept
    // rather than a re-encoding of the bytes, which could differ in padding.
    Ok(trimmed.to_owned())
}

/// `base64(SHA-1(key ++ GUID))`, per §4.2.2.
///
/// Public so a client-side test can compute what it expects, and so a caller holding a
/// key from elsewhere does not reimplement the concatenation order — the one detail that
/// silently produces a wrong accept value.
#[must_use]
pub fn accept_for(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// The headers a `101 Switching Protocols` response carries.
///
/// # Why this is a function and not a `Response`
///
/// A `101` is not a normal response: it has **no body**, it must not carry
/// `Content-Length`, and it is written with a different function from
/// [`crate::response::write_response`] — which would add a length and break the upgrade.
/// Returning the header list keeps the framing decision in the caller, where the write
/// happens, instead of here where it cannot be expressed.
///
/// `protocol` is the selected subprotocol, or `None` to decline them all.
#[must_use]
pub fn accept_headers(
    handshake: &Handshake,
    protocol: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("Upgrade", "websocket".to_owned()),
        ("Connection", "Upgrade".to_owned()),
        ("Sec-WebSocket-Accept", handshake.accept()),
    ];
    if let Some(p) = protocol {
        headers.push(("Sec-WebSocket-Protocol", p.to_owned()));
    }
    headers
}

/// The status line and headers of a `101`, without a body.
///
/// # Why the upgrade response cannot go through `write_response`
///
/// [`crate::response::write_response`] emits `Content-Length`, which a `101` must not
/// carry — the connection stops being HTTP at this point and the bytes after these
/// headers are WebSocket frames, not a body. A client that read a `Content-Length` would
/// count frame bytes as content.
#[must_use]
pub fn write_upgrade(handshake: &Handshake, protocol: Option<&str>) -> Vec<u8> {
    let mut out = String::with_capacity(256);
    out.push_str("HTTP/1.1 101 Switching Protocols\r\n");
    for (name, value) in accept_headers(handshake, protocol) {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(&value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// The response for a refused upgrade, with the supported version named.
///
/// §4.4 requires a server to send `Sec-WebSocket-Version` when it refuses on version
/// grounds, so the client can retry with a supported one instead of failing with no
/// diagnosis. The status is `400` for a malformed request and `426 Upgrade Required` for
/// a version mismatch — the latter being the only status that means "upgrade, but not
/// the way you asked".
#[must_use]
pub fn write_refusal(err: &HandshakeError) -> Vec<u8> {
    let (status, reason) = match err {
        HandshakeError::UnsupportedVersion { .. } => (426u16, "Upgrade Required"),
        _ => (400, "Bad Request"),
    };
    let mut out = String::with_capacity(256);
    // `write!` rather than `push_str(&format!(..))`: the latter allocates a second string
    // per header, which `clippy::format_push_string` flags and which is measurable on a
    // path a refused client can drive repeatedly.
    let _ = write!(out, "HTTP/1.1 {status} {reason}\r\n");
    if matches!(err, HandshakeError::UnsupportedVersion { .. }) {
        out.push_str("Sec-WebSocket-Version: ");
        out.push_str(VERSION);
        out.push_str("\r\n");
    }
    let body = err.to_string();
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    let _ = write!(out, "Content-Length: {}\r\n", body.len());
    out.push_str("Connection: close\r\n\r\n");
    out.push_str(&body);
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A header lookup over a fixed map, for the tests.
    fn headers(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_ascii_lowercase(), (*v).to_owned()))
            .collect();
        move |name: &str| map.get(&name.to_ascii_lowercase()).cloned()
    }

    /// A minimal valid handshake request.
    fn valid() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Version", "13"),
            // A 16-byte key, base64-encoded — the example from RFC 6455 §1.3.
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ]
    }

    // -- the accept value --------------------------------------------------

    /// **The accept value matches the specification's own worked example.**
    ///
    /// RFC 6455 §1.3 states that the key `dGhlIHNhbXBsZSBub25jZQ==` yields
    /// `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`. If that fails, the concatenation order, the GUID,
    /// or the encoding is wrong — and nothing else in this module can be trusted.
    #[test]
    fn the_specification_example_is_reproduced() {
        assert_eq!(
            accept_for("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            "the accept computation must match RFC 6455 §1.3"
        );
    }

    /// The GUID is included, and in the right order.
    ///
    /// The control for the test above: computing the hash of the key *alone* must produce
    /// something different. A first version that forgot the GUID would still be
    /// deterministic and would still look plausible.
    #[test]
    fn the_guid_is_part_of_the_input() {
        let without_guid = base64::engine::general_purpose::STANDARD
            .encode(Sha1::digest("dGhlIHNhbXBsZSBub25jZQ==".as_bytes()));
        assert_ne!(
            without_guid,
            accept_for("dGhlIHNhbXBsZSBub25jZQ=="),
            "the GUID must be appended, or the accept value is wrong"
        );
    }

    // -- the five checks ---------------------------------------------------

    /// A valid handshake parses.
    #[test]
    fn a_valid_handshake_parses() {
        let h = Handshake::parse("GET", headers(&valid())).expect("must accept");
        assert_eq!(h.key(), "dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(h.accept(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    /// **A non-`GET` method is refused.** §4.1 requires `GET`.
    #[test]
    fn a_non_get_method_is_refused() {
        let err = Handshake::parse("POST", headers(&valid())).expect_err("must refuse");
        assert!(matches!(err, HandshakeError::NotGet { .. }), "{err:?}");
        assert!(err.to_string().contains("POST"), "{err}");
    }

    /// A request with no `Upgrade` is refused — it is an ordinary request.
    #[test]
    fn a_request_without_upgrade_is_refused() {
        let mut h = valid();
        h.retain(|(k, _)| *k != "Upgrade");
        let err = Handshake::parse("GET", headers(&h)).expect_err("must refuse");
        assert!(matches!(err, HandshakeError::NotAnUpgrade), "{err:?}");
        assert!(
            err.to_string().contains("ordinary request"),
            "the message must say what this request actually is: {err}"
        );
    }

    /// **A `Connection` token list containing `Upgrade` is accepted.**
    ///
    /// `Connection` is a **token list**, and `keep-alive, Upgrade` is the spelling a
    /// browser sends. An equality test against `"upgrade"` would reject a correct client
    /// — which is a failure that appears as "`WebSockets` do not work in Firefox".
    #[test]
    fn a_connection_token_list_is_accepted() {
        let mut h = valid();
        for pair in &mut h {
            if pair.0 == "Connection" {
                pair.1 = "keep-alive, Upgrade";
            }
        }
        assert!(Handshake::parse("GET", headers(&h)).is_ok());

        // And the token may be anywhere in the list, in any case.
        for value in [
            "Upgrade, keep-alive",
            "upgrade",
            "UPGRADE",
            "keep-alive,upgrade",
        ] {
            let mut h = valid();
            for pair in &mut h {
                if pair.0 == "Connection" {
                    pair.1 = value;
                }
            }
            assert!(
                Handshake::parse("GET", headers(&h)).is_ok(),
                "`Connection: {value}` must be accepted"
            );
        }
    }

    /// A `Connection` that does not list `Upgrade` is refused.
    #[test]
    fn a_connection_without_the_token_is_refused() {
        let mut h = valid();
        for pair in &mut h {
            if pair.0 == "Connection" {
                pair.1 = "keep-alive";
            }
        }
        let err = Handshake::parse("GET", headers(&h)).expect_err("must refuse");
        assert!(
            matches!(err, HandshakeError::ConnectionNotUpgraded),
            "{err:?}"
        );
    }

    /// **The `Upgrade` value is matched case-insensitively.**
    #[test]
    fn the_upgrade_token_is_case_insensitive() {
        for value in ["WebSocket", "WEBSOCKET", "websocket"] {
            let mut h = valid();
            for pair in &mut h {
                if pair.0 == "Upgrade" {
                    pair.1 = value;
                }
            }
            assert!(
                Handshake::parse("GET", headers(&h)).is_ok(),
                "`Upgrade: {value}` must be accepted"
            );
        }
    }

    /// A version other than 13 is refused, and the error names what was supported.
    #[test]
    fn an_unsupported_version_is_refused() {
        let mut h = valid();
        for pair in &mut h {
            if pair.0 == "Sec-WebSocket-Version" {
                pair.1 = "8";
            }
        }
        let err = Handshake::parse("GET", headers(&h)).expect_err("must refuse");
        assert!(
            matches!(err, HandshakeError::UnsupportedVersion { .. }),
            "{err:?}"
        );
        assert!(
            err.to_string().contains("13"),
            "the message must name the version: {err}"
        );
    }

    /// A missing version is refused, distinctly from a wrong one.
    #[test]
    fn a_missing_version_is_refused() {
        let mut h = valid();
        h.retain(|(k, _)| *k != "Sec-WebSocket-Version");
        let err = Handshake::parse("GET", headers(&h)).expect_err("must refuse");
        assert!(
            matches!(err, HandshakeError::UnsupportedVersion { got: None }),
            "{err:?}"
        );
    }

    /// **A key that is not 16 bytes is refused.**
    #[test]
    fn a_wrong_length_key_is_refused() {
        for bad in [
            // 8 bytes, not 16.
            "c2hvcnQ=",
            // 20 bytes.
            "dGhpcyBpcyB0d2VudHkgYnl0ZXMh",
        ] {
            let mut h = valid();
            for pair in &mut h {
                if pair.0 == "Sec-WebSocket-Key" {
                    pair.1 = bad;
                }
            }
            let err = Handshake::parse("GET", headers(&h)).expect_err("must refuse");
            assert!(
                matches!(err, HandshakeError::BadKey { .. }),
                "{bad}: {err:?}"
            );
            assert!(
                err.to_string().contains("16"),
                "{bad}: the message must say 16: {err}"
            );
        }
    }

    /// A key that is not base64 is refused.
    #[test]
    fn a_non_base64_key_is_refused() {
        let mut h = valid();
        for pair in &mut h {
            if pair.0 == "Sec-WebSocket-Key" {
                pair.1 = "not base64 at all!!";
            }
        }
        let err = Handshake::parse("GET", headers(&h)).expect_err("must refuse");
        assert!(matches!(err, HandshakeError::BadKey { .. }), "{err:?}");
    }

    /// A missing key is refused.
    #[test]
    fn a_missing_key_is_refused() {
        let mut h = valid();
        h.retain(|(k, _)| *k != "Sec-WebSocket-Key");
        let err = Handshake::parse("GET", headers(&h)).expect_err("must refuse");
        assert!(matches!(err, HandshakeError::BadKey { .. }), "{err:?}");
    }

    // -- subprotocols ------------------------------------------------------

    /// The offered subprotocols are parsed in order.
    #[test]
    fn subprotocols_are_parsed_in_order() {
        let mut h = valid();
        h.push(("Sec-WebSocket-Protocol", "chat, superchat"));
        let hs = Handshake::parse("GET", headers(&h)).expect("valid");
        assert_eq!(hs.protocols(), ["chat", "superchat"]);
    }

    /// **The server's preference order decides**, not the client's.
    #[test]
    fn the_servers_preference_decides_the_protocol() {
        let mut h = valid();
        h.push(("Sec-WebSocket-Protocol", "chat, superchat"));
        let hs = Handshake::parse("GET", headers(&h)).expect("valid");

        // The client prefers `chat`; the server prefers `superchat`.
        assert_eq!(
            hs.select_protocol(&["superchat", "chat"]).as_deref(),
            Some("superchat"),
            "§4.1 has the server select from its own list"
        );
        // And with the server's order reversed, so does the answer.
        assert_eq!(
            hs.select_protocol(&["chat", "superchat"]).as_deref(),
            Some("chat")
        );
    }

    /// Declining every subprotocol is a valid answer.
    #[test]
    fn declining_all_subprotocols_is_valid() {
        let mut h = valid();
        h.push(("Sec-WebSocket-Protocol", "chat"));
        let hs = Handshake::parse("GET", headers(&h)).expect("valid");
        assert_eq!(hs.select_protocol(&["other"]), None);
    }

    /// A handshake with no subprotocol offer selects nothing.
    #[test]
    fn no_offer_selects_nothing() {
        let hs = Handshake::parse("GET", headers(&valid())).expect("valid");
        assert!(hs.protocols().is_empty());
        assert_eq!(hs.select_protocol(&["chat"]), None);
    }

    /// Extensions are retained verbatim and not interpreted.
    #[test]
    fn extensions_are_retained_verbatim() {
        let mut h = valid();
        h.push((
            "Sec-WebSocket-Extensions",
            "permessage-deflate; client_max_window_bits",
        ));
        let hs = Handshake::parse("GET", headers(&h)).expect("valid");
        assert_eq!(
            hs.extensions(),
            ["permessage-deflate; client_max_window_bits"]
        );
    }

    // -- the response ------------------------------------------------------

    /// The `101` carries the three required headers and **no body framing**.
    ///
    /// `Content-Length` must be absent: after a `101` the connection is no longer HTTP,
    /// and a client that read a length would count frame bytes as content.
    #[test]
    fn the_upgrade_response_has_the_three_headers_and_no_length() {
        let hs = Handshake::parse("GET", headers(&valid())).expect("valid");
        let raw = write_upgrade(&hs, None);
        let text = String::from_utf8(raw).expect("ascii");

        assert!(
            text.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
            "{text}"
        );
        assert!(text.contains("Upgrade: websocket\r\n"), "{text}");
        assert!(text.contains("Connection: Upgrade\r\n"), "{text}");
        assert!(
            text.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"),
            "{text}"
        );
        assert!(
            text.ends_with("\r\n\r\n"),
            "the head ends with a blank line: {text:?}"
        );
        assert!(
            !text.to_ascii_lowercase().contains("content-length"),
            "a 101 must not carry a length: {text}"
        );
    }

    /// A selected subprotocol is echoed; a declined one is absent entirely.
    #[test]
    fn the_selected_protocol_is_echoed_or_omitted() {
        let mut h = valid();
        h.push(("Sec-WebSocket-Protocol", "chat"));
        let hs = Handshake::parse("GET", headers(&h)).expect("valid");

        let with = String::from_utf8(write_upgrade(&hs, Some("chat"))).expect("ascii");
        assert!(with.contains("Sec-WebSocket-Protocol: chat\r\n"), "{with}");

        let without = String::from_utf8(write_upgrade(&hs, None)).expect("ascii");
        assert!(
            !without
                .to_ascii_lowercase()
                .contains("sec-websocket-protocol"),
            "declining means the header is absent, not empty: {without}"
        );
    }

    /// **A version refusal names the supported version.** §4.4 requires it.
    #[test]
    fn a_version_refusal_names_the_supported_version() {
        let err = HandshakeError::UnsupportedVersion {
            got: Some("8".to_owned()),
        };
        let raw = write_refusal(&err);
        let text = String::from_utf8(raw).expect("ascii");

        assert!(
            text.starts_with("HTTP/1.1 426 Upgrade Required\r\n"),
            "{text}"
        );
        assert!(
            text.contains("Sec-WebSocket-Version: 13\r\n"),
            "§4.4 requires the server to name what it supports: {text}"
        );
    }

    /// A malformed request gets `400`, not `426`.
    ///
    /// The distinction is what a client acts on: `426` means "retry with a different
    /// version", and `400` means "your request is malformed".
    #[test]
    fn a_malformed_request_gets_a_400() {
        let raw = write_refusal(&HandshakeError::NotAnUpgrade);
        let text = String::from_utf8(raw).expect("ascii");
        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{text}");
        assert!(
            !text.contains("Sec-WebSocket-Version"),
            "a 400 must not suggest a version retry: {text}"
        );
    }

    /// A refusal carries a body and a length, unlike the upgrade.
    #[test]
    fn a_refusal_has_a_body_and_a_length() {
        let raw = write_refusal(&HandshakeError::NotGet {
            method: "POST".to_owned(),
        });
        let text = String::from_utf8(raw).expect("ascii");
        assert!(
            text.to_ascii_lowercase().contains("content-length:"),
            "{text}"
        );
        assert!(text.contains("Connection: close"), "{text}");
        assert!(
            text.contains("POST"),
            "the reason names the actual method: {text}"
        );
    }

    /// The handshake is deterministic.
    ///
    /// §10.5 requires a deterministic run to produce identical output, and a handshake
    /// response is output. A `HashMap` over headers here would make the byte sequence
    /// vary between runs.
    #[test]
    fn the_upgrade_response_is_deterministic() {
        let hs = Handshake::parse("GET", headers(&valid())).expect("valid");
        let first = write_upgrade(&hs, Some("chat"));
        for _ in 0..50 {
            assert_eq!(write_upgrade(&hs, Some("chat")), first);
        }
    }
}
