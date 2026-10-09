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

use std::collections::BTreeSet;
use std::fmt::Write as _;

use base64::Engine as _;
use sha1::{Digest as _, Sha1};

use crate::cors::Origin;

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

/// Who may open a WebSocket, and who may name a loopback host (`F-14`).
///
/// Browsers do not apply the same-origin policy to `WebSockets`: any page can
/// open a socket to the server and the browser attaches ambient credentials.
/// The server must therefore check `Origin` itself, before the upgrade —
/// `Cross-Site WebSocket Hijacking` is not stopped by anything else.
///
/// The default is **same-origin only**: an absent `Origin` (a non-browser
/// client) upgrades, a present one must match the request's `Host` or the
/// explicit allow-list. A literal `*` in the allow-list is the explicit
/// opt-in to any origin, and it must be written to be meant.
///
/// The allow-list reuses [`Origin`]: the same validated, canonicalized type
/// the CORS policy matches against, so the two policies cannot disagree
/// about what an origin *is* — only about which ones are admitted.
///
/// ```
/// use qqq_serve::ws::WsOriginPolicy;
///
/// let policy = WsOriginPolicy::default();
/// assert!(policy.allowed().is_empty(), "same-origin only by default");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WsOriginPolicy {
    /// Origins admitted besides the request's own. Empty is same-origin only.
    allowed: BTreeSet<Origin>,
    /// A literal `*` was configured: any origin upgrades.
    allow_any: bool,
}

impl WsOriginPolicy {
    /// Same-origin only: no explicit origins, no wildcard.
    ///
    /// ```
    /// use qqq_serve::ws::WsOriginPolicy;
    ///
    /// let policy = WsOriginPolicy::same_origin();
    /// assert!(!policy.allows_any());
    /// assert!(policy.allowed().is_empty());
    /// ```
    #[must_use]
    pub fn same_origin() -> Self {
        Self::default()
    }

    /// Build from explicit origin strings plus the wildcard.
    ///
    /// # Errors
    ///
    /// [`crate::cors::CorsError::BadOrigin`] for a value that is neither a
    /// valid origin nor the literal `*`. A wildcard smuggled in as
    /// `*.example.com` is not a suffix rule — suffix matching is the bypass
    /// `cors.rs` documents — so only the exact string `*` opts in.
    ///
    /// ```
    /// use qqq_serve::ws::WsOriginPolicy;
    ///
    /// let policy = WsOriginPolicy::from_manifest(&[
    ///     "https://app.example.com".to_owned(),
    ///     "*".to_owned(),
    /// ])
    /// .expect("valid origins");
    /// assert!(policy.allows_any());
    /// assert_eq!(policy.allowed().len(), 1);
    /// assert!(WsOriginPolicy::from_manifest(&["https://*.example.com".to_owned()]).is_err());
    /// ```
    pub fn from_manifest(values: &[String]) -> Result<Self, crate::cors::CorsError> {
        use crate::cors::CorsError;
        let mut allowed = BTreeSet::new();
        let mut allow_any = false;
        for v in values {
            if v.trim() == "*" {
                allow_any = true;
            } else {
                if v.contains('*') {
                    return Err(CorsError::BadOrigin(format!(
                        "`{v}` is a wildcard host, which V1 refuses: list each origin \
                         in full, because a partial matcher is a substring matcher"
                    )));
                }
                allowed.insert(Origin::parse(v)?);
            }
        }
        Ok(Self { allowed, allow_any })
    }

    /// Whether any origin upgrades without further checks.
    ///
    /// ```
    /// use qqq_serve::ws::WsOriginPolicy;
    ///
    /// assert!(!WsOriginPolicy::default().allows_any());
    /// ```
    #[must_use]
    pub fn allows_any(&self) -> bool {
        self.allow_any
    }

    /// The explicitly allowed origins, for reporting.
    ///
    /// ```
    /// use qqq_serve::ws::WsOriginPolicy;
    ///
    /// let policy = WsOriginPolicy::from_manifest(&["https://a.example".to_owned()])
    ///     .expect("valid");
    /// assert_eq!(policy.allowed().len(), 1);
    /// ```
    #[must_use]
    pub fn allowed(&self) -> &BTreeSet<Origin> {
        &self.allowed
    }
}

/// Whether an upgrade with this `Origin` may proceed to the handshake.
///
/// `origin` is the raw header value (`None` when absent), `host` the raw
/// `Host` header. Absent upgrades (non-browser clients); present must be
/// same-origin, explicitly allowed, or covered by the `*` opt-in. Anything
/// else — including a malformed `Origin`, which is refused rather than
/// passed through — does not upgrade.
///
/// ```
/// use qqq_serve::ws::{upgrade_origin_allowed, WsOriginPolicy};
///
/// let policy = WsOriginPolicy::default();
/// assert!(upgrade_origin_allowed(&policy, None, "127.0.0.1:8080"));
/// assert!(upgrade_origin_allowed(
///     &policy,
///     Some("http://127.0.0.1:8080"),
///     "127.0.0.1:8080"
/// ));
/// assert!(!upgrade_origin_allowed(
///     &policy,
///     Some("https://evil.example"),
///     "127.0.0.1:8080"
/// ));
/// ```
#[must_use]
pub fn upgrade_origin_allowed(policy: &WsOriginPolicy, origin: Option<&str>, host: &str) -> bool {
    let Some(raw) = origin else {
        return true;
    };
    if policy.allow_any {
        return true;
    }
    let Ok(origin) = Origin::parse(raw) else {
        return false;
    };
    if policy.allowed.contains(&origin) {
        return true;
    }
    same_origin(&origin, host)
}

/// Whether a parsed `Origin` is the request's own authority.
///
/// Compared normalised: lowercase scheme and host (which [`Origin::parse`]
/// already guarantees), default ports elided on both sides. Never a
/// substring match — `http://evil-127.0.0.1:8080` is not `127.0.0.1:8080`
/// no matter how it reads.
///
/// The request's scheme is deliberately not compared: the `Host` header
/// carries none. Resolving both ports against the *origin's* scheme default
/// is fail-closed in every realizable case — an `https` page cannot reach a
/// plaintext socket (the browser blocks mixed content before sending), so a
/// downgrade mismatch refuses rather than admits.
fn same_origin(origin: &Origin, host: &str) -> bool {
    let Some((origin_scheme, origin_authority)) = origin.as_str().split_once("://") else {
        return false;
    };
    let (origin_host, origin_port) = split_authority(origin_authority);
    let (host_host, host_port) = split_authority(host.trim().to_ascii_lowercase().as_str());
    if origin_host != host_host {
        return false;
    }
    let default = default_port(origin_scheme);
    let origin_port = origin_port.filter(|p| !p.is_empty());
    let host_port = host_port.filter(|p| !p.is_empty());
    origin_port.as_deref().or(default) == host_port.as_deref().or(default)
}

/// Split `host[:port]` (IPv6 in brackets) into lowercase host and port.
///
/// The `Origin` side arrives pre-lowercased from [`Origin::parse`]; the
/// `Host` side is lowercased here, so both halves meet normalised.
fn split_authority(authority: &str) -> (String, Option<String>) {
    if let Some(stripped) = authority.strip_prefix('[') {
        // `[::1]` or `[::1]:8080`.
        match stripped.split_once("]:") {
            Some((host, port)) => (format!("[{host}]"), Some(port.to_owned())),
            None => (authority.to_ascii_lowercase(), None),
        }
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        // A second colon means an unbracketed IPv6 literal, which has no port.
        if host.contains(':') {
            (authority.to_ascii_lowercase(), None)
        } else {
            (host.to_ascii_lowercase(), Some(port.to_owned()))
        }
    } else {
        (authority.to_ascii_lowercase(), None)
    }
}

/// The default port for a scheme, when the authority names none.
fn default_port(scheme: &str) -> Option<&str> {
    match scheme {
        "http" | "ws" => Some("80"),
        "https" | "wss" => Some("443"),
        _ => None,
    }
}

/// Whether this `Host` may reach a loopback listener (`F-14`).
///
/// DNS rebinding points attacker names at 127.0.0.1; the `Host` header is
/// what distinguishes the attacker's name from the loopback names. Only the
/// loopback names (plus configured extras, with or without ports) pass —
/// everything else is refused on every route, not only `WebSockets`.
///
/// Matching is exact on the lowercased host with an optional `:port`, never
/// a substring: `127.0.0.1.evil.example` is not `127.0.0.1`.
///
/// ```
/// use qqq_serve::ws::loopback_host_allowed;
///
/// assert!(loopback_host_allowed("localhost:3000", &[]));
/// assert!(loopback_host_allowed("[::1]", &[]));
/// assert!(!loopback_host_allowed("evil.example", &[]));
/// assert!(!loopback_host_allowed("127.0.0.1.evil.example", &[]));
/// ```
#[must_use]
pub fn loopback_host_allowed(host: &str, extra: &[String]) -> bool {
    const LOOPBACK: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];
    let name = host_name(host.trim());
    LOOPBACK.contains(&name.as_str()) || extra.iter().any(|e| name == host_name(e.trim()))
}

/// The bare lowercased host without any `:port`.
///
/// Both halves — the request's `Host` and each configured extra — meet
/// stripped, so `devbox.local:8080` matches an extra written with or without
/// its port. A non-numeric or empty port is not a port at all: the whole
/// value compares, and fails closed.
fn host_name(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    // Brackets first: `[::1]:8080` splits on the wrong colon with a naive
    // `rsplit`.
    if let Some(stripped) = lower.strip_prefix('[') {
        match stripped.split_once("]:") {
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                return format!("[{h}]");
            }
            _ => return lower,
        }
    }
    lower
        .rsplit_once(':')
        .filter(|(h, p)| !h.contains(':') && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        .map_or_else(|| lower.clone(), |(h, _)| h.to_owned())
}

/// The per-connection WebSocket buffer limits (`F-14`).
///
/// Three numbers because three different multiplications threaten the heap:
/// one frame (`max_frame_bytes`), one reassembled message
/// (`max_message_bytes`), and all connections' buffered bytes together
/// (`max_total_buffer_bytes`, enforced by a process-wide semaphore). All
/// three default small (1 MiB / 1 MiB / 64 MiB) and rise only to their
/// absolute ceilings — the values the crate enforced before `F-14` — so
/// raising a cap is a conscious choice against a named number.
///
/// ```
/// use qqq_serve::ws::WsLimits;
///
/// let limits = WsLimits::default();
/// assert_eq!(limits.max_frame_bytes, 1024 * 1024);
/// assert_eq!(limits.max_message_bytes, 1024 * 1024);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsLimits {
    /// The largest single frame buffered, in bytes.
    pub max_frame_bytes: u64,
    /// The largest reassembled message, in bytes.
    pub max_message_bytes: usize,
    /// The process-wide buffered-bytes budget, in bytes.
    pub max_total_buffer_bytes: u64,
}

/// The absolute ceiling for one frame: the pre-`F-14` default.
///
/// ```
/// use qqq_serve::ws::{FRAME_LIMIT_CEILING, WsLimits};
///
/// assert!(WsLimits::default().max_frame_bytes <= FRAME_LIMIT_CEILING);
/// ```
pub const FRAME_LIMIT_CEILING: u64 = crate::ws_frame::FRAME_BYTES_CEILING;
/// The absolute ceiling for one message: the pre-`F-14` default.
///
/// ```
/// use qqq_serve::ws::{MESSAGE_LIMIT_CEILING, WsLimits};
///
/// assert!(WsLimits::default().max_message_bytes <= MESSAGE_LIMIT_CEILING);
/// ```
pub const MESSAGE_LIMIT_CEILING: usize = crate::ws_message::MESSAGE_BYTES_CEILING;
/// The absolute ceiling for the process-wide buffer budget.
///
/// ```
/// use qqq_serve::ws::{TOTAL_BUFFER_CEILING, WsLimits};
///
/// assert!(WsLimits::default().max_total_buffer_bytes <= TOTAL_BUFFER_CEILING);
/// ```
pub const TOTAL_BUFFER_CEILING: u64 = 1024 * 1024 * 1024;

impl Default for WsLimits {
    /// 1 MiB frames, 1 MiB messages, 64 MiB process-wide.
    fn default() -> Self {
        Self {
            max_frame_bytes: crate::ws_frame::MAX_FRAME_BYTES,
            max_message_bytes: crate::ws_message::MAX_MESSAGE_BYTES,
            max_total_buffer_bytes: 64 * 1024 * 1024,
        }
    }
}
impl WsLimits {
    /// Build explicit limits.
    ///
    /// # Panics
    ///
    /// If any cap exceeds its absolute ceiling — see the `*_CEILING`
    /// constants. A cap past the value the crate previously enforced must
    /// fail at startup where someone is watching, not under load. Like
    /// [`crate::limits::TenantLimits::new`], construction is the choke point.
    ///
    /// ```
    /// use qqq_serve::ws::WsLimits;
    ///
    /// let limits = WsLimits::new(65536, 65536, 1048576);
    /// assert_eq!(limits.max_frame_bytes, 65536);
    /// ```
    #[must_use]
    pub fn new(
        max_frame_bytes: u64,
        max_message_bytes: usize,
        max_total_buffer_bytes: u64,
    ) -> Self {
        assert!(
            max_frame_bytes <= FRAME_LIMIT_CEILING,
            "max_frame_bytes {max_frame_bytes} exceeds the absolute ceiling {FRAME_LIMIT_CEILING}"
        );
        assert!(
            max_message_bytes <= MESSAGE_LIMIT_CEILING,
            "max_message_bytes {max_message_bytes} exceeds the absolute ceiling {MESSAGE_LIMIT_CEILING}"
        );
        assert!(
            max_total_buffer_bytes <= TOTAL_BUFFER_CEILING,
            "max_total_buffer_bytes {max_total_buffer_bytes} exceeds the absolute ceiling {TOTAL_BUFFER_CEILING}"
        );
        Self {
            max_frame_bytes,
            max_message_bytes,
            max_total_buffer_bytes,
        }
    }
}

/// One place for the whole WebSocket policy: origins, hosts, and buffer caps.
///
/// A single struct so the three cannot be configured in disagreement — the
/// origin allow-list, the loopback host names, and the caps travel together
/// from the manifest to the connection.
///
/// ```
/// use qqq_serve::ws::WsConfig;
///
/// let config = WsConfig::default();
/// assert!(config.extra_hosts.is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsConfig {
    /// Who may upgrade besides the request's own origin.
    pub origins: WsOriginPolicy,
    /// Extra names the loopback `Host` allow-list admits.
    pub extra_hosts: Vec<String>,
    /// The buffer caps.
    pub limits: WsLimits,
}

impl Default for WsConfig {
    /// Same-origin only, loopback names only, 1 MiB caps.
    fn default() -> Self {
        Self {
            origins: WsOriginPolicy::default(),
            extra_hosts: Vec::new(),
            limits: WsLimits::default(),
        }
    }
}

/// Validate a `Sec-WebSocket-Key`.///
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

    // -- origin policy (F-14) ------------------------------------------------

    /// **A cross-origin upgrade is refused: the browser attaches ambient credentials.**
    ///
    /// `F-14`: browsers do not apply the same-origin policy to `WebSockets`, so
    /// any page can open a socket to the server with the user's cookies. The
    /// server must check `Origin` itself, before the upgrade.
    #[test]
    fn f14_cross_origin_upgrade_is_refused() {
        let policy = WsOriginPolicy::default();
        assert!(
            !upgrade_origin_allowed(&policy, Some("https://evil.example"), "127.0.0.1:8080"),
            "a foreign origin must not upgrade"
        );
    }

    /// **Same-origin upgrades pass, compared normalised — never by substring.**
    ///
    /// `Origin` is `scheme://host[:port]`, matched against the request's
    /// `Host` after lowercasing and eliding default ports. Substring matching
    /// would accept `evil-127.0.0.1` for `127.0.0.1`.
    #[test]
    fn f14_same_origin_upgrade_is_allowed() {
        let policy = WsOriginPolicy::default();
        assert!(
            upgrade_origin_allowed(&policy, Some("http://127.0.0.1:8080"), "127.0.0.1:8080"),
            "the same origin upgrades"
        );
        assert!(
            upgrade_origin_allowed(&policy, Some("HTTP://127.0.0.1:8080"), "127.0.0.1:8080"),
            "the scheme and host compare case-insensitively"
        );
        assert!(
            upgrade_origin_allowed(&policy, Some("http://127.0.0.1:80"), "127.0.0.1"),
            "default ports elide on both sides"
        );
        assert!(
            !upgrade_origin_allowed(&policy, Some("http://127.0.0.1:8080"), "127.0.0.1:9090"),
            "a different port is a different origin"
        );
        assert!(
            !upgrade_origin_allowed(
                &policy,
                Some("http://evil-127.0.0.1:8080"),
                "127.0.0.1:8080"
            ),
            "no substring matching, ever"
        );
    }

    /// **No `Origin` means a non-browser client, which is allowed.**
    ///
    /// Native clients (and the test harness) send no `Origin`. Refusing them
    /// would break every non-browser WebSocket user to stop a browser-only
    /// attack.
    #[test]
    fn f14_missing_origin_is_allowed_for_non_browser_clients() {
        let policy = WsOriginPolicy::default();
        assert!(
            upgrade_origin_allowed(&policy, None, "127.0.0.1:8080"),
            "an absent Origin is a non-browser client"
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
