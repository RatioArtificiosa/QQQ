// SPDX-License-Identifier: Apache-2.0

//! HTTP/1.1 response writing, with the trap-to-status mapping.
//!
//! Implements the response half of `SRV-001` and the status policy of Proposal
//! §9.3 (*"Guest exceeds fuel | Trap `QQQ-3002`; response is 503 with a
//! `Retry-After` … Pool exhausted | Backpressure, not unbounded queueing: sheds
//! load with 503 + `Retry-After`"*).
//!
//! # The mapping this module owns
//!
//! A guest trap is not just an error to log — it has to become a *response*,
//! and the status determines what the client does next. Getting it wrong is
//! observable:
//!
//! | What happened | Status | Why that status |
//! |---|---|---|
//! | route not found | 404 | nothing is listening there |
//! | path matched, method did not | 405 + `Allow` | the resource exists; say what it accepts |
//! | guest trapped on a bug | 500 | our guest is broken and the client can do nothing |
//! | fuel exhausted | 503 + `Retry-After` | **only when the manifest opted in** |
//! | epoch deadline exceeded | 504 | a timeout, never a crash (§9.3) |
//! | pool exhausted | 503 + `Retry-After` | load shedding, not a failure |
//! | capability denied | 500 | a deployment misconfiguration; retrying cannot help |
//!
//! Two of those rows carry an opinion worth stating:
//!
//! **Fuel exhaustion is 503 only when the manifest opted into soft limits.**
//! Otherwise it is 500. A hard fuel limit is a *bug detector* — the guest ran
//! longer than any real request should, which means infinite-loop protection
//! fired. Telling the client to retry would be advice to hit the same wall.
//! With `soft_fuel = true` the caller has declared the limit to be a capacity
//! bound, and 503 + `Retry-After` is then the honest answer.
//!
//! **Epoch deadline exceeded is 504, never 500.** §9.3 says it is "counted as a
//! timeout, never as a crash". A 500 tells a client its request was
//! malformed-by-us; 504 tells it the request was fine and we were too slow,
//! which is what happened and what a retry can fix.
//!
//! **Capability denied is 500, not 403.** A 403 says "you may not", implying
//! the client could authenticate differently. Nothing the client sends can
//! change it — the manifest does not grant the capability. 500 is the honest
//! code, and the remediation is in the log rather than in the response.

use std::fmt::Write as _;

use qqq_core::{Error, ErrorCode};

use crate::http1::Version;
use crate::route::Method;

// ---------------------------------------------------------------------------
// Reason phrases
// ---------------------------------------------------------------------------

/// The reason phrase for a status code.
///
/// # Why this is a table and not a `match` on every code
///
/// Only the codes QQQ emits are listed, and anything else gets a generic
/// phrase. RFC 9110 §15 makes the reason phrase **obsolete** — clients must
/// ignore it — so a complete table would be ~60 lines of text no client reads.
/// The codes here are the ones a human will see in `curl` output during
/// debugging, which is the only audience the phrase has.
#[must_use]
pub const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        // Unlisted codes still get a phrase, because an empty one produces
        // `HTTP/1.1 299 ` which some clients mis-parse.
        _ => "Unknown",
    }
}

/// Whether a status forbids a response body.
///
/// 204 and 304 must not carry one (RFC 9110 §15.3.5, §15.4.5), and neither may
/// any 1xx. Emitting a body anyway is a framing error: a client that reads it
/// will desynchronise, and the bytes become the next response's status line.
#[must_use]
pub const fn forbids_body(status: u16) -> bool {
    // An explicit comparison rather than `(100..200).contains(&status)`, which
    // is not const-stable.
    status == 204 || status == 304 || (status >= 100 && status < 200)
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// A response to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The headers, in the order to emit them.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// A response with a status and no body.
    #[must_use]
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A `text/plain` response.
    #[must_use]
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        let body = body.into().into_bytes();
        let mut r = Self {
            status,
            headers: Vec::new(),
            body,
        };
        r.set_header("Content-Type", "text/plain; charset=utf-8");
        r
    }

    /// Add or replace a header.
    pub fn set_header(&mut self, name: &str, value: &str) {
        if let Some(existing) = self
            .headers
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
        {
            value.clone_into(&mut existing.1);
        } else {
            self.headers.push((name.to_owned(), value.to_owned()));
        }
    }

    /// The value of a header, case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Write a response into a buffer.
///
/// # Why the body is attached here rather than streamed
///
/// Because `SRV-004` (streaming with backpressure) is not built. This function
/// writes a complete response, so the framing is correct — `Content-Length` is
/// always known and `Connection` is always explicit — and a caller cannot
/// accidentally emit a half-written chunked response. When streaming lands it
/// will be a *different* function, not a flag on this one, because the failure
/// modes are different.
///
/// # The three framing decisions
///
/// 1. **`Content-Length` is always emitted.** Even for an empty body, because a
///    response with neither `Content-Length` nor `Transfer-Encoding` leaves the
///    client guessing where it ends — and the only correct guess is "the
///    connection closed", which defeats keep-alive.
/// 2. **`Connection: close` is emitted when the request asked for it.** Without
///    it a client cannot tell whether the connection will persist, and will
///    either hang or reconnect needlessly.
/// 3. **A body is suppressed for statuses that forbid one.** See
///    [`forbids_body`]: emitting one desynchronises the stream.
#[must_use]
pub fn write_response(resp: &Response, version: Version, keep_alive: bool) -> Vec<u8> {
    // The body is measured, not the declared header, so a caller cannot
    // desynchronise the stream by setting a `Content-Length` that disagrees
    // with what it passes in.
    let mut body = &resp.body[..];
    if forbids_body(resp.status) {
        body = &[];
    }

    let mut out = String::with_capacity(128 + resp.headers.len() * 32 + body.len());
    // `write!` into a String cannot fail, so the result is intentionally
    // ignored rather than unwrapped — the alternative is a panic path for an
    // operation that has none.
    let _ = write!(
        out,
        "{} {} {}\r\n",
        version.as_str(),
        resp.status,
        reason_phrase(resp.status)
    );

    // Caller-supplied headers first, skipping the two this function owns so
    // they cannot be duplicated or contradicted.
    for (name, value) in &resp.headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        let _ = write!(out, "{name}: {value}\r\n");
    }

    let _ = write!(out, "Content-Length: {}\r\n", body.len());
    // HTTP/1.0 defaults to close, so an explicit `keep-alive` is required to
    // persist; HTTP/1.1 defaults to keep-alive, so only `close` needs sending.
    // Emitting the token unconditionally would be harmless but noisy, and
    // emitting the wrong one is a real bug.
    match (keep_alive, version) {
        (false, _) => out.push_str("Connection: close\r\n"),
        (true, Version::Http10) => out.push_str("Connection: keep-alive\r\n"),
        (true, Version::Http11) => {}
    }
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// The head of a response whose body is written afterwards, in pieces.
///
/// # Why this exists, and why it is not a flag on [`write_response`]
///
/// SSE (`SRV-010`) cannot be served by [`write_response`]. That function emits
/// `Content-Length`, which requires knowing the body's length — and an event stream's
/// body ends when the *client* disconnects, so its length is unknowable by
/// construction. §6.4's body rule makes the same point from the other direction:
///
/// > There is no point at which a request body is fully buffered unless the manifest
/// > asked for it.
///
/// `write_response`'s own documentation says the streaming form "will be a *different*
/// function, not a flag on this one, because the failure modes are different." This is
/// that function, and the reasoning holds: the two differ in framing
/// (`chunked` versus `Content-Length`), in what can go wrong (*a partial write leaves
/// the stream desynchronised* versus *the buffer was built wrong*), and in when the
/// caller finds out. A flag would mean every caller reads both paths to understand
/// either.
///
/// # What it emits
///
/// For HTTP/1.1: `Transfer-Encoding: chunked` and no `Content-Length`. Each piece the
/// caller writes afterwards must be framed as a chunk by [`write_chunk`].
///
/// For HTTP/1.0: **`Connection: close`, and no `Transfer-Encoding`.** HTTP/1.0 has no
/// chunked encoding, so the only way to delimit a body of unknown length is to close
/// the connection — the client reads until EOF. Emitting `chunked` to an HTTP/1.0
/// client would be framed as data by a client that does not understand it, which is
/// the request-smuggling shape this project has already had to defend against.
///
/// # The caller's obligations
///
/// The returned head must be written and flushed **before** the first chunk, or the
/// client sees a connected socket producing nothing and cannot tell that from a slow
/// server. `flush` is the caller's job because only the caller knows whether it has
/// more to write.
#[must_use]
pub fn write_stream_head(resp: &Response, version: Version, keep_alive: bool) -> Vec<u8> {
    let mut out = String::with_capacity(128 + resp.headers.len() * 32);
    let _ = write!(
        out,
        "{} {} {}\r\n",
        version.as_str(),
        resp.status,
        reason_phrase(resp.status)
    );

    // The same three headers `write_response` owns are skipped here, for the same
    // reason: a caller must not be able to contradict the framing. `Content-Length` is
    // additionally impossible to honour, and a caller that set one would produce a
    // response whose declared length disagrees with what follows.
    for (name, value) in &resp.headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        let _ = write!(out, "{name}: {value}\r\n");
    }

    match version {
        Version::Http11 => {
            // A 204/304 has no body by definition, so framing it as chunked would
            // promise chunks that must never arrive — see `forbids_body`.
            if forbids_body(resp.status) {
                out.push_str("Content-Length: 0\r\n");
            } else {
                out.push_str("Transfer-Encoding: chunked\r\n");
            }
        }
        Version::Http10 => {
            // No chunked encoding exists in HTTP/1.0, so EOF must delimit the body.
            out.push_str("Content-Length: 0\r\n");
        }
    }

    // Two different reasons, one outcome:
    //
    // - **HTTP/1.0 always closes**: a streaming body of unknown length cannot be
    //   delimited any other way, so the client learns where it ended at EOF.
    // - **A caller that asked for close gets it**, whatever the version.
    //
    // Testing the disjunction is what keeps both reasons visible without writing the
    // same arm twice — which is the form clippy rejects, correctly, because two
    // identical arms are indistinguishable from a copy-paste error.
    let must_close = !keep_alive || version == Version::Http10;
    if must_close {
        out.push_str("Connection: close\r\n");
    }
    // HTTP/1.1 with keep-alive needs no header: 1.1 defaults to persistent, so the
    // absence is the signal. Emitting `keep-alive` unconditionally would be harmless
    // and noisy, which is why `write_response` does not either.
    out.push_str("\r\n");
    out.into_bytes()
}

/// Frame one piece of a chunked-body response.
///
/// `piece` must already be a complete chunk up to [`CHUNK_MAX`] bytes; a longer one is
/// still framed correctly (the length prefix is computed, not assumed), so the only
/// consequence of passing something large is that the caller has chosen to buffer it.
///
/// An empty piece returns an **empty** vector rather than a zero-length chunk, because
/// a zero-length chunk *terminates* the body. Returning `0\r\n\r\n` for an empty write
/// would end the response at whatever point the caller happened to have nothing to
/// send — turning a momentary lull in an event stream into a closed response, which
/// the client reports as "the server stopped sending" with no error anywhere.
#[must_use]
pub fn write_chunk(piece: &[u8]) -> Vec<u8> {
    if piece.is_empty() {
        return Vec::new();
    }
    let mut out = format!("{:x}\r\n", piece.len()).into_bytes();
    out.extend_from_slice(piece);
    out.extend_from_slice(b"\r\n");
    out
}

/// The terminating chunk of a chunked body: zero length, then the trailer section.
#[must_use]
pub fn write_last_chunk() -> Vec<u8> {
    b"0\r\n\r\n".to_vec()
}

/// The largest piece [`write_chunk`] will frame in one chunk.
///
/// Not a limit the function enforces — it frames whatever it is given — but the size a
/// caller should target. A chunk that is too large costs memory proportional to the
/// piece (the framing copy); one that is too small spends more bytes on length
/// prefixes and more syscalls. 64 KiB is the size this project's socket buffer is
/// sized against, so a piece of this size is written in one system call on the
/// platforms it targets.
pub const CHUNK_MAX: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Trap and error mapping
// ---------------------------------------------------------------------------

/// How the host should answer when something went wrong.
///
/// Returned as a value rather than written directly, so the decision is
/// testable without a socket and so an access log can record the *reason*
/// alongside the status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorResponse {
    /// The status to send.
    pub status: u16,
    /// The body, which never contains internal detail.
    pub body: String,
    /// `Retry-After`, when the client should try again.
    pub retry_after: Option<String>,
    /// Whether to close the connection.
    pub close: bool,
    /// The error code, for the access log rather than the response.
    ///
    /// **Not sent to the client.** A `QQQ-` code identifies an internal
    /// condition, and disclosing it tells an attacker which subsystem failed.
    /// The log has it; the response does not.
    pub log_code: Option<String>,
}

/// Map a host error to an HTTP response.
///
/// # The opt-in that changes one row
///
/// `soft_fuel` is taken as a parameter because fuel exhaustion maps to 503 only
/// when the manifest declared the limit to be a capacity bound. Otherwise it is
/// a bug detector firing, and 500 is the honest answer — telling a client to
/// retry would send it back into the same wall.
#[must_use]
pub fn error_response(error: &Error, soft_fuel: bool) -> ErrorResponse {
    let code = error.code;
    let class = classify(code, soft_fuel);

    ErrorResponse {
        status: class.status(),
        // A deliberately generic body. The status already tells the client what
        // it needs; the detail is in the log, keyed by the same code.
        body: format!("{}\n", reason_phrase(class.status())),
        retry_after: class
            .should_retry()
            .then(|| retry_after_value(class.status(), Some(error))),
        close: class.must_close(),
        log_code: Some(code.id()),
    }
}

/// Map a **protocol-level** client error to an HTTP response.
///
/// # Why this is not [`error_response`]
///
/// The two answer different questions, and conflating them was a real defect
/// caught by the socket test in `tests/socket.rs`.
///
/// `error_response` maps a [`qqq_core::ErrorCode`] — a condition *inside QQQ*
/// with a stable `QQQ-XXXX` identifier. A malformed request line is not that:
/// the client sent bytes HTTP cannot parse, nothing inside QQQ failed, and no
/// `ErrorCode` describes it truthfully. Routing it through the error taxonomy
/// meant inventing a code, and `ParseError::to_error` invented
/// `ManifestSchemaViolation` — so a garbage request line produced
/// **`500 Internal Server Error`** with a log code pointing an operator at the
/// manifest.
///
/// This function therefore builds the response from the class directly. It
/// carries no `log_code`, because there is no QQQ fault to key the log on, and
/// the detail string is deliberately **not** echoed into the body: a malformed
/// request is attacker-controlled input, and reflecting it is how a response
/// becomes a vector rather than an answer.
///
/// `detail` is accepted for the caller's log line and is not sent.
#[must_use]
pub fn parse_error_response(detail: &str) -> ErrorResponse {
    let class = Failure::BadRequest;
    let _ = detail;
    ErrorResponse {
        status: class.status(),
        body: format!("{}\n", reason_phrase(class.status())),
        retry_after: None,
        close: class.must_close(),
        log_code: None,
    }
}

/// What a failure means for the client, which is what determines the status.
///
/// # Why this is an enum and not a `(status, retry, close)` tuple
///
/// The first version returned tuples from a `match`, and three different code
/// groups produced the same `(500, false, false)`. Clippy flagged the arms as
/// duplicates, and it was right for a reason that matters more than the lint:
/// **a reader could not tell the groups apart either.** Writing the same tuple
/// three times states "these are the same" without saying why, and the *why* is
/// the entire policy.
///
/// Naming the classes makes the policy the thing under test. The tests then
/// assert `classify(code) == Failure::GuestFault` rather than
/// `error_response(&err).status == 500`, which is a claim about the reason
/// instead of about a number that several reasons share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The **client** sent something HTTP cannot parse.
    ///
    /// Added after an integration test against a real socket showed a malformed
    /// request line producing `500 Internal Server Error`. The taxonomy had no
    /// client-error class at all, so every parse failure became a server fault —
    /// which sends an operator hunting for a bug in QQQ when the peer sent
    /// garbage.
    ///
    /// This is also the one class where the server's own logs should **not** be
    /// alarmed: a 400 is a normal event on a public listener, and treating it as
    /// a fault is how a log fills with noise that hides the real 500s.
    BadRequest,
    /// The guest malfunctioned. The client's request was fine.
    GuestFault,
    /// The deployment is misconfigured — most often a capability the manifest
    /// does not grant.
    Misconfiguration,
    /// A hard limit fired. This is a bug detector, not capacity.
    HardLimit,
    /// The guest ran longer than its budget: a timeout, not a crash.
    Timeout,
    /// The host is at capacity and is shedding load. A retry can succeed.
    OverCapacity,
    /// The listener itself is broken, so the connection cannot be trusted.
    ListenerFault,
}

impl Failure {
    /// The HTTP status for this class.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            // The only 4xx class, and the only one whose fix is on the client.
            Self::BadRequest => 400,
            Self::GuestFault | Self::Misconfiguration | Self::HardLimit | Self::ListenerFault => {
                500
            }
            // §9.3: counted as a timeout, never as a crash.
            Self::Timeout => 504,
            Self::OverCapacity => 503,
        }
    }

    /// Whether this class indicates a fault in the **server**.
    ///
    /// `BadRequest` is `false`, which is the reason the variant exists: access
    /// logs and alerting key on this, and a listener that pages an operator for
    /// every malformed request is one whose alerts get ignored.
    #[must_use]
    pub const fn is_server_fault(self) -> bool {
        !matches!(self, Self::BadRequest)
    }

    /// Whether the client should be told to try again.
    ///
    /// Only one class says yes. Telling a client to retry a guest bug or a
    /// misconfiguration sends it back into the same wall, and a retry loop
    /// against a deterministic failure is how a small problem becomes an
    /// outage.
    #[must_use]
    pub const fn should_retry(self) -> bool {
        matches!(self, Self::OverCapacity)
    }

    /// Whether the connection must be closed.
    ///
    /// Load shedding closes so the shed is visible immediately rather than
    /// after the client times out. A listener fault closes because the
    /// connection's framing is not trustworthy. Everything else is a
    /// request-scoped failure where the connection is still usable.
    #[must_use]
    pub const fn must_close(self) -> bool {
        matches!(self, Self::OverCapacity | Self::ListenerFault)
    }

    /// The stable name, for the access log.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad-request",
            Self::GuestFault => "guest-fault",
            Self::Misconfiguration => "misconfiguration",
            Self::HardLimit => "hard-limit",
            Self::Timeout => "timeout",
            Self::OverCapacity => "over-capacity",
            Self::ListenerFault => "listener-fault",
        }
    }
}

/// Classify an error code.
///
/// `soft_fuel` is the one configuration-dependent input: it changes whether
/// fuel exhaustion is a capacity bound or a bug detector.
#[must_use]
pub fn classify(code: ErrorCode, soft_fuel: bool) -> Failure {
    match code {
        // -- the deployment is misconfigured -------------------------------
        //
        // **Not 403.** A 403 says "you may not", implying a different
        // credential would help. Here the manifest does not grant the
        // capability, so the fix is in `qqq.toml` and no client can influence
        // it. The artifact codes join this class for the same reason: the
        // component that was deployed is wrong, and a client cannot redeploy
        // it.
        ErrorCode::CapabilityDenied
        | ErrorCode::CapabilityOutOfScope
        | ErrorCode::CapabilityWideningRefused
        | ErrorCode::SecretUseFailed
        | ErrorCode::InvalidComponentArtifact
        | ErrorCode::ComponentLoadFailed
        | ErrorCode::WitInterfaceMismatch => Failure::Misconfiguration,

        // -- hard limits ---------------------------------------------------
        //
        // A memory limit is a hard bound the guest exceeded: a defect, not
        // capacity, so not a 503.
        ErrorCode::MemoryLimitExceeded => Failure::HardLimit,

        // -- fuel, the one opt-in ------------------------------------------
        //
        // A hard fuel limit is a bug detector firing — the guest ran longer
        // than any real request should, so infinite-loop protection caught it,
        // and a retry hits the same wall. With `soft_fuel` the caller has
        // declared the limit to be a capacity bound, and 503 is then honest.
        ErrorCode::FuelExhausted => {
            if soft_fuel {
                Failure::OverCapacity
            } else {
                Failure::HardLimit
            }
        }

        // -- timeouts ------------------------------------------------------
        ErrorCode::EpochDeadlineExceeded => Failure::Timeout,

        // -- capacity ------------------------------------------------------
        ErrorCode::InstancePoolExhausted | ErrorCode::HostResourceExhausted => {
            Failure::OverCapacity
        }

        // -- the listener itself -------------------------------------------
        ErrorCode::ListenerBindFailed => Failure::ListenerFault,

        // -- everything else -------------------------------------------------
        //
        // The remaining codes are build-time and host-internal conditions —
        // `ManifestSyntaxInvalid`, `RegistryUnreachable`, `McpArgumentInvalid`
        // and the like. None of them belongs on a request path, so reaching one
        // means something is wrong with QQQ rather than with the request, and
        // `GuestFault` is the honest class: 500, no retry, connection intact.
        //
        // Spelled as a catch-all rather than an exhaustive list on purpose. A
        // new error code added later should default to "500, our fault" without
        // anyone having to remember to update this function — the failure mode
        // of forgetting should be a correct answer, not a compile error that
        // tempts someone to guess.
        _ => Failure::GuestFault,
    }
}

/// The `Retry-After` value to send.
///
/// # Why this now prefers the host's own estimate
///
/// It used to be a hardcoded `"1"`, with a comment explaining that QQQ had no
/// predictive model of when capacity returns. That was true when it was written
/// and is no longer: `HOST-012` now computes an estimate from the pool's
/// capacity and the throughput the caller has observed
/// ([`qqq_host::Pool::retry_after_seconds`]), and a saturated pool carrying that
/// estimate in its error context means the server can send a *real* number
/// instead of a placeholder.
///
/// The fallback keeps the old reasoning, because it is still correct when there
/// is no estimate to use: a fabricated value is worse than a conservative one,
/// since clients back off *to* whatever is advertised.
///
/// `error` is consulted for a `retry-after` context entry, which is the field
/// the host uses for exactly this purpose — the mapping is by *name*, so any
/// error that carries the estimate is honoured without this function needing to
/// know which subsystem produced it.
///
/// It takes the status so the signature can carry a policy later without a
/// breaking change — a 429 from a rate limiter may well want a different value
/// than a 503 from a pool.
#[must_use]
pub fn retry_after_value(status: u16, error: Option<&Error>) -> String {
    let _ = status;
    if let Some(seconds) = error
        .and_then(|e| e.context.iter().find(|(k, _)| k == "retry-after"))
        .map(|(_, v)| v.as_str())
    {
        // The value must be a bare integer per RFC 9110 §10.2.3 — either a
        // delay in seconds or an HTTP-date. Anything else is dropped in favour
        // of the conservative default rather than forwarded, because a malformed
        // `Retry-After` is ignored by clients and would silently become "retry
        // whenever", which is the stampede the header prevents.
        if !seconds.is_empty() && seconds.bytes().all(|b| b.is_ascii_digit()) {
            return seconds.to_owned();
        }
    }
    "1".to_owned()
}

/// Build the response for a request that matched no route.
#[must_use]
pub fn not_found() -> Response {
    Response::text(404, "not found\n")
}

/// Build the response for a path that exists under other methods.
///
/// The `Allow` header is required by RFC 9110 §15.5.6, and it is the part that
/// makes a 405 useful: without it the client knows its method was wrong but not
/// which one to use.
#[must_use]
pub fn method_not_allowed(allowed: &[Method]) -> Response {
    let mut r = Response::text(405, "method not allowed\n");
    let list: Vec<&str> = allowed.iter().map(|m| m.as_str()).collect();
    r.set_header("Allow", &list.join(", "));
    r
}

/// Build a response from an [`ErrorResponse`].
#[must_use]
pub fn from_error(err: &ErrorResponse) -> Response {
    let mut r = Response::text(err.status, err.body.clone());
    if let Some(retry) = &err.retry_after {
        r.set_header("Retry-After", retry);
    }
    r
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_response(bytes: &[u8]) -> (String, Vec<(String, String)>, Vec<u8>) {
        let text = String::from_utf8_lossy(bytes);
        let (head, body) = text
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("no header terminator in {}", text.escape_debug()));
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or("").to_owned();
        let headers = lines
            .map(|l| {
                let (k, v) = l.split_once(':').expect("header must have a colon");
                (k.trim().to_owned(), v.trim().to_owned())
            })
            .collect();
        (status_line, headers, body.as_bytes().to_vec())
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    // -- status line and framing -------------------------------------------

    #[test]
    fn a_basic_response_has_the_right_status_line() {
        let r = Response::text(200, "hello\n");
        let bytes = write_response(&r, Version::Http11, true);
        let (status, headers, body) = parse_response(&bytes);
        assert_eq!(status, "HTTP/1.1 200 OK");
        assert_eq!(header(&headers, "Content-Length"), Some("6"));
        assert_eq!(body, b"hello\n");
    }

    /// **The framing rule.** A response with neither `Content-Length` nor
    /// `Transfer-Encoding` leaves the client guessing where it ends, and the
    /// only correct guess is "the connection closed" — which defeats keep-alive.
    #[test]
    fn content_length_is_always_present_even_when_empty() {
        let r = Response::status(204);
        let bytes = write_response(&r, Version::Http11, true);
        let (_, headers, _) = parse_response(&bytes);
        assert_eq!(
            header(&headers, "Content-Length"),
            Some("0"),
            "an empty body still needs a length"
        );
    }

    /// The measured length wins over a caller-supplied one, so a caller cannot
    /// desynchronise the stream by setting a header that disagrees with the
    /// body it passes in.
    #[test]
    fn a_caller_supplied_content_length_cannot_contradict_the_body() {
        let mut r = Response::text(200, "abc");
        r.set_header("Content-Length", "9999");
        let bytes = write_response(&r, Version::Http11, true);
        let (_, headers, body) = parse_response(&bytes);
        assert_eq!(header(&headers, "Content-Length"), Some("3"));
        assert_eq!(body, b"abc");
        // And only one such header exists.
        let count = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .count();
        assert_eq!(count, 1, "the header must not be duplicated");
    }

    /// A status that forbids a body must not carry one: a client reading it
    /// would desynchronise and treat the bytes as the next response's status
    /// line.
    #[test]
    fn a_status_that_forbids_a_body_gets_none() {
        for status in [204, 304, 100] {
            assert!(forbids_body(status), "{status} must forbid a body");
            let r = Response::text(status, "this must not appear");
            let bytes = write_response(&r, Version::Http11, true);
            let (_, headers, body) = parse_response(&bytes);
            assert!(body.is_empty(), "{status} emitted a body: {body:?}");
            assert_eq!(header(&headers, "Content-Length"), Some("0"));
        }
    }

    #[test]
    fn ordinary_statuses_permit_a_body() {
        for status in [200, 201, 400, 404, 500, 503] {
            assert!(!forbids_body(status));
        }
    }

    // -- connection management ---------------------------------------------

    /// **The asymmetry between versions.** HTTP/1.1 defaults to keep-alive, so
    /// only `close` needs sending. HTTP/1.0 defaults to close, so a persistent
    /// connection requires an explicit `keep-alive`.
    #[test]
    fn the_connection_header_follows_the_version() {
        let r = Response::text(200, "x");

        let (_, h11_keep, _) = parse_response(&write_response(&r, Version::Http11, true));
        assert_eq!(
            header(&h11_keep, "Connection"),
            None,
            "HTTP/1.1 keep-alive is the default and needs no header"
        );

        let (_, h11_close, _) = parse_response(&write_response(&r, Version::Http11, false));
        assert_eq!(header(&h11_close, "Connection"), Some("close"));

        let (_, h10_keep, _) = parse_response(&write_response(&r, Version::Http10, true));
        assert_eq!(
            header(&h10_keep, "Connection"),
            Some("keep-alive"),
            "HTTP/1.0 must say so explicitly"
        );

        let (_, h10_close, _) = parse_response(&write_response(&r, Version::Http10, false));
        assert_eq!(header(&h10_close, "Connection"), Some("close"));
    }

    #[test]
    fn a_caller_cannot_override_the_connection_header() {
        let mut r = Response::text(200, "x");
        r.set_header("Connection", "keep-alive");
        let bytes = write_response(&r, Version::Http11, false);
        let (_, headers, _) = parse_response(&bytes);
        assert_eq!(
            header(&headers, "Connection"),
            Some("close"),
            "the framing decision wins over a caller-supplied header"
        );
    }

    #[test]
    fn a_caller_cannot_smuggle_a_transfer_encoding() {
        let mut r = Response::text(200, "x");
        r.set_header("Transfer-Encoding", "chunked");
        let bytes = write_response(&r, Version::Http11, true);
        let (_, headers, _) = parse_response(&bytes);
        assert_eq!(
            header(&headers, "Transfer-Encoding"),
            None,
            "a body writer must not claim a framing it is not using"
        );
    }

    // -- headers -----------------------------------------------------------

    #[test]
    fn caller_headers_are_emitted_in_order() {
        let mut r = Response::status(200);
        r.set_header("X-First", "1");
        r.set_header("X-Second", "2");
        let bytes = write_response(&r, Version::Http11, true);
        let text = String::from_utf8_lossy(&bytes);
        let first = text.find("X-First").expect("present");
        let second = text.find("X-Second").expect("present");
        assert!(first < second, "header order must be preserved");
    }

    #[test]
    fn setting_a_header_twice_replaces_it() {
        let mut r = Response::status(200);
        r.set_header("X-V", "1");
        r.set_header("x-v", "2");
        assert_eq!(r.header("X-V"), Some("2"));
        let bytes = write_response(&r, Version::Http11, true);
        let (_, headers, _) = parse_response(&bytes);
        let count = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("x-v"))
            .count();
        assert_eq!(count, 1, "a replaced header must not be duplicated");
    }

    #[test]
    fn a_text_response_declares_its_content_type() {
        let r = Response::text(200, "x");
        assert_eq!(
            r.header("Content-Type"),
            Some("text/plain; charset=utf-8"),
            "without a charset a browser may guess an encoding"
        );
    }

    // -- the classification, by name ---------------------------------------
    //
    // These assert the *reason*, not the status number. Several classes share
    // 500, so a status assertion cannot distinguish "the guest is broken" from
    // "the manifest is wrong" — and telling those apart is exactly what a
    // reader of the policy needs.

    #[test]
    fn guest_faults_are_classified_as_such() {
        for code in [
            ErrorCode::GuestTrap,
            ErrorCode::GuestPanic,
            ErrorCode::GuestOutOfBounds,
        ] {
            assert_eq!(
                classify(code, false),
                Failure::GuestFault,
                "{code} is the guest malfunctioning"
            );
        }
        // A QQQ bug lands in the same class, because neither is the client's to
        // fix.
        assert_eq!(
            classify(ErrorCode::InternalInvariantViolated, false),
            Failure::GuestFault
        );
    }

    #[test]
    fn misconfigurations_are_classified_as_such() {
        for code in [
            ErrorCode::CapabilityDenied,
            ErrorCode::CapabilityOutOfScope,
            ErrorCode::CapabilityWideningRefused,
            ErrorCode::SecretUseFailed,
            ErrorCode::InvalidComponentArtifact,
            ErrorCode::ComponentLoadFailed,
            ErrorCode::WitInterfaceMismatch,
        ] {
            assert_eq!(
                classify(code, false),
                Failure::Misconfiguration,
                "{code} is a deployment problem, not a client one"
            );
        }
    }

    /// The one configuration-dependent row, asserted by name in both
    /// directions.
    #[test]
    fn fuel_is_the_only_configured_classification() {
        assert_eq!(
            classify(ErrorCode::FuelExhausted, false),
            Failure::HardLimit,
            "a hard fuel limit is a bug detector, not capacity"
        );
        assert_eq!(
            classify(ErrorCode::FuelExhausted, true),
            Failure::OverCapacity,
            "with soft limits declared, it is a capacity bound"
        );
    }

    /// **Only one class invites a retry.** A retry loop against a deterministic
    /// failure is how a small problem becomes an outage.
    #[test]
    fn only_over_capacity_says_retry() {
        for class in [
            Failure::GuestFault,
            Failure::Misconfiguration,
            Failure::HardLimit,
            Failure::Timeout,
            Failure::ListenerFault,
        ] {
            assert!(
                !class.should_retry(),
                "{} must not invite a retry",
                class.as_str()
            );
        }
        assert!(Failure::OverCapacity.should_retry());
    }

    /// Closing is reserved for the cases where the connection's state is not
    /// trustworthy or the shed must be immediate.
    #[test]
    fn only_capacity_and_listener_faults_close_the_connection() {
        assert!(Failure::OverCapacity.must_close());
        assert!(Failure::ListenerFault.must_close());
        for class in [
            Failure::GuestFault,
            Failure::Misconfiguration,
            Failure::HardLimit,
            Failure::Timeout,
        ] {
            assert!(
                !class.must_close(),
                "{} is request-scoped and leaves the connection usable",
                class.as_str()
            );
        }
    }

    #[test]
    fn failure_class_names_are_stable() {
        assert_eq!(Failure::GuestFault.as_str(), "guest-fault");
        assert_eq!(Failure::Misconfiguration.as_str(), "misconfiguration");
        assert_eq!(Failure::HardLimit.as_str(), "hard-limit");
        assert_eq!(Failure::Timeout.as_str(), "timeout");
        assert_eq!(Failure::OverCapacity.as_str(), "over-capacity");
        assert_eq!(Failure::ListenerFault.as_str(), "listener-fault");
    }

    /// Every class must produce a status that has a real reason phrase, or the
    /// rendered response contains "Unknown".
    #[test]
    fn every_failure_class_has_a_status_with_a_phrase() {
        for class in [
            Failure::GuestFault,
            Failure::Misconfiguration,
            Failure::HardLimit,
            Failure::Timeout,
            Failure::OverCapacity,
            Failure::ListenerFault,
        ] {
            let s = class.status();
            assert!((500..=599).contains(&s), "{} produced {s}", class.as_str());
            assert_ne!(reason_phrase(s), "Unknown");
        }
    }

    /// The classification must be total over the error catalogue: no code may
    /// reach a state with no answer.
    #[test]
    fn every_error_code_is_classified() {
        for code in ErrorCode::all() {
            let class = classify(*code, false);
            assert!(
                (500..=599).contains(&class.status()),
                "{code} classified as {} ({})",
                class.as_str(),
                class.status()
            );
        }
    }

    // -- the trap mapping --------------------------------------------------

    fn err(code: ErrorCode) -> Error {
        Error::new(code, "test")
    }

    /// A guest bug is the guest's problem and the client can do nothing.
    #[test]
    fn a_guest_trap_is_500() {
        for code in [
            ErrorCode::GuestTrap,
            ErrorCode::GuestPanic,
            ErrorCode::GuestOutOfBounds,
            ErrorCode::InternalInvariantViolated,
        ] {
            let r = error_response(&err(code), false);
            assert_eq!(r.status, 500, "{code} must be 500");
            assert!(r.retry_after.is_none(), "500 must not invite a retry");
            assert!(
                !r.close,
                "a guest bug does not desynchronise the connection"
            );
        }
    }

    /// **The opt-in row.** A hard fuel limit is a bug detector firing; telling
    /// the client to retry sends it back into the same wall. A soft limit is a
    /// capacity bound, and 503 is then honest.
    #[test]
    fn fuel_exhaustion_is_500_unless_soft_limits_are_enabled() {
        let hard = error_response(&err(ErrorCode::FuelExhausted), false);
        assert_eq!(hard.status, 500, "a hard fuel limit is a bug, not capacity");
        assert!(hard.retry_after.is_none());

        let soft = error_response(&err(ErrorCode::FuelExhausted), true);
        assert_eq!(soft.status, 503);
        assert!(soft.retry_after.is_some());
        assert!(soft.close, "shedding load must be visible immediately");
    }

    /// **§9.3: counted as a timeout, never as a crash.** A 500 would tell the
    /// client its request was bad; 504 says the request was fine and we were
    /// too slow, which is what happened and what a retry can fix.
    #[test]
    fn an_epoch_timeout_is_504_not_500() {
        let r = error_response(&err(ErrorCode::EpochDeadlineExceeded), false);
        assert_eq!(r.status, 504);
        assert!(
            r.retry_after.is_none(),
            "504 does not carry Retry-After by default"
        );
    }

    /// Pool exhaustion is load shedding, not failure: 503 plus `Retry-After`,
    /// and the connection closes so the shed is visible immediately.
    #[test]
    fn pool_exhaustion_sheds_load_with_503() {
        for code in [
            ErrorCode::InstancePoolExhausted,
            ErrorCode::HostResourceExhausted,
        ] {
            let r = error_response(&err(code), false);
            assert_eq!(r.status, 503, "{code} must shed load");
            assert!(
                r.retry_after.is_some(),
                "the client needs to know when to retry"
            );
            assert!(r.close);
        }
    }

    /// **500, not 403.** A 403 implies the client could be authorised
    /// differently; nothing it sends changes the outcome, because the manifest
    /// does not grant the capability. The fix is in `qqq.toml`.
    #[test]
    fn a_capability_denial_is_500_not_403() {
        for code in [
            ErrorCode::CapabilityDenied,
            ErrorCode::CapabilityOutOfScope,
            ErrorCode::CapabilityWideningRefused,
            ErrorCode::SecretUseFailed,
        ] {
            let r = error_response(&err(code), false);
            assert_eq!(
                r.status, 500,
                "{code} is a deployment misconfiguration, not a client error"
            );
        }
    }

    /// A memory limit is a hard bound the guest exceeded — a defect, not
    /// capacity.
    #[test]
    fn a_memory_limit_is_500_not_503() {
        let r = error_response(&err(ErrorCode::MemoryLimitExceeded), false);
        assert_eq!(r.status, 500);
        assert!(r.retry_after.is_none());
    }

    /// **The response body never contains internal detail.** A `QQQ-` code
    /// identifies an internal condition, and disclosing it tells an attacker
    /// which subsystem failed. The log has it; the response does not.
    #[test]
    fn the_response_body_never_leaks_an_error_code() {
        for code in ErrorCode::all() {
            let r = error_response(&err(*code), false);
            assert!(
                !r.body.contains("QQQ-"),
                "{code} leaked its code into the response body: {}",
                r.body
            );
            assert!(
                !r.body.contains(code.id().as_str()) || !code.id().starts_with("QQQ"),
                "{code} leaked into the body"
            );
            // The log code is still available for the access log.
            assert_eq!(r.log_code.as_deref(), Some(code.id().as_str()));
        }
    }

    /// The body is deliberately short: the status tells the client what it
    /// needs, and a verbose error page is an information leak with a nicer
    /// font.
    #[test]
    fn error_bodies_are_minimal() {
        for code in ErrorCode::all() {
            let r = error_response(&err(*code), false);
            assert!(
                r.body.len() < 64,
                "{code} produced a {} byte body, which is more than a status phrase",
                r.body.len()
            );
        }
    }

    /// Every error code must map to a real HTTP error status, so no code can
    /// accidentally produce a 2xx on failure.
    #[test]
    fn every_error_code_maps_to_an_error_status() {
        for code in ErrorCode::all() {
            let r = error_response(&err(*code), false);
            assert!(
                (400..=599).contains(&r.status),
                "{code} produced status {}",
                r.status
            );
        }
    }

    #[test]
    fn retry_after_is_a_whole_number_of_seconds() {
        for status in [503, 500] {
            let v = retry_after_value(status, None);
            assert!(
                v.parse::<u32>().is_ok(),
                "Retry-After `{v}` must be a number of seconds"
            );
        }
    }

    /// A host-supplied estimate is used verbatim when it is a valid value.
    #[test]
    fn retry_after_prefers_the_hosts_estimate() {
        let err = Error::new(
            ErrorCode::InstancePoolExhausted,
            "the instance pool is saturated",
        )
        .with_context("retry-after", "7");

        assert_eq!(
            retry_after_value(503, Some(&err)),
            "7",
            "the pool's computed estimate must reach the client"
        );
    }

    /// A malformed estimate is discarded rather than forwarded.
    ///
    /// A client that cannot parse `Retry-After` ignores it and retries
    /// immediately, which is the stampede the header exists to prevent — so an
    /// invalid value is worse than the conservative default.
    #[test]
    fn a_malformed_retry_after_falls_back_to_the_default() {
        for bad in [
            "",
            "soon",
            "7s",
            "-1",
            "1.5",
            " ",
            "9999999999999999999999x",
        ] {
            let err = Error::new(ErrorCode::InstancePoolExhausted, "saturated")
                .with_context("retry-after", bad);
            assert_eq!(
                retry_after_value(503, Some(&err)),
                "1",
                "`{bad}` is not a valid Retry-After and must not be forwarded"
            );
        }
    }

    /// An error with no estimate uses the conservative default, which is the
    /// documented behaviour when the host has nothing better to offer.
    #[test]
    fn an_error_without_an_estimate_uses_the_default() {
        let err = Error::new(ErrorCode::InstancePoolExhausted, "saturated");
        assert_eq!(retry_after_value(503, Some(&err)), "1");
    }

    /// End to end: the error the pool actually produces must render a 503 whose
    /// `Retry-After` is the pool's estimate, not the placeholder.
    ///
    /// This is the join `HOST-012` and the server both depend on, and neither
    /// side's own tests can see it: the pool asserts the estimate is *in the
    /// context*, the response tests assert a value *renders*, and only this
    /// checks the two agree on the field name.
    #[test]
    fn a_real_pool_error_renders_its_estimate() {
        let err = qqq_host::exhausted_error(qqq_host::Exhausted::AllBusy, 64, 12);
        let rendered = error_response(&err, false);

        assert_eq!(rendered.status, 503);
        assert_eq!(
            rendered.retry_after.as_deref(),
            Some("12"),
            "the pool computed 12 seconds and the response must say so"
        );
        assert_eq!(rendered.log_code.as_deref(), Some("QQQ-6001"));
    }

    // -- convenience responses ---------------------------------------------

    #[test]
    fn not_found_is_a_404() {
        let r = not_found();
        assert_eq!(r.status, 404);
    }

    /// **The `Allow` header is what makes a 405 useful.** Without it the client
    /// knows its method was wrong but not which one to use.
    #[test]
    fn method_not_allowed_lists_what_is_allowed() {
        let r = method_not_allowed(&[Method::Get, Method::Post]);
        assert_eq!(r.status, 405);
        let allow = r.header("Allow").expect("405 must carry Allow");
        assert!(allow.contains("GET"));
        assert!(allow.contains("POST"));
    }

    #[test]
    fn a_405_with_no_methods_still_carries_the_header() {
        let r = method_not_allowed(&[]);
        assert_eq!(r.status, 405);
        // An empty `Allow` is unusual but must not be absent: a client checks
        // for the header's presence.
        assert_eq!(r.header("Allow"), Some(""));
    }

    #[test]
    fn a_response_can_be_built_from_an_error_response() {
        let e = error_response(&err(ErrorCode::InstancePoolExhausted), false);
        let r = from_error(&e);
        assert_eq!(r.status, 503);
        assert_eq!(r.header("Retry-After"), Some("1"));
    }

    // -- reason phrases ----------------------------------------------------

    #[test]
    fn every_status_qqq_emits_has_a_real_phrase() {
        for status in [
            200u16, 201, 204, 301, 302, 304, 307, 308, 400, 401, 403, 404, 405, 408, 409, 413, 415,
            422, 429, 431, 500, 501, 502, 503, 504, 505,
        ] {
            let phrase = reason_phrase(status);
            assert_ne!(phrase, "Unknown", "{status} needs a real reason phrase");
            assert!(!phrase.is_empty());
        }
    }

    /// An unlisted code still gets a non-empty phrase, because `HTTP/1.1 299 `
    /// with nothing after it is mis-parsed by some clients.
    #[test]
    fn an_unlisted_status_still_gets_a_phrase() {
        assert_eq!(reason_phrase(299), "Unknown");
        assert!(!reason_phrase(299).is_empty());
    }

    /// Every status the trap mapping can produce must have a real phrase, or
    /// the rendered response contains "Unknown".
    #[test]
    fn every_mapped_status_has_a_phrase() {
        let mut seen = Vec::new();
        for code in ErrorCode::all() {
            for soft in [false, true] {
                let r = error_response(&err(*code), soft);
                if !seen.contains(&r.status) {
                    seen.push(r.status);
                }
                assert_ne!(
                    reason_phrase(r.status),
                    "Unknown",
                    "{code} maps to {}, which has no phrase",
                    r.status
                );
            }
        }
        for s in [404, 405] {
            assert_ne!(reason_phrase(s), "Unknown");
        }
    }

    // -- end to end --------------------------------------------------------

    /// A written error response must round-trip through the parser's framing
    /// rules: a `Content-Length` that matches, and a terminated head.
    #[test]
    fn a_written_error_response_is_well_framed() {
        let e = error_response(&err(ErrorCode::InstancePoolExhausted), false);
        let r = from_error(&e);
        let bytes = write_response(&r, Version::Http11, !e.close);
        let (status, headers, body) = parse_response(&bytes);

        assert_eq!(status, "HTTP/1.1 503 Service Unavailable");
        let declared: usize = header(&headers, "Content-Length")
            .expect("length present")
            .parse()
            .expect("length is a number");
        assert_eq!(
            declared,
            body.len(),
            "the declared length must match the body, or the stream desynchronises"
        );
        assert_eq!(header(&headers, "Connection"), Some("close"));
    }

    // -- Streaming bodies: the head, the chunks, the terminator ------------
    //
    // These are the primitives SSE (`SRV-010`) needs and `write_response` cannot
    // provide: an event stream's body ends when the client disconnects, so it has no
    // length, so it cannot be framed with `Content-Length`.

    /// **An HTTP/1.1 streaming response is framed chunked and declares no length.**
    ///
    /// Emitting `Content-Length` here would be a lie the client believes: it would read
    /// exactly that many bytes and then interpret the rest of the stream as the next
    /// response.
    #[test]
    fn a_streaming_response_is_chunked_and_has_no_content_length() {
        let mut resp = Response::status(200);
        resp.set_header("Content-Type", "text/event-stream");
        let head = write_stream_head(&resp, Version::Http11, true);
        let (status, headers, _) = parse_response(&head);

        assert_eq!(status, "HTTP/1.1 200 OK");
        assert_eq!(header(&headers, "Transfer-Encoding"), Some("chunked"));
        assert_eq!(
            header(&headers, "Content-Length"),
            None,
            "a length cannot be known for a body that ends at disconnect"
        );
    }

    /// **An HTTP/1.0 streaming response closes and does not claim chunked.**
    ///
    /// HTTP/1.0 has no chunked encoding. A client that did not understand
    /// `Transfer-Encoding: chunked` would treat the chunk framing as body bytes — the
    /// request-smuggling shape this project has already had to defend against — so the
    /// only correct delimiter is EOF.
    #[test]
    fn an_http10_streaming_response_closes_and_is_not_chunked() {
        let resp = Response::status(200);
        let head = write_stream_head(&resp, Version::Http10, true);
        let (status, headers, _) = parse_response(&head);

        assert_eq!(status, "HTTP/1.0 200 OK");
        assert_eq!(
            header(&headers, "Transfer-Encoding"),
            None,
            "HTTP/1.0 has no chunked encoding"
        );
        assert_eq!(
            header(&headers, "Connection"),
            Some("close"),
            "EOF is the only way an HTTP/1.0 client learns the body ended"
        );
    }

    /// A status that forbids a body is not framed chunked.
    ///
    /// A 204 with `Transfer-Encoding: chunked` promises chunks that must never arrive,
    /// so a client waits for them. `forbids_body` already encodes which statuses those
    /// are and is reused rather than restated.
    #[test]
    fn a_bodyless_status_is_not_framed_chunked() {
        for status in [204u16, 304] {
            let resp = Response::status(status);
            let head = write_stream_head(&resp, Version::Http11, true);
            let (_, headers, _) = parse_response(&head);
            assert_eq!(
                header(&headers, "Transfer-Encoding"),
                None,
                "{status} forbids a body and must not promise chunks"
            );
            assert_eq!(header(&headers, "Content-Length"), Some("0"), "{status}");
        }
    }

    /// The caller cannot contradict the framing.
    ///
    /// A handler that sets `Content-Length` or `Transfer-Encoding` itself must not be
    /// able to produce a response whose declared framing disagrees with the bytes
    /// written next. Same rule as `write_response`: the function owns those headers.
    #[test]
    fn a_caller_cannot_override_the_streaming_framing() {
        let mut resp = Response::status(200);
        resp.set_header("Content-Length", "999");
        resp.set_header("Transfer-Encoding", "identity");
        resp.set_header("Connection", "keep-alive");
        resp.set_header("X-Custom", "kept");

        let head = write_stream_head(&resp, Version::Http11, true);
        let (_, headers, _) = parse_response(&head);

        assert_eq!(header(&headers, "Content-Length"), None);
        assert_eq!(header(&headers, "Transfer-Encoding"), Some("chunked"));
        // And an unrelated header survives, so this is not "drop everything".
        assert_eq!(header(&headers, "X-Custom"), Some("kept"));
    }

    /// A chunk is a hex length, the bytes, then CRLF.
    #[test]
    fn a_chunk_is_length_then_bytes_then_crlf() {
        assert_eq!(write_chunk(b"hello"), b"5\r\nhello\r\n".to_vec());
        assert_eq!(write_chunk(b""), Vec::<u8>::new());
        // 16 bytes is `10` in hex — the case a decimal-length bug gets wrong.
        assert_eq!(
            write_chunk(&[b'x'; 16]),
            b"10\r\nxxxxxxxxxxxxxxxx\r\n".to_vec()
        );
    }

    /// **An empty piece produces no bytes, not a terminating chunk.**
    ///
    /// This is the defect worth a test of its own. A zero-length chunk *ends* the body,
    /// so framing an empty write as `0\r\n\r\n` would terminate the response at
    /// whatever moment the caller happened to have nothing to send. For an SSE stream
    /// that lull is normal — it is what happens between events — so the client would
    /// see a closed response during ordinary operation, and nothing anywhere would
    /// report an error.
    #[test]
    fn an_empty_piece_does_not_terminate_the_body() {
        assert!(
            write_chunk(b"").is_empty(),
            "an empty write must produce no bytes; a zero-length chunk ends the body"
        );
        // The terminator is a separate, explicit operation.
        assert_eq!(write_last_chunk(), b"0\r\n\r\n".to_vec());
    }

    /// The terminator is exactly one zero-length chunk and an empty trailer section.
    #[test]
    fn the_terminator_is_a_zero_length_chunk() {
        let last = write_last_chunk();
        assert_eq!(last, b"0\r\n\r\n".to_vec());
        // Spelled out: length 0, no chunk data, empty trailer, blank line.
        assert!(last.starts_with(b"0\r\n"));
        assert!(last.ends_with(b"\r\n\r\n"));
    }

    /// The chunk framing is well-formed for any piece, including one over `CHUNK_MAX`.
    ///
    /// `write_chunk` frames whatever it is given — `CHUNK_MAX` is guidance for the
    /// caller, not a limit — so a large piece must still produce a valid chunk rather
    /// than a truncated length prefix.
    #[test]
    fn a_large_piece_is_framed_correctly() {
        let piece = vec![b'z'; CHUNK_MAX + 1];
        let framed = write_chunk(&piece);
        let text = String::from_utf8_lossy(&framed);
        let (prefix, rest) = text.split_once("\r\n").expect("length prefix");
        let declared = usize::from_str_radix(prefix, 16).expect("hex length");
        assert_eq!(
            declared,
            piece.len(),
            "the length prefix must be the piece size"
        );
        assert_eq!(
            rest.len(),
            piece.len() + 2,
            "the data plus its trailing CRLF"
        );
    }

    /// The head and chunks concatenate into a body a chunked parser can read.
    ///
    /// The integration property: three pieces plus a terminator, decoded back, equal
    /// the original payload. Each function is tested alone above; this is the test that
    /// the *three* compose — the seam where this project has found most of its defects.
    #[test]
    fn a_chunked_body_round_trips_through_the_framing() {
        let mut resp = Response::status(200);
        resp.set_header("Content-Type", "text/event-stream");
        let mut wire = write_stream_head(&resp, Version::Http11, true);

        let payload = b"data: one\n\ndata: two\n\n";
        // Split across three writes, including an empty one, because that is what a
        // real event loop does.
        wire.extend_from_slice(&write_chunk(&payload[..6]));
        wire.extend_from_slice(&write_chunk(b""));
        wire.extend_from_slice(&write_chunk(&payload[6..]));
        wire.extend_from_slice(&write_last_chunk());

        let (_, headers, body) = parse_response(&wire);
        assert_eq!(header(&headers, "Transfer-Encoding"), Some("chunked"));
        assert_eq!(
            decode_chunks(&body).expect("a valid chunked body"),
            payload.to_vec(),
            "the decoded body must equal what the caller wrote"
        );
    }

    /// Decode a chunked body, for the round-trip test above.
    fn decode_chunks(mut body: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        loop {
            let end = body
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or_else(|| format!("no chunk header in {:?}", String::from_utf8_lossy(body)))?;
            let len = usize::from_str_radix(
                std::str::from_utf8(&body[..end]).map_err(|e| e.to_string())?,
                16,
            )
            .map_err(|e| e.to_string())?;
            body = &body[end + 2..];
            if len == 0 {
                return Ok(out);
            }
            if body.len() < len + 2 {
                return Err("chunk shorter than its declared length".to_owned());
            }
            out.extend_from_slice(&body[..len]);
            body = &body[len + 2..];
        }
    }
}
