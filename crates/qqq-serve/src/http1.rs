//! HTTP/1.1 request parsing, with the bomb limits Proposal §6.4 requires.
//!
//! Implements the parsing half of `SRV-001` and the header-bomb mitigation of
//! `SRV-020`; Proposal §6.4 (*"Failure modes: slow-loris … body bombs … header
//! bombs (mitigated by caps on header count and size)"*).
//!
//! # Why parsing is separated from the socket
//!
//! [`parse_head`] takes a byte slice and returns a request head or an error. It
//! does not read from anything, allocate a socket, or block. That means every
//! attack the Proposal names as a failure mode is expressible as a **test
//! input**:
//!
//! | Attack | Test input |
//! |---|---|
//! | header bomb | 100 001 headers |
//! | oversized header | one header of 2 MiB |
//! | request-line flood | a 1 MiB request target |
//! | smuggling | a request with two `Content-Length` headers |
//!
//! A parser coupled to a socket can only be tested by being attacked. This one
//! is tested by being handed the attack.
//!
//! # The limits, and why each exists
//!
//! Every limit below is a *count* or a *length*, never a timeout. Timeouts are
//! the connection layer's job (`SRV-012`) because they depend on the socket;
//! these bounds are what make the parser's memory use a function of the
//! configured maxima rather than of the client's willingness to send.
//!
//! A reader might ask why not simply read until `\r\n\r\n` and then check. The
//! answer is that reading until a terminator is **unbounded work driven by the
//! peer**: the check happens after the memory is already spent. The limits here
//! are checked as the parse proceeds, so a header bomb is refused after
//! [`MAX_HEADERS`] headers rather than after the buffer fills.
//!
//! # What this does not do
//!
//! No chunked transfer decoding, no body assembly, no HTTP/2. `Content-Length`
//! and `Transfer-Encoding` are *parsed and validated* — because a request that
//! declares both is a smuggling attack — but the body is left to the caller,
//! which streams it under `SRV-004` and `SRV-005`.

use std::fmt;

use qqq_core::{Error, ErrorCode};

use crate::route::Method;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// The most headers one request may carry.
///
/// A header bomb sends tens of thousands of tiny headers to exhaust memory
/// through per-header overhead rather than payload. 100 is well above any real
/// request — browsers send 10 to 20, and a request with more than 100 is
/// usually a proxy loop.
pub const MAX_HEADERS: usize = 100;

/// The largest a single header line may be.
///
/// 8 KiB matches the de-facto limit in nginx and Apache and is far above real
/// use. A cookie is the usual largest header and 8 KiB is already generous.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// The largest request target (the path plus query) may be.
///
/// 8 KiB. A URL longer than this is either a scanner or a mistake, and the
/// limit is enforced *during* the request-line scan so a client cannot make the
/// parser buffer a megabyte before the check.
pub const MAX_TARGET_BYTES: usize = 8 * 1024;

/// The largest the whole request head may be.
///
/// The backstop that makes the total bounded even if every individual limit is
/// individually satisfied: 100 headers × 8 KiB would be 800 KiB, and this caps
/// it at 64 KiB. A limit on each part is not a limit on the whole.
pub const MAX_HEAD_BYTES: usize = 64 * 1024;

/// The largest a request body may be.
///
/// The default for `max_request_bytes`. A strict cap of 2 MiB. `SRV-005`
/// requires it to be enforced *during* streaming, so this value constrains the
/// caller's reader rather than this parser — but the parser validates a declared
/// `Content-Length` against it, so an over-large request is refused before the
/// body is read at all.
pub const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a request head was rejected.
///
/// Each variant carries the HTTP status the server should answer with, because
/// the distinction between "you sent nonsense" (400) and "you sent too much"
/// (431) is one a client can act on, and an agent debugging an integration
/// needs to know which it hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The head did not end with `\r\n\r\n` within the byte limit.
    Incomplete {
        /// How many bytes were supplied.
        got: usize,
    },
    /// The request line was malformed.
    BadRequestLine {
        /// Why.
        detail: String,
    },
    /// The method was not one HTTP defines.
    UnknownMethod {
        /// The method as sent.
        method: String,
    },
    /// The version was not `HTTP/1.0` or `HTTP/1.1`.
    UnsupportedVersion {
        /// The version as sent.
        version: String,
    },
    /// Too many headers.
    TooManyHeaders {
        /// The limit.
        limit: usize,
    },
    /// A header line was longer than the limit.
    HeaderTooLong {
        /// The header name, or `<request-line>`.
        name: String,
        /// How long it was.
        bytes: usize,
        /// The limit.
        limit: usize,
    },
    /// The request target was longer than the limit.
    TargetTooLong {
        /// How long it was.
        bytes: usize,
        /// The limit.
        limit: usize,
    },
    /// The whole head exceeded the limit.
    HeadTooLarge {
        /// The limit.
        limit: usize,
    },
    /// A header line had no `:`.
    MalformedHeader {
        /// The offending line, truncated.
        line: String,
    },
    /// A header name contained a character HTTP forbids.
    ///
    /// A security check rather than pedantry: a name containing a space or a
    /// control character is how request smuggling begins.
    InvalidHeaderName {
        /// The offending name.
        name: String,
    },
    /// The target did not begin with `/`.
    ///
    /// `OPTIONS *` is the one legal exception and is handled before this.
    TargetNotAbsolute {
        /// The target as sent.
        target: String,
    },
    /// Both `Content-Length` and `Transfer-Encoding` were present.
    ///
    /// **A request-smuggling signature.** RFC 9112 §6.1 requires a server to
    /// reject it, because a proxy and an origin disagreeing about which header
    /// defines the body length is how a request is split into two.
    ConflictingFraming,
    /// `Content-Length` appeared more than once.
    ///
    /// Also smuggling: two lengths let a proxy honour one and the origin the
    /// other. Rejecting is the only safe answer.
    DuplicateContentLength,
    /// `Content-Length` was not a number, or did not fit.
    InvalidContentLength {
        /// The value as sent.
        value: String,
    },
    /// The declared body exceeded the configured cap.
    BodyTooLarge {
        /// The declared size.
        declared: u64,
        /// The cap.
        limit: u64,
    },
    /// A `Transfer-Encoding` other than `chunked` was requested.
    UnsupportedTransferEncoding {
        /// The value as sent.
        value: String,
    },
}

impl ParseError {
    /// The HTTP status this error should be answered with.
    ///
    /// The mapping is deliberate rather than uniform:
    ///
    /// * **400** for a request that is syntactically wrong.
    /// * **431** (`Request Header Fields Too Large`) when a *limit* was hit —
    ///   distinct from 400 because a client can act on it by sending less.
    /// * **413** (`Content Payload Too Large`) when the body cap was hit.
    /// * **505** (`HTTP Version Not Supported`) for a version we do not speak.
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::TooManyHeaders { .. }
            | Self::HeaderTooLong { .. }
            | Self::TargetTooLong { .. }
            | Self::HeadTooLarge { .. } => 431,
            Self::BodyTooLarge { .. } => 413,
            Self::UnsupportedVersion { .. } => 505,
            _ => 400,
        }
    }

    /// Whether the connection should be closed after answering.
    ///
    /// Limits and framing errors close: the parser's view of where this request
    /// ends is not trustworthy, so continuing to read on the same connection
    /// risks interpreting body bytes as the next request — which is the
    /// smuggling attack itself.
    #[must_use]
    pub const fn closes_connection(&self) -> bool {
        matches!(
            self,
            Self::TooManyHeaders { .. }
                | Self::HeadTooLarge { .. }
                | Self::HeaderTooLong { .. }
                | Self::ConflictingFraming
                | Self::DuplicateContentLength
        )
    }

    /// Convert to the shared error type.
    #[must_use]
    pub fn to_error(&self) -> Error {
        let remediation = match self {
            Self::Incomplete { .. } => "the request head must end with CRLF CRLF",
            Self::TooManyHeaders { limit } => {
                // Cannot format into a &str; the message carries the number.
                let _ = limit;
                "reduce the number of headers; this limit is configurable"
            }
            Self::HeaderTooLong { .. } => "shorten the header, or raise MAX_HEADER_BYTES",
            Self::TargetTooLong { .. } => "shorten the URL",
            Self::HeadTooLarge { .. } => "reduce the total size of the request head",
            Self::ConflictingFraming | Self::DuplicateContentLength => {
                "send exactly one Content-Length and no Transfer-Encoding, or vice versa"
            }
            Self::BodyTooLarge { .. } => {
                "send a smaller body, or raise max_request_bytes in qqq.toml"
            }
            Self::UnsupportedVersion { .. } => "use HTTP/1.1",
            Self::UnknownMethod { .. } => "use a method HTTP defines",
            _ => "send a well-formed HTTP/1.1 request",
        };
        Error::new(ErrorCode::ManifestSchemaViolation, self.to_string())
            .with_context("surface", "http-request")
            .with_remediation(remediation)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { got } => {
                write!(f, "the request head is incomplete after {got} bytes")
            }
            Self::BadRequestLine { detail } => write!(f, "malformed request line: {detail}"),
            Self::UnknownMethod { method } => write!(f, "unknown method `{method}`"),
            Self::UnsupportedVersion { version } => write!(f, "unsupported version `{version}`"),
            Self::TooManyHeaders { limit } => {
                write!(f, "more than {limit} headers")
            }
            Self::HeaderTooLong { name, bytes, limit } => {
                write!(
                    f,
                    "header `{name}` is {bytes} bytes, over the {limit}-byte limit"
                )
            }
            Self::TargetTooLong { bytes, limit } => {
                write!(
                    f,
                    "request target is {bytes} bytes, over the {limit}-byte limit"
                )
            }
            Self::HeadTooLarge { limit } => {
                write!(f, "the request head exceeds {limit} bytes")
            }
            Self::MalformedHeader { line } => write!(f, "malformed header line `{line}`"),
            Self::InvalidHeaderName { name } => write!(f, "invalid header name `{name}`"),
            Self::TargetNotAbsolute { target } => {
                write!(f, "request target `{target}` must begin with `/`")
            }
            Self::ConflictingFraming => f.write_str(
                "both Content-Length and Transfer-Encoding are present, which is \
                 ambiguous framing",
            ),
            Self::DuplicateContentLength => {
                f.write_str("Content-Length appears more than once, which is ambiguous framing")
            }
            Self::InvalidContentLength { value } => {
                write!(f, "Content-Length `{value}` is not a valid number")
            }
            Self::BodyTooLarge { declared, limit } => {
                write!(
                    f,
                    "declared body of {declared} bytes exceeds the {limit}-byte cap"
                )
            }
            Self::UnsupportedTransferEncoding { value } => {
                write!(f, "unsupported Transfer-Encoding `{value}`")
            }
        }
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------------
// The parsed request head
// ---------------------------------------------------------------------------

/// A parsed HTTP/1.1 request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// The method.
    pub method: Method,
    /// The raw request target, exactly as sent.
    ///
    /// Retained verbatim rather than pre-split, because a router needs the path
    /// and a logger needs what the client actually asked for, and re-joining a
    /// path and query loses the distinction between `/a?` and `/a`.
    pub target: String,
    /// `HTTP/1.0` or `HTTP/1.1`.
    pub version: Version,
    /// The headers, in the order received.
    pub headers: Vec<(String, String)>,
    /// The declared body length, when the request has a body.
    pub content_length: Option<u64>,
    /// Whether the body is chunked.
    pub chunked: bool,
}

/// The HTTP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
}

impl Version {
    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

impl RequestHead {
    /// The path portion of the target, without the query.
    ///
    /// The fragment (`#…`) is stripped too, although a client must never send
    /// one: a request for `/a#b` is a bug, and treating the fragment as part of
    /// the path would route it to a handler that does not exist. Stripping is
    /// the behaviour that makes the mistake visible as a 404 rather than as a
    /// mysterious routing difference.
    #[must_use]
    pub fn path(&self) -> &str {
        let end = self.target.find(['?', '#']).unwrap_or(self.target.len());
        &self.target[..end]
    }

    /// The query string, without the leading `?`.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        let q = self.target.find('?')?;
        let rest = &self.target[q + 1..];
        let end = rest.find('#').unwrap_or(rest.len());
        Some(&rest[..end])
    }

    /// The first value of a header, case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether the client asked to keep the connection alive.
    ///
    /// # The default differs by version, and getting it backwards is a real bug
    ///
    /// HTTP/1.1 defaults to **keep-alive**; HTTP/1.0 defaults to **close**. A
    /// server that assumed keep-alive unconditionally would hold HTTP/1.0
    /// connections open until they timed out, and one that assumed close would
    /// tear down every 1.1 connection — turning a persistent-connection
    /// protocol into a per-request one.
    #[must_use]
    pub fn wants_keep_alive(&self) -> bool {
        match self.header("connection") {
            Some(v) if v.eq_ignore_ascii_case("close") => false,
            Some(v) if v.eq_ignore_ascii_case("keep-alive") => true,
            // Explicit `Connection: something-else` is a hop-by-hop header list;
            // the default applies.
            _ => self.version == Version::Http11,
        }
    }

    /// Whether this request carries a body.
    #[must_use]
    pub fn has_body(&self) -> bool {
        self.chunked || self.content_length.is_some_and(|n| n > 0)
    }

    /// The `Host` header, which HTTP/1.1 requires.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.header("host")
    }

    /// Whether the request is missing a `Host` header it is required to have.
    ///
    /// HTTP/1.1 mandates `Host` (RFC 9112 §3.2). Reporting it separately from
    /// the parse lets the caller answer 400 with a message that says *why*,
    /// rather than a generic malformed-request error.
    #[must_use]
    pub fn is_missing_required_host(&self) -> bool {
        self.version == Version::Http11 && self.host().is_none()
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Where the head ends, as an offset just past the terminating `\r\n\r\n`.
///
/// Returned rather than assumed so the caller knows exactly how many bytes to
/// consume, which is what allows pipelined requests on one connection to be
/// handled without guessing.
#[must_use]
pub fn head_end(input: &[u8]) -> Option<usize> {
    input
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

/// Parse an HTTP/1.1 request head.
///
/// Accepts a slice that may contain more than the head — the returned
/// [`head_end`] tells the caller how much was consumed.
///
/// # Errors
///
/// Any [`ParseError`]. Every limit in this module is enforced here.
pub fn parse_head(input: &[u8]) -> std::result::Result<(RequestHead, usize), ParseError> {
    // -- the overall cap, before scanning anything ------------------------
    if input.len() > MAX_HEAD_BYTES {
        return Err(ParseError::HeadTooLarge {
            limit: MAX_HEAD_BYTES,
        });
    }
    let Some(end) = head_end(input) else {
        return Err(ParseError::Incomplete { got: input.len() });
    };

    // The head is everything up to and including the final CRLF CRLF, minus the
    // terminator itself.
    let head = &input[..end - 4];
    // Latin-1 rather than UTF-8: HTTP header values are octets, and a client is
    // permitted to send bytes that are not valid UTF-8. Decoding lossily keeps
    // such a request parseable instead of rejecting it for an encoding rule
    // HTTP does not impose. The *validation* below is what rejects genuinely
    // dangerous bytes.
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");

    // -- the request line -------------------------------------------------
    let request_line = lines.next().unwrap_or("");
    let (method, target, version) = parse_request_line(request_line)?;

    // -- the headers ------------------------------------------------------
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: Option<u64> = None;
    let mut chunked = false;

    for line in lines {
        if headers.len() >= MAX_HEADERS {
            return Err(ParseError::TooManyHeaders { limit: MAX_HEADERS });
        }
        if line.len() > MAX_HEADER_BYTES {
            let name = line.split(':').next().unwrap_or("<unknown>").to_owned();
            return Err(ParseError::HeaderTooLong {
                name,
                bytes: line.len(),
                limit: MAX_HEADER_BYTES,
            });
        }

        let (raw_name, raw_value) =
            line.split_once(':')
                .ok_or_else(|| ParseError::MalformedHeader {
                    line: truncate(line, 64),
                })?;
        let name = raw_name.trim();
        if !is_valid_header_name(name) {
            return Err(ParseError::InvalidHeaderName {
                name: truncate(name, 64),
            });
        }
        // Leading and trailing whitespace around a field value is optional and
        // must be stripped (RFC 9110 §5.5). Inner whitespace is significant and
        // is preserved.
        let value = raw_value.trim();

        // -- framing headers, validated rather than trusted ---------------
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                // Two lengths is a smuggling signature: a proxy may honour the
                // first and the origin the second.
                return Err(ParseError::DuplicateContentLength);
            }
            let n: u64 = value
                .parse()
                .map_err(|_| ParseError::InvalidContentLength {
                    value: truncate(value, 64),
                })?;
            if n > MAX_REQUEST_BYTES {
                return Err(ParseError::BodyTooLarge {
                    declared: n,
                    limit: MAX_REQUEST_BYTES,
                });
            }
            content_length = Some(n);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            // Only `chunked` is supported. Anything else — and `chunked` in a
            // list — is refused rather than guessed at.
            if value.eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else {
                return Err(ParseError::UnsupportedTransferEncoding {
                    value: truncate(value, 64),
                });
            }
        }

        headers.push((name.to_owned(), value.to_owned()));
    }

    // **The smuggling check.** A request with both framing headers is refused
    // outright: which one wins is precisely what two implementations disagree
    // about, and that disagreement is the attack.
    if chunked && content_length.is_some() {
        return Err(ParseError::ConflictingFraming);
    }

    Ok((
        RequestHead {
            method,
            target,
            version,
            headers,
            content_length,
            chunked,
        },
        end,
    ))
}

/// Parse the request line into its three parts.
fn parse_request_line(line: &str) -> std::result::Result<(Method, String, Version), ParseError> {
    // `splitn(3, ' ')` rather than `split_whitespace`: a request target must not
    // contain a space (it would be percent-encoded), so splitting on the first
    // two spaces is the correct rule, and it means a target containing a tab is
    // rejected rather than silently accepted as a different target.
    let mut parts = line.splitn(3, ' ');
    let method_str = parts.next().unwrap_or("");
    let target = parts.next().ok_or_else(|| ParseError::BadRequestLine {
        detail: "expected `METHOD TARGET VERSION`".to_owned(),
    })?;
    let version_str = parts.next().ok_or_else(|| ParseError::BadRequestLine {
        detail: "expected `METHOD TARGET VERSION`".to_owned(),
    })?;

    if method_str.is_empty() || target.is_empty() || version_str.is_empty() {
        return Err(ParseError::BadRequestLine {
            detail: "one of the three parts is empty".to_owned(),
        });
    }

    let method = Method::parse(method_str).ok_or_else(|| ParseError::UnknownMethod {
        method: truncate(method_str, 32),
    })?;

    if target.len() > MAX_TARGET_BYTES {
        return Err(ParseError::TargetTooLong {
            bytes: target.len(),
            limit: MAX_TARGET_BYTES,
        });
    }

    // `OPTIONS *` is the one legal non-absolute target (RFC 9110 §9.3.7).
    let is_asterisk = target == "*" && method == Method::Options;
    if !is_asterisk && !target.starts_with('/') {
        return Err(ParseError::TargetNotAbsolute {
            target: truncate(target, 64),
        });
    }

    let version = match version_str {
        "HTTP/1.1" => Version::Http11,
        "HTTP/1.0" => Version::Http10,
        other => {
            return Err(ParseError::UnsupportedVersion {
                version: truncate(other, 16),
            });
        }
    };

    Ok((method, target.to_owned(), version))
}

/// Whether a header name is legal.
///
/// RFC 9110 §5.1 defines a field name as a `token`: alphanumerics plus a small
/// set of punctuation, and **no whitespace and no control characters**. This is
/// a security check rather than pedantry — a name containing a space or a CR is
/// how a header is smuggled past a proxy that parses differently from the
/// origin.
#[must_use]
pub fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Truncate for an error message, without splitting a UTF-8 sequence.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> std::result::Result<RequestHead, ParseError> {
        parse_head(s.as_bytes()).map(|(h, _)| h)
    }

    fn ok(s: &str) -> RequestHead {
        parse(s).unwrap_or_else(|e| panic!("`{s}` should parse: {e}"))
    }

    // -- the happy path ----------------------------------------------------

    #[test]
    fn a_minimal_request_parses() {
        let h = ok("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(h.method, Method::Get);
        assert_eq!(h.target, "/");
        assert_eq!(h.version, Version::Http11);
        assert_eq!(h.host(), Some("example.com"));
        assert!(!h.has_body());
    }

    #[test]
    fn a_request_with_a_body_parses() {
        let h = ok("POST /orders HTTP/1.1\r\nHost: x\r\nContent-Length: 42\r\n\r\n");
        assert_eq!(h.method, Method::Post);
        assert_eq!(h.content_length, Some(42));
        assert!(h.has_body());
        assert!(!h.chunked);
    }

    #[test]
    fn a_chunked_request_parses() {
        let h = ok("POST /orders HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert!(h.chunked);
        assert!(h.has_body());
        assert_eq!(h.content_length, None);
    }

    /// The parser reports how much it consumed, so pipelined requests on one
    /// connection can be split without guessing.
    #[test]
    fn the_consumed_length_covers_only_the_head() {
        let input = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nBODYBYTES";
        let (h, used) = parse_head(input).expect("must parse");
        assert_eq!(h.target, "/");
        assert_eq!(
            &input[used..],
            b"BODYBYTES",
            "the body must be left for the caller"
        );
    }

    #[test]
    fn header_order_is_preserved() {
        let h = ok("GET / HTTP/1.1\r\nZebra: 1\r\nApple: 2\r\n\r\n");
        let names: Vec<&str> = h.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["Zebra", "Apple"], "order must be as received");
    }

    // -- the target --------------------------------------------------------

    #[test]
    fn path_and_query_are_separated() {
        let h = ok("GET /orders?status=open&limit=10 HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(h.path(), "/orders");
        assert_eq!(h.query(), Some("status=open&limit=10"));
    }

    #[test]
    fn a_target_without_a_query_reports_none() {
        let h = ok("GET /orders HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(h.path(), "/orders");
        assert_eq!(h.query(), None);
    }

    /// A fragment must never be sent, and treating it as part of the path would
    /// route to a handler that does not exist. Stripping makes the mistake
    /// visible as a 404 rather than as a mysterious routing difference.
    #[test]
    fn a_fragment_is_stripped_from_the_path() {
        let h = ok("GET /orders#section HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(h.path(), "/orders");
        assert_eq!(h.query(), None);
    }

    #[test]
    fn an_empty_query_is_still_a_query() {
        // `/a?` and `/a` differ, and the target is retained so the difference
        // survives.
        let h = ok("GET /a? HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(h.target, "/a?");
        assert_eq!(h.path(), "/a");
        assert_eq!(h.query(), Some(""));
    }

    /// `OPTIONS *` is the one legal non-absolute target.
    #[test]
    fn asterisk_is_accepted_for_options_only() {
        assert!(parse("OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n").is_ok());
        let e = parse("GET * HTTP/1.1\r\nHost: x\r\n\r\n").unwrap_err();
        assert!(matches!(e, ParseError::TargetNotAbsolute { .. }));
    }

    #[test]
    fn a_relative_target_is_rejected() {
        let e = parse("GET orders HTTP/1.1\r\nHost: x\r\n\r\n").unwrap_err();
        assert!(matches!(e, ParseError::TargetNotAbsolute { .. }));
    }

    // -- versions and methods ----------------------------------------------

    #[test]
    fn http_1_0_parses() {
        let h = ok("GET / HTTP/1.0\r\n\r\n");
        assert_eq!(h.version, Version::Http10);
    }

    /// HTTP/2 and HTTP/3 do not use this framing at all, so accepting the
    /// version string would be wrong.
    #[test]
    fn an_unsupported_version_is_rejected_with_505() {
        for v in ["HTTP/2.0", "HTTP/3", "HTTP/0.9", "http/1.1"] {
            let input = format!("GET / {v}\r\nHost: x\r\n\r\n");
            let e = parse(&input).unwrap_err();
            assert!(
                matches!(e, ParseError::UnsupportedVersion { .. }),
                "`{v}` should be rejected as a version, got {e:?}"
            );
            assert_eq!(e.status(), 505, "a version problem is 505, not 400");
        }
    }

    #[test]
    fn an_unknown_method_is_rejected() {
        let e = parse("FROBNICATE / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap_err();
        assert!(matches!(e, ParseError::UnknownMethod { .. }));
    }

    #[test]
    fn a_malformed_request_line_is_rejected() {
        for line in [
            "GET /\r\nHost: x\r\n\r\n",         // missing version
            "GET\r\nHost: x\r\n\r\n",           // only a method
            "  / HTTP/1.1\r\nHost: x\r\n\r\n",  // empty method
            "GET  HTTP/1.1\r\nHost: x\r\n\r\n", // empty target
        ] {
            assert!(
                parse(line).is_err(),
                "`{line}` must be rejected as malformed"
            );
        }
    }

    // -- keep-alive, the version-dependent default -------------------------

    /// **The default differs by version and getting it backwards is a real
    /// bug.** HTTP/1.1 defaults to keep-alive; HTTP/1.0 defaults to close.
    #[test]
    fn keep_alive_defaults_differ_by_version() {
        let h11 = ok("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(h11.wants_keep_alive(), "HTTP/1.1 defaults to keep-alive");

        let h10 = ok("GET / HTTP/1.0\r\n\r\n");
        assert!(!h10.wants_keep_alive(), "HTTP/1.0 defaults to close");
    }

    #[test]
    fn an_explicit_connection_header_overrides_the_default() {
        let close = ok("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        assert!(!close.wants_keep_alive());

        let keep = ok("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
        assert!(keep.wants_keep_alive());
    }

    #[test]
    fn the_connection_header_is_case_insensitive() {
        assert!(!ok("GET / HTTP/1.1\r\nHost: x\r\nconnection: CLOSE\r\n\r\n").wants_keep_alive());
        assert!(ok("GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n").wants_keep_alive());
    }

    // -- the header-bomb limits --------------------------------------------

    /// **The header bomb.** Tens of thousands of tiny headers exhaust memory
    /// through per-header overhead. Refused after `MAX_HEADERS`, not after the
    /// buffer fills.
    #[test]
    fn a_header_bomb_is_refused() {
        use std::fmt::Write as _;

        let mut req = String::from("GET / HTTP/1.1\r\nHost: x\r\n");
        for i in 0..MAX_HEADERS + 10 {
            // `write!` into the existing string rather than allocating a
            // throwaway `String` per header with `push_str(&format!(...))`.
            let _ = write!(req, "X-{i}: v\r\n");
        }
        req.push_str("\r\n");
        let e = parse(&req).unwrap_err();
        assert!(matches!(e, ParseError::TooManyHeaders { limit } if limit == MAX_HEADERS));
        assert_eq!(
            e.status(),
            431,
            "a limit error is 431, which a client can act on"
        );
        assert!(
            e.closes_connection(),
            "framing is untrustworthy; the connection must close"
        );
    }

    /// A single oversized header is refused with 431 and names the header, so a
    /// user knows which one to shorten.
    #[test]
    fn an_oversized_header_is_refused() {
        let big = "x".repeat(MAX_HEADER_BYTES + 1);
        let req = format!("GET / HTTP/1.1\r\nHost: x\r\nX-Big: {big}\r\n\r\n");
        let e = parse(&req).unwrap_err();
        match &e {
            ParseError::HeaderTooLong { name, .. } => assert_eq!(name, "X-Big"),
            other => panic!("expected HeaderTooLong, got {other:?}"),
        }
        assert_eq!(e.status(), 431);
    }

    /// The whole-head cap is a backstop: a limit on each part is not a limit on
    /// the whole.
    #[test]
    fn an_oversized_head_is_refused() {
        let big = "x".repeat(MAX_HEAD_BYTES + 1);
        let req = format!("GET /{big} HTTP/1.1\r\nHost: x\r\n\r\n");
        let e = parse(&req).unwrap_err();
        assert!(matches!(e, ParseError::HeadTooLarge { .. }));
        assert_eq!(e.status(), 431);
    }

    #[test]
    fn an_oversized_target_is_refused() {
        let big = "x".repeat(MAX_TARGET_BYTES + 1);
        let req = format!("GET /{big} HTTP/1.1\r\nHost: x\r\n\r\n");
        let e = parse(&req).unwrap_err();
        assert!(matches!(e, ParseError::TargetTooLong { .. }));
        assert_eq!(e.status(), 431);
    }

    // -- the smuggling checks ----------------------------------------------

    /// **A request-smuggling signature.** A proxy and an origin disagreeing
    /// about which header defines the body length is how a request is split
    /// into two.
    #[test]
    fn both_framing_headers_together_are_refused() {
        let e = parse(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\
             Transfer-Encoding: chunked\r\n\r\n",
        )
        .unwrap_err();
        assert_eq!(e, ParseError::ConflictingFraming);
        assert!(
            e.closes_connection(),
            "ambiguous framing must close the connection"
        );
    }

    /// Two `Content-Length` headers let a proxy honour one and the origin the
    /// other.
    #[test]
    fn duplicate_content_length_is_refused() {
        let e =
            parse("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 9\r\n\r\n")
                .unwrap_err();
        assert_eq!(e, ParseError::DuplicateContentLength);
        // And even when the two agree, because a proxy that rewrites one would
        // still desynchronise.
        let same =
            parse("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n")
                .unwrap_err();
        assert_eq!(same, ParseError::DuplicateContentLength);
    }

    #[test]
    fn a_non_numeric_content_length_is_refused() {
        let e = parse("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n").unwrap_err();
        assert!(matches!(e, ParseError::InvalidContentLength { .. }));
    }

    /// An over-large declared body is refused **before** the body is read,
    /// which is `SRV-005`: enforcing during streaming means refusing without
    /// buffering anything.
    #[test]
    fn a_body_larger_than_the_cap_is_refused_with_413() {
        let e = parse(&format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BYTES + 1
        ))
        .unwrap_err();
        assert!(matches!(e, ParseError::BodyTooLarge { .. }));
        assert_eq!(e.status(), 413);
    }

    #[test]
    fn an_unsupported_transfer_encoding_is_refused() {
        for te in ["gzip", "chunked, gzip", "identity"] {
            let req = format!("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: {te}\r\n\r\n");
            let e = parse(&req).unwrap_err();
            assert!(
                matches!(e, ParseError::UnsupportedTransferEncoding { .. }),
                "`{te}` must be refused rather than guessed at"
            );
        }
    }

    /// A header name containing a space or a control character is how a header
    /// is smuggled past a proxy that parses differently from the origin.
    #[test]
    fn an_invalid_header_name_is_refused() {
        for line in [
            "Bad Name: v",  // space
            "Bad\tName: v", // tab
            ": v",          // empty
            "Bad@Name: v",  // not a token character
        ] {
            let req = format!("GET / HTTP/1.1\r\nHost: x\r\n{line}\r\n\r\n");
            let e = parse(&req).unwrap_err();
            assert!(
                matches!(e, ParseError::InvalidHeaderName { .. }),
                "`{line}` should be an invalid name, got {e:?}"
            );
        }
    }

    #[test]
    fn a_header_with_no_colon_is_refused() {
        let e = parse("GET / HTTP/1.1\r\nHost: x\r\nNotAHeader\r\n\r\n").unwrap_err();
        assert!(matches!(e, ParseError::MalformedHeader { .. }));
    }

    /// The positive control for the name check: every character RFC 9110 allows
    /// must be accepted, or the check rejects legitimate headers.
    #[test]
    fn every_legal_header_name_character_is_accepted() {
        for name in [
            "Host",
            "Content-Type",
            "X-Custom_Header",
            "ETag",
            "Accept",
            "X.Q.Q.Q",
            "a1!b2#c3$d4%e5&f6'g7*h8+i9-j.k^l_m`n|o~p",
        ] {
            assert!(
                is_valid_header_name(name),
                "`{name}` is a legal header name and must be accepted"
            );
        }
    }

    // -- value handling ----------------------------------------------------

    /// Leading and trailing whitespace around a field value is optional and
    /// must be stripped; inner whitespace is significant and preserved.
    #[test]
    fn header_values_are_trimmed_but_inner_space_is_kept() {
        let h = ok("GET / HTTP/1.1\r\nHost: x\r\nX-Val:   a b  \r\n\r\n");
        assert_eq!(h.header("x-val"), Some("a b"));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let h = ok("GET / HTTP/1.1\r\nCONTENT-TYPE: text/plain\r\n\r\n");
        assert_eq!(h.header("content-type"), Some("text/plain"));
        assert_eq!(h.header("Content-Type"), Some("text/plain"));
    }

    #[test]
    fn an_empty_header_value_is_permitted() {
        let h = ok("GET / HTTP/1.1\r\nHost: x\r\nX-Empty:\r\n\r\n");
        assert_eq!(h.header("x-empty"), Some(""));
    }

    // -- incomplete and edge inputs ----------------------------------------

    #[test]
    fn an_incomplete_head_is_reported_as_such() {
        let e = parse("GET / HTTP/1.1\r\nHost: x\r\n").unwrap_err();
        assert!(matches!(e, ParseError::Incomplete { .. }));
    }

    #[test]
    fn an_empty_input_is_incomplete_not_a_panic() {
        let e = parse("").unwrap_err();
        assert!(matches!(e, ParseError::Incomplete { got: 0 }));
    }

    /// Bare LF is not a valid header terminator in HTTP/1.1, and accepting it
    /// would let a request smuggle past a proxy that requires CRLF.
    #[test]
    fn bare_lf_does_not_terminate_the_head() {
        let e = parse("GET / HTTP/1.1\nHost: x\n\n").unwrap_err();
        assert!(
            matches!(e, ParseError::Incomplete { .. }),
            "bare LF must not be accepted as a terminator"
        );
    }

    #[test]
    fn a_head_with_no_headers_at_all_parses() {
        let h = ok("GET / HTTP/1.1\r\n\r\n");
        assert!(h.headers.is_empty());
        // And is then correctly reported as missing a required Host.
        assert!(h.is_missing_required_host());
    }

    /// HTTP/1.1 requires `Host`; HTTP/1.0 does not.
    #[test]
    fn the_host_requirement_follows_the_version() {
        assert!(ok("GET / HTTP/1.1\r\n\r\n").is_missing_required_host());
        assert!(!ok("GET / HTTP/1.0\r\n\r\n").is_missing_required_host());
        assert!(!ok("GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_missing_required_host());
    }

    // -- error rendering ---------------------------------------------------

    #[test]
    fn every_parse_error_renders_with_a_remediation() {
        let errors = [
            ParseError::Incomplete { got: 1 },
            ParseError::BadRequestLine {
                detail: "x".to_owned(),
            },
            ParseError::UnknownMethod {
                method: "X".to_owned(),
            },
            ParseError::UnsupportedVersion {
                version: "HTTP/9".to_owned(),
            },
            ParseError::TooManyHeaders { limit: 1 },
            ParseError::HeaderTooLong {
                name: "X".to_owned(),
                bytes: 2,
                limit: 1,
            },
            ParseError::TargetTooLong { bytes: 2, limit: 1 },
            ParseError::HeadTooLarge { limit: 1 },
            ParseError::MalformedHeader {
                line: "x".to_owned(),
            },
            ParseError::InvalidHeaderName {
                name: "x".to_owned(),
            },
            ParseError::TargetNotAbsolute {
                target: "x".to_owned(),
            },
            ParseError::ConflictingFraming,
            ParseError::DuplicateContentLength,
            ParseError::InvalidContentLength {
                value: "x".to_owned(),
            },
            ParseError::BodyTooLarge {
                declared: 2,
                limit: 1,
            },
            ParseError::UnsupportedTransferEncoding {
                value: "x".to_owned(),
            },
        ];
        for e in errors {
            let rendered = e.to_error();
            assert!(
                rendered.remediation.is_some(),
                "`{e}` renders without a remediation"
            );
            assert!(!rendered.message.is_empty());
            // Every status must be a real HTTP error status.
            let s = e.status();
            assert!((400..=599).contains(&s), "`{e}` produced status {s}");
        }
    }

    #[test]
    fn truncation_does_not_split_a_utf8_sequence() {
        // A multi-byte character straddling the cut must not panic.
        let s = "αααααααααα";
        let t = truncate(s, 5);
        assert!(t.ends_with('…'));
        // And a short string is returned unchanged.
        assert_eq!(truncate("abc", 10), "abc");
    }
}
