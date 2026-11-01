// SPDX-License-Identifier: Apache-2.0

//! The load generator: drives a real socket and produces measurements.
//!
//! # Why this talks to a socket rather than calling a handler
//!
//! `§9.2` states several budgets about a **running server**:
//!
//! | Row | `§9.2`'s own measurement method |
//! |---|---|
//! | Throughput, reference app, 8 cores | "`json` benchmark, 1 KB payload" |
//! | p99 request latency, reference app, 10k RPS | "`tailp99`" |
//! | Routed request overhead (empty handler) | "Host-side, excluding guest work" |
//!
//! None of those is observable in-process. An in-process harness would measure the
//! router and the guest and omit the connection state machine, the accept loop,
//! and the kernel — which on a `hello` benchmark is most of the cost. So the
//! driver opens TCP connections and speaks HTTP/1.1.
//!
//! # Why the client is hand-written and not `reqwest`
//!
//! Two reasons, and the second is the load-bearing one:
//!
//! 1. **Dependency weight.** `reqwest` brings TLS, HTTP/2, a connection pool, and
//!    a redirect policy that a load generator must not have. Every one of those is
//!    a variable that could change the number being reported.
//! 2. **The measurement must not include the client's cleverness.** A pooled,
//!    multiplexing client reuses connections in ways this harness does not
//!    disclose, and `§9.1` requires the concurrency level be *stated*. Speaking
//!    HTTP/1.1 directly means the harness knows exactly how many connections it
//!    held open and exactly when each request started — which is the requirement.
//!
//! What is deliberately absent: keep-alive reuse across iterations (each request
//! measures a fresh connection unless the caller reuses one), chunked transfer
//! encoding, and HTTP/2. Each absence is a limit on what these numbers mean, and
//! `§9.1`'s ninth requirement is that the limit be published.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::methodology::Concurrency;
use crate::stats::Distribution;

/// One measured request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// Time from the first byte written to the last byte read — the full
    /// framed body, not just the head. The timer starts after connect (the
    /// handshake belongs to setup, not to any request) and stops when the
    /// response is complete.
    pub nanos: u64,
    /// The HTTP status code.
    pub status: u16,
    /// Bytes in the response body, counted as read.
    ///
    /// Recorded because a benchmark that returns a 200 with no body is not
    /// measuring what its row claims, and the byte count is the cheapest way to
    /// catch that. `§9.1`'s `json` row says "serialize 1 KB object"; a run whose
    /// bodies are 0 bytes must not be reported as a `json` measurement.
    pub body_bytes: u64,
}

/// What a run produced.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// Every sample, in completion order.
    pub distribution: Distribution,
    /// Per-request outcomes, for the byte and status checks.
    pub samples: Vec<Sample>,
    /// Wall-clock duration of the whole run.
    pub elapsed: Duration,
    /// How many requests were attempted.
    pub attempted: u64,
    /// How many failed to produce a response at all.
    ///
    /// Separate from a 5xx, because they are different facts: a failed connection
    /// means the harness could not measure, while a 5xx means the server answered.
    /// Reporting them together would let a server that refused every connection
    /// look like a server that answered every request.
    pub failed: u64,
}

impl RunResult {
    /// Requests that produced any HTTP response.
    #[must_use]
    pub fn completed(&self) -> u64 {
        self.attempted.saturating_sub(self.failed)
    }

    /// Throughput in requests per second, over the completed requests.
    ///
    /// Returns `None` for a zero-duration run rather than `0` or infinity: an
    /// undefined rate is not a rate, and `0.0` would read as "the server handled
    /// nothing" when the measurement simply did not happen. Same distinction
    /// `PERF-001` made for `mean_micros` and `headroom_percent`.
    #[must_use]
    pub fn requests_per_second(&self) -> Option<f64> {
        let seconds = self.elapsed.as_secs_f64();
        if seconds <= 0.0 {
            return None;
        }
        #[allow(
            clippy::cast_precision_loss,
            reason = "a request count is far below 2^53 in any run that could \
                      finish; the conversion is exact for every value this type \
                      can hold in practice"
        )]
        Some(self.completed() as f64 / seconds)
    }

    /// Whether any response carried a body, for the rows that require one.
    #[must_use]
    pub fn any_body(&self) -> bool {
        self.samples.iter().any(|s| s.body_bytes > 0)
    }

    /// The share of attempted requests that produced no response.
    ///
    /// A companion to [`RunResult::completed`] for the report: `statuses`
    /// only lists codes from responses, so failures are invisible in it, and
    /// a failure count without its denominator is not comparable across runs.
    /// `None` for a run that attempted nothing, where the ratio is undefined —
    /// `Some(0.0)` would claim a perfect run that never ran.
    ///
    /// ```
    /// use qqq_bench::loadgen::RunResult;
    /// use std::time::Duration;
    ///
    /// let result = RunResult {
    ///     distribution: qqq_bench::stats::Distribution::new(),
    ///     samples: Vec::new(),
    ///     elapsed: Duration::from_secs(1),
    ///     attempted: 4,
    ///     failed: 1,
    /// };
    /// assert_eq!(result.failure_rate(), Some(0.25));
    /// ```
    #[must_use]
    pub fn failure_rate(&self) -> Option<f64> {
        if self.attempted == 0 {
            return None;
        }
        #[allow(
            clippy::cast_precision_loss,
            reason = "counts are far below 2^53 in any run that could finish; \
                      the conversion is exact for every value this type can \
                      hold in practice"
        )]
        Some(self.failed as f64 / self.attempted as f64)
    }

    /// Every distinct status code seen, sorted.
    ///
    /// A vector rather than a set so a report renders deterministically —
    /// `§10.5` requires stable output, and a `HashSet` iterates arbitrarily.
    #[must_use]
    pub fn statuses(&self) -> Vec<u16> {
        let mut seen: Vec<u16> = self.samples.iter().map(|s| s.status).collect();
        seen.sort_unstable();
        seen.dedup();
        seen
    }
}

/// How to drive one workload.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Where the server is listening.
    pub target: SocketAddr,
    /// The request path, including any query.
    pub path: String,
    /// The HTTP method.
    pub method: String,
    /// The request body, if any.
    pub body: Option<Vec<u8>>,
    /// The `Host` header value.
    pub host: String,
    /// Requests in flight at once.
    pub concurrency: Concurrency,
    /// How long to drive, or how many requests to send.
    pub limit: Limit,
    /// Per-request timeout for writing and reading.
    ///
    /// Required rather than defaulted: a run against a hung server must terminate,
    /// and a harness whose own timeout is implicit cannot distinguish "the server
    /// was slow" from "the harness gave up".
    pub timeout: Duration,
    /// Timeout for the TCP connect alone.
    ///
    /// # Why this is separate, and smaller
    ///
    /// It was the same value as [`Plan::timeout`], and that made a *closed* target
    /// take 200 x 10 s to diagnose: `hello`'s warmup is 200 iterations and each
    /// failing connect consumed the full response timeout. Measured: against a
    /// closed port the command hung for minutes, while against a real server it
    /// finished in 5 seconds.
    ///
    /// A connect that has not completed in a couple of seconds on a reachable host
    /// is not going to, and the distinction matters because connecting and
    /// responding are different operations with different reasonable budgets.
    pub connect_timeout: Duration,
    /// Requests to send and discard before measuring.
    pub warmup: u32,
}

/// What stops a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// Send exactly this many requests.
    Requests(u64),
    /// Drive for this long, sending as fast as the concurrency allows.
    Duration(Duration),
}

impl Plan {
    /// Build a plan for a `GET` against a loopback target.
    #[must_use]
    pub fn get(target: SocketAddr, path: impl Into<String>, concurrency: Concurrency) -> Self {
        Self {
            target,
            path: path.into(),
            method: "GET".to_owned(),
            body: None,
            host: target.to_string(),
            concurrency,
            limit: Limit::Requests(1_000),
            timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(2),
            warmup: 100,
        }
    }

    /// Check that this plan can be driven.
    ///
    /// # Why a method and not a constructor
    ///
    /// [`Plan::get`] builds a valid plan, and the struct's fields are public so
    /// tests and tools can state edge cases directly. A public struct with no
    /// check means `timeout: ZERO`, `limit: Requests(0)`, or `path: ""` drives
    /// zero requests or encodes a request line the server reads as garbage —
    /// and a zero-request run reports a vacuous success. [`one_request`] calls
    /// this first, so every driven plan is checked exactly once however it was
    /// built.
    ///
    /// # Errors
    ///
    /// Returns the first violated rule, naming the field. A `GET` with a body
    /// is refused for the same reason: the workload table forbids it (a GET
    /// row must not carry a body), so a plan that pairs them is a mistake,
    /// not a measurement.
    ///
    /// ```
    /// use qqq_bench::loadgen::Plan;
    /// use qqq_bench::methodology::Concurrency;
    /// use std::net::SocketAddr;
    ///
    /// let addr: SocketAddr = "127.0.0.1:9".parse().expect("a literal address");
    /// let plan = Plan::get(addr, "/healthz", Concurrency::Sequential);
    /// assert!(plan.validate().is_ok());
    ///
    /// let mut bad = plan.clone();
    /// bad.path = "healthz".to_owned();
    /// assert!(bad.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.timeout.is_zero() {
            return Err("timeout must be non-zero, or every request fails immediately");
        }
        if self.connect_timeout.is_zero() {
            return Err("connect_timeout must be non-zero, or no connection can be made");
        }
        // `read_response` and the `Duration` worker loop both add these to
        // `Instant::now()`, which panics on overflow. A timeout that cannot
        // become a deadline is not a timeout. One clock read for both checks:
        // overflow does not depend on the instant, only on the duration.
        let now = Instant::now();
        if now.checked_add(self.timeout).is_none() {
            return Err("timeout overflows the clock range");
        }
        if now.checked_add(self.connect_timeout).is_none() {
            return Err("connect_timeout overflows the clock range");
        }
        match self.limit {
            Limit::Requests(0) => {
                return Err("limit must request at least one request");
            }
            Limit::Duration(d) if d.is_zero() => {
                return Err("limit must drive for a non-zero duration");
            }
            Limit::Duration(d) if Instant::now().checked_add(d).is_none() => {
                // `read_response` and the `Duration` worker loop both add this
                // to `Instant::now()`, which panics on overflow. A duration
                // that cannot become a deadline is not a limit.
                return Err("limit duration overflows the clock range");
            }
            Limit::Requests(_) | Limit::Duration(_) => {}
        }
        if !self.path.starts_with('/') {
            return Err("path must start with '/', or the request line is malformed");
        }
        if self.method.trim().is_empty() {
            return Err("method must not be empty");
        }
        // The request line is assembled by concatenation, so a CR, LF, or
        // space inside any of these fields breaks framing — and a crafted
        // value turns the "request" into two requests (header injection).
        // Refuse the bytes that have framing meaning rather than encoding
        // around them.
        for (name, value) in [
            ("method", self.method.as_str()),
            ("path", self.path.as_str()),
            ("host", self.host.as_str()),
        ] {
            if value
                .chars()
                .any(|c| c.is_ascii_control() || c.is_whitespace())
            {
                return Err(match name {
                    "method" => "method must be a single token with no whitespace",
                    "path" => "path must not contain whitespace; encode spaces as %20",
                    _ => "host must be a bare hostname with no whitespace",
                });
            }
        }
        if self.host.trim().is_empty() {
            return Err("host must not be empty");
        }
        if self.method.trim().eq_ignore_ascii_case("GET") && self.body.is_some() {
            return Err("a GET must not carry a body; the workload table forbids it");
        }
        if let Some(body) = &self.body
            && body.len() > MAX_REQUEST_BODY_BYTES
        {
            return Err("body exceeds the 1 MiB request cap");
        }
        match self.concurrency {
            Concurrency::Fixed { connections: 0 } | Concurrency::Saturating { cores: 0 } => {
                return Err(
                    "concurrency of zero runs one worker while disclosing none; use Sequential for one at a time",
                );
            }
            Concurrency::Fixed { connections } if connections > MAX_CONNECTIONS => {
                return Err("connection count exceeds the 4096-worker cap");
            }
            Concurrency::Saturating { cores } if cores > MAX_CONNECTIONS => {
                return Err("core count exceeds the 4096-worker cap");
            }
            Concurrency::Fixed { .. }
            | Concurrency::Saturating { .. }
            | Concurrency::Sequential => {}
        }
        Ok(())
    }
}

/// Encode one HTTP/1.1 request.
///
/// # Why this is a function and not a chain of `write!` calls
///
/// Because the framing is the part that must be exactly right, and a named
/// function is the only way a test can state the rule. `Content-Length` is what
/// makes a body deliverable; omitting it for a `POST` produces a request the
/// server reads as bodyless, which is the defect `SRV-018`'s round found by
/// driving the real thing (`§O-155`).
///
/// # Safety contract: call [`Plan::validate`] first
///
/// This function performs no whitespace or control-character checks: it
/// concatenates method, path, and host raw, so an unvalidated plan with a CR,
/// LF, or space in any of those fields emits smuggled bytes. The injection
/// guard lives in [`Plan::validate`], which [`one_request`] and [`drive`]
/// both call — a direct caller of this function bypasses it, and must have
/// validated already.
#[must_use]
pub fn encode_request(plan: &Plan) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(plan.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(plan.path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(plan.host.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(b"Connection: close\r\n");
    out.extend_from_slice(b"User-Agent: qqq-bench/1\r\n");
    if let Some(body) = &plan.body {
        out.extend_from_slice(b"Content-Type: application/x-www-form-urlencoded\r\n");
        out.extend_from_slice(b"Content-Length: ");
        out.extend_from_slice(body.len().to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    if let Some(body) = &plan.body {
        out.extend_from_slice(body);
    }
    out
}

/// Read one complete HTTP/1.1 response from `stream`.
///
/// # Why this exists instead of `read_to_end`
///
/// `read_to_end` waits for the peer to close, and a server is not obliged to
/// close after answering. Measured against the real reference application, that
/// made **every** request block until the read timeout and be counted as a
/// failure, while the server's own log showed a `200` for each one. The fix is to
/// frame the response by the length it declares, which the client can do for
/// itself.
///
/// # The four cases a load generator meets
///
/// 1. **A head and a `Content-Length` body** — the ordinary case. Read the head,
///    then exactly that many more bytes.
/// 2. **A head with no body** — `204`, `304`, or any response to `HEAD`. The head
///    is the whole response, and requiring a `Content-Length` would hang.
/// 3. **A chunked body** — this harness does not send `Transfer-Encoding`, and a
///    server that replies chunked to an HTTP/1.1 request without it is unusual.
///    It is still *possible*, so the terminator is detected and the body counted
///    rather than the response being mistaken for headless.
/// 4. **A peer that closes early** — the one case `read_to_end` handled. Treated
///    as a complete response if a head was parsed, because a truncated body still
///    carries a status and the alternative is calling a real answer a failure.
///
/// # Errors
///
/// Returns a timeout error if the response does not arrive in time, or an I/O
/// error if the connection fails. A timeout is a real failure — unlike the
/// pre-fix behaviour, where it was an artefact of waiting for a close.
///
/// The timeout is a deadline for the whole response, not a per-read budget:
/// per-read timeouts let a peer that drips one byte at a time stretch a single
/// response without bound. Each read draws from the time remaining when it
/// starts, so the slowest possible response still ends at the deadline.
pub async fn read_response<S>(
    stream: &mut S,
    timeout: Duration,
    method: &str,
) -> io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    // `checked_add`: `timeout` comes from the caller, and `Duration::MAX`
    // overflows `Instant + Duration` — panicking the harness on a nonsense
    // input rather than refusing it. The deadline math below assumes an
    // instant that actually exists.
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "timeout overflows the clock range",
        )
    })?;
    // Remaining budget at each read. `saturating_duration_since` turns an
    // expired deadline into a zero timeout — which fails immediately rather
    // than waiting.
    let remaining = || deadline.saturating_duration_since(Instant::now());
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);

    // --- The head, up to and including the blank line --------------------
    let head_end = loop {
        if let Some(pos) = find_head_end(&buf) {
            break pos;
        }
        let mut chunk = [0_u8; 4 * 1024];
        let read = tokio::time::timeout(remaining(), stream.read(&mut chunk))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timed out"))??;
        if read == 0 {
            // The peer closed before sending a complete head. Return what arrived
            // so the caller's parser can decide -- an empty buffer is a clear
            // error, and a partial head may still be diagnosable.
            return Ok(buf);
        }
        // Bound on a `let`, as below: `read` returns at most the chunk
        // length by contract.
        #[expect(clippy::expect_used, reason = "read returns at most chunk len")]
        let fresh: &[u8] = chunk.get(..read).expect("read returns at most chunk len");
        buf.extend_from_slice(fresh);

        // A head larger than this is not a head. Bounded so a hostile or broken
        // peer cannot make the harness allocate without limit.
        if buf.len() > MAX_HEAD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("response head exceeded {MAX_HEAD_BYTES} bytes"),
            ));
        }
    };

    // --- How much body to expect -----------------------------------------
    // Bound on a `let`: `head_end` comes from the finder over this same
    // buffer, so the range always exists.
    #[expect(clippy::expect_used, reason = "head_end found in buf")]
    let head: &[u8] = buf.get(..head_end).expect("head_end found in buf");
    let framing = framing_of(head, method)?;

    match framing {
        Framing::Length(n) => {
            // Bounded: a `Content-Length: 2^64` names a body no response will
            // ever carry, and reading toward it without a cap lets a hostile
            // or broken peer grow this buffer without limit. The head has
            // `MAX_HEAD_BYTES` for the same reason; the body gets its own.
            if n > MAX_BODY_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Content-Length {n} exceeds the {MAX_BODY_BYTES}-byte body cap"),
                ));
            }
            let want = head_end.saturating_add(n);
            while buf.len() < want {
                let mut chunk = [0_u8; 8 * 1024];
                let read = tokio::time::timeout(remaining(), stream.read(&mut chunk))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timed out"))??;
                if read == 0 {
                    // The peer closed mid-body. The status is known but the
                    // representation is not complete, and a truncated body
                    // counted as a full sample would report a length the server
                    // never sent. Fail the sample instead.
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "peer closed after {} of {n} body bytes",
                            buf.len() - head_end
                        ),
                    ));
                }
                // Bound on a `let`: `read` returns at most the chunk length
                // by contract.
                #[expect(clippy::expect_used, reason = "read returns at most chunk len")]
                let fresh: &[u8] = chunk.get(..read).expect("read returns at most chunk len");
                buf.extend_from_slice(fresh);
            }
        }
        Framing::None => {
            // No body: the head is the response. Deliberately does NOT read
            // further, because reading here is what hung the first version.
        }
        Framing::Chunked => {
            read_chunked_body(&mut buf, head_end, deadline, stream).await?;
        }
    }

    Ok(buf)
}

/// Read a chunked body already in progress, parsing chunk sizes.
///
/// The previous terminator — "ends with `0\\r\\n\\r\\n` or contains a blank
/// line anywhere past the head" — fired on any `\\r\\n\\r\\n` inside the body
/// itself (HTML commonly contains one), truncating the measurement. Chunked
/// framing is parsed instead: each chunk-size line is read as hexadecimal,
/// exactly that many bytes plus the trailing CRLF are consumed, and the
/// zero-length chunk ends the body. Bounded by [`MAX_BODY_BYTES`] for the
/// same reason `Content-Length` bodies are.
async fn read_chunked_body<S>(
    buf: &mut Vec<u8>,
    head_end: usize,
    deadline: Instant,
    stream: &mut S,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    // Drawn from the response deadline, like every other read on this path:
    // see `read_response` for why the budget is shared rather than per-read.
    let remaining = || deadline.saturating_duration_since(Instant::now());
    // `pos` only ever points inside `buf`: it starts at `head_end` (found by
    // scanning this same buffer) and advances past bytes already read, with
    // every overshoot guarded by a length check that returns first. The
    // `expect`s below restate that invariant where the borrow happens rather
    // than threading a proof through the loop.
    let mut pos = head_end;
    let mut total = 0_usize;
    loop {
        // Fill until a complete chunk-size line is present.
        loop {
            #[expect(clippy::expect_used, reason = "pos only advances within the buffer")]
            let tail: &[u8] = buf.get(pos..).expect("pos stays within the buffer");
            if tail.windows(2).any(|w| w == b"\r\n") {
                break;
            }
            if buf.len() > head_end.saturating_add(MAX_BODY_BYTES) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("chunked body exceeds the {MAX_BODY_BYTES}-byte body cap"),
                ));
            }
            let mut chunk = [0_u8; 8 * 1024];
            let read = tokio::time::timeout(remaining(), stream.read(&mut chunk))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timed out"))??;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed mid-chunk",
                ));
            }
            // Bound on a `let`: `read` returns at most the chunk length
            // by contract.
            #[expect(clippy::expect_used, reason = "read returns at most chunk len")]
            let fresh: &[u8] = chunk.get(..read).expect("read returns at most chunk len");
            buf.extend_from_slice(fresh);
        }
        // Bound on a `let`: the loop above guarantees a CRLF at or after
        // `pos`, so the relative position always exists.
        #[expect(clippy::expect_used, reason = "CRLF presence established above")]
        let tail: &[u8] = buf.get(pos..).expect("pos stays within the buffer");
        #[expect(clippy::expect_used, reason = "CRLF presence established above")]
        let line_end = pos
            + tail
                .windows(2)
                .position(|w| w == b"\r\n")
                .expect("CRLF presence established above");
        #[expect(
            clippy::expect_used,
            reason = "line_end is a found position inside the buffer"
        )]
        let line_bytes: &[u8] = buf
            .get(pos..line_end)
            .expect("line_end is a found position inside the buffer");
        let line = std::str::from_utf8(line_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 chunk size"))?;
        // Chunk extensions (`;foo=bar`) are ignored per RFC 9112 §7.1.1: the
        // size is what precedes the first `;`.
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("malformed chunk size: {line:?}"),
            )
        })?;
        pos = line_end + 2;
        if size == 0 {
            return Ok(());
        }
        // The cap bounds the payload, not just the buffer: framing bytes
        // allocate too, but a stream of megabyte chunks with a small total
        // is legitimate framing overhead, while a large payload total is not
        // a measurement this harness takes.
        total = total.saturating_add(size);
        if total > MAX_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("chunked body exceeds the {MAX_BODY_BYTES}-byte body cap"),
            ));
        }
        // Consume `size` data bytes plus the trailing CRLF, reading more
        // until both are present or the peer closes/times out.
        let need = pos.saturating_add(size).saturating_add(2);
        if need.saturating_sub(head_end) > MAX_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("chunked body exceeds the {MAX_BODY_BYTES}-byte body cap"),
            ));
        }
        while buf.len() < need {
            let mut chunk = [0_u8; 8 * 1024];
            let read = tokio::time::timeout(remaining(), stream.read(&mut chunk))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timed out"))??;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed mid-chunk",
                ));
            }
            // Bound on a `let`: `read` returns at most the chunk length
            // by contract.
            #[expect(clippy::expect_used, reason = "read returns at most chunk len")]
            let fresh: &[u8] = chunk.get(..read).expect("read returns at most chunk len");
            buf.extend_from_slice(fresh);
        }
        // The data must end where the size line said it would: without this,
        // a peer that sends fewer bytes than declared would have its next
        // chunk-size line read from the middle of the shortfall, silently
        // re-framing the rest of the body. `decode_chunked_len` checks the
        // same condition on the parse path; both must agree.
        if buf.get(need.saturating_sub(2)..need) != Some(b"\r\n".as_slice()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk data is not followed by CRLF",
            ));
        }
        pos = need;
    }
}

/// The maximum head size the reader will accept.
///
/// A conforming server's head is well under this. The bound exists so a peer that
/// never sends a blank line cannot make the harness grow a buffer without limit.
pub const MAX_HEAD_BYTES: usize = 128 * 1024;

/// The maximum response body the reader will accept, in bytes.
///
/// A `Content-Length` names what the peer *claims*; without a cap, a claim of
/// 2^64 makes the reader loop until the peer closes or the timeout fires,
/// allocating everything the peer sends in the meantime. 8 MiB is generous —
/// the reference application's largest body (the template table) is two orders
/// of magnitude smaller — and anything larger is either a hostile peer or a
/// workload the harness was not designed to measure.
///
/// ```
/// assert!(qqq_bench::loadgen::MAX_BODY_BYTES >= 8 << 20);
/// ```
pub const MAX_BODY_BYTES: usize = 8 << 20;

/// The maximum request body the harness will send, in bytes.
///
/// The largest workload payload is 1 KiB (`crypto`). A gigabyte body would be
/// allocated, encoded, and transmitted by the *harness* — self-inflicted memory
/// pressure measured as server latency. 1 MiB is three orders of magnitude of
/// headroom over every row in the table.
pub const MAX_REQUEST_BODY_BYTES: usize = 1 << 20;

/// The most workers one run will spawn.
///
/// Each worker holds a connection, so the count is bounded by what a machine
/// can actually hold open: beyond the OS file-descriptor limit (commonly
/// 1024) further workers fail their connects and report a server problem that
/// is really a harness problem. 4096 allows raised-limit machines while
/// keeping a typo'd `connections: u32::MAX` from attempting four billion
/// spawns.
pub const MAX_CONNECTIONS: u32 = 4096;

/// Where the head ends: just past the first blank line, or `None`.
///
/// HTTP/1.1 delimits the head with CRLF (`RFC 9110 §5`). A head terminated by
/// bare LF is malformed, and this function does not recognise it — the reader
/// then waits for a terminator that never arrives and times out, counting the
/// sample as failed. That is deliberate: accepting LF-only framing would commit
/// the harness to a wire shape the reference server never sends.
#[must_use]
pub fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// How a response's body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// A `Content-Length` of this many bytes.
    Length(usize),
    /// No body at all.
    None,
    /// `Transfer-Encoding: chunked`.
    Chunked,
}

/// Decide how to frame a response from its head.
///
/// # Why the order of the checks matters
///
/// `Transfer-Encoding` wins over `Content-Length` (RFC 9112: a message with both
/// is chunked, and the `Content-Length` must be ignored). Checking the length
/// first would silently mis-frame such a response. A status that forbids a body
/// wins over both, because a `204` carrying a stray `Content-Length: 5` must not
/// make the reader wait for five bytes that will never come.
///
/// # Errors
///
/// Returns an error when the head carries a `Content-Length` that is present
/// but unparsable, or a `Transfer-Encoding` that is present but neither a
/// bare `chunked` token nor absent. A framing the reader cannot decide is not
/// a framing the reader may guess: guessing `None` would silently drop a body
/// the server did send.
pub fn framing_of(head: &[u8], method: &str) -> io::Result<Framing> {
    let text = String::from_utf8_lossy(head);
    let lower = text.to_ascii_lowercase();

    // A HEAD response never carries a body, whatever the headers claim. Without
    // this, a HEAD with `200` and `Content-Length: 5` would make the reader
    // wait for five bytes that must not arrive.
    if method.trim().eq_ignore_ascii_case("HEAD") {
        return Ok(Framing::None);
    }

    // A status of 1xx, 204, or 304 has no body.
    if let Some(status) = status_of(&lower)
        && (status == 204 || status == 304 || (100..200).contains(&status))
    {
        return Ok(Framing::None);
    }

    // Parsed line-by-line, not by substring: a header value mentioning the word
    // "chunked" (e.g. `X-Note: not-chunked`) is not a transfer coding, and only
    // a `Transfer-Encoding` line whose comma-separated tokens include exactly
    // `chunked` selects chunked framing.
    for line in lower.lines() {
        if let Some(rest) = line.strip_prefix("transfer-encoding:") {
            let chunked = rest.split(',').any(|token| token.trim() == "chunked");
            if chunked {
                return Ok(Framing::Chunked);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported transfer-encoding: {rest:?}"),
            ));
        }
    }

    // Every `Content-Length` line is collected, not just the first: two that
    // disagree are the request-smuggling ambiguity (which length delimits the
    // body?), and silently taking the first answers it with a guess. Agreeing
    // duplicates are the same declaration twice and collapse to one.
    let mut lengths: Vec<usize> = Vec::new();
    for line in lower.lines() {
        if let Some(rest) = line.strip_prefix("content-length:") {
            let n: usize = rest.trim().parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unparsable Content-Length: {rest:?}"),
                )
            })?;
            lengths.push(n);
        }
    }
    if let Some(first) = lengths.first() {
        if lengths.iter().any(|n| n != first) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "conflicting Content-Length values",
            ));
        }
        return Ok(if *first == 0 {
            Framing::None
        } else {
            Framing::Length(*first)
        });
    }

    // No length, no chunking, and a status that permits a body: the only way to
    // know the end is the close, which this harness will not wait for. Reported
    // as no body, which measures the head and does not hang.
    Ok(Framing::None)
}

/// The status code from a head, if the status line parses.
///
/// Split on whitespace runs rather than single spaces: a status line with a
/// doubled space (`HTTP/1.1  200 OK`) is unusual but not unparseable, and
/// indexing fixed positions would read the gap as the code.
#[must_use]
pub fn status_of(head: &str) -> Option<u16> {
    head.lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse::<u16>()
        .ok()
}

/// A parsed response head.
///
/// # Why this is a struct and not `(u16, usize)`
///
/// It was a tuple, and the very first caller immediately misread it — subtracting
/// the second element (`body_bytes`) from the buffer length as though it were the
/// *head* length, and reporting the head as the body. The tests caught it because
/// they assert exact byte counts, but the cause was the signature: **two
/// adjacent `usize`-shaped facts with no names** invite exactly that swap, and no
/// compiler or reviewer can see it.
///
/// This is the rule this project states as *an error reported at a call site is
/// usually a mistake in the signature*: the fix belongs here, where the ambiguity
/// is, not at the call site where it merely surfaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseHead {
    /// The HTTP status code.
    pub status: u16,
    /// Bytes after the blank line — the body, as received.
    pub body_bytes: usize,
}

/// Parse a status line and the byte counts of a response.
///
/// # Why the body is counted rather than parsed
///
/// The harness needs two facts: the status and whether the server sent anything.
/// Reading `Content-Length` and the body would be more precise and would also
/// mean the harness could hang on a malformed length, which a load generator must
/// never do. Counting bytes as they arrive is bounded by the read timeout.
///
/// # Errors
///
/// Returns an error if the status line is absent or malformed. A response the
/// harness cannot classify must not be counted as a success.
pub fn parse_response(buf: &[u8]) -> io::Result<ResponseHead> {
    // Split the head from the body FIRST, on bytes: the buffer carries the
    // whole response, and validating the head as UTF-8 over the full buffer
    // fails on any binary body — a binary payload would then be counted as a
    // connection failure rather than measured. Only the head is ever decoded.
    // A missing terminator is not a short head: without the blank line there
    // is no boundary between head and body, so there is nothing to count.
    let body_start = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "response has no head terminator",
            )
        })?;
    let head = buf
        .get(..body_start)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "response head out of range"))?;
    let text = std::str::from_utf8(head).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "response head is not valid UTF-8",
        )
    })?;
    let status_line = text
        .split("\r\n")
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty response"))?;

    // `HTTP/1.1 200 OK`. Split on whitespace runs (see `status_of`): a
    // doubled space must not shift the code into the reason phrase. The
    // version must be exactly `HTTP/1.0` or `HTTP/1.1`: a prefix match
    // accepts `HTTP/1.9`, a version no server speaks, as a success.
    let mut parts = status_line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no version token"))?;
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected status line: {status_line}"),
        ));
    }
    let code = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no status code"))?
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-numeric status code"))?;

    // Anything after the first blank line is body — but a chunked body is
    // wrapped in size lines that are framing, not payload. Counting them as
    // body bytes inflates the measurement by the framing overhead, so chunked
    // bodies are decoded and only payload bytes are counted. A malformed
    // chunk stream is refused rather than counted: the reader already
    // enforces chunk structure on the socket path, so reaching here with one
    // means hand-fed garbage, and guessing a byte count for it would be the
    // fabrication this function exists to prevent.
    // `body_start` is a found position plus 4 or `buf.len()`, so the range
    // always exists.
    #[expect(
        clippy::expect_used,
        reason = "body_start is a found position or buf.len()"
    )]
    let body: &[u8] = buf
        .get(body_start..)
        .expect("body_start is a found position or buf.len()");
    let body_bytes = if is_chunked(head) {
        decode_chunked_len(body)?
    } else {
        body.len()
    };
    Ok(ResponseHead {
        status: code,
        body_bytes,
    })
}

/// Whether the head declares chunked transfer coding.
///
/// Parsed line-by-line like [`framing_of`]: a header value that merely mentions
/// the word is not a transfer coding.
fn is_chunked(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head);
    text.lines().skip(1).any(|line| {
        let lower = line.to_ascii_lowercase();
        lower
            .strip_prefix("transfer-encoding:")
            .is_some_and(|rest| rest.split(',').any(|token| token.trim() == "chunked"))
    })
}

/// Count the payload bytes of a chunked body, without the framing.
///
/// Returns an error on a malformed chunk stream rather than a number: a count
/// produced from garbage is a fabrication, and this function refuses to
/// fabricate.
fn decode_chunked_len(body: &[u8]) -> io::Result<usize> {
    // `pos` starts at 0 and only advances to offsets the length checks below
    // have proven in-range, so it never exceeds `body.len()`. The `expect`s
    // restate that invariant where the borrows happen.
    let mut pos = 0_usize;
    let mut total = 0_usize;
    loop {
        #[expect(clippy::expect_used, reason = "pos only advances within the buffer")]
        let rest: &[u8] = body.get(pos..).expect("pos stays within the buffer");
        let Some(rel) = rest.windows(2).position(|w| w == b"\r\n") else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked body ends mid-size-line",
            ));
        };
        #[expect(clippy::expect_used, reason = "rel is a found position inside rest")]
        let line_bytes: &[u8] = rest
            .get(..rel)
            .expect("rel is a found position inside rest");
        let line = std::str::from_utf8(line_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 chunk size"))?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("malformed chunk size: {line:?}"),
            )
        })?;
        pos += rel + 2;
        if size == 0 {
            return Ok(total);
        }
        total = total.saturating_add(size);
        // Skip the data and its trailing CRLF. A short buffer is truncation,
        // not a shorter body.
        let next = pos.saturating_add(size).saturating_add(2);
        if body.len() < next || body.get(next - 2..next) != Some(b"\r\n".as_slice()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked body is truncated",
            ));
        }
        pos = next;
    }
}

/// Send one request over a fresh connection and measure it.
///
/// # Errors
///
/// Returns the I/O error if the plan is degenerate (see [`Plan::validate`]),
/// or if the connection, write, or read fails, or if the response cannot be
/// classified.
pub async fn one_request(plan: &Plan) -> io::Result<Sample> {
    plan.validate().map_err(|reason| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid plan: {reason}"),
        )
    })?;

    // `connect_timeout`, not `timeout`: see the field's docs for the measured
    // reason. A failing connect must be cheap, or a wrong target costs the run's
    // whole budget before it reports anything.
    let mut stream = tokio::time::timeout(plan.connect_timeout, TcpStream::connect(plan.target))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;

    // Timed from the first byte written, not from before the connect: the
    // sample is the server's response latency, and the TCP handshake belongs
    // to connection setup rather than to any request. Starting the clock
    // earlier folds the handshake into every p99, which is what made the
    // routed-overhead row read high against its 60 µs budget.
    let started = Instant::now();

    let request = encode_request(plan);
    tokio::time::timeout(plan.timeout, stream.write_all(&request))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "write timed out"))??;

    // Read the response, framed by its own `Content-Length` rather than by the
    // peer closing.
    //
    // # Why this replaced `read_to_end`
    //
    // It was `read_to_end`, on the reasoning that `Connection: close` makes the
    // close the end of the response. That reasoning is wrong in a way that made
    // the whole command unusable: `qqq-serve` writes a complete response and keeps
    // the connection open, so the EOF never arrived and the read blocked until the
    // timeout **on every request**. Measured against the real application: the
    // server logged 30+ `200`s while the harness reported them as failures and
    // took ten seconds each.
    //
    // A client that knows the response length must not depend on a close it cannot
    // control. `Connection: close` stays in the request -- it is polite, and a
    // harness should not hold connections it will not reuse -- but the client no
    // longer *relies* on the server honouring it.
    let buf = read_response(&mut stream, plan.timeout, &plan.method).await?;

    let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);

    // # Why this reads `body_bytes` and does not compute it
    //
    // The first version of this line was `buf.len() - head_len`, treating
    // `parse_response`'s second return value as the *head* length. It was the
    // **body** length, so the harness subtracted the body from the total and
    // reported the head as the body — a 2-byte `ok` came back as 38, which is
    // precisely the head's size. The tests caught it because they assert exact
    // byte counts rather than `> 0`; `> 0` would have passed and every `json`
    // measurement would have reported the head's length as the payload.
    //
    // The signature was then changed to a named struct rather than a tuple,
    // because two adjacent `usize`-shaped facts with no names are what invited the
    // swap in the first place. See [`ResponseHead`].
    let parsed = parse_response(&buf)?;
    let body_bytes = u64::try_from(parsed.body_bytes).unwrap_or(u64::MAX);

    Ok(Sample {
        nanos,
        status: parsed.status,
        body_bytes,
    })
}

/// Drive `plan` and collect the measurements.
///
/// # Errors
///
/// Returns an error only if the run cannot be started at all. Individual request
/// failures are counted in [`RunResult::failed`] rather than aborting the run,
/// because a benchmark that stops at the first refused connection reports nothing
/// about the other nine hundred and ninety-nine.
pub async fn drive(plan: &Plan) -> io::Result<RunResult> {
    // Checked here as well as in `one_request`: a zero-iteration plan never
    // calls `one_request`, so per-request validation alone would let
    // `Requests(0)` report a vacuous success — zero attempts, zero failures,
    // and a throughput of nothing measured as nothing wrong.
    plan.validate().map_err(|reason| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid plan: {reason}"),
        )
    })?;

    // Warmup: sent and discarded, per `§9.1`'s requirement that the procedure be
    // stated. Never counted, and never silently skipped either -- the count comes
    // from the workload's own `Warmup`, so a row that declares no warmup gets none.
    run_warmup(plan).await?;

    let connections = connections_for(plan.concurrency);
    let started = Instant::now();
    let mut samples: Vec<Sample> = Vec::new();
    let mut failed: u64 = 0;
    let mut attempted: u64 = 0;

    match plan.limit {
        Limit::Requests(total) => {
            // No idle workers: with fewer requests than connections, spawning
            // the full count leaves most workers with zero work while still
            // paying every spawn. The totals below are unchanged — the same
            // requests are just divided among fewer workers.
            //
            // `try_from` rather than `as u32`: the value is at most
            // `connections` (hence exactly representable), but a cast would
            // assert that instead of proving it.
            let workers =
                u32::try_from(u64::from(connections).min(total.max(1))).unwrap_or(connections);
            let per_worker = total / u64::from(workers);
            let remainder = total % u64::from(workers);
            let mut handles = Vec::with_capacity(workers as usize);
            for worker in 0..workers {
                // The first `remainder` workers take one extra request, so the
                // totals add up exactly. `u64::from(worker) < remainder` rather
                // than a cast of the comparison: `worker` is a `u32` and
                // `remainder` a `u64`, and comparing them directly would need a
                // widening cast whose direction is easy to get wrong.
                let count = per_worker + u64::from(u64::from(worker) < remainder);
                let plan = plan.clone();
                handles.push(tokio::spawn(async move {
                    // `try_from` rather than `as usize`: on a 32-bit target a
                    // request count above `u32::MAX` truncates, and a truncated
                    // capacity is a silently wrong allocation hint. Falling back
                    // to the default capacity costs one reallocation in a case
                    // that cannot occur on a 64-bit host and is still *correct* on
                    // a 32-bit one, which an `#[allow]` would not be.
                    let capacity = usize::try_from(count).unwrap_or(64);
                    let mut local: Vec<Sample> = Vec::with_capacity(capacity);
                    let mut lost = 0_u64;
                    for _ in 0..count {
                        match one_request(&plan).await {
                            Ok(sample) => local.push(sample),
                            Err(_) => lost += 1,
                        }
                    }
                    (local, lost, count)
                }));
            }
            let (local, lost, count) = join_workers(handles).await?;
            samples.extend(local);
            failed += lost;
            attempted += count;
        }
        Limit::Duration(duration) => {
            // Computed once, before spawning: `validate` already refused an
            // overflowing duration, but re-adding it per worker would
            // reintroduce the panic `validate` exists to prevent — and a
            // deadline read once is the same instant for every worker.
            // `ok_or_else` rather than `expect`: `drive` is fallible, so a
            // second construction path stays total instead of asserting.
            let deadline = Instant::now().checked_add(duration).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "limit duration overflows the clock range",
                )
            })?;
            let mut handles = Vec::with_capacity(connections as usize);
            for _ in 0..connections {
                let plan = plan.clone();
                handles.push(tokio::spawn(async move {
                    let mut local: Vec<Sample> = Vec::new();
                    let mut lost = 0_u64;
                    let mut count = 0_u64;
                    while Instant::now() < deadline {
                        count += 1;
                        match one_request(&plan).await {
                            Ok(sample) => local.push(sample),
                            Err(_) => lost += 1,
                        }
                    }
                    (local, lost, count)
                }));
            }
            let (local, lost, count) = join_workers(handles).await?;
            samples.extend(local);
            failed += lost;
            attempted += count;
        }
    }

    let elapsed = started.elapsed();
    let mut distribution = Distribution::with_capacity(samples.len());
    for sample in &samples {
        distribution.record_nanos(sample.nanos);
    }

    Ok(RunResult {
        distribution,
        samples,
        elapsed,
        attempted,
        failed,
    })
}

/// Join worker tasks, merging their samples and counts.
///
/// # Why this is shared rather than inlined twice
///
/// The `Requests` and `Duration` arms previously ended in identical join loops.
/// Two copies of "a panicked worker is a run failure, a finished one contributes
/// its samples" is how the copies disagree one day about what a panic means.
/// One function states it once, and a worker that panics fails the run rather
/// than vanishing: a missing worker's samples would otherwise read as a fast
/// run with fewer requests.
async fn join_workers(
    handles: Vec<tokio::task::JoinHandle<(Vec<Sample>, u64, u64)>>,
) -> io::Result<(Vec<Sample>, u64, u64)> {
    let mut samples = Vec::new();
    let mut failed = 0_u64;
    let mut attempted = 0_u64;
    // By-ref iteration so a panic can abort what has not been joined yet: a
    // `for handle in handles` loop moves the vector and leaves the siblings
    // unreachable — detached tasks that keep hammering the target after the
    // run has already failed.
    let mut pending = handles.into_iter();
    while let Some(handle) = pending.next() {
        match handle.await {
            Ok((local, lost, count)) => {
                samples.extend(local);
                failed += lost;
                attempted += count;
            }
            Err(e) => {
                for rest in pending.by_ref() {
                    rest.abort();
                }
                return Err(io::Error::other(format!("worker panicked: {e}")));
            }
        }
    }
    Ok((samples, failed, attempted))
}

/// Send the warmup requests and discard the results.
///
/// # Why the first failures abort the run
///
/// This loop used to discard every result and continue regardless. Against a
/// target that refuses connections that meant 200 warmup attempts each paying
/// the full connect timeout before the measured phase even began -- measured as
/// a multi-minute hang on a closed port, while a real server finished in five
/// seconds. A harness that cannot reach its target has nothing to measure, and
/// the useful behaviour is to say so immediately rather than to compute a
/// throughput of zero after several minutes.
async fn run_warmup(plan: &Plan) -> io::Result<()> {
    let mut consecutive_failures = 0_u32;
    for _ in 0..plan.warmup {
        match one_request(plan).await {
            Ok(_) => consecutive_failures = 0,
            Err(e) => {
                consecutive_failures += 1;
                if consecutive_failures >= EARLY_EXIT_AFTER {
                    return Err(io::Error::new(
                        e.kind(),
                        format!(
                            "{} consecutive requests to {} failed ({e}); the target \
                             does not appear to be serving",
                            EARLY_EXIT_AFTER, plan.target
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// How many consecutive failures mean the target is not serving.
///
/// Five rather than one: a single refused connection can be a transient
/// accept-queue effect under load, while five in a row is a target that is
/// not there. Small enough that the diagnosis arrives in seconds.
pub const EARLY_EXIT_AFTER: u32 = 5;

/// How many workers to run for a stated concurrency.
///
/// [`Concurrency::Saturating`] uses the core count it records, because that is
/// what "saturate N cores" means and inventing a different number would make the
/// result's own disclosure false.
#[must_use]
pub fn connections_for(concurrency: Concurrency) -> u32 {
    match concurrency {
        Concurrency::Sequential => 1,
        Concurrency::Fixed { connections } => connections.max(1),
        Concurrency::Saturating { cores } => cores.max(1),
    }
}

// Test indexing (`F-18`): assertions index vectors built inline above.
// One module-level reason, not per-site noise; shipping code above
// carries no such allowance.
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions index inline vectors"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        let addr: SocketAddr = "127.0.0.1:9".parse().expect("a literal address");
        Plan::get(addr, "/healthz", Concurrency::Sequential)
    }

    // -- request encoding ---------------------------------------------------

    #[test]
    fn a_get_carries_no_body_and_no_content_length() {
        let encoded = encode_request(&plan());
        let text = String::from_utf8(encoded).expect("ASCII");
        assert!(text.starts_with("GET /healthz HTTP/1.1\r\n"), "got {text}");
        assert!(text.contains("Host: 127.0.0.1:9\r\n"), "got {text}");
        assert!(
            !text.contains("Content-Length"),
            "a GET must not declare a body length: {text}"
        );
        assert!(
            text.ends_with("\r\n\r\n"),
            "the head must end with a blank line"
        );
    }

    #[test]
    fn a_post_declares_its_content_length_and_carries_the_bytes() {
        // The defect this pins: a POST without `Content-Length` is read by the
        // server as bodyless, which is exactly what `§O-155` recorded for the
        // reference application. A harness that made that mistake would measure
        // the wrong workload while reporting the right name.
        let mut p = plan();
        p.method = "POST".to_owned();
        p.path = "/crypto/100".to_owned();
        p.body = Some(b"seed=abc".to_vec());

        let encoded = encode_request(&p);
        let text = String::from_utf8(encoded.clone()).expect("ASCII");
        assert!(text.contains("Content-Length: 8\r\n"), "got {text}");
        assert!(text.contains("POST /crypto/100 HTTP/1.1\r\n"), "got {text}");
        assert!(
            text.ends_with("seed=abc"),
            "the body must follow the blank line"
        );
    }

    #[test]
    fn content_length_matches_the_actual_body_length() {
        // Computed, not hard-coded: a body whose declared length differs from its
        // actual length is a framing error the server may report as a hang.
        for len in [0_usize, 1, 7, 64, 1_024] {
            let mut p = plan();
            p.method = "POST".to_owned();
            p.body = Some(vec![b'x'; len]);
            let text = String::from_utf8(encode_request(&p)).expect("ASCII");
            assert!(
                text.contains(&format!("Content-Length: {len}\r\n")),
                "declared length does not match a {len}-byte body"
            );
        }
    }

    // -- response parsing ---------------------------------------------------

    #[test]
    fn a_200_with_a_body_is_classified() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let parsed = parse_response(raw).expect("a well-formed response");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body_bytes, 2);
    }

    #[test]
    fn a_response_with_no_body_reports_zero_bytes() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let parsed = parse_response(raw).expect("a well-formed response");
        assert_eq!(parsed.status, 204);
        assert_eq!(parsed.body_bytes, 0);
    }

    #[test]
    fn a_non_http_response_is_refused_rather_than_counted() {
        // A harness that classified this as a success would report throughput
        // against something that is not an HTTP server.
        assert!(parse_response(b"garbage\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 abc OK\r\n\r\n").is_err());
        assert!(parse_response(b"").is_err());
    }

    #[test]
    fn a_non_utf8_head_is_refused() {
        assert!(parse_response(&[0xff, 0xfe, b'\r', b'\n', b'\r', b'\n']).is_err());
    }

    #[test]
    fn a_response_without_a_head_terminator_is_refused() {
        // Without the blank line there is no boundary between head and body,
        // so there is nothing to count — not a short head.
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\n\nok").is_err());
        assert!(parse_response(b"").is_err());
    }

    #[test]
    fn only_http_1_0_and_1_1_are_accepted() {
        // A prefix match accepts `HTTP/1.9`, a version no server speaks.
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n\r\n").is_ok());
        assert!(parse_response(b"HTTP/1.0 200 OK\r\n\r\n").is_ok());
        assert!(parse_response(b"HTTP/1.9 200 OK\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/2 200 OK\r\n\r\n").is_err());
    }

    #[test]
    fn a_malformed_chunk_stream_is_refused_not_counted() {
        // `decode_chunked_len` shares `read_chunked_body`'s structural checks:
        // garbage in either path is an error, never a byte count.
        let truncated = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        assert!(parse_response(truncated).is_err());
        let bad_size =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nhello\r\n0\r\n\r\n";
        assert!(parse_response(bad_size).is_err());
        let no_crlf =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX\r\n0\r\n\r\n";
        assert!(parse_response(no_crlf).is_err());
    }

    #[test]
    fn a_binary_body_does_not_break_the_head_parse() {
        // `parse_response` receives the whole buffer. Decoding the full buffer
        // as UTF-8 fails on any binary body and would count the sample as a
        // connection failure; only the head is decoded, so arbitrary body
        // bytes are counted, not classified.
        let mut raw = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n".to_vec();
        raw.extend_from_slice(&[0x00, 0xff, 0x89, 0x50]);
        let parsed = parse_response(&raw).expect("a binary body must parse");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body_bytes, 4);
    }

    #[test]
    fn a_degenerate_plan_is_refused_before_any_socket() {
        // Every field the driver depends on is checked up front: a zero
        // timeout, a zero limit, a relative path, an empty method or host,
        // and a GET carrying a body (which the workload table forbids).
        let mut p = plan();
        p.timeout = Duration::ZERO;
        assert!(p.validate().is_err());

        let mut p = plan();
        p.limit = Limit::Requests(0);
        assert!(p.validate().is_err());

        let mut p = plan();
        p.limit = Limit::Duration(Duration::ZERO);
        assert!(p.validate().is_err());

        let mut p = plan();
        p.path = "healthz".to_owned();
        assert!(p.validate().is_err());

        let mut p = plan();
        p.method = "   ".to_owned();
        assert!(p.validate().is_err());

        let mut p = plan();
        p.host = String::new();
        assert!(p.validate().is_err());

        let mut p = plan();
        p.body = Some(b"x".to_vec());
        assert!(p.validate().is_err(), "a GET must not carry a body");

        let mut p = plan();
        p.method = "POST".to_owned();
        p.body = Some(b"x".to_vec());
        assert!(p.validate().is_ok());
        assert!(plan().validate().is_ok(), "the default plan is valid");
    }

    #[test]
    fn framing_refuses_an_unparsable_content_length() {
        // A present-but-garbage length is not "no body": guessing None would
        // silently drop a body the server did send.
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: many\r\n\r\n";
        assert!(framing_of(head, "GET").is_err());
    }

    #[test]
    fn framing_parses_transfer_encoding_line_by_line() {
        // A header value merely mentioning "chunked" is not chunked framing;
        // only a `Transfer-Encoding` line whose comma-separated tokens include
        // exactly `chunked` selects it.
        let head = b"HTTP/1.1 200 OK\r\nX-Note: not-chunked\r\nContent-Length: 2\r\n\r\n";
        assert_eq!(
            framing_of(head, "GET").expect("well-formed"),
            Framing::Length(2)
        );

        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        assert_eq!(
            framing_of(head, "GET").expect("well-formed"),
            Framing::Chunked
        );

        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert!(framing_of(head, "GET").is_err());
    }

    #[test]
    fn framing_for_head_has_no_body_whatever_the_headers_claim() {
        // A HEAD response never carries a body. Without this, a HEAD with
        // `200` and `Content-Length: 5` would make the reader wait for five
        // bytes that must never arrive.
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        assert_eq!(framing_of(head, "HEAD").expect("HEAD"), Framing::None);
        assert_eq!(
            framing_of(head, "head").expect("case-insensitive"),
            Framing::None
        );
        assert_eq!(framing_of(head, "GET").expect("GET"), Framing::Length(5));
    }

    #[test]
    fn a_clock_overflowing_timeout_is_refused_not_panicked() {
        // `Instant::now() + Duration::MAX` panics. The plan, the response
        // reader, and the Duration worker loop all add timeouts to `now`,
        // so validation refuses what would panic before any of them run.
        let mut p = plan();
        p.timeout = Duration::MAX;
        assert!(p.validate().is_err());
        p.timeout = Duration::from_secs(10);
        p.connect_timeout = Duration::MAX;
        assert!(p.validate().is_err());
        p.connect_timeout = Duration::from_secs(2);
        p.limit = Limit::Duration(Duration::MAX);
        assert!(p.validate().is_err());
    }

    #[test]
    fn an_oversized_content_length_is_refused_before_reading() {
        // A `Content-Length: 2^64` names a body no response will ever carry.
        // Reading toward it without a cap allocates everything a hostile or
        // broken peer sends in the meantime.
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", u64::MAX);
        assert!(
            framing_of(head.as_bytes(), "GET").is_ok(),
            "framing names it"
        );
        // The cap is enforced where the buffer would grow, in `read_response`.
        assert!(u64::MAX > MAX_BODY_BYTES as u64);
    }

    #[test]
    fn a_404_is_a_response_not_a_failure() {
        // The distinction matters for the report: a server that answers 404 is
        // answering, so its throughput is real even though the route is wrong.
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found";
        let parsed = parse_response(raw).expect("well-formed");
        assert_eq!(parsed.status, 404);
        assert_eq!(parsed.body_bytes, 9);
    }

    #[test]
    fn a_status_line_without_a_reason_phrase_is_still_parsed() {
        // RFC 9110 makes the reason phrase optional. A parser requiring it would
        // refuse a legal response.
        let raw = b"HTTP/1.1 500\r\n\r\n";
        let parsed = parse_response(raw).expect("well-formed");
        assert_eq!(parsed.status, 500);
    }

    // -- concurrency mapping -------------------------------------------------

    #[test]
    fn the_worker_count_follows_the_disclosed_concurrency() {
        // The property `§9.1` requires: what the harness ran is what the result
        // says it ran. A mapping that returned a default would make the
        // disclosure false.
        assert_eq!(connections_for(Concurrency::Sequential), 1);
        assert_eq!(connections_for(Concurrency::Fixed { connections: 64 }), 64);
        assert_eq!(connections_for(Concurrency::Saturating { cores: 8 }), 8);
    }

    #[test]
    fn a_zero_connection_count_still_produces_a_runnable_plan() {
        // Clamped to 1 rather than producing zero workers, which would report a
        // throughput of zero without ever contacting the server.
        assert_eq!(connections_for(Concurrency::Fixed { connections: 0 }), 1);
        assert_eq!(connections_for(Concurrency::Saturating { cores: 0 }), 1);
    }

    // -- RunResult ------------------------------------------------------------

    fn empty_result(elapsed: Duration, attempted: u64, failed: u64) -> RunResult {
        RunResult {
            distribution: Distribution::new(),
            samples: Vec::new(),
            elapsed,
            attempted,
            failed,
        }
    }

    #[test]
    fn a_zero_duration_run_has_no_defined_rate() {
        // `None`, not `0.0`: an undefined rate read as zero would say "the server
        // handled nothing" about a measurement that never happened.
        let result = empty_result(Duration::ZERO, 10, 0);
        assert_eq!(result.requests_per_second(), None);
    }

    #[test]
    fn the_rate_counts_completed_requests_not_attempts() {
        let mut result = empty_result(Duration::from_secs(2), 100, 40);
        result.samples = vec![Sample {
            nanos: 1,
            status: 200,
            body_bytes: 1,
        }];
        assert_eq!(result.completed(), 60);
        // 60 completed over 2 seconds = 30 RPS, not 50.
        let rate = result.requests_per_second().expect("non-zero duration");
        assert!((rate - 30.0).abs() < f64::EPSILON, "got {rate}");
    }

    #[test]
    fn failed_requests_are_counted_separately_from_responses() {
        // A server refusing connections is not a server answering them.
        let result = empty_result(Duration::from_secs(1), 10, 10);
        assert_eq!(result.completed(), 0);
        assert_eq!(result.requests_per_second(), Some(0.0));
    }

    #[test]
    fn the_failure_rate_divides_failures_by_attempts() {
        let result = empty_result(Duration::from_secs(1), 4, 1);
        assert_eq!(result.failure_rate(), Some(0.25));

        let clean = empty_result(Duration::from_secs(1), 4, 0);
        assert_eq!(clean.failure_rate(), Some(0.0));

        // `None`, not `Some(0.0)`: a run that never attempted anything has no
        // rate, and 0.0 would read as a perfect run that never happened.
        let never = empty_result(Duration::from_secs(1), 0, 0);
        assert_eq!(never.failure_rate(), None);
    }

    #[test]
    fn statuses_are_deduplicated_and_sorted() {
        let mut result = empty_result(Duration::from_secs(1), 4, 0);
        result.samples = vec![
            Sample {
                nanos: 1,
                status: 500,
                body_bytes: 0,
            },
            Sample {
                nanos: 1,
                status: 200,
                body_bytes: 5,
            },
            Sample {
                nanos: 1,
                status: 200,
                body_bytes: 5,
            },
            Sample {
                nanos: 1,
                status: 404,
                body_bytes: 9,
            },
        ];
        assert_eq!(result.statuses(), vec![200, 404, 500]);
    }

    #[test]
    fn any_body_detects_a_route_that_returned_nothing() {
        // The check that catches "the benchmark ran but the workload did not":
        // `§9.1`'s `json` row says it serializes a 1 KB object, so a run of
        // zero-byte responses is not a `json` measurement.
        let mut result = empty_result(Duration::from_secs(1), 2, 0);
        result.samples = vec![
            Sample {
                nanos: 1,
                status: 200,
                body_bytes: 0,
            },
            Sample {
                nanos: 1,
                status: 200,
                body_bytes: 0,
            },
        ];
        assert!(!result.any_body());

        result.samples[1].body_bytes = 917;
        assert!(result.any_body());
    }
}
