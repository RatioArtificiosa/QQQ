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
    /// Time from the first byte written to the last byte of the response head read.
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
/// Returns a timeout error if the head does not arrive in time, or an I/O error if
/// the connection fails. A timeout is a real failure — unlike the pre-fix
/// behaviour, where it was an artefact of waiting for a close.
pub async fn read_response<S>(stream: &mut S, timeout: Duration) -> io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);

    // --- The head, up to and including the blank line --------------------
    let head_end = loop {
        if let Some(pos) = find_head_end(&buf) {
            break pos;
        }
        let mut chunk = [0_u8; 4 * 1024];
        let read = tokio::time::timeout(timeout, stream.read(&mut chunk))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timed out"))??;
        if read == 0 {
            // The peer closed before sending a complete head. Return what arrived
            // so the caller's parser can decide -- an empty buffer is a clear
            // error, and a partial head may still be diagnosable.
            return Ok(buf);
        }
        buf.extend_from_slice(&chunk[..read]);

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
    let framing = framing_of(&buf[..head_end]);

    match framing {
        Framing::Length(n) => {
            let want = head_end.saturating_add(n);
            while buf.len() < want {
                let mut chunk = [0_u8; 8 * 1024];
                let read = tokio::time::timeout(timeout, stream.read(&mut chunk))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timed out"))??;
                if read == 0 {
                    // The peer closed mid-body. The status is already known, so
                    // this is a short read rather than a failure to measure.
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
            }
        }
        Framing::None => {
            // No body: the head is the response. Deliberately does NOT read
            // further, because reading here is what hung the first version.
        }
        Framing::Chunked => {
            // Read until the terminating zero-length chunk, which ends with the
            // `\r\n\r\n` trailer sequence. Bounded by the same head cap logic
            // via the timeout rather than a byte limit, because a legitimate
            // chunked body can be large.
            loop {
                if buf.ends_with(b"0\r\n\r\n") || find_head_end(&buf[head_end..]).is_some() {
                    break;
                }
                let mut chunk = [0_u8; 8 * 1024];
                let read = tokio::time::timeout(timeout, stream.read(&mut chunk))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timed out"))??;
                if read == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
            }
        }
    }

    Ok(buf)
}

/// The maximum head size the reader will accept.
///
/// A conforming server's head is well under this. The bound exists so a peer that
/// never sends a blank line cannot make the harness grow a buffer without limit.
pub const MAX_HEAD_BYTES: usize = 128 * 1024;

/// Where the head ends: just past the first blank line, or `None`.
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
#[must_use]
pub fn framing_of(head: &[u8]) -> Framing {
    let text = String::from_utf8_lossy(head);
    let lower = text.to_ascii_lowercase();

    // A status of 1xx, 204, or 304 has no body.
    if let Some(status) = status_of(&lower) {
        if status == 204 || status == 304 || (100..200).contains(&status) {
            return Framing::None;
        }
    }

    if lower.contains("transfer-encoding:") && lower.contains("chunked") {
        return Framing::Chunked;
    }

    for line in lower.lines() {
        if let Some(rest) = line.strip_prefix("content-length:") {
            if let Ok(n) = rest.trim().parse::<usize>() {
                return if n == 0 {
                    Framing::None
                } else {
                    Framing::Length(n)
                };
            }
        }
    }

    // No length, no chunking, and a status that permits a body: the only way to
    // know the end is the close, which this harness will not wait for. Reported
    // as no body, which measures the head and does not hang.
    Framing::None
}

/// The status code from a head, if the status line parses.
#[must_use]
pub fn status_of(head: &str) -> Option<u16> {
    head.lines().next()?.split(' ').nth(1)?.parse::<u16>().ok()
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
pub fn parse_response(head: &[u8]) -> io::Result<ResponseHead> {
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

    // `HTTP/1.1 200 OK`
    let mut parts = status_line.split(' ');
    let version = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no version token"))?;
    if !version.starts_with("HTTP/1.") {
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

    // The head ends at the first blank line; anything after is body.
    let body_start = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(head.len(), |p| p + 4);
    Ok(ResponseHead {
        status: code,
        body_bytes: head.len() - body_start,
    })
}

/// Send one request over a fresh connection and measure it.
///
/// # Errors
///
/// Returns the I/O error if the connection, write, or read fails, or if the
/// response cannot be classified.
pub async fn one_request(plan: &Plan) -> io::Result<Sample> {
    let started = Instant::now();

    // `connect_timeout`, not `timeout`: see the field's docs for the measured
    // reason. A failing connect must be cheap, or a wrong target costs the run's
    // whole budget before it reports anything.
    let mut stream = tokio::time::timeout(plan.connect_timeout, TcpStream::connect(plan.target))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;

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
    let buf = read_response(&mut stream, plan.timeout).await?;

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
    // Warmup: sent and discarded, per `§9.1`'s requirement that the procedure be
    // stated. Never counted, and never silently skipped either -- the count comes
    // from the workload's own `Warmup`, so a row that declares no warmup gets none.
    //
    // # Why the first failures abort the run
    //
    // This loop used to discard every result and continue regardless. Against a
    // target that refuses connections that meant 200 warmup attempts each paying
    // the full connect timeout before the measured phase even began -- measured as
    // a multi-minute hang on a closed port, while a real server finished in five
    // seconds. A harness that cannot reach its target has nothing to measure, and
    // the useful behaviour is to say so immediately rather than to compute a
    // throughput of zero after several minutes.
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

    let connections = connections_for(plan.concurrency);
    let started = Instant::now();
    let mut samples: Vec<Sample> = Vec::new();
    let mut failed: u64 = 0;
    let mut attempted: u64 = 0;

    match plan.limit {
        Limit::Requests(total) => {
            let per_worker = total / u64::from(connections);
            let remainder = total % u64::from(connections);
            let mut handles = Vec::with_capacity(connections as usize);
            for worker in 0..connections {
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
            for handle in handles {
                let (local, lost, count) = handle
                    .await
                    .map_err(|e| io::Error::other(format!("worker panicked: {e}")))?;
                samples.extend(local);
                failed += lost;
                attempted += count;
            }
        }
        Limit::Duration(duration) => {
            let mut handles = Vec::with_capacity(connections as usize);
            for _ in 0..connections {
                let plan = plan.clone();
                handles.push(tokio::spawn(async move {
                    let deadline = Instant::now() + duration;
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
            for handle in handles {
                let (local, lost, count) = handle
                    .await
                    .map_err(|e| io::Error::other(format!("worker panicked: {e}")))?;
                samples.extend(local);
                failed += lost;
                attempted += count;
            }
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
