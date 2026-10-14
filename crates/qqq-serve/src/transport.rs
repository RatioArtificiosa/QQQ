// SPDX-License-Identifier: Apache-2.0

//! The serving transport abstraction (`F-16` Option A, Wave 8).
//!
//! One narrow seam between the socket and QQQ policy: every transport
//! yields a [`RequestHead`], streams the body, and takes a response
//! through [`Responder`]. The in-house HTTP/1.1 path implements it today;
//! the hyper path implements it next; the dispatch pipeline above the
//! seam never learns which one served the connection.
//!
//! # Why head / body-stream / responder, and nothing else
//!
//! QQQ policy (routing, tenant limits, output budgets, F-02 validation,
//! F-14 checks, access log) consumes exactly three things: who asked for
//! what (the head), the bytes that follow (the body, bounded elsewhere),
//! and a way to answer (the responder). Anything wider — connection
//! state, frame types, ALPN tokens — would let policy depend on the
//! transport, which is how a migration silently forks behaviour. The
//! seam is narrow so both sides stay honest.
//!
//! # Where the limits live
//!
//! Wire-level flood knobs live in [`HyperLimits`] and are applied to the
//! real hyper builders by [`apply_http1`] and [`apply_http2`] — except
//! [`HyperLimits::idle_timeout`] and [`HyperLimits::max_response_body_bytes`],
//! which hyper cannot express and the serve path enforces QQQ-side for
//! both protocols. They are named here so the bounds have one home.
//! QQQ-level budgets (tenant ceilings, output budgets, body caps) stay in
//! QQQ middleware around the transport, never in it.

use std::time::Duration;

/// One request's head, independent of the wire protocol (`F-16`).
///
/// Method, target, and version as strings (not enums) so a future
/// protocol's vocabulary does not require changing the seam: policy
/// matches on what it understands and refuses the rest, exactly as the
/// in-house path does today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// The method as written (`GET`, `POST`, …).
    ///
    /// ```
    /// use qqq_serve::transport::RequestHead;
    ///
    /// let head = RequestHead {
    ///     method: "GET".to_owned(),
    ///     target: "/".to_owned(),
    ///     version: "HTTP/1.1".to_owned(),
    ///     headers: Vec::new(),
    /// };
    /// assert_eq!(head.method, "GET");
    /// ```
    pub method: String,
    /// The request target as written.
    ///
    /// ```
    /// use qqq_serve::transport::RequestHead;
    ///
    /// let head = RequestHead {
    ///     method: "GET".to_owned(),
    ///     target: "/orders?id=1".to_owned(),
    ///     version: "HTTP/1.1".to_owned(),
    ///     headers: Vec::new(),
    /// };
    /// assert_eq!(head.target, "/orders?id=1");
    /// ```
    pub target: String,
    /// The version as written (`HTTP/1.1`, `HTTP/2`).
    ///
    /// ```
    /// use qqq_serve::transport::RequestHead;
    ///
    /// let head = RequestHead {
    ///     method: "GET".to_owned(),
    ///     target: "/".to_owned(),
    ///     version: "HTTP/1.1".to_owned(),
    ///     headers: Vec::new(),
    /// };
    /// assert_eq!(head.version, "HTTP/1.1");
    /// ```
    pub version: String,
    /// Header pairs in received order.
    ///
    /// ```
    /// use qqq_serve::transport::RequestHead;
    ///
    /// let head = RequestHead {
    ///     method: "GET".to_owned(),
    ///     target: "/".to_owned(),
    ///     version: "HTTP/1.1".to_owned(),
    ///     headers: vec![("host".to_owned(), "x".to_owned())],
    /// };
    /// assert_eq!(head.headers.len(), 1);
    /// ```
    pub headers: Vec<(String, String)>,
}

/// Answering one request (`F-16`).
///
/// The responder carries the status, headers, and body back across the
/// seam; framing (content-length vs chunked vs close) is the
/// transport's job, bounded by the body budgets above the seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The numeric status.
    ///
    /// ```
    /// use qqq_serve::transport::Response;
    ///
    /// let response = Response {
    ///     status: 200,
    ///     headers: Vec::new(),
    ///     body: b"ok".to_vec(),
    /// };
    /// assert_eq!(response.status, 200);
    /// ```
    pub status: u16,
    /// Response headers.
    ///
    /// ```
    /// use qqq_serve::transport::Response;
    ///
    /// let response = Response {
    ///     status: 200,
    ///     headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
    ///     body: Vec::new(),
    /// };
    /// assert_eq!(response.headers.len(), 1);
    /// ```
    pub headers: Vec<(String, String)>,
    /// The complete response body.
    ///
    /// ```
    /// use qqq_serve::transport::Response;
    ///
    /// let response = Response {
    ///     status: 200,
    ///     headers: Vec::new(),
    ///     body: b"ok".to_vec(),
    /// };
    /// assert_eq!(response.body, b"ok");
    /// ```
    pub body: Vec<u8>,
}

/// One serving transport behind the seam (`F-16`).
///
/// Object-safe and `Send`: the accept loop holds one `Arc<dyn Transport>`
/// and serves every connection through it, whatever implements it.
pub trait Transport: Send + Sync {
    /// A human name for logs (`in-house-http1`, `hyper`).
    fn name(&self) -> &'static str;

    /// Whether this transport speaks HTTP/2 on some connection.
    ///
    /// The ALPN default keys off this: a transport that answers `false`
    /// must never be offered `h2`, which is what makes the
    /// `f16_default_alpn_does_not_advertise_h2_without_the_h2_loop`
    /// property structural rather than conventional.
    fn serves_h2(&self) -> bool;
}

/// Wire-level flood knobs for the hyper path (`F-16`).
///
/// Every field maps to one hyper builder setting (see [`apply_http1`]
/// and [`apply_http2`]) except `idle_timeout` and
/// `max_response_body_bytes`, which hyper cannot express and the serve
/// path enforces QQQ-side — they are named here so the bounds have one
/// home. Nothing else here is QQQ policy: tenant ceilings, output
/// budgets, and body caps stay in middleware. Defaults are the
/// conservative values from the audit's Option B list, so switching
/// transports never silently widens a bound the in-house path enforced
/// more strictly.
///
/// ```
/// use qqq_serve::transport::HyperLimits;
///
/// let limits = HyperLimits::default();
/// assert_eq!(limits.max_concurrent_streams, 100);
/// assert_eq!(limits.max_response_body_bytes, 1 << 20);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HyperLimits {
    /// Slow-head timeout (slow-loris bound).
    ///
    /// ```
    /// use qqq_serve::transport::HyperLimits;
    /// use std::time::Duration;
    ///
    /// assert_eq!(HyperLimits::default().header_read_timeout, Duration::from_secs(10));
    /// ```
    pub header_read_timeout: Duration,
    /// Largest HTTP/1.1 head buffer.
    ///
    /// ```
    /// use qqq_serve::transport::HyperLimits;
    ///
    /// assert_eq!(HyperLimits::default().http1_max_buf_bytes, 64 << 10);
    /// ```
    pub http1_max_buf_bytes: usize,
    /// Most headers on one HTTP/1.1 request.
    ///
    /// Hyper's own default happens to agree; the map sets it anyway,
    /// because a default is not a contract and hyper says so itself.
    ///
    /// ```
    /// use qqq_serve::transport::HyperLimits;
    ///
    /// assert_eq!(HyperLimits::default().http1_max_headers, 100);
    /// ```
    pub http1_max_headers: usize,
    /// Longest single HTTP/1.1 header line.
    ///
    /// Hyper leaves this unset by default (only the buffer governs), so
    /// without the map a 9 KiB line sails through a bound QQQ enforces
    /// at 8 KiB — the gap `hyper_header_size_cap_refuses_through_the_builder`
    /// pins.
    ///
    /// ```
    /// use qqq_serve::transport::HyperLimits;
    ///
    /// assert_eq!(HyperLimits::default().http1_max_header_size, 8 << 10);
    /// ```
    pub http1_max_header_size: usize,
    /// Largest decoded HTTP/2 header list.
    ///
    /// ```
    /// use qqq_serve::transport::HyperLimits;
    ///
    /// assert_eq!(HyperLimits::default().h2_max_header_list_bytes, 1 << 20);
    /// ```
    pub h2_max_header_list_bytes: u32,
    /// Concurrent streams per HTTP/2 connection.
    ///
    /// ```
    /// use qqq_serve::transport::HyperLimits;
    ///
    /// assert_eq!(HyperLimits::default().max_concurrent_streams, 100);
    /// ```
    pub max_concurrent_streams: u32,
    /// Streams awaiting reset-acknowledgement (Rapid Reset budget).
    ///
    /// ```
    /// use qqq_serve::transport::HyperLimits;
    ///
    /// assert_eq!(HyperLimits::default().max_pending_reset_streams, 200);
    /// ```
    pub max_pending_reset_streams: usize,
    /// Server-initiated resets before the connection closes (`MadeYouReset`).
    ///
    /// ```
    /// use qqq_serve::transport::HyperLimits;
    ///
    /// assert_eq!(HyperLimits::default().max_local_error_reset_streams, 200);
    /// ```
    pub max_local_error_reset_streams: usize,
    /// Largest response body the server will assemble.
    ///
    /// A QQQ-middleware budget, not a hyper setting — hyper has no
    /// response-body cap. No serving code enforces it yet: the serve-path
    /// commit wires it where response bodies are built or streamed.
    /// Adjacent caps (the WebSocket message 1 MiB, tenant body caps) are
    /// not this bound; until the serve path lands, this field names the
    /// number both sides must read so neither invents its own.
    ///
    /// ```
    /// use qqq_serve::transport::HyperLimits;
    ///
    /// assert_eq!(HyperLimits::default().max_response_body_bytes, 1 << 20);
    /// ```
    pub max_response_body_bytes: u64,
    /// HTTP/2 PING cadence — and nothing else.
    ///
    /// Hyper's `keep_alive_interval` sets how often PING frames go out;
    /// it does not bound an idle connection. The idle bound is
    /// [`HyperLimits::idle_timeout`], enforced QQQ-side for both
    /// protocols. The two are deliberately different fields: equating
    /// PING cadence with the idle bound lets a quiet connection live
    /// forever on PINGs alone.
    ///
    /// Default 75 s: numerically the idle default, but otherwise
    /// unrelated. The in-house path answers PINGs and never sends them,
    /// so this cadence has no in-house mirror.
    ///
    /// ```
    /// use qqq_serve::transport::HyperLimits;
    /// use std::time::Duration;
    ///
    /// assert_eq!(HyperLimits::default().h2_ping_interval, Duration::from_secs(75));
    /// ```
    pub h2_ping_interval: Duration,
    /// Idle-connection bound, QQQ-enforced for both protocols.
    ///
    /// Carried here so the two transports cannot disagree about what the
    /// bound is — but hyper does not enforce it. The serve path wraps
    /// each connection in this deadline (the in-house path closes from
    /// `Connection::poll` with `CloseReason::IdleTimeout`); until the
    /// serve-path commit lands, this field documents the bound the map
    /// must carry, enforced on the in-house side only.
    ///
    /// ```
    /// use qqq_serve::transport::HyperLimits;
    /// use std::time::Duration;
    ///
    /// assert_eq!(HyperLimits::default().idle_timeout, Duration::from_secs(75));
    /// ```
    pub idle_timeout: Duration,
    /// Most requests served on one connection before it closes.
    ///
    /// Hyper has no per-connection request ceiling, so the serve path
    /// counts and closes QQQ-side — mirroring `Connection`'s
    /// `RequestLimit`, including the warning: the last response carries
    /// `Connection: close`, and the next request is refused by closing.
    ///
    /// ```
    /// use qqq_serve::transport::HyperLimits;
    ///
    /// assert_eq!(HyperLimits::default().max_requests_per_connection, 1_000);
    /// ```
    pub max_requests_per_connection: u32,
    /// How long a drain may take before in-flight requests are cut off.
    ///
    /// QQQ-side like the idle bound: the serve path bounds graceful
    /// shutdown with this, mirroring `ConnectionConfig::drain_timeout`.
    ///
    /// ```
    /// use qqq_serve::transport::HyperLimits;
    /// use std::time::Duration;
    ///
    /// assert_eq!(HyperLimits::default().drain_timeout, Duration::from_secs(30));
    /// ```
    pub drain_timeout: Duration,
}

impl Default for HyperLimits {
    fn default() -> Self {
        Self {
            // Mirrors `ConnectionConfig::header_timeout`: a slow head is a
            // held slot, on either transport.
            header_read_timeout: Duration::from_secs(10),
            // Mirrors the in-house `MAX_HEAD_BYTES`: switching transports
            // must not widen what the parser accepted.
            http1_max_buf_bytes: 64 << 10,
            // Mirrors `MAX_HEADERS` / `MAX_HEADER_BYTES` for the same
            // reason: hyper's header count default agrees today but is
            // not a contract, and its per-line size is unset by default.
            http1_max_headers: crate::http1::MAX_HEADERS,
            http1_max_header_size: crate::http1::MAX_HEADER_BYTES,
            // Mirrors the in-house `MAX_HEADER_BLOCK_BYTES`.
            h2_max_header_list_bytes: 1 << 20,
            // RFC 9113 §6.5.2 recommends no smaller than 100.
            max_concurrent_streams: 100,
            // The audit's 200/s control-frame budget, as a stream count:
            // bursts above it close the connection rather than queue.
            max_pending_reset_streams: 200,
            max_local_error_reset_streams: 200,
            // Response-body budget for the serve path (1 MiB): named here
            // so both sides read one number, enforced where bodies are
            // built, not by hyper.
            max_response_body_bytes: 1 << 20,
            // PING cadence, not an idle bound: never derived from config.
            h2_ping_interval: Duration::from_secs(75),
            // Mirrors `ConnectionConfig::idle_timeout`.
            idle_timeout: Duration::from_secs(75),
            // Mirrors `ConnectionConfig::max_requests`: 1000 amortises a
            // handshake across a session while keeping a leak visible.
            max_requests_per_connection: 1_000,
            // Mirrors `ConnectionConfig::drain_timeout`.
            drain_timeout: Duration::from_secs(30),
        }
    }
}

/// Derive the hyper knobs from the serving config (`F-16`).
///
/// One function so the two transports cannot disagree about what a
/// limit is: the in-house path reads `ConnectionConfig` directly and
/// this reads it the same way. Periods come from the connection
/// config; byte caps from the parser constants they mirror.
///
/// ```
/// use qqq_serve::conn::ConnectionConfig;
/// use qqq_serve::transport::hyper_limits_for;
///
/// let limits = hyper_limits_for(&ConnectionConfig::default());
/// assert_eq!(limits.header_read_timeout, ConnectionConfig::default().header_timeout);
/// assert_eq!(limits.idle_timeout, ConnectionConfig::default().idle_timeout);
/// assert_eq!(limits.max_requests_per_connection, ConnectionConfig::default().max_requests);
/// assert_eq!(limits.drain_timeout, ConnectionConfig::default().drain_timeout);
/// ```
#[must_use]
pub fn hyper_limits_for(config: &crate::conn::ConnectionConfig) -> HyperLimits {
    HyperLimits {
        header_read_timeout: config.header_timeout,
        idle_timeout: config.idle_timeout,
        max_requests_per_connection: config.max_requests,
        drain_timeout: config.drain_timeout,
        ..HyperLimits::default()
    }
}

/// Apply the knobs to a hyper HTTP/1.1 server builder (`F-16`).
///
/// Thin by design: every number arrives decided in [`HyperLimits`], so
/// this function cannot invent policy — and a test that reads the
/// builder back would test hyper, not us. Covered by the mapping test
/// on [`hyper_limits_for`] plus the integration path that serves
/// through the configured builder. The timer is set first because hyper
/// panics when `header_read_timeout` is configured without one (hyper
/// 1.12.0 `http1.rs` and `common/time.rs`: "Panics if ... configured
/// without a `Timer`"), and that panic lands on the serving task.
pub fn apply_http1(builder: &mut hyper::server::conn::http1::Builder, limits: &HyperLimits) {
    builder.timer(hyper_util::rt::TokioTimer::new());
    builder.header_read_timeout(Some(limits.header_read_timeout));
    builder.max_buf_size(limits.http1_max_buf_bytes);
    builder.max_headers(limits.http1_max_headers);
    builder.max_header_size(limits.http1_max_header_size);
    builder.keep_alive(true);
}

/// Apply the knobs to a hyper HTTP/2 server builder (`F-16`).
///
/// Same contract as [`apply_http1`]: mapping is tested, application is
/// thin. `max_header_list_size` is infallible-u32 in hyper; the
/// `u32`-typed field carries that, so no conversion exists to get wrong.
/// The timer is set for the same reason as in [`apply_http1`]: without
/// it the PING cadence is inert and the bound it promises is §11-shaped.
pub fn apply_http2<E>(builder: &mut hyper::server::conn::http2::Builder<E>, limits: &HyperLimits) {
    builder.timer(hyper_util::rt::TokioTimer::new());
    builder.max_concurrent_streams(limits.max_concurrent_streams);
    builder.max_header_list_size(limits.h2_max_header_list_bytes);
    builder.max_pending_accept_reset_streams(limits.max_pending_reset_streams);
    builder.max_local_error_reset_streams(limits.max_local_error_reset_streams);
    builder.keep_alive_interval(Some(limits.h2_ping_interval));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mapping preserves the connection config's periods: a change to
    /// either timeout that forgot the map would silently desynchronise the
    /// transports, and this test is the tripwire.
    #[test]
    fn hyper_limits_follow_the_connection_config() {
        let config = crate::conn::ConnectionConfig {
            header_timeout: Duration::from_secs(3),
            idle_timeout: Duration::from_secs(30),
            ..crate::conn::ConnectionConfig::default()
        };
        let limits = hyper_limits_for(&config);
        assert_eq!(limits.header_read_timeout, Duration::from_secs(3));
        assert_eq!(limits.idle_timeout, Duration::from_secs(30));
        // Connection budgets ride the same map: a ceiling the map forgot
        // would leave one transport unbounded.
        assert_eq!(
            limits.max_requests_per_connection,
            crate::conn::ConnectionConfig::default().max_requests
        );
        assert_eq!(
            limits.drain_timeout,
            crate::conn::ConnectionConfig::default().drain_timeout
        );
        // The PING cadence is not config: the map must not derive it from
        // the idle bound (see `h2_ping_cadence_is_not_the_idle_bound`).
        assert_eq!(
            limits.h2_ping_interval,
            HyperLimits::default().h2_ping_interval
        );
        // Byte caps are transport-independent constants, not config: the
        // map must not invent per-deployment values for them.
        assert_eq!(limits.http1_max_buf_bytes, 64 << 10);
        assert_eq!(limits.http1_max_headers, crate::http1::MAX_HEADERS);
        assert_eq!(limits.http1_max_header_size, crate::http1::MAX_HEADER_BYTES);
        assert_eq!(limits.h2_max_header_list_bytes, 1 << 20);
        assert_eq!(limits.max_concurrent_streams, 100);
    }

    /// The reset budgets are finite and non-zero: an unset (`None`) budget
    /// in hyper means unbounded, and the whole point of the map is that no
    /// bound stays infinite by accident.
    #[test]
    fn reset_budgets_are_finite() {
        let limits = HyperLimits::default();
        assert!(limits.max_pending_reset_streams > 0);
        assert!(limits.max_local_error_reset_streams > 0);
        assert!(limits.max_response_body_bytes > 0);
    }

    /// Unwrap-free test helper: the crate denies `unwrap_used` everywhere
    /// including tests, so fallible setup goes through here with a message.
    fn ok<T, E: core::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("test setup failed ({what}): {error:?}"),
        }
    }

    /// How a stalled-head connection died: either way the server killed
    /// it, which is what the timeout test requires. The join on the
    /// server task proves the kill was the timeout and not a panic.
    enum StalledEnd {
        /// Clean FIN: `read` returned EOF.
        Clean,
        /// The socket died any other way (reset, abort).
        Reset,
    }

    /// The H2 keep-alive cadence must not follow the idle bound: PINGs keep
    /// a connection fresh through middleboxes while the idle timeout ends
    /// it, and one number cannot do both jobs. Two deployments with
    /// different idle bounds must get the same PING cadence.
    #[test]
    fn h2_ping_cadence_is_not_the_idle_bound() {
        let calm = crate::conn::ConnectionConfig {
            idle_timeout: Duration::from_secs(30),
            ..crate::conn::ConnectionConfig::default()
        };
        let strict = crate::conn::ConnectionConfig {
            idle_timeout: Duration::from_secs(300),
            ..crate::conn::ConnectionConfig::default()
        };
        let calm_limits = hyper_limits_for(&calm);
        let strict_limits = hyper_limits_for(&strict);
        assert_eq!(
            calm_limits.h2_ping_interval, strict_limits.h2_ping_interval,
            "PING cadence must not move with the idle bound"
        );
        // ...while the idle bound itself still carries each deployment's
        // value: separation must not drop the bound on either side.
        assert_eq!(calm_limits.idle_timeout, Duration::from_secs(30));
        assert_eq!(strict_limits.idle_timeout, Duration::from_secs(300));
    }

    /// The header timeout must actually fire through the configured
    /// builder: hyper goes inert when `header_read_timeout` is set without
    /// a `Timer`, so a believed-live timeout with no timer is the §11
    /// shape. This serves a real connection that stalls mid-head and
    /// requires the server to close it — without the timer the read stays
    /// open past the deadline and the test fails.
    #[tokio::test]
    async fn http1_header_timeout_fires_through_the_configured_builder() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let limits = HyperLimits {
            header_read_timeout: Duration::from_millis(50),
            ..HyperLimits::default()
        };
        let listener = ok(
            tokio::net::TcpListener::bind("127.0.0.1:0").await,
            "bind loopback",
        );
        let addr = ok(listener.local_addr(), "listener address");
        let server = tokio::spawn(async move {
            let (stream, _) = ok(listener.accept().await, "accept");
            let mut builder = hyper::server::conn::http1::Builder::new();
            apply_http1(&mut builder, &limits);
            let service = hyper::service::service_fn(
                |_request: hyper::Request<hyper::body::Incoming>| async {
                    Ok::<_, hyper::Error>(hyper::Response::new(http_body_util::Full::new(
                        bytes::Bytes::new(),
                    )))
                },
            );
            // A stalled head must end the connection, never the test.
            let _ = builder
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await;
        });
        let mut client = ok(tokio::net::TcpStream::connect(addr).await, "connect");
        ok(
            client.write_all(b"GET / HTTP/1.1\r\n").await,
            "send a stalled partial head",
        );
        // The server must close an unfinished head past the timeout: drain
        // any rejection bytes, then require death inside the deadline.
        let outcome = tokio::time::timeout(Duration::from_secs(5), async {
            let mut buf = [0u8; 64];
            loop {
                match client.read(&mut buf).await {
                    Ok(0) => return StalledEnd::Clean,
                    Ok(_) => {}
                    // The error is not the signal: any socket death is a
                    // server-side kill, and the join below proves the kill
                    // was the timeout rather than a panic.
                    Err(_error) => return StalledEnd::Reset,
                }
            }
        })
        .await;
        match outcome {
            Ok(StalledEnd::Clean | StalledEnd::Reset) => {}
            Err(error) => panic!("server left a stalled head open past the deadline: {error:?}"),
        }
        // EOF alone proves nothing: a panicking server also drops the
        // socket. The task must have survived — pre-fix this join reaps
        // hyper's missing-timer panic, which is the red this test exists
        // to catch.
        match outcome {
            Ok(StalledEnd::Clean | StalledEnd::Reset) => {}
            Err(error) => panic!("server left a stalled head open past the deadline: {error:?}"),
        }
        match server.await {
            Ok(()) => {}
            Err(error) => panic!("server task did not survive: {error}"),
        }
    }

    /// The single-header cap must fire through the configured builder:
    /// QQQ refuses a header line past `MAX_HEADER_BYTES` (8 KiB) with 431,
    /// but hyper's `max_header_size` defaults to unset (only the 64 KiB
    /// buffer governs). Without the map, a 9 KiB header sails through a
    /// believed-live bound — the §11 shape at the settings layer.
    #[tokio::test]
    async fn hyper_header_size_cap_refuses_through_the_builder() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let limits = HyperLimits::default();
        let listener = ok(
            tokio::net::TcpListener::bind("127.0.0.1:0").await,
            "bind loopback",
        );
        let addr = ok(listener.local_addr(), "listener address");
        let server = tokio::spawn(async move {
            let (stream, _) = ok(listener.accept().await, "accept");
            let mut builder = hyper::server::conn::http1::Builder::new();
            apply_http1(&mut builder, &limits);
            let service = hyper::service::service_fn(
                |_request: hyper::Request<hyper::body::Incoming>| async {
                    Ok::<_, hyper::Error>(hyper::Response::new(http_body_util::Full::new(
                        bytes::Bytes::new(),
                    )))
                },
            );
            let _ = builder
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await;
        });
        let mut client = ok(tokio::net::TcpStream::connect(addr).await, "connect");
        let big = "x".repeat(9 * 1024);
        let head = format!("GET / HTTP/1.1\r\nHost: x\r\nX-Big: {big}\r\n\r\n");
        ok(
            client.write_all(head.as_bytes()).await,
            "send over-long header",
        );
        // A 9 KiB header line is past the 8 KiB QQQ cap: the server must
        // kill the connection rather than route the request.
        let outcome = tokio::time::timeout(Duration::from_secs(5), async {
            let mut buf = [0u8; 64];
            loop {
                match client.read(&mut buf).await {
                    Ok(0) => return StalledEnd::Clean,
                    Ok(_) => {}
                    Err(_error) => return StalledEnd::Reset,
                }
            }
        })
        .await;
        match outcome {
            Ok(StalledEnd::Clean | StalledEnd::Reset) => {}
            Err(error) => panic!("server accepted a 9 KiB header line: {error:?}"),
        }
        match server.await {
            Ok(()) => {}
            Err(error) => panic!("server task did not survive: {error}"),
        }
    }
}
