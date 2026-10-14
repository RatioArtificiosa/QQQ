// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! The hyper serve path against the in-house path, over real sockets.
//!
//! # Why two servers per test
//!
//! The migration's promise is that policy lives in one place with two
//! transports calling it. A test that drives only the hyper path proves
//! the hyper path answers; it cannot prove it answers *the same*. Every
//! differential test below sends identical bytes to both paths and
//! compares status, body, and the framing headers — the rows where the
//! paths disagree on purpose (hyper closes where in-house answers
//! `400`/`431`, the new outbound cap, the ceiling answer) assert the
//! disagreement explicitly, so a future change cannot silently widen it.
//!
//! A test that drove `map_head` directly would pass with `serve_hyper_h1`
//! never called at all — the two-correct-halves shape (`§O-045a`).

use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use qqq_io::listener::{ListenAddr, Shutdown};
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::auth::{AuthPolicy, RouteAuth};
use qqq_serve::cors::Cors;
use qqq_serve::limits::{GlobalBucket, Limits, TenantLimits};
use qqq_serve::metrics::{HttpMetrics, TenantLabels};
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::serve_hyper::serve_hyper_h1;
use qqq_serve::server::{
    ConnectionContext, ConnectionId, Dispatch, Handler, RouteMatch, Served, ServerConfig, serve,
};
use qqq_serve::transport::{HyperLimits, hyper_limits_for};
use qqq_serve::ws::WsConfig;
use qqq_serve::{ConnectionConfig, Response};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A running in-house server, stopped when dropped (the `socket.rs` shape).
struct Inhouse {
    addr: SocketAddr,
    shutdown: Shutdown,
}

impl Drop for Inhouse {
    fn drop(&mut self) {
        // Stop the accept loop at test end: the spawned `serve` task
        // would otherwise outlive the test, holding its port until the
        // runtime dies.
        self.shutdown.signal();
    }
}

impl Inhouse {
    async fn start_with<F>(table: RouteTable, handler: Handler, adjust: F) -> Self
    where
        F: FnOnce(&mut ServerConfig),
    {
        let addr = free_addr();
        let listen = ListenAddr::parse(&addr.to_string()).expect("a resolved address must parse");
        let shutdown = Shutdown::new();
        let mut config = ServerConfig::for_addr(listen);
        // Parity with the hyper harness, which wires no process budget
        // unless a test asks: the budget under test belongs to the test.
        config.global_budget = None;
        adjust(&mut config);
        let local = shutdown.clone();
        tokio::spawn(async move {
            let logger = Logger::new(Format::Json, Level::Error);
            if let Err(e) = serve(config, table, Dispatch::flat(handler), local, logger).await {
                eprintln!("server stopped early: {}", e.render());
            }
        });
        let server = Self { addr, shutdown };
        server.wait_until_accepting().await;
        server
    }

    async fn wait_until_accepting(&self) {
        for _ in 0..200 {
            if TcpStream::connect(self.addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// Owned context pieces for one hyper connection; the driver task owns
/// this, so no borrow crosses the spawn boundary.
struct Pieces {
    shutdown: Shutdown,
    logger: Logger,
    cors: Option<Cors>,
    metrics_path: Option<String>,
    auth: Option<Arc<AuthPolicy>>,
    idle: Option<Duration>,
    metrics: Option<Arc<HttpMetrics>>,
    limits: Option<Arc<TenantLimits>>,
    global_requests: Option<Arc<GlobalBucket>>,
    ws: WsConfig,
    loopback_only: bool,
    ws_buffer: Arc<tokio::sync::Semaphore>,
    tenant_labels: Arc<TenantLabels>,
}

impl Pieces {
    fn bare() -> Self {
        Self {
            shutdown: Shutdown::new(),
            logger: Logger::new(Format::Json, Level::Error),
            cors: None,
            metrics_path: None,
            auth: None,
            idle: None,
            metrics: None,
            limits: None,
            global_requests: None,
            ws: WsConfig::default(),
            loopback_only: false,
            ws_buffer: Arc::new(tokio::sync::Semaphore::new(16)),
            tenant_labels: Arc::new(TenantLabels::new()),
        }
    }
}

/// One hyper-driven listener: the driver serves connections until the
/// test signals shutdown, so each exchange is a fresh connection like
/// the in-house harness. `finish` stops the loop and reports the last
/// connection's outcome.
struct Hyper {
    addr: SocketAddr,
    shutdown: Shutdown,
    driver: JoinHandle<Served>,
}

impl Hyper {
    async fn start(
        table: RouteTable,
        dispatch: Dispatch,
        limits: HyperLimits,
        pieces: Pieces,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("listener address");
        let shutdown = pieces.shutdown.clone();
        let driver = tokio::spawn(async move {
            let mut last = Served::ClientClosed;
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, peer) = accepted.expect("accept");
                        let id = ConnectionId::new(peer, 1);
                        let ctx = ConnectionContext {
                            id: &id,
                            shutdown: &pieces.shutdown,
                            logger: &pieces.logger,
                            cors: pieces.cors.as_ref(),
                            metrics_path: pieces.metrics_path.as_deref(),
                            sampler: None,
                            auth: pieces.auth.as_ref(),
                            idle_timeout: pieces.idle,
                            metrics: pieces.metrics.as_ref(),
                            limits: pieces.limits.as_ref(),
                            global_requests: pieces.global_requests.as_ref(),
                            ws: &pieces.ws,
                            loopback_only: pieces.loopback_only,
                            ws_buffer: &pieces.ws_buffer,
                            tenant_labels: &pieces.tenant_labels,
                        };
                        last = serve_hyper_h1(stream, &table, &dispatch, &limits, &ctx).await;
                    }
                    () = pieces.shutdown.wait() => break,
                }
            }
            last
        });
        Self {
            addr,
            shutdown,
            driver,
        }
    }

    async fn finish(self) -> Served {
        self.shutdown.signal();
        self.driver.await.expect("driver")
    }
}

/// One raw exchange: status line, headers, body, and whether the server
/// closed afterwards.
struct Wire {
    status: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    closed: bool,
}

/// Send raw bytes, read one response, then report whether the connection
/// died. `extra` runs after the response (a second request for
/// keep-alive, nothing for close checks).
async fn exchange(addr: SocketAddr, request: &[u8], wait_close: bool) -> Wire {
    exchange_as(addr, request, false, wait_close).await
}

/// `exchange` with the request method known: a `HEAD` response carries
/// no body bytes despite its `Content-Length`, so the harness must not
/// read one — the connection would close first and the read would fail.
async fn exchange_as(
    addr: SocketAddr,
    request: &[u8],
    head_request: bool,
    wait_close: bool,
) -> Wire {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(request).await.expect("write head");
    stream.flush().await.expect("flush");
    let (status, headers, body) = read_response(&mut stream, head_request).await;
    let closed = if wait_close {
        close_observed(&mut stream).await
    } else {
        false
    };
    Wire {
        status,
        headers,
        body,
        closed,
    }
}

async fn read_response(
    stream: &mut TcpStream,
    head_request: bool,
) -> (String, Vec<(String, String)>, Vec<u8>) {
    let mut head = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.expect("read head byte");
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or("").to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':').expect("header colon");
        headers.push((k.trim().to_lowercase(), v.trim().to_owned()));
    }
    let len: usize = if head_request {
        0
    } else {
        headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0)
    };
    let mut body = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut body).await.expect("read body");
    }
    (status, headers, body)
}

/// True when the server closed: EOF or reset inside the deadline.
async fn close_observed(stream: &mut TcpStream) -> bool {
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = [0u8; 64];
        loop {
            match stream.read(&mut buf).await {
                Ok(n) => {
                    if n == 0 {
                        return true;
                    }
                }
                Err(_) => return true,
            }
        }
    })
    .await;
    outcome.unwrap_or(false)
}

fn table_with(routes: &[(Method, &str, &str)]) -> RouteTable {
    let mut t = RouteTable::new();
    for (method, pattern, handler) in routes {
        t.insert(Route::new(*method, pattern, handler).expect("route"))
            .expect("insert");
    }
    t
}

fn hello_handler() -> Handler {
    Arc::new(|_head, m: &RouteMatch| Response::text(200, format!("hello from {}", m.handler)))
}

fn free_addr() -> SocketAddr {
    let probe = StdListener::bind("127.0.0.1:0").expect("probe bind");
    let addr = probe.local_addr().expect("probe address");
    drop(probe);
    addr
}

fn header<'a>(wire: &'a Wire, name: &str) -> Option<&'a str> {
    wire.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Compare by status code: hyper writes the http-crate canonical reason
/// phrases while the in-house writer uses `reason_phrase`, and the two
/// spell 413 differently ("Payload" vs "Content Too Large"). Codes are
/// the contract — phrases are advisory per RFC 9110 — so differential
/// pairs compare codes, and the phrase delta is recorded, not hidden.
fn code_of(status: &str) -> &str {
    status.get(..12).unwrap_or(status)
}

/// The default connection config as hyper limits: idle 75 s would make
/// every close-check test wait, so tests that need a verdict pass their
/// own `HyperLimits` and this stays for the happy paths.
fn default_limits() -> HyperLimits {
    hyper_limits_for(&ConnectionConfig::default())
}

// ---------------------------------------------------------------------------
// Differential: flat routes
// ---------------------------------------------------------------------------

/// The same `GET` answers the same on both paths.
#[tokio::test]
async fn hyper_flat_200_matches_in_house() {
    let routes = [(Method::Get, "/hello", "h")];
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |_| {}).await;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let request = b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let a = exchange(inhouse.addr, request, true).await;
    let b = exchange(hyper.addr, request, true).await;
    assert_eq!(a.status, "HTTP/1.1 200 OK");
    assert_eq!(code_of(&b.status), code_of(&a.status));
    assert_eq!(b.body, a.body);
    assert_eq!(header(&b, "content-length"), header(&a, "content-length"));
}

/// Unknown paths and methods refuse identically.
#[tokio::test]
async fn hyper_404_and_405_match() {
    let routes = [(Method::Get, "/hello", "h")];
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |_| {}).await;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    for request in [
        "GET /nope HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "POST /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    ] {
        let a = exchange(inhouse.addr, request.as_bytes(), true).await;
        let b = exchange(hyper.addr, request.as_bytes(), true).await;
        assert_eq!(
            code_of(&b.status),
            code_of(&a.status),
            "status for {request:?}"
        );
        assert_eq!(b.body, a.body, "body for {request:?}");
    }
}

/// `HEAD` strips the body but keeps the real length, on both paths.
#[tokio::test]
async fn hyper_head_strips_body_keeps_length() {
    let routes = [(Method::Get, "/hello", "h"), (Method::Head, "/hello", "h")];
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |_| {}).await;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let get = b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let head = b"HEAD /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let get_body = exchange(inhouse.addr, get, true).await.body;
    let a = exchange_as(inhouse.addr, head, true, true).await;
    let b = exchange_as(hyper.addr, head, true, true).await;
    assert!(a.body.is_empty() && b.body.is_empty(), "no HEAD bytes");
    assert_eq!(code_of(&b.status), code_of(&a.status));
    assert_eq!(
        header(&b, "content-length"),
        Some(get_body.len().to_string().as_str()),
        "length describes the GET representation"
    );
    assert_eq!(header(&b, "content-length"), header(&a, "content-length"));
}

/// A foreign `Host` on a loopback listener is `421` on both paths.
#[tokio::test]
async fn hyper_421_foreign_host_on_loopback() {
    let routes = [(Method::Get, "/hello", "h")];
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |_| {}).await;
    let mut pieces = Pieces::bare();
    pieces.loopback_only = true;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        pieces,
    )
    .await;
    // 127.0.0.1 listeners are loopback-only on both harnesses.
    let request = b"GET /hello HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n";
    let a = exchange(inhouse.addr, request, true).await;
    let b = exchange(hyper.addr, request, true).await;
    assert_eq!(a.status, "HTTP/1.1 421 Misdirected Request");
    assert_eq!(code_of(&b.status), code_of(&a.status));
    assert_eq!(b.body, a.body);
    assert!(b.closed && a.closed, "rebinding answers close");
}

/// Tenant rate and declared-body caps refuse identically.
#[tokio::test]
async fn hyper_429_and_413_match() {
    let routes = [(Method::Get, "/hello", "h"), (Method::Post, "/hello", "h")];
    let rate = TenantLimits::uniform(Limits::with_rate(1, Duration::from_secs(60)));
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |config| {
        config.limits = Some(Arc::new(rate));
    })
    .await;
    let mut pieces = Pieces::bare();
    pieces.limits = Some(Arc::new(TenantLimits::uniform(Limits::with_rate(
        1,
        Duration::from_secs(60),
    ))));
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        pieces,
    )
    .await;
    let one = b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    // First request spends the allowance on both paths.
    assert_eq!(
        exchange(inhouse.addr, one, true).await.status,
        "HTTP/1.1 200 OK"
    );
    assert_eq!(
        exchange(hyper.addr, one, true).await.status,
        "HTTP/1.1 200 OK"
    );
    // Second request is over it on both paths.
    let a = exchange(inhouse.addr, one, true).await;
    let b = exchange(hyper.addr, one, true).await;
    assert_eq!(a.status, "HTTP/1.1 429 Too Many Requests");
    assert_eq!(code_of(&b.status), code_of(&a.status));
    assert_eq!(b.body, a.body);

    // Declared-body cap: fresh servers, one POST with a large declaration.
    let capped = TenantLimits::uniform(Limits::with_body(10));
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |config| {
        config.limits = Some(Arc::new(capped));
    })
    .await;
    let mut pieces = Pieces::bare();
    pieces.limits = Some(Arc::new(TenantLimits::uniform(Limits::with_body(10))));
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        pieces,
    )
    .await;
    let post =
        b"POST /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 100\r\n\r\n";
    let a = exchange(inhouse.addr, post, true).await;
    let b = exchange(hyper.addr, post, true).await;
    assert_eq!(a.status, "HTTP/1.1 413 Content Too Large");
    assert_eq!(code_of(&b.status), code_of(&a.status));
    assert_eq!(b.body, a.body);
}

/// A denied route is `403` with the same headers on both paths.
#[tokio::test]
async fn hyper_403_auth_matches() {
    let routes = [(Method::Get, "/secret", "s")];
    let mut policy = AuthPolicy::new();
    policy.insert("/secret", "s", RouteAuth::Refused { mode: "deny" });
    let policy = Arc::new(policy);
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |config| {
        config.auth = Some(Arc::clone(&policy));
    })
    .await;
    let mut pieces = Pieces::bare();
    pieces.auth = Some(Arc::clone(&policy));
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        pieces,
    )
    .await;
    let request = b"GET /secret HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let a = exchange(inhouse.addr, request, true).await;
    let b = exchange(hyper.addr, request, true).await;
    assert_eq!(a.status, "HTTP/1.1 403 Forbidden");
    assert_eq!(code_of(&b.status), code_of(&a.status));
    assert_eq!(b.body, a.body);
    assert_eq!(
        header(&b, "x-qqq-error"),
        Some("unauthenticated"),
        "refusal names itself"
    );
    assert_eq!(header(&b, "x-qqq-error"), header(&a, "x-qqq-error"));
}

/// A CORS preflight answers before routing, on both paths.
#[tokio::test]
async fn hyper_preflight_matches() {
    let routes = [(Method::Get, "/hello", "h")];
    let cors = || {
        Cors::from_manifest(["https://app.example.com"])
            .expect("valid")
            .with_methods(["GET"])
    };
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |config| {
        config.cors = Some(cors());
    })
    .await;
    let mut pieces = Pieces::bare();
    pieces.cors = Some(cors());
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        pieces,
    )
    .await;
    let request = "OPTIONS /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: https://app.example.com\r\nAccess-Control-Request-Method: GET\r\n\r\n";
    let a = exchange(inhouse.addr, request.as_bytes(), true).await;
    let b = exchange(hyper.addr, request.as_bytes(), true).await;
    assert_eq!(a.status, "HTTP/1.1 204 No Content");
    assert_eq!(code_of(&b.status), code_of(&a.status));
    assert_eq!(
        header(&b, "access-control-allow-origin"),
        header(&a, "access-control-allow-origin")
    );
}

/// The server-owned metrics path answers on both paths.
#[tokio::test]
async fn hyper_metrics_path_matches() {
    let routes = [(Method::Get, "/hello", "h")];
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |config| {
        config.metrics = Some(Arc::new(HttpMetrics::new()));
        config.metrics_path = Some("/metrics".to_owned());
    })
    .await;
    let mut pieces = Pieces::bare();
    pieces.metrics = Some(Arc::new(HttpMetrics::new()));
    pieces.metrics_path = Some("/metrics".to_owned());
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        pieces,
    )
    .await;
    let request = b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let a = exchange(inhouse.addr, request, true).await;
    let b = exchange(hyper.addr, request, true).await;
    assert_eq!(a.status, "HTTP/1.1 200 OK");
    assert_eq!(code_of(&b.status), code_of(&a.status));
    // Not byte equality: each server owns its registry, and the
    // in-house side counts its own accept-probe connections. Same
    // shape, same content type, same counters present.
    assert_eq!(header(&b, "content-type"), header(&a, "content-type"));
    for body in [&a.body, &b.body] {
        let text = String::from_utf8_lossy(body);
        assert!(
            text.contains("qqq_http_requests_total"),
            "registry content present"
        );
    }
}

// ---------------------------------------------------------------------------
// Differential: framing and smuggling
// ---------------------------------------------------------------------------

/// Conflicted and doubled framing refuse `400` on both paths.
#[tokio::test]
async fn hyper_framing_conflicts_match() {
    let routes = [(Method::Post, "/a", "h")];
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |_| {}).await;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    for request in [
        // Two hosts: virtual-host routing disagrees with the proxy.
        "POST /a HTTP/1.1\r\nHost: localhost\r\nHost: y\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        // Unknown method: not one HTTP defines.
        "FROBNICATE /a HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    ] {
        let a = exchange(inhouse.addr, request.as_bytes(), true).await;
        let b = exchange(hyper.addr, request.as_bytes(), true).await;
        assert_eq!(
            a.status, "HTTP/1.1 400 Bad Request",
            "in-house for {request:?}"
        );
        assert_eq!(
            code_of(&b.status),
            code_of(&a.status),
            "hyper agrees for {request:?}"
        );
        assert_eq!(b.body, a.body, "same refusal body for {request:?}");
        assert!(b.closed, "framing lies close the hyper connection");
    }
}

/// Doubled `Content-Length`: hyper answers its own bare `400` natively
/// (no body) before the service runs, while the in-house path builds
/// the shared refusal. Status agrees, bodies differ by construction —
/// pinned so the delta cannot silently widen.
#[tokio::test]
async fn hyper_duplicate_content_length_refuses_natively() {
    let routes = [(Method::Post, "/a", "h")];
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |_| {}).await;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let request = "POST /a HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!";
    let a = exchange(inhouse.addr, request.as_bytes(), true).await;
    assert_eq!(a.status, "HTTP/1.1 400 Bad Request");
    let b = exchange(hyper.addr, request.as_bytes(), true).await;
    assert_eq!(code_of(&b.status), code_of(&a.status));
    assert!(b.body.is_empty(), "hyper's native 400 carries no body");
    assert!(b.closed);
}

/// Both framings at once: the in-house path answers `400`
/// (`ConflictingFraming`), while hyper strips `Content-Length` before
/// the service sees it — so the hyper path fails chunked decoding and
/// answers the shared `GuestFault` `500`. Both refuse and both close;
/// the status is the documented delta, forced by hyper's normalisation.
#[tokio::test]
async fn hyper_conflicting_framing_refuses_differently() {
    let routes = [(Method::Post, "/a", "h")];
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |_| {}).await;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let request = "POST /a HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello";
    let a = exchange(inhouse.addr, request.as_bytes(), true).await;
    assert_eq!(a.status, "HTTP/1.1 400 Bad Request");
    assert!(a.closed);
    let b = exchange(hyper.addr, request.as_bytes(), true).await;
    assert_eq!(b.status, "HTTP/1.1 500 Internal Server Error");
    assert!(b.closed, "the hyper path still kills the connection");
}

/// Malformed heads hyper rejects below the service close the connection
/// or answer a bare `400` natively; the in-house path answers `400` with
/// the shared refusal body. Both refuse — the shape is the documented
/// delta, the refusal is the agreement.
#[tokio::test]
async fn hyper_parse_level_failures_close() {
    let routes = [(Method::Get, "/a", "h")];
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |_| {}).await;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    // Past the 100-header cap: hyper answers `431` natively (canonical
    // phrase) and closes, where the in-house path answers the shared
    // `400` (dead taxonomy again). Codes differ by construction here —
    // the agreement is refusal plus close, pinned on both sides.
    let mut request = String::from("GET /a HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for i in 0..101 {
        use std::fmt::Write as _;
        write!(request, "X-Pad-{i}: v\r\n").expect("format to String");
    }
    request.push_str("\r\n");
    let a = exchange(inhouse.addr, request.as_bytes(), true).await;
    assert_eq!(a.status, "HTTP/1.1 400 Bad Request");
    assert!(a.closed);
    let b = exchange(hyper.addr, request.as_bytes(), true).await;
    assert_eq!(code_of(&b.status), "HTTP/1.1 431");
    assert!(b.closed, "over-count heads close");
}

/// A space before the colon, and obs-fold continuations, are refused
/// natively by hyper's parser with a bare `400` (no body) — status
/// agrees with the in-house refusal, body differs by construction.
#[tokio::test]
async fn hyper_parse_level_rows_refuse_natively() {
    let routes = [(Method::Get, "/a", "h")];
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |_| {}).await;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    for request in [
        "GET /a HTTP/1.1\r\nHost : localhost\r\nConnection: close\r\n\r\n",
        "GET /a HTTP/1.1\r\nHost: localhost\r\n folded: yes\r\nConnection: close\r\n\r\n",
    ] {
        let a = exchange(inhouse.addr, request.as_bytes(), true).await;
        assert_eq!(
            a.status, "HTTP/1.1 400 Bad Request",
            "in-house for {request:?}"
        );
        let b = exchange(hyper.addr, request.as_bytes(), true).await;
        assert_eq!(
            code_of(&b.status),
            code_of(&a.status),
            "hyper agrees for {request:?}"
        );
        assert!(b.body.is_empty(), "hyper's native 400 carries no body");
        assert!(b.closed);
    }
}

/// Absolute-form targets are not routable: the in-house path answers
/// `400`, and the hyper path must too — hyper normalises absolute-form
/// to origin-form, so the map refuses any URI with a scheme rather than
/// serving a request the oracle would not.
#[tokio::test]
async fn hyper_absolute_form_is_not_routed() {
    let routes = [(Method::Get, "/b", "h")];
    let inhouse = Inhouse::start_with(table_with(&routes), hello_handler(), |_| {}).await;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let request = b"GET http://x/b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let a = exchange(inhouse.addr, request, true).await;
    assert_eq!(a.status, "HTTP/1.1 400 Bad Request");
    let b = exchange(hyper.addr, request, true).await;
    assert_eq!(
        b.status, a.status,
        "hyper must not serve absolute-form as origin-form"
    );
    assert_eq!(b.body, a.body);
}

/// A valid chunked body arrives intact on both paths.
#[tokio::test]
async fn hyper_chunked_body_matches() {
    let routes = [(Method::Post, "/echo", "echo")];
    let inhouse = Inhouse::start_with(table_with(&routes), echo_handler(), |_| {}).await;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(echo_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let request = "POST /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let a = exchange(inhouse.addr, request.as_bytes(), true).await;
    let b = exchange(hyper.addr, request.as_bytes(), true).await;
    assert_eq!(a.status, "HTTP/1.1 200 OK");
    assert_eq!(code_of(&b.status), code_of(&a.status));
    assert_eq!(b.body, a.body);
}

fn echo_handler() -> Handler {
    Arc::new(|head, _m: &RouteMatch| {
        let len = head.content_length.unwrap_or(0);
        Response::text(200, format!("len={len}"))
    })
}

/// An over-cap body — declared or streaming — is `413` and closes, both paths.
#[tokio::test]
async fn hyper_body_cap_matches() {
    let routes = [(Method::Post, "/echo", "echo")];
    // Declared over the 2 MiB parser cap.
    let big_len = 3 * 1024 * 1024;
    let inhouse = Inhouse::start_with(table_with(&routes), echo_handler(), |_| {}).await;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(echo_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let head = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {big_len}\r\n\r\n"
    );
    let a = exchange(inhouse.addr, head.as_bytes(), true).await;
    let b = exchange(hyper.addr, head.as_bytes(), true).await;
    // Both answer `400`, not `413`: the shared parse-error constructor
    // hardcodes `Failure::BadRequest`, so the `ParseError::status()`
    // taxonomy (431/413/505) never reaches the wire on either path. The
    // mapping is unit-pinned in `http1.rs` but unwired — a believed-live
    // control recorded for the follow-up that wires it on both paths at
    // once, never one side first.
    assert_eq!(a.status, "HTTP/1.1 400 Bad Request");
    assert_eq!(code_of(&b.status), code_of(&a.status));
    assert_eq!(b.body, a.body);
    assert!(a.closed && b.closed, "over-cap bodies close");

    // Streaming over the cap: chunked, never declared. Both paths fail
    // the shared reader and answer the shared `GuestFault` constructor,
    // which is `500` — a declared over-cap is `400` instead, because the
    // shared parse-error constructor hardcodes `BadRequest` (see above).
    let mut chunked =
        b"POST /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_vec();
    let piece = format!("{:x}\r\n", 64 * 1024);
    for _ in 0..40 {
        chunked.extend_from_slice(piece.as_bytes());
        chunked.extend_from_slice(&vec![0xA5; 64 * 1024]);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let a = exchange(inhouse.addr, &chunked, true).await;
    let b = exchange(hyper.addr, &chunked, true).await;
    assert_eq!(
        a.status, "HTTP/1.1 500 Internal Server Error",
        "in-house streaming over-cap is GuestFault"
    );
    assert_eq!(b.status, a.status, "hyper streaming cap agrees");
    assert!(a.closed && b.closed, "streaming over-cap closes");
}

// ---------------------------------------------------------------------------
// Hyper-only: new enforcement the oracle does not have
// ---------------------------------------------------------------------------

/// A handler response past the outbound cap is `500` on the hyper path.
/// The in-house path serves it (200): the cap is new enforcement, and
/// the deletion gate converges the two. Both behaviours are pinned so
/// the divergence cannot silently widen.
#[tokio::test]
async fn hyper_oversize_response_is_500() {
    let routes = [(Method::Get, "/big", "big")];
    let big: Handler = Arc::new(|_head, _m: &RouteMatch| {
        let mut r = Response::text(200, "x");
        r.body = vec![0xA5; (1 << 20) + 1];
        r
    });
    let inhouse = Inhouse::start_with(table_with(&routes), Arc::clone(&big), |_| {}).await;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(big),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let request = b"GET /big HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let a = exchange(inhouse.addr, request, true).await;
    assert_eq!(
        a.status, "HTTP/1.1 200 OK",
        "in-house has no outbound cap (deletion-gate divergence)"
    );
    let b = exchange(hyper.addr, request, true).await;
    assert_eq!(b.status, "HTTP/1.1 500 Internal Server Error");
    assert!(
        String::from_utf8_lossy(&b.body).contains("exceeds"),
        "the 500 names the cap"
    );
}

/// A handler response with no wire meaning is `500` on the hyper path.
#[tokio::test]
async fn hyper_invalid_handler_response_is_500() {
    let routes = [(Method::Get, "/bad", "bad")];
    let bad: Handler = Arc::new(|_head, _m: &RouteMatch| Response::status(99));
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(bad),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let request = b"GET /bad HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let b = exchange(hyper.addr, request, true).await;
    assert_eq!(b.status, "HTTP/1.1 500 Internal Server Error");
}

// ---------------------------------------------------------------------------
// Hyper-only: connection lifecycle
// ---------------------------------------------------------------------------

/// Three sequential requests share one hyper connection.
#[tokio::test]
async fn hyper_keep_alive_serves_three() {
    let routes = [(Method::Get, "/hello", "h")];
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let mut stream = TcpStream::connect(hyper.addr).await.expect("connect");
    for _ in 0..3 {
        stream
            .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write");
        let (status, _, body) = read_response(&mut stream, false).await;
        assert_eq!(status, "HTTP/1.1 200 OK");
        assert_eq!(body, b"hello from h");
    }
}

/// An idle hyper connection dies on the idle bound, reported as such.
#[tokio::test]
async fn hyper_idle_closes_with_idle_timeout() {
    let routes = [(Method::Get, "/hello", "h")];
    let mut limits = default_limits();
    limits.idle_timeout = Duration::from_millis(150);
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        limits,
        Pieces::bare(),
    )
    .await;
    let mut stream = TcpStream::connect(hyper.addr).await.expect("connect");
    assert!(
        close_observed(&mut stream).await,
        "idle connection must close"
    );
    match hyper.finish().await {
        Served::IdleTimeout => {}
        other => panic!("expected IdleTimeout, got {other:?}"),
    }
}

/// Shutdown drains: the in-flight request completes, then the connection ends.
#[tokio::test]
async fn hyper_drain_finishes_inflight() {
    let routes = [(Method::Get, "/slow", "slow")];
    let slow: Handler = Arc::new(|_head, _m: &RouteMatch| {
        std::thread::sleep(Duration::from_millis(300));
        Response::text(200, "slow done")
    });
    let mut pieces = Pieces::bare();
    let shutdown = Shutdown::new();
    pieces.shutdown = shutdown.clone();
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(slow),
        default_limits(),
        pieces,
    )
    .await;
    let mut stream = TcpStream::connect(hyper.addr).await.expect("connect");
    stream
        .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write");
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown.signal();
    let (status, _, body) = read_response(&mut stream, false).await;
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert_eq!(body, b"slow done");
    match hyper.finish().await {
        Served::Drained => {}
        other => panic!("expected Drained, got {other:?}"),
    }
}

/// The per-connection ceiling warns on the last response, then refuses.
#[tokio::test]
async fn hyper_max_requests_closes_with_warning() {
    let routes = [(Method::Get, "/hello", "h")];
    let mut limits = default_limits();
    limits.max_requests_per_connection = 2;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        limits,
        Pieces::bare(),
    )
    .await;
    let mut stream = TcpStream::connect(hyper.addr).await.expect("connect");
    stream
        .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write 1");
    let (first, _, _) = read_response(&mut stream, false).await;
    assert_eq!(first, "HTTP/1.1 200 OK");
    stream
        .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write 2");
    let (second, headers, _) = read_response(&mut stream, false).await;
    assert_eq!(second, "HTTP/1.1 200 OK");
    let close = headers
        .iter()
        .find(|(k, _)| k == "connection")
        .map(|(_, v)| v.as_str());
    assert_eq!(close, Some("close"), "the ceiling response warns");
    // The connection is already dead: the warned response was the last
    // one, and a third request has nothing to read from — the server
    // RSTs it. Past-ceiling `503` is a multiplexing case (a second
    // stream starting past the ceiling mid-flight), pinned by the
    // `ceiling_for` unit test, not by sequential HTTP/1.
    assert!(
        close_observed(&mut stream).await,
        "closed after the ceiling warning"
    );
    let _ = hyper.finish().await;
}
