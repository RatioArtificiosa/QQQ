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
use std::sync::atomic::{AtomicBool, Ordering};
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
        let table = Arc::new(table);
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
                            tenant_hosts: None,
                        };
                        last = serve_hyper_h1(
                            stream,
                            Arc::clone(&table),
                            dispatch.clone(),
                            limits,
                            &ctx,
                        )
                        .await;
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

/// A refusal the client may never see: on Windows the kernel may RST a
/// refused-and-closed connection before the response arrives (§O-505,
/// §O-598). Either outcome proves refusal; what must never happen is
/// the handler running on a truncated body, which the flag handlers
/// below pin.
///
/// `Dead` means exactly one thing: the server received at least the
/// head and then ended the connection (EOF or reset mid-read).
/// Connect, write, flush, and timeout failures panic instead: the
/// harnesses prove liveness, the request is ~100 bytes, and a hung
/// server enforces nothing — folding any of those into `Dead` would
/// mask a missing cap or a broken harness.
enum Refusal {
    /// The intact refusal response, with whether the connection closed.
    Answered(Wire),
    /// The server ended the connection instead of answering.
    Dead,
}

/// Send a complete head, then read whatever the server did: the refusal
/// response, or a dead connection. Never panics on the socket — a reset
/// during the read is the outcome, not a harness failure.
async fn refuse_exchange(addr: SocketAddr, request: &[u8]) -> Refusal {
    // Connect failures panic: both harnesses prove liveness first, so
    // an unreachable server is a broken harness, not a refusal.
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        panic!("test server unreachable");
    };
    // Write failures panic too: the request is ~100 bytes to a live
    // localhost server, so a failed write is a broken harness, not a
    // server that refused — only what the server received and ended
    // may pass as `Dead`.
    stream.write_all(request).await.expect("write head");
    stream.flush().await.expect("flush head");
    // Generous deadline, and a timeout panics rather than passing: a
    // server that neither answers nor closes enforces nothing, and
    // folding its silence into `Dead` would mask a missing cap.
    let outcome =
        tokio::time::timeout(Duration::from_secs(10), read_response_opt(&mut stream)).await;
    match outcome {
        Ok(Some((status, headers, body))) => {
            let closed = close_observed(&mut stream).await;
            Refusal::Answered(Wire {
                status,
                headers,
                body,
                closed,
            })
        }
        Ok(None) => Refusal::Dead,
        Err(error) => panic!("server hung instead of refusing: {error:?}"),
    }
}

/// Read a refusal outcome off a live stream: the intact response, or
/// `Dead` when the server already killed the connection. A hung server
/// panics, for the reason `Refusal` documents.
async fn read_outcome(stream: &mut TcpStream) -> Refusal {
    let outcome = tokio::time::timeout(Duration::from_secs(10), read_response_opt(stream)).await;
    match outcome {
        Ok(Some((status, headers, body))) => {
            let closed = close_observed(stream).await;
            Refusal::Answered(Wire {
                status,
                headers,
                body,
                closed,
            })
        }
        Ok(None) => Refusal::Dead,
        Err(error) => panic!("server hung instead of refusing: {error:?}"),
    }
}

/// `read_response` without panics on the socket: `None` when the
/// connection died before a complete head, or the body fell short of
/// `Content-Length`. A head the server did send but that does not
/// parse is a server bug, not a refusal — those panic rather than
/// folding into `None`, so garbage can never pass as `Dead`.
async fn read_response_opt(
    stream: &mut TcpStream,
) -> Option<(String, Vec<(String, String)>, Vec<u8>)> {
    let mut head = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if stream.read_exact(&mut byte).await.is_err() {
            return None;
        }
        head.push(byte[0]);
        assert!(
            head.len() <= 128 * 1024,
            "server sent an oversized response head"
        );
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
        let Some((k, v)) = line.split_once(':') else {
            panic!("server sent a malformed header line: {line:?}");
        };
        headers.push((k.trim().to_lowercase(), v.trim().to_owned()));
    }
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    if len > 0 && stream.read_exact(&mut body).await.is_err() {
        return None;
    }
    Some((status, headers, body))
}

/// Best-effort flood sender: head, then `count` copies of `piece`,
/// then the terminating chunk. The server may reset mid-upload, which
/// ends the send rather than failing the test — the refusal is observed
/// on the read side.
/// How a flood send ended: the whole flood went out, the server ended
/// it early (reset or close mid-upload — the refusal arriving as
/// connection death), or a write stalled past its deadline (the server
/// neither reads nor closes, which is a hang, not a refusal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FloodSend {
    Done,
    ClosedEarly,
    Stalled,
}

/// A flood send with how much body data the stack accepted: `Dead`
/// (and `Answered`) are only meaningful past the cap — a close before
/// the server could have consumed an over-cap body never exercised the
/// bound. Only chunk *data* counts, not wire bytes: head and chunk
/// framing ride along but the cap counts bodies. Only fully written
/// pieces credit their data length, so `data_written` is a lower bound
/// on what was pushed (a failed piece may have moved partial bytes).
/// Residual, stated plainly: pushed past-cap data proves the server
/// *received* past-cap bytes only up to socket buffers — a server that
/// closed early for no reason with full buffers would still pass.
/// No code path closes early without refusing first, and the flag plus
/// the `Answered` status triangulate the rest; the alternative — no
/// tolerance for the Windows RST race — fails the suite on the
/// platform instead of testing it.
struct FloodOutcome {
    send: FloodSend,
    data_written: u64,
}

/// Best-effort flood sender with write deadlines: head, then `count`
/// copies of `piece`, then the terminating chunk. Stalls propagate as
/// `Stalled` at every site — including the flush — so a hung peer can
/// never be mistaken for a refusal. Only chunk data counts toward
/// `data_written` (see `FloodOutcome`); head, framing, and terminator
/// ride along uncounted.
async fn send_flood(
    stream: &mut TcpStream,
    head: &[u8],
    piece: &[u8],
    piece_data: u64,
    count: usize,
) -> FloodOutcome {
    let mut data_written: u64 = 0;
    match timed_write(stream, head).await {
        Ok(_) => {}
        Err(WriteFail::Closed) => {
            return FloodOutcome {
                send: FloodSend::ClosedEarly,
                data_written,
            };
        }
        Err(WriteFail::Stalled) => {
            return FloodOutcome {
                send: FloodSend::Stalled,
                data_written,
            };
        }
    }
    for _ in 0..count {
        match timed_write(stream, piece).await {
            Ok(_) => data_written += piece_data,
            Err(WriteFail::Closed) => {
                return FloodOutcome {
                    send: FloodSend::ClosedEarly,
                    data_written,
                };
            }
            Err(WriteFail::Stalled) => {
                return FloodOutcome {
                    send: FloodSend::Stalled,
                    data_written,
                };
            }
        }
    }
    match timed_write(stream, b"0\r\n\r\n").await {
        Ok(_) => {}
        Err(WriteFail::Closed) => {
            return FloodOutcome {
                send: FloodSend::ClosedEarly,
                data_written,
            };
        }
        Err(WriteFail::Stalled) => {
            return FloodOutcome {
                send: FloodSend::Stalled,
                data_written,
            };
        }
    }
    match timed_flush(stream).await {
        Ok(()) => {}
        Err(WriteFail::Closed) => {
            return FloodOutcome {
                send: FloodSend::ClosedEarly,
                data_written,
            };
        }
        Err(WriteFail::Stalled) => {
            return FloodOutcome {
                send: FloodSend::Stalled,
                data_written,
            };
        }
    }
    FloodOutcome {
        send: FloodSend::Done,
        data_written,
    }
}

/// Why a bounded write failed: the peer ended it, or nothing moved.
enum WriteFail {
    Closed,
    Stalled,
}

/// One write with a deadline, reporting how much the stack accepted. A
/// stalled write is a hung peer, and hanging is louder than passing: it
/// panics at the call site.
async fn timed_write(stream: &mut TcpStream, bytes: &[u8]) -> Result<u64, WriteFail> {
    match tokio::time::timeout(Duration::from_secs(10), stream.write_all(bytes)).await {
        Ok(Ok(())) => Ok(bytes.len() as u64),
        Ok(Err(_)) => Err(WriteFail::Closed),
        Err(_) => Err(WriteFail::Stalled),
    }
}

/// One flush with a deadline: a peer that takes the bytes and never
/// flushes them through is hung, not refusing.
async fn timed_flush(stream: &mut TcpStream) -> Result<(), WriteFail> {
    match tokio::time::timeout(Duration::from_secs(10), stream.flush()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(WriteFail::Closed),
        Err(_) => Err(WriteFail::Stalled),
    }
}

/// Send raw bytes, read one response, then report whether the connection
/// died.
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

async fn read_response_head(stream: &mut TcpStream) -> (String, Vec<(String, String)>) {
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
    (status, headers)
}

async fn read_response(
    stream: &mut TcpStream,
    head_request: bool,
) -> (String, Vec<(String, String)>, Vec<u8>) {
    let (status, headers) = read_response_head(stream).await;
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

/// An over-cap body — declared or streaming — never reaches a handler,
/// on either path. The refusal itself may arrive intact or the kernel
/// may RST first (§O-505, §O-598: refusal plus close is a race on
/// Windows); both outcomes prove refusal, and the handler flag proves
/// no truncated body was served.
#[tokio::test]
async fn hyper_body_cap_matches() {
    let routes = [(Method::Post, "/echo", "echo")];
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let handler: Handler = Arc::new(move |_head, _m: &RouteMatch| {
        flag.store(true, Ordering::SeqCst);
        Response::text(200, "must not run")
    });
    // Declared over the 2 MiB parser cap: head only, nothing to upload.
    let big_len = 3 * 1024 * 1024;
    let inhouse = Inhouse::start_with(table_with(&routes), Arc::clone(&handler), |_| {}).await;
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(handler),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let head = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {big_len}\r\n\r\n"
    );
    // Both answer `400`, not `413`: the shared parse-error constructor
    // hardcodes `Failure::BadRequest`, so the `ParseError::status()`
    // taxonomy (431/413/505) never reaches the wire on either path. The
    // mapping is unit-pinned in `http1.rs` but unwired — a believed-live
    // control recorded for the follow-up that wires it on both paths at
    // once, never one side first.
    for (side, addr) in [("in-house", inhouse.addr), ("hyper", hyper.addr)] {
        match refuse_exchange(addr, head.as_bytes()).await {
            Refusal::Answered(wire) => {
                assert_eq!(
                    wire.status, "HTTP/1.1 400 Bad Request",
                    "{side} declared cap"
                );
                assert!(wire.closed, "{side} reclaims the connection");
            }
            // The kernel RST before the refusal arrived: refusal all the
            // same, per the convention above.
            Refusal::Dead => {}
        }
    }

    // Streaming over the cap: chunked, never declared. An intact refusal
    // is the shared `GuestFault` `500`; a dead connection is the same
    // refusal lost to the race. Either way the handler must not have run.
    let flood_head =
        b"POST /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut piece = format!("{:x}\r\n", 64 * 1024).into_bytes();
    piece.extend_from_slice(&vec![0xA5; 64 * 1024]);
    piece.extend_from_slice(b"\r\n");
    for (side, addr) in [("in-house", inhouse.addr), ("hyper", hyper.addr)] {
        let Ok(mut stream) = TcpStream::connect(addr).await else {
            panic!("{side} test server unreachable");
        };
        // Past-cap data is the proof either way: the server can only
        // have refused for the cap after its count crossed it, and a
        // locally pushed past-cap body is the client's evidence of
        // that. The gate is strict (`>`): exactly at the cap the server
        // must still accept.
        let cap = qqq_serve::http1::MAX_REQUEST_BYTES;
        let outcome = send_flood(&mut stream, flood_head, &piece, 64 * 1024, 40).await;
        match outcome.send {
            FloodSend::Done | FloodSend::ClosedEarly => {}
            FloodSend::Stalled => panic!("{side} hung mid-upload instead of refusing"),
        }
        match read_outcome(&mut stream).await {
            Refusal::Answered(wire) => {
                assert_eq!(
                    wire.status, "HTTP/1.1 500 Internal Server Error",
                    "{side} streaming over-cap is GuestFault"
                );
                assert!(wire.closed, "{side} reclaims the connection");
                assert!(
                    outcome.data_written > cap,
                    "{side} answered 500 with only {written} body bytes on the wire",
                    written = outcome.data_written
                );
            }
            // Dead is only meaningful past the cap: a close before the
            // server could have consumed an over-cap body never
            // exercised the bound (see `FloodOutcome`).
            Refusal::Dead => {
                assert!(
                    outcome.data_written > cap,
                    "{side} closed after {written} body bytes, before the cap could fire",
                    written = outcome.data_written
                );
            }
        }
    }
    assert!(
        !ran.load(Ordering::SeqCst),
        "no truncated body reached a handler on either path"
    );
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

/// Activity resets the idle bound on HTTP/1 too: six keep-alive
/// `GET`s 150ms apart on a 300ms bound all answer 200. (Wiring pin
/// for the h1 driver arm — the red-first proof lives on the h2 side,
/// where the shared `answer()` instrumentation is identical.)
#[tokio::test]
async fn hyper_activity_resets_the_idle_bound() {
    let routes = [(Method::Get, "/hello", "h")];
    let mut limits = default_limits();
    limits.idle_timeout = Duration::from_millis(300);
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        limits,
        Pieces::bare(),
    )
    .await;
    let mut stream = TcpStream::connect(hyper.addr).await.expect("connect");
    for n in 0..6 {
        stream
            .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write");
        let (status, _, body) = read_response(&mut stream, false).await;
        assert_eq!(
            status, "HTTP/1.1 200 OK",
            "request {n} on an active connection"
        );
        assert_eq!(body, b"hello from h");
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// A slow reader still receives the whole body under a sane bound:
/// 256KB read 4KB per 50ms (~3s) against the default 75s idle. (An
/// end-to-end contract pin, not a mechanism proof — the mechanism
/// proof is `watch_body_stamps_on_poll`. Adversarial corners stay
/// out of contract: with a tiny idle bound AND a trickle slower
/// than hyper's ~64KB write quantum per bound, polls cluster at the
/// send's start and the bound can reclaim mid-send. The in-house
/// path never idle-closes mid-send; matching that exactly would
/// need a send-completion signal hyper does not expose, so the
/// residual is recorded in `HyperLimits::idle_timeout`, not hidden.)
#[tokio::test]
async fn hyper_slow_reader_gets_full_body() {
    let routes = [(Method::Get, "/big", "big")];
    let big: Handler =
        Arc::new(|_head, _m: &RouteMatch| Response::text(200, "y".repeat(256 * 1024)));
    let hyper = Hyper::start(
        table_with(&routes),
        Dispatch::flat(big),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let mut stream = TcpStream::connect(hyper.addr).await.expect("connect");
    stream
        .write_all(b"GET /big HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write");
    // Head first, then trickle the body: 4KB per 50ms while a 256KB
    // transfer spans about 3 seconds — a twenty-fifth of the bound,
    // so only the mechanism is exercised, never the clock.
    let (status, headers) = read_response_head(&mut stream).await;
    assert_eq!(status, "HTTP/1.1 200 OK");
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .expect("content-length");
    assert_eq!(len, 256 * 1024);
    let mut body = vec![0u8; len];
    let mut got = 0usize;
    while got < len {
        let end = (got + 4096).min(len);
        stream
            .read_exact(&mut body[got..end])
            .await
            .expect("body trickle reads to the end, never truncated");
        got = end;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(body.iter().all(|&b| b == b'y'));
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

// ---------------------------------------------------------------------------
// Transport seam: any stream, not just TCP
// ---------------------------------------------------------------------------

/// The hyper path serves any byte stream, not just a socket: a flat
/// route round-trips over an in-memory duplex with no listener, no
/// port, and no TCP at all. This is the seam the TLS commit
/// terminates into — a server-side `TlsStream` must flow where this
/// duplex flows. Fails to compile until `serve_hyper_h1` stops
/// demanding a `TcpStream`.
#[tokio::test]
async fn hyper_h1_serves_a_non_tcp_stream() {
    let table = Arc::new(table_with(&[(Method::Get, "/hello", "h")]));
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
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
        tenant_hosts: None,
    };
    let (mut client, server_io) = tokio::io::duplex(65536);
    let serving = serve_hyper_h1(
        server_io,
        Arc::clone(&table),
        Dispatch::flat(hello_handler()),
        default_limits(),
        &ctx,
    );
    let exchange = async move {
        client
            .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("request writes to duplex");
        client.flush().await.expect("flush");
        let mut head = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            assert!(
                client.read_exact(&mut byte).await.is_ok(),
                "server closed before answering"
            );
            head.push(byte[0]);
            assert!(head.len() <= 64 * 1024, "response head bounded");
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        let mut lines = text.split("\r\n");
        let status = lines.next().unwrap_or("").to_owned();
        let mut length = 0usize;
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.trim().eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().expect("content-length parses");
            }
        }
        let mut body = vec![0u8; length];
        client.read_exact(&mut body).await.expect("body arrives");
        (status, body)
    };
    let (served, (status, body)) = tokio::join!(serving, async {
        // Deadline on the client arm: a server that stalls
        // before responding must fail loudly, never hang the
        // suite.
        tokio::time::timeout(Duration::from_secs(60), exchange)
            .await
            .expect("server answers over duplex")
    });
    assert_eq!(status, "HTTP/1.1 200 OK", "flat route answers over duplex");
    assert_eq!(body, b"hello from h");
    assert_eq!(
        served,
        Served::ClientClosed,
        "close-request ends the connection"
    );
}
