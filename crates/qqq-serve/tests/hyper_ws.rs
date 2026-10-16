// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! WebSocket upgrades over the hyper path (`F-16` parity).
//!
//! The hyper path answers upgrade routes with `501` until this
//! lands; these tests demand the real handshake — `101` with the
//! RFC 6455 §1.3 accept value, a masked echo round trip, and a
//! clean close — plus the two loud refusals (non-upgrade,
//! foreign origin). The client is spec-written (masking per §5.1),
//! like `tests/websocket.rs`, so a server that skips unmasking
//! hears garbage instead of green.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use qqq_io::listener::Shutdown;
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::metrics::TenantLabels;
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::serve_hyper::serve_hyper_h1;
use qqq_serve::server::{ConnectionContext, ConnectionId, Dispatch, Handler, RouteMatch, Served};
use qqq_serve::transport::{HyperLimits, hyper_limits_for};
use qqq_serve::ws::WsConfig;
use qqq_serve::ws_conn::Echo;
use qqq_serve::{ConnectionConfig, Response};

/// Owned context pieces for one hyper connection.
struct Pieces {
    shutdown: Shutdown,
    logger: Logger,
    cors: Option<qqq_serve::cors::Cors>,
    metrics_path: Option<String>,
    auth: Option<Arc<qqq_serve::auth::AuthPolicy>>,
    idle: Option<Duration>,
    metrics: Option<Arc<qqq_serve::metrics::HttpMetrics>>,
    limits: Option<Arc<qqq_serve::limits::TenantLimits>>,
    global_requests: Option<Arc<qqq_serve::limits::GlobalBucket>>,
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

fn table_with(routes: &[(Method, &str, &str)]) -> RouteTable {
    let mut t = RouteTable::new();
    for (method, pattern, handler) in routes {
        t.insert(Route::new(*method, pattern, handler).expect("route"))
            .expect("insert");
    }
    t
}

fn flat_handler() -> Handler {
    Arc::new(|_head, m: &RouteMatch| Response::text(200, format!("flat {}", m.handler)))
}

fn default_limits() -> HyperLimits {
    hyper_limits_for(&ConnectionConfig::default())
}

/// One hyper-driven listener serving a WebSocket route until shutdown.
struct HyperWs {
    addr: SocketAddr,
    shutdown: Shutdown,
    driver: JoinHandle<Served>,
}

impl HyperWs {
    async fn start(pieces: Pieces) -> Self {
        let table = Arc::new(table_with(&[(Method::Get, "/ws", "ws")]));
        let dispatch = Dispatch::flat(flat_handler()).with_websocket("ws", Arc::new(Echo));
        let limits = default_limits();
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

/// The RFC 6455 §1.3 example key, so the accept value is known.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// Send an upgrade request, with an optional `Origin`.
async fn upgrade_request(addr: SocketAddr, origin: Option<&str>) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let mut req = format!(
        "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n"
    );
    if let Some(o) = origin {
        use std::fmt::Write as _;
        write!(req, "Origin: {o}\r\n").expect("writes to a String");
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    stream.flush().await.expect("flush");
    stream
}

/// Read until the blank line ending a response head.
async fn read_head(stream: &mut TcpStream) -> String {
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut byte = [0u8; 1];
        loop {
            match stream.read(&mut byte).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    out.push(byte[0]);
                    if out.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
    })
    .await
    .expect("server answers the handshake");
    String::from_utf8_lossy(&out).into_owned()
}

/// Write a masked client text frame, as §5.1 requires.
async fn write_client_text(stream: &mut TcpStream, payload: &[u8]) {
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    let mut out = vec![0x81u8];
    let len = payload.len();
    if len < 126 {
        #[allow(clippy::cast_possible_truncation)]
        out.push(0x80 | len as u8);
    } else {
        out.push(0x80 | 0x7E);
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        out.push(b ^ mask[i % 4]);
    }
    stream.write_all(&out).await.expect("write frame");
    stream.flush().await.expect("flush");
}

/// Read one unmasked server frame: opcode plus payload.
async fn read_server_frame(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut header = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut header))
        .await
        .ok()?
        .ok()?;
    let opcode = header[0] & 0x0F;
    assert_eq!(
        header[1] & 0x80,
        0,
        "§5.1: a server must not mask the frames it sends"
    );
    let len = match header[1] & 0x7F {
        126 => {
            let mut b = [0u8; 2];
            tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut b))
                .await
                .ok()?
                .ok()?;
            u16::from_be_bytes(b) as usize
        }
        127 => {
            let mut b = [0u8; 8];
            tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut b))
                .await
                .ok()?
                .ok()?;
            #[allow(clippy::cast_possible_truncation)]
            let n = u64::from_be_bytes(b) as usize;
            n
        }
        n => n as usize,
    };
    let mut payload = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut payload))
        .await
        .ok()?
        .ok()?;
    Some((opcode, payload))
}

/// A real upgrade over hyper gets a `101` with the correct accept
/// value, then the echo loop answers a masked frame and the close
/// handshake completes.
#[tokio::test]
async fn hyper_ws_echo_round_trip() {
    let server = HyperWs::start(Pieces::bare()).await;
    let mut client =
        tokio::time::timeout(Duration::from_secs(60), upgrade_request(server.addr, None))
            .await
            .expect("server accepts the handshake");
    let head = read_head(&mut client).await;
    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "upgrade answers 101:\n{head}"
    );
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("sec-websocket-accept: {ACCEPT}").to_ascii_lowercase()),
        "accept value proves the server read the key:\n{head}"
    );
    write_client_text(&mut client, b"hello").await;
    let (opcode, echoed) = read_server_frame(&mut client).await.expect("echo arrives");
    assert_eq!(opcode, 0x1, "echo is a text frame");
    assert_eq!(echoed, b"hello");
    // Clean close: empty close frame, server echoes close.
    let mut close = vec![0x88u8, 0x80u8];
    close.extend_from_slice(&[0x12u8, 0x34, 0x56, 0x78]);
    client.write_all(&close).await.expect("write close");
    client.flush().await.expect("flush");
    let (opcode, _) = read_server_frame(&mut client)
        .await
        .expect("close echo arrives");
    assert_eq!(opcode, 0x8, "server echoes the close");
    let _ = server.finish().await;
}

/// A WebSocket route without an upgrade header is never hijacked:
/// no `101`, ever.
#[tokio::test]
async fn hyper_ws_route_without_an_upgrade_is_not_hijacked() {
    let server = HyperWs::start(Pieces::bare()).await;
    let mut client = TcpStream::connect(server.addr).await.expect("connect");
    client
        .write_all(b"GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    client.flush().await.expect("flush");
    let head = read_head(&mut client).await;
    assert!(
        !head.contains("101"),
        "it must never be answered with a 101:\n{head}"
    );
    let _ = server.finish().await;
}

/// A cross-origin upgrade is refused with 403 before any upgrade.
#[tokio::test]
async fn hyper_ws_cross_origin_upgrade_is_refused() {
    let server = HyperWs::start(Pieces::bare()).await;
    let mut client = tokio::time::timeout(
        Duration::from_secs(60),
        upgrade_request(server.addr, Some("https://evil.example")),
    )
    .await
    .expect("server answers the handshake attempt");
    let head = read_head(&mut client).await;
    assert!(
        head.starts_with("HTTP/1.1 403"),
        "a foreign origin must be refused pre-upgrade:\n{head}"
    );
    assert!(!head.contains("101"), "no upgrade on refusal");
    let _ = server.finish().await;
}
