// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! Streaming and SSE responses over the hyper path (`F-16` parity).
//!
//! The hyper path answers streaming routes with `501` until this
//! lands; these tests demand true streaming — the first event
//! arriving while the handler is still parked (a buffered path
//! would deadlock, not merely fail), event bytes round-tripping,
//! and the same over HTTP/2. Red until the channel writer lands.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use qqq_io::listener::Shutdown;
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::metrics::TenantLabels;
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::serve_hyper::serve_hyper_h1;
use qqq_serve::server::{ConnectionContext, ConnectionId, Dispatch, Handler, RouteMatch, Served};
use qqq_serve::sse::Event;
use qqq_serve::stream::{StreamError, StreamWriter};
use qqq_serve::transport::{HyperLimits, hyper_limits_for};
use qqq_serve::ws::WsConfig;
use qqq_serve::{ConnectionConfig, RequestHead, Response};

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
    Arc::new(|_head: &RequestHead, _m: &RouteMatch| Response::text(200, "flat"))
}

fn default_limits() -> HyperLimits {
    hyper_limits_for(&ConnectionConfig::default())
}

/// A handler that emits one event, parks until released, then emits
/// a second: the first-event-before-return proof needs the park.
fn gated_handler(
    gate: oneshot::Receiver<()>,
    invocations: Arc<AtomicUsize>,
) -> qqq_serve::stream::StreamingHandler {
    let gate = Arc::new(tokio::sync::Mutex::new(Some(gate)));
    Arc::new(
        move |_head: &RequestHead,
              _m: &RouteMatch,
              w: &mut StreamWriter<'_>|
              -> Pin<
            Box<dyn std::future::Future<Output = Result<(), StreamError>> + Send + '_>,
        > {
            let gate = Arc::clone(&gate);
            let invocations = Arc::clone(&invocations);
            Box::pin(async move {
                invocations.fetch_add(1, Ordering::SeqCst);
                w.write_now(b"data: first\n\n")
                    .await
                    .map_err(|e| StreamError::Transport(e.to_string()))?;
                if let Some(rx) = gate.lock().await.take() {
                    let _ = rx.await;
                }
                w.write_now(b"data: second\n\n")
                    .await
                    .map_err(|e| StreamError::Transport(e.to_string()))?;
                Ok(())
            })
        },
    )
}

/// One hyper-driven listener; each exchange is a fresh connection.
struct Hyper {
    addr: SocketAddr,
    shutdown: Shutdown,
    driver: JoinHandle<Served>,
}

impl Hyper {
    async fn start(dispatch: Dispatch, pieces: Pieces) -> Self {
        // GET serves events; POST exists so the chunked-body
        // refusal test routes instead of 404ing.
        let table = Arc::new(table_with(&[
            (Method::Get, "/events", "stream"),
            (Method::Post, "/events", "stream"),
        ]));
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

    async fn finish(self) {
        self.shutdown.signal();
        let _ = self.driver.await;
    }
}

/// Read until `needle` appears or the timeout expires.
async fn read_until(stream: &mut TcpStream, needle: &str) -> Vec<u8> {
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    out.extend_from_slice(&chunk[..n]);
                    if String::from_utf8_lossy(&out).contains(needle) {
                        break;
                    }
                }
            }
        }
    })
    .await
    .expect("server speaks while the handler runs");
    out
}

/// A streaming route delivers its first event before the handler
/// finishes: the handler parks until the test releases it, so a
/// path that buffered the whole body would deadlock here.
#[tokio::test]
async fn hyper_streaming_delivers_first_event_before_handler_returns() {
    let (tx, rx) = oneshot::channel();
    let invocations = Arc::new(AtomicUsize::new(0));
    let dispatch = Dispatch::flat(flat_handler())
        .with_streaming("stream", gated_handler(rx, Arc::clone(&invocations)));
    let server = Hyper::start(dispatch, Pieces::bare()).await;
    let mut client = TcpStream::connect(server.addr).await.expect("connect");
    client
        .write_all(b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    client.flush().await.expect("flush");
    let got = read_until(&mut client, "data: first").await;
    let text = String::from_utf8_lossy(&got).into_owned();
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "streaming answers 200, not a refusal:\n{text}"
    );
    assert!(
        text.contains("data: first"),
        "the first event arrives while the handler is parked:\n{text}"
    );
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        1,
        "the handler ran exactly once"
    );
    tx.send(()).expect("release the handler");
    let rest = read_until(&mut client, "data: second").await;
    assert!(
        String::from_utf8_lossy(&rest).contains("data: second"),
        "the stream continues after release"
    );
    server.finish().await;
}

/// SSE event bytes cross the hyper path unchanged: the codec's
/// bytes in, the same bytes out, framed as chunks on the wire.
#[tokio::test]
async fn hyper_sse_event_bytes_round_trip() {
    let expected = Event::data("hello").encode();
    assert!(!expected.is_empty(), "the codec produces bytes");
    let handler: qqq_serve::stream::StreamingHandler = Arc::new(
        move |_head: &RequestHead,
              _m: &RouteMatch,
              w: &mut StreamWriter<'_>|
              -> Pin<
            Box<dyn std::future::Future<Output = Result<(), StreamError>> + Send + '_>,
        > {
            let expected = expected.clone();
            Box::pin(async move {
                w.write_now(&expected)
                    .await
                    .map_err(|e| StreamError::Transport(e.to_string()))?;
                Ok(())
            })
        },
    );
    let dispatch = Dispatch::flat(flat_handler()).with_streaming("stream", handler);
    let server = Hyper::start(dispatch, Pieces::bare()).await;
    let mut client = TcpStream::connect(server.addr).await.expect("connect");
    client
        .write_all(b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    client.flush().await.expect("flush");
    let got = read_until(&mut client, "data:hello").await;
    let text = String::from_utf8_lossy(&got).into_owned();
    assert!(
        text.contains("data:hello"),
        "event bytes arrive intact:\n{text}"
    );
    server.finish().await;
}

/// A chunked body on a streaming route is refused before the
/// handler runs: committing to a stream with bytes in flight
/// bypasses the body cap. Mirrors the in-house refusal.
#[tokio::test]
async fn hyper_streaming_chunked_body_is_refused() {
    let (tx, rx) = oneshot::channel();
    let invocations = Arc::new(AtomicUsize::new(0));
    let dispatch = Dispatch::flat(flat_handler())
        .with_streaming("stream", gated_handler(rx, Arc::clone(&invocations)));
    let server = Hyper::start(dispatch, Pieces::bare()).await;
    let _ = tx;
    let mut client = TcpStream::connect(server.addr).await.expect("connect");
    client
        .write_all(
            b"POST /events HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        )
        .await
        .expect("write");
    client.flush().await.expect("flush");
    let got = read_until(&mut client, "\r\n\r\n").await;
    let text = String::from_utf8_lossy(&got).into_owned();
    assert!(
        text.starts_with("HTTP/1.1 400"),
        "a chunked streaming body must be refused:\n{text}"
    );
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "the handler must never see a refused body"
    );
    server.finish().await;
}

// ---------------------------------------------------------------------------
// HTTP/2 streaming over hyper
// ---------------------------------------------------------------------------

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn h2_frame(ftype: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("test frames are small");
    let mut out = Vec::with_capacity(9 + payload.len());
    out.push(u8::try_from(len >> 16).expect("length fits 24 bits"));
    out.push(u8::try_from((len >> 8) & 0xff).expect("length fits 24 bits"));
    out.push(u8::try_from(len & 0xff).expect("length fits 24 bits"));
    out.push(ftype);
    out.push(flags);
    out.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Read one frame off any stream.
async fn h2_read_frame(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Option<(u8, u8, u32, Vec<u8>)> {
    let mut head = [0u8; 9];
    stream.read_exact(&mut head).await.ok()?;
    let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
    assert!(len <= 1024 * 1024, "server sent an over-large frame");
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await.ok()?;
    }
    let sid = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
    Some((head[3], head[4], sid, payload))
}

/// Raw h2 handshake plus fresh HPACK codecs: preface, empty
/// SETTINGS, the server's SETTINGS, then the ack. Shared setup,
/// not a verdict — every h2 test shakes the same hand.
async fn h2_shake_hands(
    io: &mut tokio::io::DuplexStream,
) -> (qqq_serve::h2::hpack::Encoder, qqq_serve::h2::hpack::Decoder) {
    use qqq_serve::h2::hpack::{Decoder, Encoder};
    let mut hello = H2_PREFACE.to_vec();
    hello.extend_from_slice(&h2_frame(0x4, 0, 0, &[]));
    io.write_all(&hello).await.expect("preface writes");
    loop {
        let Some((ftype, flags, _, _)) =
            tokio::time::timeout(Duration::from_secs(10), h2_read_frame(&mut *io))
                .await
                .expect("server speaks")
        else {
            panic!("server died during handshake");
        };
        if ftype == 0x4 && (flags & 0x1) == 0 {
            break;
        }
    }
    io.write_all(&h2_frame(0x4, 0x1, 0, &[]))
        .await
        .expect("ack writes");
    (Encoder::new(), Decoder::new())
}

/// GET `path` over a shaken h2 connection and collect the stream:
/// HEADERS out, then HEADERS/DATA in until `END_STREAM`. Releases
/// `gate` on the first event so a parked handler continues — the
/// release is the test's liveness proof, not framing, which is
/// why it lives in the reader rather than the handler.
async fn h2_get_events(
    io: &mut tokio::io::DuplexStream,
    encoder: &mut qqq_serve::h2::hpack::Encoder,
    decoder: &mut qqq_serve::h2::hpack::Decoder,
    path: &str,
    mut gate: Option<oneshot::Sender<()>>,
) -> (u16, Vec<u8>) {
    use qqq_serve::h2::hpack::HeaderField;
    let block = encoder.encode(&[
        HeaderField::new(":method", "GET"),
        HeaderField::new(":path", path),
        HeaderField::new(":scheme", "http"),
        HeaderField::new(":authority", "localhost"),
    ]);
    io.write_all(&h2_frame(0x1, 0x4 | 0x1, 1, &block))
        .await
        .expect("headers write");
    let mut status = 0u16;
    let mut body = Vec::new();
    let mut released = false;
    loop {
        let Some((ftype, flags, sid, payload)) =
            tokio::time::timeout(Duration::from_secs(10), h2_read_frame(&mut *io))
                .await
                .expect("server speaks")
        else {
            panic!("server died mid-stream");
        };
        if sid == 0 {
            continue;
        }
        if ftype == 0x1 {
            for field in decoder.decode(&payload).expect("decode") {
                if field.name == ":status" {
                    status = field.value.parse().expect("numeric status");
                }
            }
        } else if ftype == 0x0 {
            body.extend_from_slice(&payload);
            if !released && String::from_utf8_lossy(&body).contains("data: first") {
                released = true;
                if let Some(gate) = gate.take() {
                    gate.send(()).expect("release the handler");
                }
            }
            if (flags & 0x1) != 0 {
                break;
            }
        }
    }
    (status, body)
}

/// One h2 connection context over borrowed pieces: the three
/// duplex tests build the same struct, and the third copy is
/// what tripped the line budget — one home for the boilerplate.
fn h2_conn_ctx<'a>(pieces: &'a Pieces, id: &'a ConnectionId) -> ConnectionContext<'a> {
    ConnectionContext {
        id,
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
    }
}

/// Events stream over HTTP/2 DATA frames: the same handler bytes,
/// the same first-event-before-return proof, framed by hyper.
#[tokio::test]
async fn hyper_h2_streaming_delivers_events_as_data() {
    use qqq_serve::serve_hyper::serve_hyper_h2;

    let table = Arc::new(table_with(&[(Method::Get, "/events", "stream")]));
    let (tx, rx) = oneshot::channel();
    let invocations = Arc::new(AtomicUsize::new(0));
    let dispatch = Dispatch::flat(flat_handler())
        .with_streaming("stream", gated_handler(rx, Arc::clone(&invocations)));
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let limits = HyperLimits {
        // A short drain bound: the default would outlast the
        // close-watch below, and the verdict under test is *that*
        // the shutdown drains, not how long production allows it.
        drain_timeout: Duration::from_millis(100),
        ..default_limits()
    };
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, Arc::clone(&table), dispatch, limits, &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        let mut io = client_io;
        let (mut encoder, mut decoder) = h2_shake_hands(&mut io).await;
        let (status, body) =
            h2_get_events(&mut io, &mut encoder, &mut decoder, "/events", Some(tx)).await;
        assert_eq!(status, 200, "h2 streaming answers 200");
        let text = String::from_utf8_lossy(&body).into_owned();
        assert!(
            text.contains("data: first") && text.contains("data: second"),
            "both events arrive over DATA:\n{text}"
        );
        shutdown.signal();
        // Stay open until the server drains and closes: dropping
        // here would race EOF against the shutdown signal and the
        // outcome would be `ClientClosed` instead of `Drained`
        // (same race the duplex h2 test pins). A server that never
        // closes enforces nothing — time out loudly.
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            let mut byte = [0u8; 1];
            while io.read_exact(&mut byte).await.is_ok() {}
        })
        .await;
        closed.expect("server drains and closes after shutdown");
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("stream completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the stream");
}

/// A parked streaming handler ends with its connection: server
/// shutdown aborts the detached task instead of leaking it.
/// In-house abandons the connection task the same way at the
/// drain deadline (the accept loop's `JoinSet`), so the abort is
/// parity, not policy — and its silence (no record) matches the
/// abandon, which never reaches the emit either.
#[tokio::test]
async fn hyper_h2_parked_streaming_handler_dies_with_the_connection() {
    use qqq_serve::h2::hpack::HeaderField;
    use qqq_serve::serve_hyper::serve_hyper_h2;

    let dropped = Arc::new(AtomicBool::new(false));
    let handler: qqq_serve::stream::StreamingHandler = Arc::new({
        let dropped = Arc::clone(&dropped);
        move |_head: &RequestHead,
              _m: &RouteMatch,
              _w: &mut StreamWriter<'_>|
              -> Pin<
            Box<dyn std::future::Future<Output = Result<(), StreamError>> + Send + '_>,
        > {
            let dropped = Arc::clone(&dropped);
            Box::pin(async move {
                struct Guard(Arc<AtomicBool>);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::SeqCst);
                    }
                }
                let _guard = Guard(dropped);
                std::future::pending::<Result<(), StreamError>>().await
            })
        }
    });
    let table = Arc::new(table_with(&[(Method::Get, "/events", "stream")]));
    let dispatch = Dispatch::flat(flat_handler()).with_streaming("stream", handler);
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let limits = HyperLimits {
        drain_timeout: Duration::from_millis(100),
        ..default_limits()
    };
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, Arc::clone(&table), dispatch, limits, &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        let mut io = client_io;
        let (mut encoder, _) = h2_shake_hands(&mut io).await;
        let block = encoder.encode(&[
            HeaderField::new(":method", "GET"),
            HeaderField::new(":path", "/events"),
            HeaderField::new(":scheme", "http"),
            HeaderField::new(":authority", "localhost"),
        ]);
        io.write_all(&h2_frame(0x1, 0x4 | 0x1, 1, &block))
            .await
            .expect("headers write");
        // No response read: the handler parks before writing
        // anything, which is the leak shape — shutdown must end
        // it anyway.
        shutdown.signal();
        // Stay open so the shutdown verdict is deterministic
        // (EOF would race it into `ClientClosed`).
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            let mut byte = [0u8; 1];
            while io.read_exact(&mut byte).await.is_ok() {}
        })
        .await;
        closed.expect("server drains and closes after shutdown");
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("shutdown completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the connection");
    let mut fired = false;
    for _ in 0..500 {
        if dropped.load(Ordering::SeqCst) {
            fired = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        fired,
        "the parked handler task must die with its connection, not leak"
    );
}

/// One event plus an invocation count: the declared-length and
/// DATA-without-length pins below need a handler that proves it
/// ran and that its bytes crossed.
fn counting_handler(invocations: Arc<AtomicUsize>) -> qqq_serve::stream::StreamingHandler {
    Arc::new(
        move |_head: &RequestHead,
              _m: &RouteMatch,
              w: &mut StreamWriter<'_>|
              -> Pin<
            Box<dyn std::future::Future<Output = Result<(), StreamError>> + Send + '_>,
        > {
            let invocations = Arc::clone(&invocations);
            Box::pin(async move {
                invocations.fetch_add(1, Ordering::SeqCst);
                w.write_now(b"data: hi\n\n")
                    .await
                    .map_err(|e| StreamError::Transport(e.to_string()))?;
                Ok(())
            })
        },
    )
}

/// A declared-length body reaches a streaming handler on hyper,
/// exactly as in-house: `special_route_has_body` names only
/// unbounded (chunked) bodies, because a declared length is
/// already capped by the parser before dispatch. The in-house
/// half of this differential is
/// `streaming_route::a_streaming_route_does_not_read_the_request_body`.
#[tokio::test]
async fn hyper_streaming_declared_length_body_reaches_the_handler() {
    let invocations = Arc::new(AtomicUsize::new(0));
    let dispatch = Dispatch::flat(flat_handler())
        .with_streaming("stream", counting_handler(Arc::clone(&invocations)));
    let server = Hyper::start(dispatch, Pieces::bare()).await;
    let mut client = TcpStream::connect(server.addr).await.expect("connect");
    client
        .write_all(b"POST /events HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
        .await
        .expect("write");
    client.flush().await.expect("flush");
    let got = read_until(&mut client, "data: hi").await;
    let text = String::from_utf8_lossy(&got).into_owned();
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "a declared-length body is policy, not a refusal:\n{text}"
    );
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        1,
        "the handler ran exactly once"
    );
    server.finish().await;
}

/// An HTTP/2 streaming request with DATA but no declared length
/// takes the same path: the refusal names chunked framing, and
/// h2 has none — unread DATA is window-bounded, not unbounded.
/// Pins the flagged case as policy, not bypass.
#[tokio::test]
async fn hyper_h2_streaming_data_without_length_reaches_the_handler() {
    use qqq_serve::h2::hpack::HeaderField;
    use qqq_serve::serve_hyper::serve_hyper_h2;

    let invocations = Arc::new(AtomicUsize::new(0));
    let table = Arc::new(table_with(&[(Method::Post, "/events", "stream")]));
    let dispatch = Dispatch::flat(flat_handler())
        .with_streaming("stream", counting_handler(Arc::clone(&invocations)));
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let limits = HyperLimits {
        drain_timeout: Duration::from_millis(100),
        ..default_limits()
    };
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, Arc::clone(&table), dispatch, limits, &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        let mut io = client_io;
        let (mut encoder, mut decoder) = h2_shake_hands(&mut io).await;
        let block = encoder.encode(&[
            HeaderField::new(":method", "POST"),
            HeaderField::new(":path", "/events"),
            HeaderField::new(":scheme", "http"),
            HeaderField::new(":authority", "localhost"),
        ]);
        io.write_all(&h2_frame(0x1, 0x4, 1, &block))
            .await
            .expect("headers write");
        io.write_all(&h2_frame(0x0, 0x1, 1, b"hello"))
            .await
            .expect("data writes");
        let mut status = 0u16;
        let mut body = Vec::new();
        loop {
            let Some((ftype, flags, sid, payload)) =
                tokio::time::timeout(Duration::from_secs(10), h2_read_frame(&mut io))
                    .await
                    .expect("server speaks")
            else {
                panic!("server died mid-stream");
            };
            if sid == 0 {
                continue;
            }
            if ftype == 0x1 {
                for field in decoder.decode(&payload).expect("decode") {
                    if field.name == ":status" {
                        status = field.value.parse().expect("numeric status");
                    }
                }
            } else if ftype == 0x0 {
                body.extend_from_slice(&payload);
                if (flags & 0x1) != 0 {
                    break;
                }
            }
        }
        assert_eq!(
            status, 200,
            "h2 DATA without length is policy, not a refusal"
        );
        assert!(
            String::from_utf8_lossy(&body).contains("data: hi"),
            "the handler ran and its bytes crossed"
        );
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            1,
            "the handler ran exactly once"
        );
        shutdown.signal();
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            let mut byte = [0u8; 1];
            while io.read_exact(&mut byte).await.is_ok() {}
        })
        .await;
        closed.expect("server drains and closes after shutdown");
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("stream completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the stream");
}
