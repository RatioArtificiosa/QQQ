// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! Hyper HTTP/2 serving against raw frames, including the §O-676 flood
//! acceptance tests.
//!
//! # Why raw sockets instead of an h2 client
//!
//! No h2 client dependency exists in this workspace (the owner's
//! non-negotiable: Hyper owns framing on the serve path, and the
//! in-house `h2/` is the test oracle, not a client library). A raw
//! socket speaks exactly what the test means — including malformed
//! and abusive inputs no well-behaved client can produce — while the
//! in-house HPACK codec builds and reads header blocks, which is
//! codec reuse, not protocol duplication.
//!
//! # What "undrained" means in the flood tests
//!
//! The flood bytes go out with no reads between them, so the server's
//! sends buffer exactly as they would under attack. Only after the
//! blast does the test read, observing GOAWAY, close, and how much the
//! server sent — the three §O-676 facts.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use qqq_io::listener::Shutdown;
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::h2::hpack::{Decoder, Encoder, HeaderField};
use qqq_serve::metrics::TenantLabels;
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::serve_hyper::serve_hyper_h2;
use qqq_serve::server::{ConnectionContext, ConnectionId, Dispatch, Handler, RouteMatch, Served};
use qqq_serve::transport::{HyperLimits, hyper_limits_for};
use qqq_serve::ws::WsConfig;
use qqq_serve::{ConnectionConfig, Response};

// Frame types (RFC 9113 §6).
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;

// Flags.
const ACK: u8 = 0x1;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

// Error codes (RFC 9113 §7).
const CANCEL: u32 = 0x8;
const ENHANCE_YOUR_CALM: u32 = 0xb;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Build one wire frame: 9-byte header plus payload.
fn frame(ftype: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
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

fn ping(payload: [u8; 8]) -> Vec<u8> {
    frame(PING, 0, 0, &payload)
}

fn settings(payload: &[u8]) -> Vec<u8> {
    frame(SETTINGS, 0, 0, payload)
}

fn settings_ack() -> Vec<u8> {
    frame(SETTINGS, ACK, 0, &[])
}

fn rst(stream: u32, code: u32) -> Vec<u8> {
    frame(RST_STREAM, 0, stream, &code.to_be_bytes())
}

/// One wire frame as read.
struct H2Frame {
    ftype: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

/// Read one frame, or `None` when the connection died first.
async fn read_frame(stream: &mut TcpStream) -> Option<H2Frame> {
    let mut head = [0u8; 9];
    stream.read_exact(&mut head).await.ok()?;
    let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
    assert!(len <= 1024 * 1024, "server sent an over-large frame");
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await.ok()?;
    }
    let id = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
    Some(H2Frame {
        ftype: head[3],
        flags: head[4],
        stream: id,
        payload,
    })
}

async fn read_frame_timeout(stream: &mut TcpStream, wait: Duration) -> Option<H2Frame> {
    tokio::time::timeout(wait, read_frame(stream))
        .await
        .ok()
        .flatten()
}

/// A handshaked h2 connection with HPACK state for both directions.
struct H2 {
    stream: TcpStream,
    encoder: Encoder,
    decoder: Decoder,
    next_stream: u32,
    /// Streams whose responses completed: late frames for them (flow
    /// accounting, cleanups) sort past the current read instead of
    /// failing it.
    completed: std::collections::HashSet<u32>,
    /// Responses in flight on other streams: the server may answer
    /// concurrent streams in any order (that is what multiplexing
    /// means), so frames for a stream being read arrive mixed with
    /// frames for its siblings. Each stream's partial response waits
    /// here until its `END_STREAM`; HPACK decoding still happens in
    /// arrival order through the one shared decoder, which is what
    /// keeps the dynamic table in sync.
    pending: std::collections::HashMap<u32, PartialResponse>,
}

/// One stream's response as it accumulates.
#[derive(Default)]
struct PartialResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    done: bool,
}

impl H2 {
    /// Connect, speak the preface, and settle the handshake: read the
    /// server's `SETTINGS`, acknowledge it, and swallow the connection
    /// `WINDOW_UPDATE` hyper sends alongside.
    async fn connect(addr: SocketAddr) -> Self {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let mut hello = PREFACE.to_vec();
        hello.extend_from_slice(&settings(&[]));
        stream.write_all(&hello).await.expect("preface");
        let mut h2 = Self {
            stream,
            encoder: Encoder::new(),
            decoder: Decoder::new(),
            next_stream: 1,
            completed: std::collections::HashSet::new(),
            pending: std::collections::HashMap::new(),
        };
        loop {
            let frame = read_frame_timeout(&mut h2.stream, Duration::from_secs(5))
                .await
                .expect("server settings");
            if frame.ftype == SETTINGS && (frame.flags & ACK) == 0 {
                break;
            }
        }
        h2.stream.write_all(&settings_ack()).await.expect("ack");
        h2
    }

    /// Send one `GET` request head, open stream, no body.
    async fn get(&mut self, path: &str) -> u32 {
        let id = self.next_stream;
        self.next_stream += 2;
        let block = self.encoder.encode(&[
            HeaderField::new(":method", "GET"),
            HeaderField::new(":path", path),
            HeaderField::new(":scheme", "http"),
            HeaderField::new(":authority", "localhost"),
        ]);
        let bytes = frame(HEADERS, END_HEADERS | END_STREAM, id, &block);
        self.stream.write_all(&bytes).await.expect("headers");
        id
    }

    /// Read one response: `HEADERS` (decoded) then `DATA` to `END_STREAM`.
    ///
    /// Sibling streams sort, not fail: frames for other live streams
    /// accumulate in `pending` (decoded in arrival order, which is what
    /// the HPACK table requires) until this stream's own `END_STREAM`
    /// completes it. A reset kills only its own read — anything else
    /// would make every multiplexed test an ordering bet.
    async fn response(&mut self, id: u32) -> (u16, Vec<(String, String)>, Vec<u8>) {
        loop {
            // Peek, never drop: removing an unfinished entry here
            // would discard its decoded head on every pass.
            if self.pending.get(&id).is_some_and(|partial| partial.done) {
                let partial = self.pending.remove(&id).expect("entry checked above");
                self.completed.insert(id);
                return (partial.status, partial.headers, partial.body);
            }
            let frame = read_frame_timeout(&mut self.stream, Duration::from_secs(10))
                .await
                .expect("response frame");
            // Connection-level housekeeping sorts itself, including a
            // GOAWAY that graceful shutdown announces before answering
            // in-flight streams. Late frames for completed streams sort
            // past too (flow accounting, cleanups arriving after their
            // response was consumed).
            if frame.stream == 0 || self.completed.contains(&frame.stream) {
                continue;
            }
            match frame.ftype {
                HEADERS => {
                    let fields = self.decoder.decode(&frame.payload).expect("decode");
                    let partial = self.pending.entry(frame.stream).or_default();
                    for field in fields {
                        if field.name == ":status" {
                            partial.status = field.value.parse().expect("numeric status");
                        } else {
                            partial.headers.push((field.name, field.value));
                        }
                    }
                    if frame.flags & END_STREAM != 0 {
                        partial.done = true;
                    }
                }
                DATA => {
                    let partial = self.pending.entry(frame.stream).or_default();
                    partial.body.extend_from_slice(&frame.payload);
                    if frame.flags & END_STREAM != 0 {
                        partial.done = true;
                    }
                }
                RST_STREAM => {
                    assert!(frame.stream != id, "stream {id} was reset before answering");
                    self.pending.remove(&frame.stream);
                    self.completed.insert(frame.stream);
                }
                _ => {
                    panic!(
                        "stream frame of unexpected type {} on stream {}",
                        frame.ftype, frame.stream
                    );
                }
            }
        }
    }
}

/// Owned context pieces for one hyper h2 connection (mirrors the h1
/// harness: the driver task owns everything, so no borrow crosses the
/// spawn boundary).
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

/// One hyper-h2-driven listener; the driver serves connections until
/// shutdown and reports the last outcome.
struct HyperH2 {
    addr: SocketAddr,
    shutdown: Shutdown,
    driver: JoinHandle<Served>,
}

impl HyperH2 {
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
                        };
                        last = serve_hyper_h2(
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

fn default_limits() -> HyperLimits {
    hyper_limits_for(&ConnectionConfig::default())
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

// ---------------------------------------------------------------------------
// Differential: flat routes over h2
// ---------------------------------------------------------------------------

/// The same `GET` answers the same over prior-knowledge h2.
#[tokio::test]
async fn h2_flat_200_matches() {
    let routes = [(Method::Get, "/hello", "h")];
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let mut h2 = H2::connect(hyper.addr).await;
    let id = h2.get("/hello").await;
    let (status, _headers, body) = h2.response(id).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello from h");
    let _ = hyper.finish().await;
}

/// Interleaved answers sort by stream: `/slow` (200ms) opens first
/// but `/fast` answers first, and reading the slow stream first still
/// returns the slow answer. The old harness asserted arrival order
/// and died here whenever the scheduler answered out of order
/// (measured on macos CI at the `response arrives on its stream`
/// assert). Deterministic: the 200ms sleep guarantees the fast
/// stream's frames arrive while the slow read is waiting.
#[tokio::test]
async fn h2_interleaved_responses_sort_by_stream() {
    let mut body_map = std::collections::BTreeMap::new();
    body_map.insert(
        "slow".to_owned(),
        Arc::new(
            |_head: &qqq_serve::http1::RequestHead, _body: &qqq_serve::BodyBytes, _tenant: &str| {
                std::thread::sleep(Duration::from_millis(200));
                Response::text(200, "slow body")
            },
        ) as qqq_serve::BodyHandler,
    );
    let dispatch = Dispatch {
        flat: hello_handler(),
        streaming: Arc::new(std::collections::BTreeMap::new()),
        websocket: Arc::new(std::collections::BTreeMap::new()),
        body: Arc::new(body_map),
    };
    let hyper = HyperH2::start(
        table_with(&[(Method::Get, "/slow", "slow"), (Method::Get, "/fast", "h")]),
        dispatch,
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let mut h2 = H2::connect(hyper.addr).await;
    let slow = h2.get("/slow").await;
    let fast = h2.get("/fast").await;
    let (slow_status, _, slow_body) = h2.response(slow).await;
    assert_eq!(slow_status, 200);
    assert_eq!(slow_body, b"slow body");
    let (fast_status, _, fast_body) = h2.response(fast).await;
    assert_eq!(fast_status, 200);
    assert_eq!(fast_body, b"hello from h");
    let _ = hyper.finish().await;
}

/// Two streams multiplex on one connection, both answered.
#[tokio::test]
async fn h2_multiplexed_requests_share_a_connection() {
    let routes = [(Method::Get, "/hello", "h")];
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let mut h2 = H2::connect(hyper.addr).await;
    let first = h2.get("/hello").await;
    let second = h2.get("/hello").await;
    let (one, _, body_one) = h2.response(first).await;
    let (two, _, body_two) = h2.response(second).await;
    assert_eq!((one, two), (200, 200));
    assert_eq!(body_one, b"hello from h");
    assert_eq!(body_two, b"hello from h");
    let _ = hyper.finish().await;
}

/// `:authority` becomes the `Host` the loopback check reads: a foreign
/// authority on a loopback listener is `421` over h2 too.
#[tokio::test]
async fn h2_foreign_authority_is_421_on_loopback() {
    let routes = [(Method::Get, "/hello", "h")];
    let mut pieces = Pieces::bare();
    pieces.loopback_only = true;
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        pieces,
    )
    .await;
    let mut h2 = H2::connect(hyper.addr).await;
    let id = h2.next_stream;
    h2.next_stream += 2;
    let block = h2.encoder.encode(&[
        HeaderField::new(":method", "GET"),
        HeaderField::new(":path", "/hello"),
        HeaderField::new(":scheme", "http"),
        HeaderField::new(":authority", "evil.test"),
    ]);
    h2.stream
        .write_all(&frame(HEADERS, END_HEADERS | END_STREAM, id, &block))
        .await
        .expect("headers");
    let (status, _, _) = h2.response(id).await;
    assert_eq!(status, 421);
    let _ = hyper.finish().await;
}

/// A `Transfer-Encoding` other than chunked never reaches the
/// service: hyper resets the stream at the framing layer, and the
/// connection survives for the next request.
#[tokio::test]
async fn h2_other_transfer_encoding_is_refused() {
    let routes = [(Method::Post, "/a", "h"), (Method::Get, "/hello", "h")];
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let mut h2 = H2::connect(hyper.addr).await;
    let id = h2.next_stream;
    h2.next_stream += 2;
    let block = h2.encoder.encode(&[
        HeaderField::new(":method", "POST"),
        HeaderField::new(":path", "/a"),
        HeaderField::new(":scheme", "http"),
        HeaderField::new(":authority", "localhost"),
        HeaderField::new("transfer-encoding", "gzip"),
    ]);
    h2.stream
        .write_all(&frame(HEADERS, END_HEADERS | END_STREAM, id, &block))
        .await
        .expect("headers");
    // The stream dies with `RST_STREAM`; anything else (a routed
    // response, a dead connection) fails loudly below.
    let reset = loop {
        let frame = read_frame_timeout(&mut h2.stream, Duration::from_secs(10))
            .await
            .expect("reset frame");
        if frame.stream == id && frame.ftype == RST_STREAM {
            break frame;
        }
        assert_eq!(frame.stream, 0, "only housekeeping may interleave");
    };
    assert_eq!(reset.payload.len(), 4, "reset carries a code");
    // The connection survives its reset stream.
    let again = h2.get("/hello").await;
    let (status, _, body) = h2.response(again).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello from h");
    let _ = hyper.finish().await;
}

/// A body without `Content-Length` streams to the cap instead of being
/// lost: h2 has no chunked framing, so undeclared DATA must be counted,
/// not ignored — and the handler sees the actual bytes.
#[tokio::test]
async fn h2_body_without_length_streams_to_cap() {
    let routes = [(Method::Post, "/echo", "echo")];
    let mut body_map = std::collections::BTreeMap::new();
    body_map.insert(
        "echo".to_owned(),
        Arc::new(
            |_head: &qqq_serve::http1::RequestHead, body: &qqq_serve::BodyBytes, _tenant: &str| {
                let text = match body {
                    qqq_serve::BodyBytes::Buffered(bytes) => {
                        String::from_utf8_lossy(bytes).into_owned()
                    }
                    qqq_serve::BodyBytes::Absent => "<absent>".to_owned(),
                    qqq_serve::BodyBytes::TooLarge => "<too-large>".to_owned(),
                };
                Response::text(200, text)
            },
        ) as qqq_serve::BodyHandler,
    );
    let dispatch = Dispatch {
        flat: hello_handler(),
        streaming: Arc::new(std::collections::BTreeMap::new()),
        websocket: Arc::new(std::collections::BTreeMap::new()),
        body: Arc::new(body_map),
    };
    let hyper = HyperH2::start(
        table_with(&routes),
        dispatch,
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let mut h2 = H2::connect(hyper.addr).await;
    let id = h2.next_stream;
    h2.next_stream += 2;
    let block = h2.encoder.encode(&[
        HeaderField::new(":method", "POST"),
        HeaderField::new(":path", "/echo"),
        HeaderField::new(":scheme", "http"),
        HeaderField::new(":authority", "localhost"),
    ]);
    h2.stream
        .write_all(&frame(HEADERS, END_HEADERS, id, &block))
        .await
        .expect("headers");
    // DATA without END_STREAM, then DATA with END_STREAM: 10 bytes, no length.
    h2.stream
        .write_all(&frame(DATA, 0, id, b"hello"))
        .await
        .expect("data");
    h2.stream
        .write_all(&frame(DATA, END_STREAM, id, b"world"))
        .await
        .expect("data end");
    let (status, _, body) = h2.response(id).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"helloworld");
    let _ = hyper.finish().await;
}

// ---------------------------------------------------------------------------
// §O-676 flood acceptance
//
// Two of the three floods below document a measured gap, not a
// cutoff: hyper 1.12 over h2 0.4.20 auto-acks PINGs and SETTINGS at
// the codec level with no rate knob (verified against the h2 0.4.20
// source: the server builder offers reset-stream and buffer knobs,
// nothing that counts PINGs), so the §O-676 `GOAWAY(ENHANCE_YOUR_CALM)`
// cutoff is inexpressible on this stack. Each test's gap record says
// exactly that, and the names say what is actually pinned —
// answered/acked without collapse — so a green suite never reads as
// a cutoff that does not exist. The mitigations that do transfer:
// every PING costs 17 bytes each way (symmetric, no amplification),
// pong state is a single slot (no memory growth), and the QQQ
// whole-connection idle and drain bounds still reclaim the peer.
// ---------------------------------------------------------------------------

/// Raw preface-plus-SETTINGS handshake without response tracking, for
/// floods that never read until the blast is done.
async fn flood_handshake(addr: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let mut hello = PREFACE.to_vec();
    hello.extend_from_slice(&settings(&[]));
    stream.write_all(&hello).await.expect("preface");
    // Settle the handshake: read the server's SETTINGS, acknowledge it.
    loop {
        let frame = read_frame_timeout(&mut stream, Duration::from_secs(5))
            .await
            .expect("server settings");
        if frame.ftype == SETTINGS && (frame.flags & ACK) == 0 {
            break;
        }
    }
    stream.write_all(&settings_ack()).await.expect("ack");
    stream
}

/// PING handling, then flood survival, as two phases with different
/// contracts — because one test cannot promise both.
///
/// Phase 1 is strict and deterministic: 1k undrained PINGs (17KB,
/// inside every kernel buffer on earth) are all answered, no GOAWAY
/// intervenes, and the connection serves a `GET` after. This proves
/// the mechanism: PINGs answered, HPACK untouched, server alive.
///
/// Phase 2 blasts 100k undrained and pins only SERVER survival: the
/// flood connection may die mid-blast — idle reclamation, reset
/// budgets, and backpressure deadlock are all correct behaviors
/// under a real flood, and on a starved runner the blast outruns
/// every absolute bound (measured: the 300s binary on Windows CI).
/// What must never happen is the server dying with it, so the final
/// `GET` goes over a FRESH connection. A dead server fails there;
/// a hung server times out there. No branch asserts less: the fresh
/// `GET` always executes.
#[tokio::test]
async fn f16_ping_flood_answered_without_collapse() {
    let routes = [(Method::Get, "/hello", "h")];
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    // Phase 1: 1k undrained PINGs, every one answered.
    let mut stream = flood_handshake(hyper.addr).await;
    let mut opaque = [0u8; 8];
    for i in 0..1_000u32 {
        opaque[..4].copy_from_slice(&i.to_be_bytes());
        opaque[4..].copy_from_slice(&i.to_be_bytes());
        stream.write_all(&ping(opaque)).await.expect("ping");
    }
    stream.flush().await.expect("flush");
    // Read exactly the 1k PONGs (then stop — no trailing timeout):
    // each PING is answered, none is coalesced, no GOAWAY intervenes.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut pongs = 0u32;
    let mut goaway = None;
    while pongs < 1_000 {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "PONGs stalled at {pongs}/1000");
        let frame = read_frame_timeout(&mut stream, left)
            .await
            .expect("PONG stream stays live");
        if frame.ftype == PING && (frame.flags & ACK) != 0 {
            pongs += 1;
        } else if frame.ftype == GOAWAY {
            goaway = Some(frame.payload.len());
            break;
        }
    }
    assert_eq!(pongs, 1_000, "every PING is answered");
    assert_eq!(goaway, None, "no GOAWAY intervenes (see gap record above)");
    // Alive afterwards: a fresh GET on the same connection answers 200.
    // PINGs never touch HPACK state, so a fresh codec is in sync.
    let mut h2 = H2 {
        stream,
        encoder: Encoder::new(),
        decoder: Decoder::new(),
        next_stream: 1,
        completed: std::collections::HashSet::new(),
        pending: std::collections::HashMap::new(),
    };
    let id = h2.get("/hello").await;
    let (status, _, body) = h2.response(id).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello from h");
    drop(h2);
    // Phase 2: 100k undrained PINGs; only server survival is pinned.
    // Write errors end the blast early: a dead flood connection is a
    // permitted outcome (see above), and the fresh `GET` below is
    // what distinguishes survival from collapse.
    let mut flood = flood_handshake(hyper.addr).await;
    let mut opaque = [0u8; 8];
    for i in 0..100_000u32 {
        opaque[..4].copy_from_slice(&i.to_be_bytes());
        opaque[4..].copy_from_slice(&i.to_be_bytes());
        // Each write bounded: a fully backpressured blast blocks
        // forever rather than failing, and the fresh-connection `GET`
        // below cannot bound a loop it follows. Timeout and error
        // both end the blast; survival is pinned after it either way.
        let wrote =
            tokio::time::timeout(Duration::from_secs(5), flood.write_all(&ping(opaque))).await;
        if !matches!(wrote, Ok(Ok(()))) {
            break;
        }
    }
    let _ = flood.flush().await;
    drop(flood);
    let mut h2 = H2::connect(hyper.addr).await;
    let id = h2.get("/hello").await;
    let (status, _, body) = h2.response(id).await;
    assert_eq!(status, 200, "the server serves after the flood");
    assert_eq!(body, b"hello from h");
    let _ = hyper.finish().await;
}

/// 10k undrained empty SETTINGS: hyper acknowledges each one and
/// stays up — same gap record as the PING flood (no settings-rate
/// knob in h2), same proof of no collapse, same live server after.
#[tokio::test]
async fn f16_settings_flood_acked_without_collapse() {
    let routes = [(Method::Get, "/hello", "h")];
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let mut stream = flood_handshake(hyper.addr).await;
    for _ in 0..10_000 {
        stream.write_all(&settings(&[])).await.expect("settings");
    }
    stream.flush().await.expect("flush");
    // Read exactly the 10k ACKs: each SETTINGS is answered, none cut off.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut acks = 0u32;
    let mut goaway = false;
    while acks < 10_000 {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "ACKs stalled at {acks}/10000");
        let frame = read_frame_timeout(&mut stream, left)
            .await
            .expect("ACK stream stays live");
        if frame.ftype == SETTINGS && (frame.flags & ACK) != 0 {
            acks += 1;
        } else if frame.ftype == GOAWAY {
            goaway = true;
            break;
        }
    }
    assert_eq!(acks, 10_000, "every SETTINGS is acknowledged");
    assert!(!goaway, "no GOAWAY intervenes (see gap record above)");
    let mut h2 = H2 {
        stream,
        encoder: Encoder::new(),
        decoder: Decoder::new(),
        next_stream: 1,
        completed: std::collections::HashSet::new(),
        pending: std::collections::HashMap::new(),
    };
    let id = h2.get("/hello").await;
    let (status, _, body) = h2.response(id).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello from h");
    let _ = hyper.finish().await;
}

/// The budget knobs move the cutoff: with both reset budgets raised
/// to 100k, the same waves complete with the connection alive — the
/// causal proof that the death above is the budgets firing, not a
/// harness artifact. Both knobs, because EITHER fires under pressure:
/// `max_local_error_reset_streams` counts the server's refusal RSTs
/// while `max_pending_accept_reset_streams` counts client RSTs still
/// queued for accept, and a starved scheduler deepens the queue until
/// the second fires first (measured on CI: GOAWAY with only the first
/// raised). Paired with the cutoff test, the two pin both directions:
/// budgets at 200 die early, at 100k survive.
#[tokio::test]
async fn h2_reset_budget_knob_moves_the_cutoff() {
    let routes = [(Method::Get, "/hello", "h")];
    let slow: Handler = Arc::new(|_head, _m: &RouteMatch| {
        std::thread::sleep(Duration::from_millis(100));
        Response::text(200, "slow")
    });
    let mut limits = default_limits();
    // Causal test: if the wave death is the reset budgets (200),
    // raising both must move or remove the death.
    limits.max_local_error_reset_streams = 100_000;
    limits.max_pending_reset_streams = 100_000;
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(slow),
        limits,
        Pieces::bare(),
    )
    .await;
    let mut stream = flood_handshake(hyper.addr).await;
    let mut encoder = Encoder::new();
    let mut id: u32 = 1;
    let mut write_failed_at = None;
    for _wave in 0..5 {
        let mut ids = Vec::new();
        for _ in 0..150 {
            let block = encoder.encode(&[
                HeaderField::new(":method", "GET"),
                HeaderField::new(":path", "/hello"),
                HeaderField::new(":scheme", "http"),
                HeaderField::new(":authority", "localhost"),
            ]);
            if stream
                .write_all(&frame(HEADERS, END_HEADERS, id, &block))
                .await
                .is_err()
            {
                write_failed_at = Some(id);
                break;
            }
            ids.push(id);
            id += 2;
        }
        if write_failed_at.is_some() {
            break;
        }
        stream.flush().await.expect("flush");
        for id in ids {
            if stream.write_all(&rst(id, CANCEL)).await.is_err() {
                write_failed_at = Some(id);
                break;
            }
        }
        if write_failed_at.is_some() {
            break;
        }
        stream.flush().await.expect("flush");
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut goaway = false;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match read_frame_timeout(&mut stream, left).await {
            Some(frame) => {
                if frame.ftype == GOAWAY {
                    goaway = true;
                    break;
                }
            }
            None => break,
        }
    }
    assert!(!goaway, "no cutoff with the budget raised");
    assert!(
        write_failed_at.is_none(),
        "all waves complete with the budget raised"
    );
    // Alive and functional afterwards: a fresh GET answers 200.
    let mut h2 = H2 {
        stream,
        encoder: Encoder::new(),
        decoder: Decoder::new(),
        next_stream: id,
        completed: std::collections::HashSet::new(),
        pending: std::collections::HashMap::new(),
    };
    let fresh = h2.get("/hello").await;
    let (status, _, body) = h2.response(fresh).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"slow");
    let _ = hyper.finish().await;
}

/// 10k sequential `HEADERS`+`RST_STREAM` pairs: absorbed silently.
///
/// Each client reset frees its concurrency slot before the next open,
/// so nothing accumulates and no budget fires — measured, not
/// assumed. The server stays up and fully functional after all 10k,
/// which is the assertions below. Contrast with
/// `f16_rapid_reset_cannot_exceed_stream_budget`, where concurrent
/// pressure (not sequential resets) is what the budget counts.
///
/// The ceiling sits above the flood on purpose: every attempted answer
/// counts toward `max_requests_per_connection` — including a reset
/// stream answered 500 into a dead socket, exactly as the in-house
/// `reject_body` answers into one — so 10k streams against the default
/// ceiling of 1k would end in an honest 503, not the 200 below. That
/// counting is pinned by `h2_ceiling_counts_every_answered_request`;
/// here the ceiling is raised so the test measures reset absorption,
/// not the ceiling.
#[tokio::test]
async fn h2_sequential_resets_absorbed() {
    let routes = [(Method::Get, "/hello", "h")];
    let mut limits = default_limits();
    limits.max_requests_per_connection = 100_000;
    // Raised with the ceiling for the same reason: a tight open+RST
    // loop outruns the accept queue even on a fast machine (proven by
    // fault injection: a budget of 5 GOAWAYs the flood in 0.01s), and
    // a starved scheduler widens the gap. The test measures reset
    // absorption, not accept-queue depth.
    limits.max_pending_reset_streams = 100_000;
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        limits,
        Pieces::bare(),
    )
    .await;
    let stream = flood_handshake(hyper.addr).await;
    // One codec pair for blast, drain, and final GET: decoding the
    // drained responses with the same decoder the GET reads through
    // keeps the HPACK table in sync throughout.
    let mut h2 = H2 {
        stream,
        encoder: Encoder::new(),
        decoder: Decoder::new(),
        next_stream: 1,
        completed: std::collections::HashSet::new(),
        pending: std::collections::HashMap::new(),
    };
    for n in 0..10_000 {
        let block = h2.encoder.encode(&[
            HeaderField::new(":method", "GET"),
            HeaderField::new(":path", "/hello"),
            HeaderField::new(":scheme", "http"),
            HeaderField::new(":authority", "localhost"),
        ]);
        let id = h2.next_stream;
        h2.next_stream += 2;
        h2.stream
            .write_all(&frame(HEADERS, END_HEADERS, id, &block))
            .await
            .expect("headers");
        h2.stream.write_all(&rst(id, CANCEL)).await.expect("reset");
        // Drain completed responses as they arrive: without reads,
        // 10k uncollected responses would back the server's send
        // buffer into an unrelated death (measured). Draining keeps
        // this test about reset absorption, and every decoded HEADERS
        // is proof the server kept serving through the flood.
        if n % 100 == 99 {
            loop {
                match read_frame_timeout(&mut h2.stream, Duration::from_millis(5)).await {
                    // Decode (not skip) to keep the HPACK table in sync
                    // for the final GET; responses here are expected and
                    // harmless.
                    Some(frame) if frame.ftype == HEADERS => {
                        h2.decoder.decode(&frame.payload).expect("decode");
                    }
                    Some(_) => {}
                    None => break,
                }
            }
        }
    }
    h2.stream.flush().await.expect("flush");
    // Alive and functional after all 10k: a fresh GET answers 200.
    // (No served-count assert: every stream is reset before its
    // instant service can answer, so responses here would be a race,
    // not a signal. Absorption is the connection surviving, proven by
    // the GET below.)
    let fresh = h2.get("/hello").await;
    let (status, _, body) = h2.response(fresh).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello from h");
    let _ = hyper.finish().await;
}

/// Concurrent opens against a blocked service: past 100 concurrent
/// the server refuses with `RST_STREAM`, refusals count toward the
/// 200 `max_local_error_reset_streams` budget, and the connection
/// dies well before 10k streams. Only that budget can fire here: this
/// test sends no client RSTs, and the pending-accept budget counts
/// peer-sent resets on unaccepted streams (h2 `recv_reset`), so it
/// stays at zero by construction. The cutoff arrives as a TCP close,
/// not the `GOAWAY` the budget names: hyper aborts instead of
/// flushing it (a `GOAWAY`, if one ever appears, must still be
/// `ENHANCE_YOUR_CALM`).
///
/// Why concurrent opens and not sequential `HEADERS`+`RST` pairs:
/// each client reset frees its concurrency slot before the next open,
/// so sequential pairs never accumulate and are absorbed silently
/// (pinned by `h2_sequential_resets_absorbed`). Pressure — and hence
/// refusals — requires unfinished streams to pile up, which is what
/// the blocked service guarantees. The knob-contrast test below
/// proves the reset budgets are the cause.
#[tokio::test]
async fn f16_rapid_reset_cannot_exceed_stream_budget() {
    let routes = [(Method::Get, "/hello", "h")];
    let slow: Handler = Arc::new(|_head, _m: &RouteMatch| {
        std::thread::sleep(Duration::from_secs(1));
        Response::text(200, "slow")
    });
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(slow),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let mut stream = flood_handshake(hyper.addr).await;
    let mut encoder = Encoder::new();
    // 400 opens: ~100 accepted (blocked), ~200 refused (budget), then
    // the cutoff. Bounded far below 10k either way.
    for i in 0..400u32 {
        let id = 1 + 2 * i;
        let block = encoder.encode(&[
            HeaderField::new(":method", "GET"),
            HeaderField::new(":path", "/hello"),
            HeaderField::new(":scheme", "http"),
            HeaderField::new(":authority", "localhost"),
        ]);
        if stream
            .write_all(&frame(HEADERS, END_HEADERS, id, &block))
            .await
            .is_err()
        {
            break;
        }
    }
    stream.flush().await.expect("flush");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut goaway = None;
    let mut rsts = 0u32;
    let mut closed = false;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        let Some(frame) = read_frame_timeout(&mut stream, left).await else {
            closed = true;
            break;
        };
        if frame.ftype == GOAWAY && frame.payload.len() >= 8 {
            goaway = Some(u32::from_be_bytes([
                frame.payload[4],
                frame.payload[5],
                frame.payload[6],
                frame.payload[7],
            ]));
        } else if frame.ftype == RST_STREAM {
            rsts += 1;
        }
    }
    if let Some(code) = goaway {
        assert_eq!(
            code, ENHANCE_YOUR_CALM,
            "a cutoff GOAWAY is ENHANCE_YOUR_CALM"
        );
    }
    assert!(
        rsts >= 100,
        "refusals happened (concurrency bound enforced), saw {rsts} resets"
    );
    assert!(closed, "the pressured connection dies");
    let _ = hyper.finish().await;
}

// ---------------------------------------------------------------------------
// h2 lifecycle
// ---------------------------------------------------------------------------

/// Activity resets the idle bound: six `GET`s 150ms apart on a
/// 300ms bound all answer 200 — the connection is never idle between
/// them. An absolute-from-connect bound kills it at 300ms instead
/// (the in-house `Connection` accrues idle only between requests and
/// never mid-request). This test is red against the absolute driver.
#[tokio::test]
async fn h2_activity_resets_the_idle_bound() {
    let routes = [(Method::Get, "/hello", "h")];
    let mut limits = default_limits();
    limits.idle_timeout = Duration::from_millis(300);
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        limits,
        Pieces::bare(),
    )
    .await;
    let mut h2 = H2::connect(hyper.addr).await;
    for n in 0..6 {
        let id = h2.get("/hello").await;
        let (status, _, body) = h2.response(id).await;
        assert_eq!(status, 200, "request {n} on an active connection");
        assert_eq!(body, b"hello from h");
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let _ = hyper.finish().await;
}

/// An idle h2 connection dies on the idle bound, reported as such.
#[tokio::test]
async fn h2_idle_closes_with_idle_timeout() {
    let routes = [(Method::Get, "/hello", "h")];
    let mut limits = default_limits();
    limits.idle_timeout = Duration::from_millis(150);
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        limits,
        Pieces::bare(),
    )
    .await;
    // Settle the handshake first, so only the idle timer can fire.
    // Then read to the end, not to the first bytes: the server may
    // still have housekeeping (WINDOW_UPDATE) in flight, and stopping
    // at it would signal shutdown before the idle bound — racing the
    // very outcome under test.
    let mut stream = flood_handshake(hyper.addr).await;
    let closed = loop {
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => break true,
            Ok(Ok(_)) => {}
            Err(_) => break false,
        }
    };
    assert!(closed, "idle connection must close, not hang");
    match hyper.finish().await {
        Served::IdleTimeout => {}
        other => panic!("expected IdleTimeout, got {other:?}"),
    }
}

/// PING floods do not extend the idle bound: codec-level traffic
/// never stamps activity, so a peer holding a connection open with
/// cheap frames is still reclaimed on the idle deadline. This is
/// the live cutoff for the flood class the `answered/acked`
/// renames describe — hyper auto-acks PINGs with no rate knob, so
/// the bound that ends the connection is idleness, not count.
#[tokio::test]
async fn h2_pings_do_not_extend_the_idle_bound() {
    let routes = [(Method::Get, "/hello", "h")];
    let mut limits = default_limits();
    limits.idle_timeout = Duration::from_millis(300);
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        limits,
        Pieces::bare(),
    )
    .await;
    let stream = flood_handshake(hyper.addr).await;
    // PING every 50 ms — well inside the 300 ms bound, so any
    // activity accounting that counted codec traffic would keep
    // this connection alive indefinitely. The pongs prove the
    // traffic flows (read and discarded below); the EOF proves it
    // does not count toward idleness.
    let (mut rd, mut wr) = stream.into_split();
    let ping_task = tokio::spawn(async move {
        let mut n = 0u64;
        while wr.write_all(&ping(n.to_be_bytes())).await.is_ok() {
            n += 1;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        n
    });
    let closed = loop {
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_secs(5), rd.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => break true,
            Ok(Ok(_)) => {}
            Err(_) => break false,
        }
    };
    let pings = ping_task.await.unwrap_or(0);
    assert!(
        pings >= 2,
        "pings must actually flow for the pin to mean anything, sent {pings}"
    );
    assert!(
        closed,
        "a ping-flooded idle connection must close, not hang"
    );
    match hyper.finish().await {
        Served::IdleTimeout => {}
        other => panic!("expected IdleTimeout, got {other:?}"),
    }
}

/// Past the ceiling, h2 answers `503` and stays up: no per-response
/// close signal exists on h2, so the client reconnects for service
/// while the connection persists to idle.
#[tokio::test]
async fn h2_ceiling_persists_503() {
    let routes = [(Method::Get, "/hello", "h")];
    let mut limits = default_limits();
    limits.max_requests_per_connection = 1;
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        limits,
        Pieces::bare(),
    )
    .await;
    let mut h2 = H2::connect(hyper.addr).await;
    let first = h2.get("/hello").await;
    let (one, _, _) = h2.response(first).await;
    assert_eq!(one, 200);
    let second = h2.get("/hello").await;
    let (two, _, _) = h2.response(second).await;
    assert_eq!(two, 503, "past-ceiling h2 answers 503, connection alive");
    let _ = hyper.finish().await;
}

/// A past-ceiling 503 is recorded and metered like every other
/// refusal: the wire answer and the operator's record must agree, or
/// the bound fires invisibly under flood. The metric is the assertion
/// (the access line goes to stdout, which a test cannot capture per
/// case; the record and the metric read the same recorded response
/// through adjacent calls, so the counter proves the path runs — and
/// the name claims metering only, not log inspection).
#[tokio::test]
async fn h2_ceiling_refusal_is_recorded_and_metered() {
    use qqq_serve::metrics::{HttpMetrics, Method as MetricMethod, StatusClass};

    let routes = [(Method::Get, "/hello", "h")];
    let mut limits = default_limits();
    limits.max_requests_per_connection = 1;
    let metrics = Arc::new(HttpMetrics::new());
    let mut pieces = Pieces::bare();
    pieces.metrics = Some(Arc::clone(&metrics));
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        limits,
        pieces,
    )
    .await;
    let mut h2 = H2::connect(hyper.addr).await;
    let first = h2.get("/hello").await;
    let (one, _, _) = h2.response(first).await;
    assert_eq!(one, 200);
    let second = h2.get("/hello").await;
    let (two, _, _) = h2.response(second).await;
    assert_eq!(two, 503, "past-ceiling h2 answers 503");
    assert_eq!(
        metrics.requests_for(MetricMethod::Get, StatusClass::Success),
        1,
        "the served request meters Success once"
    );
    assert_eq!(
        metrics.requests_for(MetricMethod::Get, StatusClass::ServerError),
        1,
        "the ceiling refusal meters ServerError once"
    );
    let _ = hyper.finish().await;
}

/// An over-cap handler body wires 500 AND meters 500: the record must
/// describe the wire bytes, so a 200 the handler produced but the
/// boundary refused never appears as a success anywhere.
#[tokio::test]
async fn h2_over_cap_handler_body_wires_500_and_meters_500() {
    use qqq_serve::metrics::{HttpMetrics, Method as MetricMethod, StatusClass};

    let routes = [(Method::Get, "/big", "big")];
    let big: Handler =
        Arc::new(|_head, _m: &RouteMatch| Response::text(200, "x".repeat(2 * 1024 * 1024)));
    let metrics = Arc::new(HttpMetrics::new());
    let mut pieces = Pieces::bare();
    pieces.metrics = Some(Arc::clone(&metrics));
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(big),
        default_limits(),
        pieces,
    )
    .await;
    let mut h2 = H2::connect(hyper.addr).await;
    let id = h2.get("/big").await;
    let (status, _, _) = h2.response(id).await;
    assert_eq!(status, 500, "the cap refuses on the wire");
    assert_eq!(
        metrics.requests_for(MetricMethod::Get, StatusClass::ServerError),
        1,
        "the refusal meters ServerError, not the handler's 200"
    );
    assert_eq!(
        metrics.requests_for(MetricMethod::Get, StatusClass::Success),
        0,
        "no success is recorded for a refused body"
    );
    let _ = hyper.finish().await;
}

/// Reset streams count toward the ceiling: five `HEADERS`+`RST_STREAM`
/// pairs against a ceiling of 3 leave the next `GET` past it.
///
/// The count is attempted answers, not wire-written responses: a reset
/// stream's 500 is computed, logged, and dropped into a dead socket —
/// exactly the in-house `reject_body` shape — and the work already
/// happened, so the ceiling must see it. Not counting would let a
/// reset flood do unbounded work on one connection. The in-house path
/// bounds the same flood by closing the socket on the failed write; h2
/// cannot (a dead stream must not kill its siblings), so the ceiling
/// carries the bound instead. Found red: 10k resets against the
/// default ceiling ended in 503, not absorption — the ceiling test
/// above pins the count for live streams, this one pins it for dead
/// ones.
#[tokio::test]
async fn h2_reset_streams_count_toward_the_ceiling() {
    let routes = [(Method::Get, "/hello", "h")];
    let mut limits = default_limits();
    limits.max_requests_per_connection = 3;
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        limits,
        Pieces::bare(),
    )
    .await;
    let stream = flood_handshake(hyper.addr).await;
    let mut h2 = H2 {
        stream,
        encoder: Encoder::new(),
        decoder: Decoder::new(),
        next_stream: 1,
        completed: std::collections::HashSet::new(),
        pending: std::collections::HashMap::new(),
    };
    for _ in 0..5 {
        let block = h2.encoder.encode(&[
            HeaderField::new(":method", "GET"),
            HeaderField::new(":path", "/hello"),
            HeaderField::new(":scheme", "http"),
            HeaderField::new(":authority", "localhost"),
        ]);
        let id = h2.next_stream;
        h2.next_stream += 2;
        h2.stream
            .write_all(&frame(HEADERS, END_HEADERS, id, &block))
            .await
            .expect("headers");
        h2.stream.write_all(&rst(id, CANCEL)).await.expect("reset");
    }
    h2.stream.flush().await.expect("flush");
    // Drain to quiet, decoding every HEADERS so the table stays in
    // sync for the GET below; the reset answers are expected here.
    loop {
        match read_frame_timeout(&mut h2.stream, Duration::from_millis(50)).await {
            Some(frame) if frame.ftype == HEADERS => {
                h2.decoder.decode(&frame.payload).expect("decode");
            }
            Some(_) => {}
            None => break,
        }
    }
    let fresh = h2.get("/hello").await;
    let (status, _, body) = h2.response(fresh).await;
    assert_eq!(status, 503, "dead streams consumed the ceiling of 3");
    assert!(
        body.windows(15).any(|w| w == b"request ceiling"),
        "the refusal names the ceiling: {}",
        String::from_utf8_lossy(&body)
    );
    let _ = hyper.finish().await;
}

/// Shutdown drains: the in-flight h2 request completes, then the
/// connection ends.
#[tokio::test]
async fn h2_drain_finishes_inflight() {
    let routes = [(Method::Get, "/slow", "slow")];
    let slow: Handler = Arc::new(|_head, _m: &RouteMatch| {
        std::thread::sleep(Duration::from_millis(300));
        Response::text(200, "slow done")
    });
    let mut pieces = Pieces::bare();
    let shutdown = Shutdown::new();
    pieces.shutdown = shutdown.clone();
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(slow),
        default_limits(),
        pieces,
    )
    .await;
    let mut h2 = H2::connect(hyper.addr).await;
    let id = h2.next_stream;
    h2.next_stream += 2;
    let block = h2.encoder.encode(&[
        HeaderField::new(":method", "GET"),
        HeaderField::new(":path", "/slow"),
        HeaderField::new(":scheme", "http"),
        HeaderField::new(":authority", "localhost"),
    ]);
    h2.stream
        .write_all(&frame(HEADERS, END_HEADERS | END_STREAM, id, &block))
        .await
        .expect("headers");
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown.signal();
    let (status, _, body) = h2.response(id).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"slow done");
    match hyper.finish().await {
        Served::Drained => {}
        other => panic!("expected Drained, got {other:?}"),
    }
}

/// An over-cap h2 body is refused on its stream without killing the
/// connection: framing stays sound per stream.
#[tokio::test]
async fn h2_over_cap_body_refused() {
    let routes = [(Method::Post, "/echo", "echo")];
    let echo: Handler = Arc::new(|head, _m: &RouteMatch| {
        let len = head.content_length.unwrap_or(0);
        Response::text(200, format!("len={len}"))
    });
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(echo),
        default_limits(),
        Pieces::bare(),
    )
    .await;
    let mut h2 = H2::connect(hyper.addr).await;
    let id = h2.next_stream;
    h2.next_stream += 2;
    let block = h2.encoder.encode(&[
        HeaderField::new(":method", "POST"),
        HeaderField::new(":path", "/echo"),
        HeaderField::new(":scheme", "http"),
        HeaderField::new(":authority", "localhost"),
        HeaderField::new("content-length", format!("{}", 3 * 1024 * 1024)),
    ]);
    h2.stream
        .write_all(&frame(HEADERS, END_HEADERS, id, &block))
        .await
        .expect("headers");
    // No DATA follows: the declared cap refuses on the head alone.
    let (status, _, _) = h2.response(id).await;
    // Both transports share the parse-error constructor, which
    // hardcodes `BadRequest` — see the h1 differential suite.
    assert_eq!(status, 400);
    // The connection survives its refused stream: a small body goes
    // through on a fresh stream.
    let small = h2.next_stream;
    h2.next_stream += 2;
    let block = h2.encoder.encode(&[
        HeaderField::new(":method", "POST"),
        HeaderField::new(":path", "/echo"),
        HeaderField::new(":scheme", "http"),
        HeaderField::new(":authority", "localhost"),
        HeaderField::new("content-length", "5"),
    ]);
    h2.stream
        .write_all(&frame(HEADERS, END_HEADERS, small, &block))
        .await
        .expect("headers");
    h2.stream
        .write_all(&frame(DATA, END_STREAM, small, b"hello"))
        .await
        .expect("data");
    let (ok, _, body) = h2.response(small).await;
    assert_eq!(ok, 200);
    assert_eq!(body, b"len=5");
    let _ = hyper.finish().await;
}

/// The metrics path answers over h2 like h1.
#[tokio::test]
async fn h2_metrics_path_matches() {
    let routes = [(Method::Get, "/hello", "h")];
    let mut pieces = Pieces::bare();
    pieces.metrics = Some(Arc::new(qqq_serve::metrics::HttpMetrics::new()));
    pieces.metrics_path = Some("/metrics".to_owned());
    let hyper = HyperH2::start(
        table_with(&routes),
        Dispatch::flat(hello_handler()),
        default_limits(),
        pieces,
    )
    .await;
    let mut h2 = H2::connect(hyper.addr).await;
    let id = h2.next_stream;
    h2.next_stream += 2;
    let block = h2.encoder.encode(&[
        HeaderField::new(":method", "GET"),
        HeaderField::new(":path", "/metrics"),
        HeaderField::new(":scheme", "http"),
        HeaderField::new(":authority", "localhost"),
    ]);
    h2.stream
        .write_all(&frame(HEADERS, END_HEADERS | END_STREAM, id, &block))
        .await
        .expect("headers");
    let (status, headers, body) = h2.response(id).await;
    assert_eq!(status, 200);
    assert_eq!(
        header(&headers, "content-type"),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    assert!(
        String::from_utf8_lossy(&body).contains("qqq_http_requests_total"),
        "registry content present"
    );
    let _ = hyper.finish().await;
}

// ---------------------------------------------------------------------------
// Transport seam: any stream, not just TCP
// ---------------------------------------------------------------------------

/// Read one frame off any stream: the duplex twin of `read_frame`,
/// which is pinned to `TcpStream`. Same bound, same panic shape —
/// a dead connection is `None`, an over-large frame is a harness
/// bug, never a silent pass.
async fn read_duplex_frame(stream: &mut tokio::io::DuplexStream) -> Option<(u8, u8, u32, Vec<u8>)> {
    use tokio::io::AsyncReadExt as _;
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

/// The hyper h2 path serves any byte stream: preface, SETTINGS,
/// one `GET` stream, and the 200 + body round-trip, all over an
/// in-memory duplex. Same seam as the h1 test — a server-side
/// `TlsStream` must flow where this duplex flows. Fails to compile
/// until `serve_hyper_h2` stops demanding a `TcpStream`.
///
/// Scope honesty: this proves the seam (non-TCP bytes served) and
/// eventual closure after shutdown — not drain *quality*. A
/// timeout-cut drain returns the same `Drained` as a graceful one
/// with one completed stream, so graceful-vs-forced belongs to the
/// drain proofs, not to this test.
#[tokio::test]
async fn hyper_h2_serves_a_non_tcp_stream() {
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
    };
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    // Cloned before the context borrows `pieces`: the client arm
    // signals shutdown after reading its response, which ends the
    // multiplexed connection deterministically as `Drained`.
    let shutdown = pieces.shutdown.clone();
    // A short drain bound: the default 30 s would outlast the
    // close-watch below, and the verdict under test is *that* the
    // shutdown drains, not how long production allows it.
    let limits = HyperLimits {
        drain_timeout: Duration::from_millis(100),
        ..default_limits()
    };
    let serve = serve_hyper_h2(
        server_io,
        Arc::clone(&table),
        Dispatch::flat(hello_handler()),
        limits,
        &ctx,
    );
    let client = async move {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut io = client_io;
        let mut hello = PREFACE.to_vec();
        hello.extend_from_slice(&settings(&[]));
        io.write_all(&hello).await.expect("preface writes");
        // Settle the handshake: server SETTINGS, then ack.
        loop {
            let Some((ftype, flags, _, _)) = read_duplex_frame(&mut io).await else {
                panic!("server died during handshake");
            };
            if ftype == SETTINGS && (flags & ACK) == 0 {
                break;
            }
        }
        io.write_all(&settings_ack()).await.expect("ack writes");
        let mut encoder = Encoder::new();
        let mut decoder = Decoder::new();
        let block = encoder.encode(&[
            HeaderField::new(":method", "GET"),
            HeaderField::new(":path", "/hello"),
            HeaderField::new(":scheme", "http"),
            HeaderField::new(":authority", "localhost"),
        ]);
        io.write_all(&frame(HEADERS, END_HEADERS | END_STREAM, 1, &block))
            .await
            .expect("headers write");
        let mut status = 0u16;
        let mut body = Vec::new();
        loop {
            let Some((ftype, flags, stream, payload)) = read_duplex_frame(&mut io).await else {
                panic!("server died mid-response");
            };
            if stream == 0 {
                continue;
            }
            if ftype == HEADERS {
                for field in decoder.decode(&payload).expect("decode") {
                    if field.name == ":status" {
                        status = field.value.parse().expect("numeric status");
                    }
                }
            } else if ftype == DATA {
                body.extend_from_slice(&payload);
                if (flags & END_STREAM) != 0 {
                    break;
                }
            }
        }
        assert_eq!(status, 200, "flat route answers over duplex h2");
        assert_eq!(body, b"hello from h");
        shutdown.signal();
        // Stay open until the server drains and closes: dropping
        // here would race EOF against the shutdown signal and the
        // outcome would be `ClientClosed` instead of `Drained`.
        // A server that never closes enforces nothing — time out
        // loudly rather than hanging the suite.
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            let mut byte = [0u8; 1];
            while io.read_exact(&mut byte).await.is_ok() {}
        })
        .await;
        closed.expect("server drains and closes after shutdown");
    };
    // Deadlines on the client arm: a server that stalls
    // before responding must fail loudly, never hang the
    // suite (the close-watch inside already times out; this
    // covers the handshake and the response).
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("server answers over duplex");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the connection");
}
