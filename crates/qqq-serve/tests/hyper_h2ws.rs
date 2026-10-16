// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! WebSocket over HTTP/2 extended-CONNECT (RFC 8441) on the hyper path.
//!
//! The hyper path answered h2 upgrade routes with `501` until this
//! lands; these tests demand the real mechanism — server SETTINGS
//! advertising `ENABLE_CONNECT_PROTOCOL`, a `200` with the RFC 6455
//! §1.3 accept value, a masked echo round trip over DATA, and a
//! clean close — plus the loud refusals (no `:protocol`, foreign
//! protocol, foreign origin, bad version/key, CONNECT to a flat
//! route). The client is spec-written like `hyper_ws.rs`, so the
//! server's HPACK, framing, and unmasking are all exercised.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use qqq_io::listener::Shutdown;
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::metrics::TenantLabels;
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::serve_hyper::serve_hyper_h2;
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

/// One h2 connection context over borrowed pieces: every duplex
/// test builds the same struct.
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
    }
}

/// Limits with a short drain bound: the default would outlast the
/// close-watch, and the verdict under test is *that* shutdown
/// drains, not how long production allows it.
fn drain_limits() -> HyperLimits {
    HyperLimits {
        drain_timeout: Duration::from_millis(100),
        ..default_limits()
    }
}

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The RFC 6455 §1.3 example key, so the accept value is known.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 8441 §3): the setting
/// whose presence proves the builder flag is live, not believed.
const ENABLE_CONNECT_PROTOCOL: u16 = 0x8;

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

/// Raw h2 handshake plus fresh HPACK codecs, returning the server's
/// SETTINGS payload so tests can assert on advertised settings.
async fn h2_shake_hands(
    io: &mut tokio::io::DuplexStream,
) -> (
    qqq_serve::h2::hpack::Encoder,
    qqq_serve::h2::hpack::Decoder,
    Vec<u8>,
) {
    use qqq_serve::h2::hpack::{Decoder, Encoder};
    let mut hello = H2_PREFACE.to_vec();
    hello.extend_from_slice(&h2_frame(0x4, 0, 0, &[]));
    io.write_all(&hello).await.expect("preface writes");
    let settings = loop {
        let Some((ftype, flags, _, payload)) =
            tokio::time::timeout(Duration::from_secs(10), h2_read_frame(&mut *io))
                .await
                .expect("server speaks")
        else {
            panic!("server died during handshake");
        };
        if ftype == 0x4 && (flags & 0x1) == 0 {
            break payload;
        }
    };
    io.write_all(&h2_frame(0x4, 0x1, 0, &[]))
        .await
        .expect("ack writes");
    (Encoder::new(), Decoder::new(), settings)
}

/// Whether the SETTINGS payload advertises a setting id.
fn settings_has(payload: &[u8], id: u16) -> bool {
    let (chunks, _) = payload.as_chunks::<6>();
    chunks
        .iter()
        .any(|entry| u16::from_be_bytes([entry[0], entry[1]]) == id)
}

/// Send HEADERS for an extended-CONNECT with the given `:protocol`
/// (`None` omits it) plus extra headers, stream open for WS data.
async fn h2_connect(
    io: &mut tokio::io::DuplexStream,
    encoder: &mut qqq_serve::h2::hpack::Encoder,
    protocol: Option<&str>,
    extra: &[(&str, &str)],
) {
    use qqq_serve::h2::hpack::HeaderField;
    let mut fields = vec![
        HeaderField::new(":method", "CONNECT"),
        HeaderField::new(":scheme", "http"),
        HeaderField::new(":path", "/ws"),
        HeaderField::new(":authority", "localhost"),
    ];
    if let Some(protocol) = protocol {
        fields.push(HeaderField::new(":protocol", protocol));
    }
    for (name, value) in extra {
        fields.push(HeaderField::new(*name, *value));
    }
    let block = encoder.encode(&fields);
    io.write_all(&h2_frame(0x1, 0x4, 1, &block))
        .await
        .expect("headers write");
}

/// Read stream 1's response HEADERS, returning status and fields.
async fn h2_read_response_head(
    io: &mut tokio::io::DuplexStream,
    decoder: &mut qqq_serve::h2::hpack::Decoder,
) -> (u16, Vec<(String, String)>) {
    let mut status = 0u16;
    let mut fields = Vec::new();
    loop {
        let Some((ftype, _, sid, payload)) =
            tokio::time::timeout(Duration::from_secs(10), h2_read_frame(&mut *io))
                .await
                .expect("server speaks")
        else {
            panic!("server died mid-response");
        };
        if sid == 0 {
            continue;
        }
        if ftype == 0x1 {
            for field in decoder.decode(&payload).expect("decode") {
                if field.name == ":status" {
                    status = field.value.parse().expect("numeric status");
                } else {
                    fields.push((field.name.clone(), field.value.clone()));
                }
            }
            return (status, fields);
        }
    }
}

/// Stay open until the server drains and closes: dropping would
/// race EOF against the shutdown signal into `ClientClosed`.
async fn h2_close_watch(io: &mut tokio::io::DuplexStream) {
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        let mut byte = [0u8; 1];
        while io.read_exact(&mut byte).await.is_ok() {}
    })
    .await;
    closed.expect("server drains and closes after shutdown");
}

/// One masked client text frame, as RFC 6455 §5.1 requires.
fn ws_masked_text(payload: &[u8]) -> Vec<u8> {
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    let mut out = vec![0x81u8];
    assert!(payload.len() < 126, "test payloads are small");
    #[allow(clippy::cast_possible_truncation)]
    out.push(0x80 | payload.len() as u8);
    out.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        out.push(b ^ mask[i % 4]);
    }
    out
}

/// One masked client close frame with no body.
fn ws_masked_close() -> Vec<u8> {
    vec![0x88u8, 0x80u8, 0x12u8, 0x34, 0x56, 0x78]
}

/// Read unmasked server WS frames out of DATA until one arrives,
/// returning its opcode and payload.
async fn ws_read_frame(io: &mut tokio::io::DuplexStream) -> (u8, Vec<u8>) {
    loop {
        let Some((ftype, _, sid, payload)) =
            tokio::time::timeout(Duration::from_secs(10), h2_read_frame(&mut *io))
                .await
                .expect("server speaks")
        else {
            panic!("server died mid-frame");
        };
        if sid == 0 || ftype != 0x0 || payload.len() < 2 {
            continue;
        }
        assert_eq!(
            payload[1] & 0x80,
            0,
            "a server must not mask the frames it sends"
        );
        let opcode = payload[0] & 0x0F;
        let len = (payload[1] & 0x7F) as usize;
        assert!(payload.len() >= 2 + len, "a whole frame arrives");
        return (opcode, payload[2..2 + len].to_vec());
    }
}

fn ws_routes() -> (Arc<RouteTable>, Dispatch) {
    let table = Arc::new(table_with(&[
        (Method::Connect, "/ws", "ws"),
        (Method::Get, "/ws", "ws"),
        (Method::Get, "/flat", "flat"),
    ]));
    let dispatch = Dispatch::flat(flat_handler()).with_websocket("ws", Arc::new(Echo));
    (table, dispatch)
}

/// The server advertises `ENABLE_CONNECT_PROTOCOL`: without the
/// builder flag no client may even attempt the mechanism, so the
/// setting bytes are the proof the flag is live, not believed.
#[tokio::test]
async fn h2ws_server_advertises_extended_connect() {
    let (table, dispatch) = ws_routes();
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, table, dispatch, drain_limits(), &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        let mut io = client_io;
        let (_, _, settings) = h2_shake_hands(&mut io).await;
        assert!(
            settings_has(&settings, ENABLE_CONNECT_PROTOCOL),
            "server SETTINGS must advertise extended CONNECT (0x8)"
        );
        shutdown.signal();
        h2_close_watch(&mut io).await;
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("handshake completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the connection");
}

/// A full RFC 8441 round trip: `CONNECT` with `:protocol:
/// websocket` answers `200` with the §1.3 accept value, a masked
/// frame echoes, and the close handshake completes.
#[tokio::test]
async fn h2ws_extended_connect_echo_round_trip() {
    let (table, dispatch) = ws_routes();
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, table, dispatch, drain_limits(), &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        let mut io = client_io;
        let (mut encoder, mut decoder, _) = h2_shake_hands(&mut io).await;
        h2_connect(
            &mut io,
            &mut encoder,
            Some("websocket"),
            &[("sec-websocket-version", "13"), ("sec-websocket-key", KEY)],
        )
        .await;
        let (status, fields) = h2_read_response_head(&mut io, &mut decoder).await;
        assert_eq!(status, 200, "extended CONNECT answers 200, not 101");
        let accept = fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-accept"));
        assert_eq!(
            accept.map(|(_, v)| v.as_str()),
            Some(ACCEPT),
            "accept proves the server read the key: {fields:?}"
        );
        assert!(
            fields
                .iter()
                .all(|(k, _)| !k.eq_ignore_ascii_case("connection")),
            "connection headers are forbidden on h2: {fields:?}"
        );
        io.write_all(&h2_frame(0x0, 0, 1, &ws_masked_text(b"hello")))
            .await
            .expect("frame writes");
        let (opcode, echoed) = ws_read_frame(&mut io).await;
        assert_eq!(opcode, 0x1, "echo is a text frame");
        assert_eq!(echoed, b"hello");
        io.write_all(&h2_frame(0x0, 0, 1, &ws_masked_close()))
            .await
            .expect("close writes");
        let (opcode, _) = ws_read_frame(&mut io).await;
        assert_eq!(opcode, 0x8, "server echoes the close");
        shutdown.signal();
        h2_close_watch(&mut io).await;
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("round trip completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the connection");
}

/// `CONNECT` without `:protocol` is proxying, not bootstrapping:
/// the stream dies un-upgraded — hyper resets it at the framing
/// layer, so no `200` and no frames ever follow.
#[tokio::test]
async fn h2ws_connect_without_protocol_is_refused() {
    let (table, dispatch) = ws_routes();
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, table, dispatch, drain_limits(), &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        let mut io = client_io;
        let (mut encoder, decoder, _) = h2_shake_hands(&mut io).await;
        h2_connect(
            &mut io,
            &mut encoder,
            None,
            &[("sec-websocket-version", "13"), ("sec-websocket-key", KEY)],
        )
        .await;
        // The stream is reset, never answered: collect what arrives
        // so the failure names the actual wire behaviour.
        let mut seen = Vec::new();
        let deadline = tokio::time::sleep(Duration::from_secs(3));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                () = &mut deadline => break,
                frame = h2_read_frame(&mut io) => {
                    let Some((ftype, flags, sid, _)) = frame else { break };
                    seen.push((ftype, flags, sid));
                    if sid == 1 && (ftype == 0x1 || ftype == 0x3) {
                        break;
                    }
                }
            }
        }
        assert!(
            seen.iter()
                .any(|(ftype, _, sid)| *ftype == 0x3 && *sid == 1),
            "proxying CONNECT dies reset, never framed: {seen:?}"
        );
        let _ = decoder;
        shutdown.signal();
        h2_close_watch(&mut io).await;
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("refusal completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the connection");
}

/// A `:protocol` this server does not speak is 501: recognized
/// mechanism, unimplemented protocol — never a silent 400.
#[tokio::test]
async fn h2ws_unsupported_protocol_is_not_implemented() {
    let (table, dispatch) = ws_routes();
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, table, dispatch, drain_limits(), &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        let mut io = client_io;
        let (mut encoder, mut decoder, _) = h2_shake_hands(&mut io).await;
        h2_connect(&mut io, &mut encoder, Some("bogus"), &[]).await;
        let (status, _) = h2_read_response_head(&mut io, &mut decoder).await;
        assert_eq!(status, 501, "an unspoken protocol is unimplemented");
        shutdown.signal();
        h2_close_watch(&mut io).await;
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("refusal completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the connection");
}

/// A foreign origin never reaches the frame loop, like on h1.
#[tokio::test]
async fn h2ws_cross_origin_connect_is_refused() {
    let (table, dispatch) = ws_routes();
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, table, dispatch, drain_limits(), &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        let mut io = client_io;
        let (mut encoder, mut decoder, _) = h2_shake_hands(&mut io).await;
        h2_connect(
            &mut io,
            &mut encoder,
            Some("websocket"),
            &[
                ("sec-websocket-version", "13"),
                ("sec-websocket-key", KEY),
                ("origin", "https://evil.example"),
            ],
        )
        .await;
        let (status, _) = h2_read_response_head(&mut io, &mut decoder).await;
        assert_eq!(status, 403, "a foreign origin is refused pre-handshake");
        shutdown.signal();
        h2_close_watch(&mut io).await;
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("refusal completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the connection");
}

/// A wrong version still names the retry version with 426.
#[tokio::test]
async fn h2ws_wrong_version_names_the_retry() {
    let (table, dispatch) = ws_routes();
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, table, dispatch, drain_limits(), &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        let mut io = client_io;
        let (mut encoder, mut decoder, _) = h2_shake_hands(&mut io).await;
        h2_connect(
            &mut io,
            &mut encoder,
            Some("websocket"),
            &[("sec-websocket-version", "8"), ("sec-websocket-key", KEY)],
        )
        .await;
        let (status, fields) = h2_read_response_head(&mut io, &mut decoder).await;
        assert_eq!(status, 426, "a wrong version names the retry, not 400");
        assert!(
            fields
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("sec-websocket-version") && v == "13"),
            "the 426 names version 13: {fields:?}"
        );
        shutdown.signal();
        h2_close_watch(&mut io).await;
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("refusal completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the connection");
}

/// A short key is a 400: the server cannot prove it read a key
/// that is not one.
#[tokio::test]
async fn h2ws_short_key_is_refused() {
    let (table, dispatch) = ws_routes();
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, table, dispatch, drain_limits(), &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        let mut io = client_io;
        let (mut encoder, mut decoder, _) = h2_shake_hands(&mut io).await;
        h2_connect(
            &mut io,
            &mut encoder,
            Some("websocket"),
            &[
                ("sec-websocket-version", "13"),
                ("sec-websocket-key", "c2hvcnQ="),
            ],
        )
        .await;
        let (status, _) = h2_read_response_head(&mut io, &mut decoder).await;
        assert_eq!(status, 400, "a short key is refused");
        shutdown.signal();
        h2_close_watch(&mut io).await;
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("refusal completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the connection");
}

/// `CONNECT` to a route with no WebSocket handler falls through
/// to ordinary routing — an explicit 405 (path exists, method
/// disallowed), never a hijack.
#[tokio::test]
async fn h2ws_connect_to_a_flat_route_is_not_hijacked() {
    let (table, dispatch) = ws_routes();
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, table, dispatch, drain_limits(), &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        use qqq_serve::h2::hpack::HeaderField;
        let mut io = client_io;
        let (mut encoder, mut decoder, _) = h2_shake_hands(&mut io).await;
        // CONNECT at the flat route: no WS handler owns it.
        let block = encoder.encode(&[
            HeaderField::new(":method", "CONNECT"),
            HeaderField::new(":scheme", "http"),
            HeaderField::new(":path", "/flat"),
            HeaderField::new(":authority", "localhost"),
            HeaderField::new(":protocol", "websocket"),
            HeaderField::new("sec-websocket-version", "13"),
            HeaderField::new("sec-websocket-key", KEY),
        ]);
        io.write_all(&h2_frame(0x1, 0x4, 1, &block))
            .await
            .expect("headers write");
        let (status, _) = h2_read_response_head(&mut io, &mut decoder).await;
        assert_eq!(status, 405, "a flat route is routed, never hijacked");
        shutdown.signal();
        h2_close_watch(&mut io).await;
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("routing completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the connection");
}

/// A `GET` at a WebSocket route over h2 is an ordinary request,
/// never framed: the h2 form of the h1 not-an-upgrade 400, so the
/// two protocols cannot disagree about what a missing handshake
/// is worth.
#[tokio::test]
async fn h2ws_get_to_a_ws_route_is_not_upgraded() {
    use qqq_serve::h2::hpack::HeaderField;
    let (table, dispatch) = ws_routes();
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, table, dispatch, drain_limits(), &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        let mut io = client_io;
        let (mut encoder, mut decoder, _) = h2_shake_hands(&mut io).await;
        let block = encoder.encode(&[
            HeaderField::new(":method", "GET"),
            HeaderField::new(":scheme", "http"),
            HeaderField::new(":path", "/ws"),
            HeaderField::new(":authority", "localhost"),
        ]);
        io.write_all(&h2_frame(0x1, 0x4 | 0x1, 1, &block))
            .await
            .expect("headers write");
        let (status, _) = h2_read_response_head(&mut io, &mut decoder).await;
        assert_eq!(
            status, 400,
            "a missing handshake is a 400 on both protocols"
        );
        shutdown.signal();
        h2_close_watch(&mut io).await;
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("refusal completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the connection");
}

/// `Transfer-Encoding` on h2 is a connection-specific header, so
/// hyper resets the stream before the service ever sees it — the
/// same framing-layer explicitness as the missing-`:protocol`
/// case, and the reason the arm checks only declared lengths.
#[tokio::test]
async fn h2ws_chunked_te_dies_at_the_framing_layer() {
    use qqq_serve::h2::hpack::HeaderField;
    let (table, dispatch) = ws_routes();
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, table, dispatch, drain_limits(), &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        let mut io = client_io;
        let (mut encoder, _, _) = h2_shake_hands(&mut io).await;
        let block = encoder.encode(&[
            HeaderField::new(":method", "CONNECT"),
            HeaderField::new(":scheme", "http"),
            HeaderField::new(":path", "/ws"),
            HeaderField::new(":authority", "localhost"),
            HeaderField::new(":protocol", "websocket"),
            HeaderField::new("sec-websocket-version", "13"),
            HeaderField::new("sec-websocket-key", KEY),
            HeaderField::new("transfer-encoding", "chunked"),
        ]);
        io.write_all(&h2_frame(0x1, 0x4, 1, &block))
            .await
            .expect("headers write");
        let mut reset = false;
        let deadline = tokio::time::sleep(Duration::from_secs(3));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                () = &mut deadline => break,
                frame = h2_read_frame(&mut io) => {
                    let Some((ftype, _, sid, _)) = frame else { break };
                    if sid == 1 && ftype == 0x3 {
                        reset = true;
                        break;
                    }
                    assert!(
                        !(sid == 1 && ftype == 0x1),
                        "a TE: chunked CONNECT must not be answered"
                    );
                }
            }
        }
        assert!(
            reset,
            "connection-specific framing dies reset, never answered"
        );
        shutdown.signal();
        h2_close_watch(&mut io).await;
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("reset completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "shutdown drains the connection");
}

/// A protocol violation followed by shutdown still drains: the
/// connection verdict outranks the request's, and the error lives
/// in the access record the loop already emitted — `Drained`
/// never meant "nothing went wrong".
#[tokio::test]
async fn h2ws_protocol_error_keeps_drain() {
    let (table, dispatch) = ws_routes();
    let pieces = Pieces::bare();
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let id = ConnectionId::new(peer, 1);
    let ctx = h2_conn_ctx(&pieces, &id);
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let serve = serve_hyper_h2(server_io, table, dispatch, drain_limits(), &ctx);
    let shutdown = pieces.shutdown.clone();
    let client = async move {
        let mut io = client_io;
        let (mut encoder, mut decoder, _) = h2_shake_hands(&mut io).await;
        h2_connect(
            &mut io,
            &mut encoder,
            Some("websocket"),
            &[("sec-websocket-version", "13"), ("sec-websocket-key", KEY)],
        )
        .await;
        let (status, _) = h2_read_response_head(&mut io, &mut decoder).await;
        assert_eq!(status, 200, "the handshake completes first");
        // An unmasked client frame violates §5.1: the loop ends in
        // a protocol error on its own, before shutdown arrives.
        io.write_all(&h2_frame(
            0x0,
            0,
            1,
            &[0x81u8, 0x05u8, b'h', b'e', b'l', b'l', b'o'],
        ))
        .await
        .expect("violation writes");
        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown.signal();
        h2_close_watch(&mut io).await;
    };
    let client = async {
        tokio::time::timeout(Duration::from_secs(60), client)
            .await
            .expect("violation completes");
    };
    let (served, ()) = tokio::join!(serve, client);
    assert_eq!(served, Served::Drained, "drain outranks the loop's error");
}
