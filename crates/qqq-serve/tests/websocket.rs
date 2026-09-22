// SPDX-License-Identifier: Apache-2.0

//! `WebSockets` served through `serve`, end to end (`SRV-009`).
//!
//! # Why this is the test the three layers were missing
//!
//! The handshake, the frame codec and message assembly were each complete and tested, and
//! **none was reachable from `serve`** — the same shape `§O-130` records for CORS and SSE.
//! These tests start the real accept loop, speak the real protocol over a real socket as a
//! **client** would, and assert on the bytes that come back.
//!
//! # The client here is written from the specification
//!
//! Its masking, its close echo and its UTF-8 handling are all per RFC 6455 rather than per
//! our encoder. A client built from our own `encode` would agree with a wrong server —
//! both would mask or neither would, and the test would pass.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use qqq_io::listener::{ListenAddr, Shutdown};
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::server::{serve, Dispatch, Handler, ServerConfig};
use qqq_serve::ws_conn::{Echo, WebSocketHandler};
use qqq_serve::{RequestHead, Response, RouteMatch};

/// A port nobody is using, for the reason `tests/socket.rs` documents.
fn free_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = l.local_addr().expect("addr");
    drop(l);
    a
}

/// A table with `GET /ws` routed to the handler named `ws`.
fn table() -> RouteTable {
    let mut t = RouteTable::new();
    t.insert(Route::new(Method::Get, "/ws", "ws").expect("valid route"))
        .expect("distinct route");
    t
}

fn flat_handler() -> Handler {
    Arc::new(|_head: &RequestHead, _m: &RouteMatch| Response::text(200, "flat"))
}

/// A running server with a WebSocket route.
struct Server {
    addr: SocketAddr,
    shutdown: Shutdown,
}

impl Server {
    async fn start(ws: Arc<dyn WebSocketHandler>) -> Self {
        // Retried, because between `free_addr` dropping its listener and `serve` binding the
        // port, another test in this process -- or another process on the runner -- can take
        // it. That happened in CI: `could not bind 127.0.0.1:57009`, after 405 seconds of
        // waiting on a port someone else owned. Waiting cannot help; a **fresh port** can.
        for _ in 0..16 {
            let addr = free_addr();
            let listen = ListenAddr::parse(&addr.to_string()).expect("parses");
            let shutdown = Shutdown::new();
            let config = ServerConfig::for_addr(listen);
            let local = shutdown.clone();
            // Cloned per attempt: the task takes ownership, and a retry needs another one.
            let ws = Arc::clone(&ws);
            let probe = tokio::spawn(async move {
                if let Err(e) = serve(
                    config,
                    table(),
                    Dispatch::flat(flat_handler()).with_websocket("ws", ws),
                    local,
                    Logger::new(Format::Json, Level::Error),
                )
                .await
                {
                    eprintln!("server stopped early: {}", e.render());
                }
            });

            let s = Self { addr, shutdown };
            for _ in 0..200 {
                if TcpStream::connect(s.addr).await.is_ok() {
                    return s;
                }
                // The task finishing means the bind failed, so waiting is pointless.
                if probe.is_finished() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            s.shutdown.signal();
            let _ = probe.await;
        }
        // Every attempt lost the port race, which means something is badly wrong: 16 fresh
        // ephemeral ports in a row is not bad luck. `bind_free` explains the race this
        // retries around.
        panic!("could not bind a server after 16 attempts on 16 different ports");
    }

    /// Connect and send a WebSocket upgrade request, returning the live stream.
    async fn connect_ws(&self, key: &str) -> TcpStream {
        let mut stream = TcpStream::connect(self.addr).await.expect("connect");
        let req = format!(
            "GET /ws HTTP/1.1\r\nHost: x\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: {key}\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.expect("write");
        stream.flush().await.expect("flush");
        stream
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.signal();
    }
}

/// Read until `needle` appears, or the timeout expires.
async fn read_until(stream: &mut TcpStream, needle: &str) -> String {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
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
    .await;
    String::from_utf8_lossy(&out).into_owned()
}

/// Read exactly the bytes of the handshake response, stopping at its blank line.
async fn read_head(stream: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
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
    .await;
    String::from_utf8_lossy(&out).into_owned()
}

/// Read one server frame, unmasked as §5.1 requires of a server.
async fn read_server_frame(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut header = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
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
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut b))
                .await
                .ok()?
                .ok()?;
            u16::from_be_bytes(b) as usize
        }
        127 => {
            let mut b = [0u8; 8];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut b))
                .await
                .ok()?
                .ok()?;
            // A test frame is never near `usize::MAX`; the 64-bit form is read for
            // completeness.
            #[allow(clippy::cast_possible_truncation)]
            let n = u64::from_be_bytes(b) as usize;
            n
        }
        n => n as usize,
    };
    let mut payload = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut payload))
        .await
        .ok()?
        .ok()?;
    Some((opcode, payload))
}

/// Write a **masked** client frame, as §5.1 requires.
///
/// `fin` is a parameter because a helper that always sets it cannot express a fragment —
/// and a test about fragmentation that cannot send one is a test of nothing. A first
/// version of this file had no parameter, and the fragmentation test passed while
/// asserting on two whole messages.
async fn write_client_frame_full(stream: &mut TcpStream, opcode: u8, fin: bool, payload: &[u8]) {
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    let mut out = vec![(if fin { 0x80u8 } else { 0 }) | opcode];
    let len = payload.len();
    if len < 126 {
        // Guarded by the comparison: a value below 126 fits a `u8`.
        #[allow(clippy::cast_possible_truncation)]
        out.push(0x80 | len as u8);
    } else {
        // `0x7E` rather than `126`: a decimal literal in a bitwise expression hides which
        // bits are meant, and the mask bit is the point of this line.
        out.push(0x80 | 0x7E);
        // A test frame is far below `u16::MAX`; the 16-bit form is written for \
        // completeness. `encode` in `ws_frame.rs` has the same guarded cast.
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

/// A whole (final) client frame, for the common case.
async fn write_client_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) {
    write_client_frame_full(stream, opcode, true, payload).await;
}

/// The RFC 6455 §1.3 example key, so the accept value is known in advance.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

// ---------------------------------------------------------------------------
// The handshake, through `serve`
// ---------------------------------------------------------------------------

/// **A real upgrade request gets a `101` with the correct accept value.**
#[tokio::test]
async fn an_upgrade_through_serve_returns_101() {
    let server = Server::start(Arc::new(Echo)).await;
    let mut client = server.connect_ws(KEY).await;
    let head = read_head(&mut client).await;

    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{head}"
    );
    assert!(head.contains("Upgrade: websocket\r\n"), "{head}");
    assert!(head.contains("Connection: Upgrade\r\n"), "{head}");
    assert!(
        head.contains(&format!("Sec-WebSocket-Accept: {ACCEPT}\r\n")),
        "the accept must match RFC 6455 §1.3: {head}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("content-length"),
        "a 101 must not carry a length: {head}"
    );
}

/// **A message is echoed back through the real server.**
///
/// The whole path: the client masks, the server unmasks, assembles, hands to the handler,
/// and writes an unmasked frame back.
#[tokio::test]
async fn a_text_message_is_echoed() {
    let server = Server::start(Arc::new(Echo)).await;
    let mut client = server.connect_ws(KEY).await;
    let head = read_head(&mut client).await;
    assert!(head.contains("101"), "{head}");

    write_client_frame(&mut client, 0x1, b"hello").await;
    let (opcode, payload) = read_server_frame(&mut client)
        .await
        .expect("the echo must arrive");

    assert_eq!(opcode, 0x1, "a text message echoes as text");
    assert_eq!(payload, b"hello");
}

/// A binary message echoes as binary.
#[tokio::test]
async fn a_binary_message_is_echoed_as_binary() {
    let server = Server::start(Arc::new(Echo)).await;
    let mut client = server.connect_ws(KEY).await;
    read_head(&mut client).await;

    write_client_frame(&mut client, 0x2, &[0, 1, 2, 253, 254, 255]).await;
    let (opcode, payload) = read_server_frame(&mut client).await.expect("echo");
    assert_eq!(opcode, 0x2, "a binary message echoes as binary");
    assert_eq!(payload, vec![0, 1, 2, 253, 254, 255]);
}

/// **A `Ping` is answered with a `Pong` carrying the same payload.** §5.5.3.
///
/// The rule the frame codec cannot enforce, because it has nowhere to send the answer. A
/// connection that ignored pings is dropped by every intermediary that uses them as a
/// liveness probe, and the failure looks like "the connection drops after 60 seconds".
#[tokio::test]
async fn a_ping_is_answered_with_a_pong() {
    let server = Server::start(Arc::new(Echo)).await;
    let mut client = server.connect_ws(KEY).await;
    read_head(&mut client).await;

    write_client_frame(&mut client, 0x9, b"nonce-42").await;
    let (opcode, payload) = read_server_frame(&mut client).await.expect("pong");

    assert_eq!(opcode, 0xA, "a ping is answered with a pong");
    assert_eq!(
        payload, b"nonce-42",
        "§5.5.3: the pong must carry the ping's payload, or a nonce-based probe cannot \
         tell its own ping from anyone else's"
    );
}

/// **A `Close` is echoed before the connection ends.** §5.5.1.
///
/// A client that does not receive the echo cannot distinguish a clean close from a fault,
/// and a client that cannot tell will reconnect — turning a deliberate shutdown into a
/// reconnect storm.
#[tokio::test]
async fn a_close_is_echoed() {
    let server = Server::start(Arc::new(Echo)).await;
    let mut client = server.connect_ws(KEY).await;
    read_head(&mut client).await;

    let mut payload = 1000u16.to_be_bytes().to_vec();
    payload.extend_from_slice(b"bye");
    write_client_frame(&mut client, 0x8, &payload).await;

    let (opcode, echoed) = read_server_frame(&mut client)
        .await
        .expect("the close must be echoed");
    assert_eq!(opcode, 0x8, "the close echo is a close frame");
    assert!(
        echoed.len() >= 2,
        "the echo carries a status code: {echoed:?}"
    );
    assert_eq!(
        u16::from_be_bytes([echoed[0], echoed[1]]),
        1000,
        "the echo carries the peer's own code"
    );
}

/// **A fragmented message arrives at the handler as one whole message.**
///
/// The path the assembler exists for, over a real socket: two frames with the first's
/// `fin` clear, and **one** echo back carrying the joined payload. An implementation that
/// dispatched each frame separately would send two echoes, and one that dropped the first
/// fragment would send `lo`.
#[tokio::test]
async fn a_fragmented_message_reaches_the_handler_whole() {
    let server = Server::start(Arc::new(Echo)).await;
    let mut client = server.connect_ws(KEY).await;
    read_head(&mut client).await;

    // "Hel" with `fin` clear, then "lo, world" as a continuation with `fin` set.
    write_client_frame_full(&mut client, 0x1, false, b"Hel").await;
    write_client_frame_full(&mut client, 0x0, true, b"lo, world").await;

    let (opcode, payload) = read_server_frame(&mut client)
        .await
        .expect("the assembled echo must arrive");
    assert_eq!(opcode, 0x1, "the message keeps the first frame's kind");
    assert_eq!(
        payload, b"Hello, world",
        "the handler must see one message, not two fragments"
    );

    // And there is **no** second echo, which is what proves the first fragment was not
    // dispatched on its own.
    let extra =
        tokio::time::timeout(Duration::from_millis(200), read_server_frame(&mut client)).await;
    assert!(
        extra.is_err(),
        "a fragmented message must produce exactly one echo, got a second frame"
    );
}

/// **A `Ping` between fragments does not reset the message.** §5.4.
///
/// The rule a state machine is most likely to get wrong, and the one that only appears
/// under a ping — rare in tests, constant in production behind a load balancer that keeps
/// idle connections alive with them.
#[tokio::test]
async fn a_ping_between_fragments_does_not_reset_the_message() {
    let server = Server::start(Arc::new(Echo)).await;
    let mut client = server.connect_ws(KEY).await;
    read_head(&mut client).await;

    write_client_frame_full(&mut client, 0x1, false, b"first-").await;
    // A ping, mid-message. §5.4 permits it.
    write_client_frame(&mut client, 0x9, b"keepalive").await;
    write_client_frame_full(&mut client, 0x0, true, b"second").await;

    // The pong comes first, because the ping was answered immediately.
    let (opcode, payload) = read_server_frame(&mut client).await.expect("pong");
    assert_eq!(opcode, 0xA);
    assert_eq!(payload, b"keepalive");

    // Then the **whole** message, proving the ping did not reset the accumulation.
    let (opcode, payload) = read_server_frame(&mut client).await.expect("echo");
    assert_eq!(opcode, 0x1);
    assert_eq!(
        payload, b"first-second",
        "the message must survive the interleaved ping"
    );
}

/// **An unmasked client frame is refused, and the connection is closed with a code.**
///
/// §5.1. The message is not merely strictness: a client that can make a proxy see a valid
/// HTTP request inside a frame is the cache-poisoning attack the masking rule prevents.
#[tokio::test]
async fn an_unmasked_client_frame_gets_a_close_with_a_code() {
    let server = Server::start(Arc::new(Echo)).await;
    let mut client = server.connect_ws(KEY).await;
    read_head(&mut client).await;

    // A text frame with the mask bit clear -- exactly what §5.1 forbids.
    client
        .write_all(&[0x81, 0x03, b'b', b'a', b'd'])
        .await
        .expect("write");
    client.flush().await.expect("flush");

    let (opcode, payload) = read_server_frame(&mut client)
        .await
        .expect("the server must close with a reason");
    assert_eq!(opcode, 0x8, "the refusal is a close frame");
    assert!(payload.len() >= 2, "{payload:?}");
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]),
        1002,
        "§7.4.1: a protocol error is 1002, and the reason must be sent"
    );
}

/// **A WebSocket route without an upgrade header is answered as ordinary HTTP.**
///
/// §4.2.1: a request that is not an upgrade is not a WebSocket. Answering it with a `101`
/// would put the connection into frame mode for a client still speaking HTTP.
#[tokio::test]
async fn a_websocket_route_without_an_upgrade_is_not_hijacked() {
    let server = Server::start(Arc::new(Echo)).await;

    let mut client = TcpStream::connect(server.addr).await.expect("connect");
    client
        .write_all(b"GET /ws HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    client.flush().await.expect("flush");

    let response = read_until(&mut client, "\r\n\r\n").await;
    assert!(
        response.contains("400"),
        "a non-upgrade to a WebSocket route is a 400: {response}"
    );
    assert!(
        !response.contains("101"),
        "it must never be answered with a 101: {response}"
    );
}

/// **A frame sent in the SAME write as the handshake is not lost.**
///
/// The client's TCP stack may coalesce the upgrade request and the first frame, and a
/// client is entitled to send them together — §4.1 says the connection becomes a WebSocket
/// as soon as the server's `101` is *sent*, not when the client has read it.
///
/// The server reads a head into a buffer that may contain **more than the head**, and
/// passing that buffer on is the whole point: a `run_frames` starting from an empty buffer
/// silently discards the first frame. The symptom is a client whose first message is
/// ignored — and only when the two are coalesced, which depends on timing and is therefore
/// invisible in the usual test where they are sent separately.
#[tokio::test]
async fn a_frame_coalesced_with_the_handshake_is_not_lost() {
    let server = Server::start(Arc::new(Echo)).await;

    let mut client = TcpStream::connect(server.addr).await.expect("connect");
    let mut request = format!(
        "GET /ws HTTP/1.1\r\nHost: x\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {KEY}\r\n\r\n"
    )
    .into_bytes();

    // Append a masked text frame to the SAME write: one syscall, one read on the server.
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    let payload = b"coalesced";
    request.push(0x80 | 0x1);
    // `payload` is 9 bytes; the comparison guard is what makes the cast safe.
    let len = u8::try_from(payload.len()).expect("a short test payload");
    request.push(0x80 | len);
    request.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        request.push(b ^ mask[i % 4]);
    }

    client.write_all(&request).await.expect("write");
    client.flush().await.expect("flush");

    // Read the 101 first.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte)).await {
            Ok(Ok(1)) => head.push(byte[0]),
            // A close, an error, or a timeout all end the read: the head is whatever
            // arrived before it.
            _ => break,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(head.contains("101"), "{head}");

    let (opcode, echoed) = read_server_frame(&mut client)
        .await
        .expect("the coalesced frame must be answered");
    assert_eq!(opcode, 0x1);
    assert_eq!(
        echoed, b"coalesced",
        "a frame coalesced with the handshake must not be discarded"
    );
}

/// **A graceful shutdown reaches an upgraded connection.**
///
/// The lifecycle gap `CodeRabbit` found, and the reason it is severe: a `WebSocket` has no
/// natural end, so a `run_frames` that simply blocks on `read` **never returns**. One idle
/// client would then keep `serve` from ever finishing — a graceful restart that hangs
/// forever, which in production is a deploy that never completes.
///
/// The connection must close with `1001` ("going away"), which is what §7.4.1 defines for
/// exactly this: the *server* is ending the connection, so the client knows it is over
/// rather than broken, and does not retry against a server that is going down.
#[tokio::test]
async fn a_shutdown_reaches_an_upgraded_connection() {
    let server = Server::start(Arc::new(Echo)).await;
    let mut client = server.connect_ws(KEY).await;
    let head = read_head(&mut client).await;
    assert!(head.contains("101"), "{head}");

    // No traffic at all: the socket is idle and the server is parked on its read.
    server.shutdown.signal();

    let (opcode, payload) =
        tokio::time::timeout(Duration::from_secs(5), read_server_frame(&mut client))
            .await
            .expect("the shutdown must reach an idle upgraded connection, not hang")
            .expect("a close frame");

    assert_eq!(opcode, 0x8, "the server closes with a close frame");
    assert!(payload.len() >= 2, "{payload:?}");
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]),
        1001,
        "§7.4.1: the server is going away, so 1001 -- a code blaming the client would \
         make it retry against a server that is shutting down"
    );
}

/// **A coalesced frame does not stop the shutdown working.**
///
/// The control for the test above: a connection that has *already* received a frame must
/// still observe the shutdown. A loop that only checked the signal on the first iteration
/// would pass the previous test and fail this one.
#[tokio::test]
async fn a_shutdown_reaches_a_connection_after_traffic() {
    let server = Server::start(Arc::new(Echo)).await;
    let mut client = server.connect_ws(KEY).await;
    read_head(&mut client).await;

    write_client_frame(&mut client, 0x1, b"before").await;
    let (opcode, payload) = read_server_frame(&mut client).await.expect("echo");
    assert_eq!(opcode, 0x1);
    assert_eq!(payload, b"before");

    server.shutdown.signal();
    let (opcode, payload) =
        tokio::time::timeout(Duration::from_secs(5), read_server_frame(&mut client))
            .await
            .expect("the shutdown must still reach it")
            .expect("a close frame");
    assert_eq!(opcode, 0x8, "{payload:?}");
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1001);
}

/// A route with no WebSocket handler still uses the flat one.
///
/// The control: `Dispatch` must not change routing for routes that registered nothing.
#[tokio::test]
async fn a_route_without_a_websocket_handler_uses_the_flat_one() {
    let addr = free_addr();
    let listen = ListenAddr::parse(&addr.to_string()).expect("parses");
    let shutdown = Shutdown::new();
    let config = ServerConfig::for_addr(listen);
    let local = shutdown.clone();

    let mut t = RouteTable::new();
    t.insert(Route::new(Method::Get, "/plain", "plain").expect("valid"))
        .expect("distinct");
    tokio::spawn(async move {
        let _ = serve(
            config,
            t,
            Dispatch::flat(flat_handler()),
            local,
            Logger::new(Format::Json, Level::Error),
        )
        .await;
    });
    for _ in 0..200 {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut client = TcpStream::connect(addr).await.expect("connect");
    client
        .write_all(b"GET /plain HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    client.flush().await.expect("flush");
    let response = read_until(&mut client, "flat").await;

    assert!(response.contains("200 OK"), "{response}");
    assert!(response.ends_with("flat"), "{response}");
    shutdown.signal();
}
