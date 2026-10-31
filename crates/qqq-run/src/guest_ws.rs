// SPDX-License-Identifier: Apache-2.0

//! Guest-backed WebSocket handlers: one guest call per message.
//!
//! A WebSocket route upgrades the connection and then needs someone to
//! answer messages. The guest ABI has no duplex export, so there is no
//! standing guest call to route frames to — but `handle` answers one
//! request, and a message *is* a request: the bridge turns each inbound
//! data message into a `POST` against the route's path with the message
//! as the body, calls the guest through the live app (hot-swap generation
//! tracking, budgets, audit — the same path as every flat request), and
//! sends the response body back as a message of the same kind.
//!
//! # What this is not
//!
//! It is not full-duplex messaging and it is not server push: every guest
//! interaction is one request in, one response out, and the server never
//! speaks first. A guest export that holds a socket open needs the
//! `incoming-streaming` WIT interface, which does not exist yet — the day
//! it lands, this bridge becomes the compatibility path for guests that
//! only implement `handle`, not the way every route works.
//!
//! # Why POST, and why the route's path
//!
//! The handshake was a GET, but replaying GET with a body would ask the
//! guest to read a body off a method whose handlers may ignore it. POST
//! says "this carries a write", which is what a client message is. The
//! path is the route's declared path so the guest routes it the same way
//! it routes the HTTP request it already knows how to answer.

use std::sync::Arc;

use qqq_serve::http1::{RequestHead, Version};
use qqq_serve::route::Method;
use qqq_serve::ws_conn::{WebSocketHandler, WsSender};
use qqq_serve::ws_frame::Frame;
use qqq_serve::ws_message::Message;

/// A WebSocket handler that answers every message from the guest.
///
/// ```
/// # use std::sync::Arc;
/// # use qqq_run::guest_ws::GuestWsBridge;
/// let dispatch: qqq_serve::BodyHandler = Arc::new(|_, _, _| {
///     qqq_serve::Response::text(200, "hi")
/// });
/// let handler = GuestWsBridge::for_route(&dispatch, "/ws", None);
/// assert!(Arc::strong_count(&handler) >= 1);
/// ```
pub struct GuestWsBridge {
    dispatch: qqq_serve::BodyHandler,
    path: String,
    limits: Option<std::sync::Arc<qqq_serve::limits::TenantLimits>>,
}

impl GuestWsBridge {
    /// Build a handler that answers through `dispatch` as `path`.
    ///
    /// `dispatch` is the app's body-aware dispatch (hot-swap generation
    /// tracking included); `path` is the route the messages are answered
    /// under, and must be the route the manifest row declares. `limits`
    /// is the manifest's per-tenant limiter: the handshake ran the
    /// pre-reading gates once, but each message is a new request-sized
    /// use and must be gated again, or one connection spends unbounded
    /// guest instantiations past the rate and body caps.
    ///
    /// Named `for_route` rather than `new` because it returns the trait
    /// object the dispatcher stores, not the bridge itself.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use qqq_run::guest_ws::GuestWsBridge;
    /// let dispatch: qqq_serve::BodyHandler = Arc::new(|_, _, _| {
    ///     qqq_serve::Response::text(200, "hi")
    /// });
    /// let handler = GuestWsBridge::for_route(&dispatch, "/ws", None);
    /// assert!(std::sync::Arc::strong_count(&handler) >= 1);
    /// ```
    #[must_use]
    pub fn for_route(
        dispatch: &qqq_serve::BodyHandler,
        path: &str,
        limits: Option<std::sync::Arc<qqq_serve::limits::TenantLimits>>,
    ) -> Arc<dyn WebSocketHandler> {
        Arc::new(Self {
            dispatch: Arc::clone(dispatch),
            path: path.to_owned(),
            limits,
        })
    }
}

impl WebSocketHandler for GuestWsBridge {
    fn on_message<'a>(
        &'a self,
        message: &'a Message,
        send: &'a mut WsSender<'a>,
        tenant: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let dispatch = Arc::clone(&self.dispatch);
        let limits = self.limits.clone();
        let msg_len = message.payload.len();
        let head = RequestHead {
            method: Method::Post,
            target: self.path.clone(),
            version: Version::Http11,
            headers: vec![(
                "content-type".to_owned(),
                "application/octet-stream".to_owned(),
            )],
            content_length: Some(message.payload.len() as u64),
            chunked: false,
        };
        let body = qqq_serve::BodyBytes::Buffered(message.payload.clone());
        let kind = message.kind;
        let tenant = tenant.to_owned();
        Box::pin(async move {
            // Per-message gates: the handshake ran `refuse_before_reading`
            // once, but each frame is a new request-sized use. A body over
            // the tenant's cap closes `1009`, a spent rate window closes
            // `1013` — the same refusals the flat path renders as `413` and
            // `429`, expressed as the close codes a frame-mode client reads.
            // The tenant label is a peer IP today, so it parses; a future
            // non-IP label skips the check rather than forging a key.
            if let Some(limits) = limits.as_ref() {
                let len = u64::try_from(msg_len).unwrap_or(u64::MAX);
                if let Some(key) = tenant_key_for(&tenant) {
                    if limits.check_body(key, len).is_err() {
                        send.send_frame(&Frame::close(1009, "message exceeds tenant body cap"))
                            .await;
                        return;
                    }
                    if limits
                        .check_and_record(key, std::time::Instant::now())
                        .is_err()
                    {
                        send.send_frame(&Frame::close(
                            1013,
                            "tenant rate exceeded, try again later",
                        ))
                        .await;
                        return;
                    }
                }
            }
            // The guest call blocks: run it off the async executor for the
            // same reason `dispatch_off_thread` exists. A guest failure is
            // answered, not dropped — the dispatch maps it to a 502 body
            // with a Failed audit row naming this tenant, so the client
            // sees the failure instead of waiting on an answer that will
            // never arrive. Only an infrastructure failure (the blocking
            // task itself dying, which cannot be a guest verdict) closes
            // the connection, with 1011.
            match tokio::task::spawn_blocking(move || dispatch(&head, &body, &tenant)).await {
                Ok(response) => {
                    send.send(kind, &response.body).await;
                }
                Err(_) => {
                    send.send_frame(&Frame::close(1011, "host task failed"))
                        .await;
                }
            }
        })
    }
}

/// The tenant key for a serve label, when the label is a peer IP.
///
/// Serve labels are peer IPs today (`tenant_of` keys on the client IP),
/// so this parses. A future authenticated subject would not parse and
/// skips the per-message check rather than mapping to another tenant's
/// key — fail-open on the check is wrong, but forging a key is worse,
/// and the handshake gates already ran for the connection.
fn tenant_key_for(tenant: &str) -> Option<qqq_host::tenant::TenantKey> {
    tenant
        .parse::<std::net::IpAddr>()
        .ok()
        .map(qqq_host::tenant::tenant_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_handler::GuestApp;

    /// The echo guest answers every message with its own bytes, so the
    /// round trip measures the bridge rather than the guest.
    fn echo_app() -> std::sync::Arc<GuestApp> {
        let source = include_str!("../tests/fixtures/echo-http.wat");
        let manifest = qqq_cap::Manifest::parse(
            "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n\
             [capabilities.http]\nserver = true\n",
        )
        .expect("a minimal manifest parses");
        let engine = wasmtime::Engine::new(
            &qqq_host::config::EngineConfig::default()
                .to_wasmtime_config()
                .expect("engine config"),
        )
        .expect("engine");
        std::sync::Arc::new(
            GuestApp::with_capacity(
                engine,
                source.as_bytes(),
                qqq_cap::resolve::GrantSet::from_manifest(&manifest),
                qqq_host::LimitSet {
                    memory_bytes: 64 * 1024 * 1024,
                    fuel: 1_000_000_000,
                    epoch_deadline_ms: 10_000,
                    max_open_handles: 64,
                    max_subrequests: 16,
                },
                "127.0.0.1:8080",
                1,
            )
            .expect("the echo fixture must build"),
        )
    }

    /// A message through the live socket must reach the guest and come back
    /// byte-identical: the handshake upgrades, the masked client frame is
    /// answered unmasked, and the audit row names the loopback tenant the
    /// peer resolved to. A duplex unit test cannot build `WsSender` (its
    /// stream field is private to `qqq-serve`), and a live socket proves
    /// more — the dispatched path, not the handler in isolation.
    #[tokio::test]
    async fn a_message_round_trips_through_the_guest() {
        let app = echo_app();
        let bridge = GuestWsBridge::for_route(&app.dispatch_with_body(), "/ws", None);
        let (addr, shutdown, server_task) = serve_bridge(bridge).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        write_handshake(&mut client).await;
        let head = read_head(&mut client).await;
        assert!(head.contains("101"), "upgrade must succeed: {head}");

        write_masked_text(&mut client, b"hello-ws").await;
        let (opcode, body) = read_server_frame(&mut client).await;
        assert_eq!(opcode, 0x1, "a text message echoes as text");
        assert_eq!(&body, b"hello-ws", "the guest echo must round-trip");

        // The loopback peer resolves to its own address as tenant label.
        let (records, _) = app.audit_snapshot();
        assert!(
            records
                .iter()
                .any(|r| r.tenant.as_ref().is_some_and(|t| t.as_str() == "127.0.0.1")),
            "the guest call must be attributed to the calling tenant"
        );
        shutdown.signal();
        let _ = server_task.await;
    }

    /// A message over the tenant's body cap never reaches the guest: the
    /// bridge closes `1009`, the flat-path `413` expressed as the close
    /// code a frame-mode client reads.
    #[tokio::test]
    async fn a_message_over_the_body_cap_closes_with_1009() {
        let app = echo_app();
        let limits = std::sync::Arc::new(qqq_serve::limits::TenantLimits::uniform(
            qqq_serve::limits::Limits {
                max_body_bytes: Some(4),
                ..qqq_serve::limits::Limits::none()
            },
        ));
        let bridge = GuestWsBridge::for_route(&app.dispatch_with_body(), "/ws", Some(limits));
        let (addr, shutdown, server_task) = serve_bridge(bridge).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        write_handshake(&mut client).await;
        let head = read_head(&mut client).await;
        assert!(head.contains("101"), "upgrade must succeed: {head}");

        write_masked_text(&mut client, b"hello-ws").await;
        let (opcode, body) = read_server_frame(&mut client).await;
        assert_eq!(opcode, 0x8, "an over-cap message must close, not echo");
        assert_eq!(
            close_code(&body),
            Some(1009),
            "the close code must name the body cap: {body:?}"
        );
        shutdown.signal();
        let _ = server_task.await;
    }

    /// A second message past a spent rate window never reaches the guest:
    /// the bridge closes `1013`, the flat-path `429` as a close code.
    #[tokio::test]
    async fn a_second_message_past_the_rate_closes_with_1013() {
        use std::time::Duration;

        let app = echo_app();
        let limits = std::sync::Arc::new(qqq_serve::limits::TenantLimits::uniform(
            qqq_serve::limits::Limits {
                max_requests_per_window: Some(1),
                window: Duration::from_secs(60),
                ..qqq_serve::limits::Limits::none()
            },
        ));
        let bridge = GuestWsBridge::for_route(&app.dispatch_with_body(), "/ws", Some(limits));
        let (addr, shutdown, server_task) = serve_bridge(bridge).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        write_handshake(&mut client).await;
        let head = read_head(&mut client).await;
        assert!(head.contains("101"), "upgrade must succeed: {head}");

        write_masked_text(&mut client, b"hi").await;
        let (opcode, _) = read_server_frame(&mut client).await;
        assert_eq!(opcode, 0x1, "the first message fits the window");

        write_masked_text(&mut client, b"hi").await;
        let (opcode, body) = read_server_frame(&mut client).await;
        assert_eq!(opcode, 0x8, "a spent window must close, not echo");
        assert_eq!(
            close_code(&body),
            Some(1013),
            "the close code must name the rate limit: {body:?}"
        );
        shutdown.signal();
        let _ = server_task.await;
    }

    /// The close code a server close frame carries, if it carries one.
    ///
    /// A close payload is a two-byte code plus a reason; a frame shorter
    /// than two bytes carries no code. `get` rather than indexing so an
    /// empty close cannot panic the test that reads it.
    fn close_code(body: &[u8]) -> Option<u16> {
        let bytes: [u8; 2] = body.get(..2)?.try_into().ok()?;
        Some(u16::from_be_bytes(bytes))
    }

    /// Serve the bridge on a loopback port, the way
    /// `qqq-serve/tests/websocket.rs` does.
    async fn serve_bridge(
        bridge: std::sync::Arc<dyn WebSocketHandler>,
    ) -> (
        std::net::SocketAddr,
        qqq_io::listener::Shutdown,
        tokio::task::JoinHandle<()>,
    ) {
        use std::net::SocketAddr;

        let mut table = qqq_serve::route::RouteTable::new();
        table
            .insert(
                qqq_serve::route::Route::new(qqq_serve::route::Method::Get, "/ws", "chat")
                    .expect("valid route"),
            )
            .expect("distinct route");
        let dispatch = qqq_serve::server::Dispatch::flat(std::sync::Arc::new(
            |_head: &qqq_serve::RequestHead, _m: &qqq_serve::RouteMatch| {
                qqq_serve::Response::text(500, "flat must not answer a ws route")
            },
        ))
        .with_websocket("chat", bridge);

        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr: SocketAddr = probe.local_addr().expect("addr");
        drop(probe);
        let listen = qqq_io::listener::ListenAddr::parse(&addr.to_string()).expect("parses");
        let shutdown = qqq_io::listener::Shutdown::new();
        let local = shutdown.clone();
        let server_task = tokio::spawn(async move {
            let _ = qqq_serve::server::serve(
                qqq_serve::server::ServerConfig::for_addr(listen),
                table,
                qqq_serve::server::TenantDispatch::new(dispatch),
                local,
                qqq_serve::access_log::Logger::new(
                    qqq_serve::access_log::Format::Json,
                    qqq_serve::access_log::Level::Error,
                ),
            )
            .await;
        });
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        (addr, shutdown, server_task)
    }

    /// Send the RFC 6455 §1.3 handshake for `/ws`.
    async fn write_handshake(client: &mut tokio::net::TcpStream) {
        use tokio::io::AsyncWriteExt as _;

        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let req = format!(
            "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Upgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
        );
        client
            .write_all(req.as_bytes())
            .await
            .expect("write handshake");
        client.flush().await.expect("flush");
    }

    /// Read the handshake head through the blank line.
    async fn read_head(client: &mut tokio::net::TcpStream) -> String {
        use tokio::io::AsyncReadExt as _;

        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match client.read(&mut byte).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        head.push(byte[0]);
                        if head.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
        })
        .await;
        String::from_utf8_lossy(&head).into_owned()
    }

    /// One masked text frame, per RFC 6455 §5.1.
    async fn write_masked_text(client: &mut tokio::net::TcpStream, payload: &[u8]) {
        use tokio::io::AsyncWriteExt as _;

        let mask = [0x12u8, 0x34, 0x56, 0x78];
        let len = u8::try_from(payload.len()).expect("test payload fits one length byte");
        let mut out = vec![0x81u8, 0x80 | len];
        out.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            let pad = mask.get(i % 4).copied().expect("mask has four bytes");
            out.push(b ^ pad);
        }
        client.write_all(&out).await.expect("write frame");
        client.flush().await.expect("flush");
    }

    /// One unmasked server frame back, per RFC 6455 §5.1.
    async fn read_server_frame(client: &mut tokio::net::TcpStream) -> (u8, Vec<u8>) {
        use tokio::io::AsyncReadExt as _;

        let mut header = [0u8; 2];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_exact(&mut header),
        )
        .await
        .expect("timeout")
        .expect("read header");
        assert_eq!(
            header[1] & 0x80,
            0,
            "a server must not mask the frames it sends"
        );
        let len = usize::from(header[1] & 0x7F);
        let mut body = vec![0u8; len];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_exact(&mut body),
        )
        .await
        .expect("timeout")
        .expect("read body");
        (header[0] & 0x0F, body)
    }
}
