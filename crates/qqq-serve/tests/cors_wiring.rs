// SPDX-License-Identifier: Apache-2.0

//! CORS headers over a real socket (`SRV-019`).
//!
//! # Why these drive `serve`
//!
//! `cors.rs`'s own 29 tests cover the policy exhaustively — the bypasses, the defaults,
//! the preflight checks. None of them can show that a header **reaches a client**,
//! because that happens in `serve_connection` after the handler runs. A policy with
//! perfect unit tests and no call site is dead code that looks tested, which is exactly
//! what `SRV-019` was until `Dispatch` made the emission point reachable.
//!
//! # What the policy layer cannot check and these can
//!
//! That a **denial leaves the response intact** — same status, same body, only the grant
//! header absent. That a **404 carries the grant**, so a browser can read the error
//! rather than reporting an opaque network failure. That a **preflight never reaches a
//! handler**, and that an ordinary `OPTIONS` still does. Each is a wiring property.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use qqq_io::listener::{ListenAddr, Shutdown};
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::cors::Cors;
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::server::{serve, Dispatch, Handler, ServerConfig};
use qqq_serve::{RequestHead, Response, RouteMatch};

/// A port nobody is using, for the reason `tests/socket.rs` documents.
fn free_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = l.local_addr().expect("addr");
    drop(l);
    a
}

/// A table with `GET /orders` and `POST /orders`.
fn table() -> RouteTable {
    let mut t = RouteTable::new();
    for method in [Method::Get, Method::Post] {
        t.insert(Route::new(method, "/orders", "orders").expect("valid route"))
            .expect("distinct route");
    }
    t
}

/// A handler that echoes the method it was called with, so a test can tell whether a
/// preflight reached the handler or was answered by the policy.
fn named_handler() -> Handler {
    Arc::new(|head: &RequestHead, _m: &RouteMatch| {
        Response::text(200, format!("handler:{}", head.method.as_str()))
    })
}

/// A running server, stopped when dropped.
struct Server {
    addr: SocketAddr,
    shutdown: Shutdown,
}

impl Server {
    async fn start(cors: Option<Cors>) -> Self {
        let addr = free_addr();
        let listen = ListenAddr::parse(&addr.to_string()).expect("parses");
        let shutdown = Shutdown::new();
        let mut config = ServerConfig::for_addr(listen);
        config.cors = cors;
        let local = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(
                config,
                table(),
                Dispatch::flat(named_handler()),
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
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the server never accepted a connection on {}", s.addr);
    }

    /// Send a raw request and return the whole response.
    async fn request(&self, raw: &str) -> String {
        let mut stream = TcpStream::connect(self.addr).await.expect("connect");
        stream.write_all(raw.as_bytes()).await.expect("write");
        stream.flush().await.expect("flush");
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let mut chunk = [0u8; 4096];
            loop {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => out.extend_from_slice(&chunk[..n]),
                }
            }
        })
        .await;
        String::from_utf8_lossy(&out).into_owned()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.signal();
    }
}

// ---------------------------------------------------------------------------
// The default is deny
// ---------------------------------------------------------------------------

/// **A server with no CORS configuration emits no CORS header at all.**
///
/// The safe default, asserted through the real server. The header's **absence** is the
/// assertion: a server that emitted `Access-Control-Allow-Origin` without being
/// configured would have made the application cross-origin-readable by default.
#[tokio::test]
async fn a_server_with_no_cors_configuration_emits_nothing() {
    let server = Server::start(None).await;
    let got = server
        .request("GET /orders HTTP/1.1\r\nHost: x\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n")
        .await;

    assert!(got.contains("200 OK"), "{got}");
    assert!(
        !got.to_ascii_lowercase().contains("access-control-"),
        "a server with no policy must emit no CORS header: {got}"
    );
}

/// A configured origin is granted, and an unconfigured one is not.
#[tokio::test]
async fn a_configured_origin_is_granted_and_another_is_not() {
    let server = Server::start(Some(
        Cors::from_manifest(["https://app.example.com"]).expect("valid"),
    ))
    .await;

    let granted = server
        .request("GET /orders HTTP/1.1\r\nHost: x\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n")
        .await;
    assert!(
        granted.contains("Access-Control-Allow-Origin: https://app.example.com"),
        "{granted}"
    );
    assert!(granted.contains("Vary: Origin"), "{granted}");

    let denied = server
        .request("GET /orders HTTP/1.1\r\nHost: x\r\nOrigin: https://evil.example.com\r\nConnection: close\r\n\r\n")
        .await;
    assert!(
        !denied
            .to_ascii_lowercase()
            .contains("access-control-allow-origin"),
        "an unlisted origin gets no grant: {denied}"
    );
    assert!(
        denied.contains("200 OK"),
        "a denial is not a wrong status — the response is unchanged: {denied}"
    );
    assert!(
        denied.contains("Vary: Origin"),
        "a denial is origin-dependent, so a cache must not treat it as one entity: {denied}"
    );
}

/// **A 404 carries the grant, so a browser can read the error.**
///
/// Without it the browser reports an opaque network failure and the developer learns
/// nothing about the status the server chose. This is the reason CORS is applied to
/// every response rather than only to successes.
#[tokio::test]
async fn an_error_response_carries_the_grant() {
    let server = Server::start(Some(
        Cors::from_manifest(["https://app.example.com"]).expect("valid"),
    ))
    .await;

    let got = server
        .request("GET /missing HTTP/1.1\r\nHost: x\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n")
        .await;

    assert!(got.contains("404"), "{got}");
    assert!(
        got.contains("Access-Control-Allow-Origin: https://app.example.com"),
        "an error must be readable by the origin that caused it: {got}"
    );
}

/// A request with no `Origin` gets no `Vary`, because nothing is origin-dependent.
#[tokio::test]
async fn a_request_with_no_origin_gets_no_vary() {
    let server = Server::start(Some(
        Cors::from_manifest(["https://app.example.com"]).expect("valid"),
    ))
    .await;

    let got = server
        .request("GET /orders HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;

    assert!(got.contains("200 OK"), "{got}");
    assert!(
        !got.to_ascii_lowercase().contains("vary"),
        "a response that does not depend on the origin must not fragment the cache: {got}"
    );
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

/// **A granted preflight is answered by the policy, not by the handler.**
///
/// The handler echoes the method it received, so its absence from the body proves the
/// preflight never reached it — which is what makes this a policy rather than a
/// convention a handler could forget.
#[tokio::test]
async fn a_granted_preflight_never_reaches_the_handler() {
    let cors = Cors::from_manifest(["https://app.example.com"])
        .expect("valid")
        .with_methods(["GET", "POST"])
        .with_allowed_headers(["content-type"])
        .with_max_age(600);
    let server = Server::start(Some(cors)).await;

    let got = server
        .request(
            "OPTIONS /orders HTTP/1.1\r\nHost: x\r\n\
             Origin: https://app.example.com\r\n\
             Access-Control-Request-Method: POST\r\n\
             Access-Control-Request-Headers: content-type\r\n\
             Connection: close\r\n\r\n",
        )
        .await;

    assert!(got.contains("204"), "a granted preflight is 204: {got}");
    assert!(
        got.contains("Access-Control-Allow-Methods: POST"),
        "the requested method is echoed back having been checked: {got}"
    );
    assert!(
        got.contains("Access-Control-Allow-Headers: content-type"),
        "{got}"
    );
    assert!(got.contains("Access-Control-Max-Age: 600"), "{got}");
    assert!(
        !got.contains("handler:"),
        "the preflight must not reach the handler: {got}"
    );
}

/// **A preflight for a method the policy does not allow is refused.**
///
/// The check that makes a preflight a policy: without it the browser believes it may
/// `DELETE` a route the server only accepts `GET` on.
#[tokio::test]
async fn a_preflight_for_a_disallowed_method_is_refused() {
    let cors = Cors::from_manifest(["https://app.example.com"])
        .expect("valid")
        .with_methods(["GET"]);
    let server = Server::start(Some(cors)).await;

    let got = server
        .request(
            "OPTIONS /orders HTTP/1.1\r\nHost: x\r\n\
             Origin: https://app.example.com\r\n\
             Access-Control-Request-Method: DELETE\r\n\
             Connection: close\r\n\r\n",
        )
        .await;

    assert!(got.contains("403"), "a refused preflight is 403: {got}");
    assert!(
        !got.contains("Access-Control-Allow-Methods"),
        "a refusal must not advertise the method it refused: {got}"
    );
}

/// A preflight from an unlisted origin is refused, and grants nothing.
#[tokio::test]
async fn a_preflight_from_an_unlisted_origin_is_refused() {
    let cors = Cors::from_manifest(["https://app.example.com"])
        .expect("valid")
        .with_methods(["GET"]);
    let server = Server::start(Some(cors)).await;

    let got = server
        .request(
            "OPTIONS /orders HTTP/1.1\r\nHost: x\r\n\
             Origin: https://evil.example.com\r\n\
             Access-Control-Request-Method: GET\r\n\
             Connection: close\r\n\r\n",
        )
        .await;

    assert!(got.contains("403"), "{got}");
    assert!(
        !got.to_ascii_lowercase()
            .contains("access-control-allow-origin"),
        "{got}"
    );
}

/// **An `OPTIONS` with no `Access-Control-Request-Method` is not a preflight.**
///
/// The control: it reaches the handler like any other request, so the preflight branch
/// is not swallowing ordinary `OPTIONS`.
#[tokio::test]
async fn an_ordinary_options_reaches_the_handler() {
    let cors = Cors::from_manifest(["https://app.example.com"])
        .expect("valid")
        .with_methods(["GET"]);
    let server = Server::start(Some(cors)).await;

    let got = server
        .request("OPTIONS /orders HTTP/1.1\r\nHost: x\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n")
        .await;

    // No `OPTIONS` route exists, so the router answers 405 with the allowance — the
    // point being that the *policy* did not answer it.
    assert!(
        got.contains("405") || got.contains("handler:"),
        "an ordinary OPTIONS is routed, not treated as a preflight: {got}"
    );
    assert!(
        !got.contains("Access-Control-Allow-Methods"),
        "no preflight headers on a non-preflight: {got}"
    );
}

/// A preflight for an unknown path is still answered by the policy.
///
/// The browser is asking about the path, not calling it, so a 404 would be
/// indistinguishable from an unknown route — and would make the browser refuse a request
/// the server would have served.
#[tokio::test]
async fn a_preflight_for_an_unknown_path_is_still_a_policy_decision() {
    let cors = Cors::from_manifest(["https://app.example.com"])
        .expect("valid")
        .with_methods(["GET"]);
    let server = Server::start(Some(cors)).await;

    let got = server
        .request(
            "OPTIONS /not-a-route HTTP/1.1\r\nHost: x\r\n\
             Origin: https://app.example.com\r\n\
             Access-Control-Request-Method: GET\r\n\
             Connection: close\r\n\r\n",
        )
        .await;

    assert!(
        got.contains("204"),
        "the path is not routed during a preflight: {got}"
    );
    assert!(got.contains("Access-Control-Allow-Methods: GET"), "{got}");
}
