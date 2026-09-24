// SPDX-License-Identifier: Apache-2.0

//! Per-tenant limits enforced through `serve`, end to end (`SRV-020`).
//!
//! # Why these drive `serve`
//!
//! `limits.rs`'s 20 tests cover the decision exhaustively — the caps, the windows, the tenant
//! ceiling, the reclaim sweep. None of them can show that a **request is refused**, because
//! that happens in `serve_connection` before the handler runs. A limiter with perfect unit
//! tests and no call site is dead code that looks tested, which is what it was until this
//! wiring existed — the shape `§O-130` records five times now.
//!
//! # What only these can check
//!
//! That the refusal is a **status the client receives**, not a log line: `429` for too many
//! requests and `413` for too large a body, which are different facts with different remedies.
//! And that the allowance is genuinely **per tenant** across connections, which unit tests
//! cannot show because they never open a socket.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use qqq_io::listener::{ListenAddr, Shutdown};
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::limits::{Limits, TenantLimits};
use qqq_serve::metrics::{HttpMetrics, Outcome};
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

fn table() -> RouteTable {
    let mut t = RouteTable::new();
    t.insert(Route::new(Method::Get, "/ok", "ok").expect("valid route"))
        .expect("distinct");
    t.insert(Route::new(Method::Post, "/ok", "ok").expect("valid route"))
        .expect("distinct");
    t
}

fn handler() -> Handler {
    Arc::new(|_head: &RequestHead, _m: &RouteMatch| Response::text(200, "ok"))
}

/// A running server with its own registry and limiter.
struct Server {
    addr: SocketAddr,
    shutdown: Shutdown,
    metrics: Arc<HttpMetrics>,
}

impl Server {
    async fn start(limits: Option<Limits>) -> Self {
        Self::start_with(limits.map(TenantLimits::uniform)).await
    }

    /// Start with a full `TenantLimits`, so a test can exercise `per_tenant`.
    async fn start_with(limits: Option<TenantLimits>) -> Self {
        // Wrapped once, outside the retry loop. `TenantLimits` is deliberately not `Clone`
        // -- it owns the rate counters, so a clone would be a second set of them -- but
        // `Arc` gives each attempt the same one.
        let limits = limits.map(Arc::new);
        // Retried, because between `free_addr` dropping its listener and `serve` binding the
        // port, another test in this process -- or another process on the runner -- can take
        // it. That is a real CI failure this crate has already had.
        for _ in 0..16 {
            let addr = free_addr();
            let listen = ListenAddr::parse(&addr.to_string()).expect("parses");
            let shutdown = Shutdown::new();
            let mut config = ServerConfig::for_addr(listen);
            let metrics = Arc::new(HttpMetrics::new());
            config.metrics = Some(Arc::clone(&metrics));
            config.limits = limits.clone();
            let local = shutdown.clone();

            let probe = tokio::spawn(async move {
                if let Err(e) = serve(
                    config,
                    table(),
                    Dispatch::flat(handler()),
                    local,
                    Logger::new(Format::Json, Level::Error),
                )
                .await
                {
                    eprintln!("server stopped early: {}", e.render());
                }
            });

            let s = Self {
                addr,
                shutdown,
                metrics,
            };
            for _ in 0..200 {
                if TcpStream::connect(s.addr).await.is_ok() {
                    return s;
                }
                if probe.is_finished() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            s.shutdown.signal();
            let _ = probe.await;
        }
        panic!("could not bind a server after 16 attempts on 16 different ports");
    }

    /// Send one raw request on its own connection and read the whole response.
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
// A body cap
// ---------------------------------------------------------------------------

/// **A `per_tenant` entry keyed by the client's address is applied to a real request.**
///
/// # The defect this closes
///
/// `RequestLimits::per_tenant` was documented as *"keyed by tenant name"* while
/// `tenant_of` returns `peer.ip().to_string()` and `limits_for` looks the tenant up by
/// that string. So the entry could never match: it parsed, it validated, `qqqai inspect`
/// listed it, and it was never applied. A policy that read as live and was not — the shape
/// this repository has recorded more than twenty times. `§O-185`.
///
/// # Why this test and not a unit test
///
/// The unit test proves `limits_for` looks a string up in a map. Only this proves the
/// string the **server** passes is the one the manifest author wrote — which is the half
/// that was wrong, and the half no unit test on the limiter can reach.
///
/// The client connects over the loopback interface, so its peer address is `127.0.0.1`,
/// and that is the key the manifest entry uses.
#[tokio::test]
async fn a_per_tenant_entry_keyed_by_the_peer_address_is_applied() {
    let limits = TenantLimits::new(
        [(
            "127.0.0.1".to_owned(),
            qqq_serve::limits::Limits::with_body(16),
        )],
        qqq_serve::limits::Limits::with_body(1000),
    );
    let server = Server::start_with(Some(limits)).await;

    // 100 bytes is under the fallback and over the per-tenant cap, so the answer says
    // which one the server chose.
    let got = server
        .request("POST /ok HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
        .await;

    assert!(
        got.contains("413"),
        "the per-tenant entry for 127.0.0.1 must apply to a loopback client, so a 100-byte \
         body is over its 16-byte cap: {got}"
    );
    assert!(!got.contains("200 OK"), "the handler must not run: {got}");
}

/// **The control: an entry for a different address does not apply.**
///
/// Without this, the test above would pass on a server that applied every `per_tenant`
/// entry to every request — which is a worse defect than the one it checks for, since a
/// cap meant for one caller would throttle everyone.
#[tokio::test]
async fn a_per_tenant_entry_for_another_address_is_not_applied() {
    let limits = TenantLimits::new(
        [(
            // Documentation range (RFC 5737): a real address, never the loopback peer.
            "198.51.100.7".to_owned(),
            qqq_serve::limits::Limits::with_body(16),
        )],
        qqq_serve::limits::Limits::with_body(1000),
    );
    let server = Server::start_with(Some(limits)).await;

    // The body is **sent**, unlike the test above: 100 bytes is under this server's
    // fallback cap, so the request is not refused on its declared length and the server
    // reads it. Declaring without sending would test the read timeout instead.
    let body = "a".repeat(100);
    let raw = format!(
        "POST /ok HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{body}"
    );
    let got = server.request(&raw).await;

    assert!(
        got.contains("200 OK"),
        "the fallback applies to a peer with no entry, so a 100-byte body is served: {got}"
    );
}

/// A body over the tenant's cap is refused with `413`, before the handler runs.
///
/// Checked against the **declared** length, so the server never reads the body it is refusing
/// — which is the entire point of a cap. A test that sent the body anyway would pass against
/// an implementation that read first and refused later, and that implementation has already
/// paid the cost the cap exists to prevent.
#[tokio::test]
async fn a_body_over_the_cap_is_refused_with_413() {
    let server = Server::start(Some(Limits::with_body(16))).await;

    let got = server
        .request(
            "POST /ok HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n",
        )
        .await;

    assert!(got.contains("413"), "a body cap refusal is 413: {got}");
    assert!(
        !got.contains("200 OK"),
        "the handler must not have run: {got}"
    );
}

/// A body at the cap is served; one byte over is refused.
///
/// The boundary control. `<=` is the rule, so exactly the cap must pass — an exclusive
/// comparison makes the documented cap a lie by one byte.
#[tokio::test]
async fn a_body_at_the_cap_is_served() {
    let server = Server::start(Some(Limits::with_body(5))).await;

    let at = server
        .request(
            "POST /ok HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await;
    assert!(
        at.contains("200 OK"),
        "exactly the cap must be served: {at}"
    );

    let over = server
        .request(
            "POST /ok HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello!",
        )
        .await;
    assert!(over.contains("413"), "one over must be refused: {over}");
}

/// A server with no limiter serves bodies of any size.
///
/// The control for the wiring itself: `ServerConfig::limits` defaults to `None`, and a server
/// that invented a cap would change behaviour for a manifest that never asked for one.
#[tokio::test]
async fn no_limiter_means_no_cap() {
    let server = Server::start(None).await;

    // The body must actually be sent. A first version declared `Content-Length: 5000` and sent
    // nothing, so `drain_body` waited out its read timeout and the connection closed with an
    // **empty** response -- the server was correct and the test was wrong. A declared length
    // the client never delivers is a different scenario (a slow or stalled client) with its
    // own handling, not what this control is about.
    let mut body = String::new();
    for _ in 0..5000 {
        body.push('x');
    }
    let got = server
        .request(&format!(
            "POST /ok HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n{body}"
        ))
        .await;
    assert!(
        got.contains("200 OK"),
        "no limiter must mean no cap: {got:?}"
    );
}

// ---------------------------------------------------------------------------
// A rate limit
// ---------------------------------------------------------------------------

/// **The rate limit refuses with `429` once the allowance is spent.**
///
/// `429` and not `413`: "you are sending too often" and "you are sending too much" are
/// different facts, and a client that received one status for both would retry a body it can
/// never send or shrink a payload when it should have waited.
#[tokio::test]
async fn a_rate_limit_refuses_with_429() {
    let server = Server::start(Some(Limits::with_rate(2, Duration::from_secs(60)))).await;

    for i in 0..2 {
        let ok = server
            .request("GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await;
        assert!(
            ok.contains("200 OK"),
            "request {i} is within the allowance: {ok}"
        );
    }

    let refused = server
        .request("GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;
    assert!(
        refused.contains("429"),
        "the third must be refused: {refused}"
    );
}

/// **The allowance is per tenant across connections, not per connection.**
///
/// The property a per-connection copy of the limiter would break — and it would break it
/// silently, because each connection's own allowance would look correct in isolation. The
/// test opens a **new connection** for each request, which is what makes the distinction
/// visible: with a limiter cloned per connection, every request would succeed forever.
#[tokio::test]
async fn the_allowance_spans_connections() {
    let server = Server::start(Some(Limits::with_rate(3, Duration::from_secs(60)))).await;

    // Three connections, each its own socket.
    for i in 0..3 {
        let ok = server
            .request("GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await;
        assert!(
            ok.contains("200 OK"),
            "connection {i} is within the allowance: {ok}"
        );
    }

    // A fourth, on yet another socket, must be refused.
    let refused = server
        .request("GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;
    assert!(
        refused.contains("429"),
        "a fourth connection must be refused: the allowance is per TENANT, not per socket: \\
         {refused}"
    );
}

// ---------------------------------------------------------------------------
// The refusal is observable
// ---------------------------------------------------------------------------

/// **A refused request reaches the access log and the metrics.**
///
/// A denial an operator cannot see is indistinguishable from a request that vanished, and the
/// two need different responses. The metric is the `Refused` outcome, which is its own series
/// rather than folded into a success or a protocol error.
#[tokio::test]
async fn a_refusal_is_recorded() {
    let server = Server::start(Some(Limits::with_rate(1, Duration::from_secs(60)))).await;

    server
        .request("GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;
    server
        .request("GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;

    // The refused connection is reported as `Refused`, and it is not a success.
    for _ in 0..100 {
        if server.metrics.connections_for(Outcome::Refused) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        server.metrics.connections_for(Outcome::Refused) >= 1,
        "a refusal must be its own outcome, not folded into another"
    );

    // Both requests were recorded: the refused one is still a request the server handled,
    // because counting only the served ones would make the refusal invisible in the rate.
    assert!(
        server.metrics.total_requests() >= 1,
        "the served request must be counted"
    );
}

// ---------------------------------------------------------------------------
// The per-tenant connection ceiling (`SRV-020`)
// ---------------------------------------------------------------------------

/// **A per-tenant `max_connections` is enforced by the ledger, before dispatch.**
///
/// The limit is a connection count rather than a request count, so connections are
/// *held* open: a dropped stream would release its slot and the next connection would be
/// admitted, which would test the happy path instead.
///
/// # Why the ceiling is filled rather than assumed
///
/// `Server::start_with` probes readiness by connecting, and that connection is counted.
/// It is then dropped, so its slot is released -- but the release is asynchronous, so how
/// many slots are busy when the body below starts is not fixed. The first version assumed
/// one and asserted against a ceiling of two, which left the connection under test admitted
/// as the second. Filling the ceiling explicitly makes the precondition the test's own
/// statement rather than a property of the harness, and the whole point of the test is the
/// assertion after the ceiling is full.
///
/// The refusal is the ledger's own -- a bare status line with `content-length: 0` and no
/// `X-QQQ-Error` -- not a routed 503. Under `qqq-run` that distinction is invisible because
/// its fixture's guest is unbuilt; the positive control below proves the difference by
/// reaching a real 200.
#[tokio::test]
async fn a_per_tenant_connection_ceiling_is_enforced() {
    const CEILING: u32 = 2;
    let limits = TenantLimits::with_connections([("127.0.0.1".to_owned(), CEILING)], 16);
    let server = Server::start_with(Some(limits)).await;

    // Hold `CEILING` connections open. Each is kept alive for the whole test, which is what
    // makes it occupy a slot.
    let mut held: Vec<TcpStream> = Vec::new();
    for _ in 0..CEILING {
        let mut c = TcpStream::connect(server.addr).await.expect("held connect");
        c.write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
            .await
            .expect("write");
        c.flush().await.expect("flush");
        let mut buf = [0u8; 256];
        let _ = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await;
        // Pushed **after** the read, and kept for the whole test: the stream must stay
        // alive or the server releases the slot and the ceiling never fills.
        held.push(c);
        // Let the server ledger this connection before the next arrives.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The ceiling is now full, so this connection must be refused by the ledger.
    let refused = server
        .request("GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;
    assert!(
        refused.starts_with("HTTP/1.1 503") && refused.contains("content-length: 0"),
        "a tenant at its ceiling must be refused by the ledger:\n{refused}"
    );
    assert!(
        !refused.contains("X-QQQ-Error"),
        "the refusal must come from the ledger, which has no route to name:\n{refused}"
    );

    drop(held);
}

/// The positive control: one held connection, at the same ceiling, leaves the next
/// connection served **200**.
///
/// Without this, the test above would pass against a server that refused the next
/// connection for any reason -- an overloaded pool, a broken limiter, anything. Here the
/// only difference from the test above is that the ceiling is not full, so a 200 isolates
/// the ceiling as the cause.
#[tokio::test]
async fn a_connection_under_the_ceiling_is_served() {
    let limits = TenantLimits::with_connections([("127.0.0.1".to_owned(), 2)], 16);
    let server = Server::start_with(Some(limits)).await;

    // One held connection, so the ceiling has room for one more.
    let mut c = TcpStream::connect(server.addr).await.expect("held connect");
    c.write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
        .await
        .expect("write");
    c.flush().await.expect("flush");
    let mut buf = [0u8; 256];
    let _ = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let under_ceiling = server
        .request("GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;
    assert!(
        under_ceiling.starts_with("HTTP/1.1 200"),
        "a connection under the ceiling must be served:\n{under_ceiling}"
    );

    drop(c);
}
