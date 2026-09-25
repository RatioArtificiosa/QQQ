// SPDX-License-Identifier: Apache-2.0

//! The metric set, recorded through `serve` on a real socket (`OBS-005`, `SRV-020`).
//!
//! # Why these drive `serve`
//!
//! `metrics.rs`'s 25 tests cover the registry exhaustively — the cardinality bounds, the
//! histogram, the tenant ceiling. None of them can show that a **request reaches it**,
//! because that happens in `serve_connection` after the handler runs. A registry with
//! perfect unit tests and no call site is dead code that looks tested, which is exactly what
//! `metrics.rs` was until this wiring existed — the shape `§O-130` records four times over.
//!
//! # What only these can check
//!
//! That a **response the server chose** is what gets counted, not the handler's intent: a
//! 404 from the router and a 200 from a handler must land in different series. That the
//! counter is **per response**, so a keep-alive connection with three requests records
//! three. And that a connection opening and closing is one open and one close, not two of
//! either.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use qqq_io::listener::{ListenAddr, Shutdown};
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::metrics::{HttpMetrics, Method, Outcome, StatusClass};
use qqq_serve::route::{Method as RouteMethod, Route, RouteTable};
use qqq_serve::server::{serve, Dispatch, Handler, ServerConfig};
use qqq_serve::{RequestHead, Response, RouteMatch};

/// A port nobody is using, for the reason `tests/socket.rs` documents.
fn free_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = l.local_addr().expect("addr");
    drop(l);
    a
}

/// `GET /ok` answers 200; `POST /ok` answers 201; anything else 404s.
fn table() -> RouteTable {
    let mut t = RouteTable::new();
    for method in [RouteMethod::Get, RouteMethod::Post] {
        t.insert(Route::new(method, "/ok", "ok").expect("valid route"))
            .expect("distinct");
    }
    t
}

fn handler() -> Handler {
    Arc::new(|head: &RequestHead, _m: &RouteMatch| match head.method {
        RouteMethod::Post => Response::text(201, "created"),
        _ => Response::text(200, "ok"),
    })
}

/// A running server with its own registry.
struct Server {
    addr: SocketAddr,
    shutdown: Shutdown,
    metrics: Arc<HttpMetrics>,
}

impl Server {
    async fn start() -> Self {
        // Retried, because between `free_addr` dropping its listener and `serve` binding the
        // port, another test in this process -- or another process on the runner -- can take
        // it. That happened in CI: `could not bind 127.0.0.1:57009`, after 405 seconds of
        // waiting on a port someone else owned. Waiting cannot help; a **fresh port** can.
        for _ in 0..16 {
            let addr = free_addr();
            let listen = ListenAddr::parse(&addr.to_string()).expect("parses");
            let shutdown = Shutdown::new();
            let mut config = ServerConfig::for_addr(listen);
            let metrics = Arc::new(HttpMetrics::new());
            config.metrics = Some(Arc::clone(&metrics));
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
                // The task finishing early means the bind failed; waiting cannot help.
                if probe.is_finished() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            s.shutdown.signal();
            let _ = probe.await;
        }
        // Sixteen fresh ephemeral ports in a row is not bad luck.
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
// A request reaches the registry at all
// ---------------------------------------------------------------------------

/// **One request through the real server is one request in the registry.**
///
/// The wiring test. Before it, `HttpMetrics` was correct and unreachable.
#[tokio::test]
async fn a_request_is_recorded_through_serve() {
    let server = Server::start().await;
    assert_eq!(server.metrics.total_requests(), 0, "nothing yet");

    let got = server
        .request("GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;
    assert!(got.contains("200 OK"), "{got}");

    assert_eq!(
        server.metrics.total_requests(),
        1,
        "the request must reach the registry"
    );
    assert_eq!(
        server
            .metrics
            .requests_for(Method::Get, StatusClass::Success),
        1
    );
}

/// **The status the server chose is what gets counted, not the handler's intent.**
///
/// A 404 comes from the router and never reaches the handler; a 201 comes from the handler.
/// Both must land in their own series, which only the real dispatch path can show.
#[tokio::test]
async fn the_servers_chosen_status_is_recorded() {
    let server = Server::start().await;

    server
        .request("GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;
    server
        .request("POST /ok HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await;
    let missing = server
        .request("GET /missing HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;
    assert!(missing.contains("404"), "{missing}");

    assert_eq!(
        server
            .metrics
            .requests_for(Method::Get, StatusClass::Success),
        1
    );
    assert_eq!(
        server
            .metrics
            .requests_for(Method::Post, StatusClass::Success),
        1,
        "a 201 is a 2xx: the class, not the code"
    );
    assert_eq!(
        server
            .metrics
            .requests_for(Method::Get, StatusClass::ClientError),
        1,
        "the 404 the *router* produced must be counted"
    );
    assert_eq!(server.metrics.total_requests(), 3);
}

/// **A keep-alive connection with three requests records three.**
///
/// The per-response counter, as opposed to a per-connection one. A counter incremented on
/// connection open would record 1 here, and that is the mistake this measures.
#[tokio::test]
async fn each_request_on_a_connection_is_recorded() {
    let server = Server::start().await;

    let mut stream = TcpStream::connect(server.addr).await.expect("connect");
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    for _ in 0..3 {
        stream
            .write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect("write");
        stream.flush().await.expect("flush");
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("a response")
            .expect("read");
        response.extend_from_slice(&chunk[..n]);
    }

    let text = String::from_utf8_lossy(&response);
    assert_eq!(text.matches("200 OK").count(), 3, "{text}");
    assert_eq!(
        server
            .metrics
            .requests_for(Method::Get, StatusClass::Success),
        3,
        "three requests on one connection must be three, not one"
    );
}

/// **Bytes in and out are recorded, per tenant.**
#[tokio::test]
async fn body_bytes_are_recorded() {
    let server = Server::start().await;

    server
        .request(
            "POST /ok HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await;

    // The tenant key is the **peer IP address**: `tenant_of` derives it from the socket,
    // and there is no manifest-declared tenant yet. A first version of this test asserted
    // `"default"` and failed -- which is how the cardinality defect below was found.
    let key = "127.0.0.1";
    assert_eq!(
        server.metrics.bytes_in_for(key),
        5,
        "the bytes that crossed the socket, not the declared length"
    );
    assert!(
        server.metrics.bytes_out_for(key) > 0,
        "the response body was written"
    );
}

/// **The peer address becomes one series key, not one per request.**
///
/// `tenant_of` returns the peer's address, so recording it directly would create one time
/// series per client — §10.2's cardinality violation in its worst form, because the value
/// is entirely attacker-chosen.
///
/// # What this test asserts, and what it does not
///
/// It asserts the **wiring**: a request is recorded under the peer address, and one client
/// produces **one** series rather than one per request — that the closed set is *applied*
/// rather than merely defined, which is where the defect was (the set was correct and
/// unused).
///
/// It does **not** exercise the ceiling. It was titled `the_peer_ip_is_a_bounded_label` and
/// its comment said *"past 64 distinct peers, further ones collapse into one `other`
/// series"* — and this fixture can show neither: it sends one request from one client, and
/// reaching the ceiling over real sockets would need 65 distinct source addresses. The
/// assertion `series_count() == 1` is about the *lower* bound, so a reader was being told
/// the test covered a bound it verifies the opposite edge of.
///
/// **The ceiling is covered where it can be.** `metrics.rs`'s unit tests
/// `tenants_past_the_ceiling_collapse_to_other`,
/// `an_existing_tenant_keeps_its_label_past_the_ceiling`, `the_tenant_ceiling_is_enforced`
/// and `the_ceiling_boundary_is_exact` drive `TenantLabels` directly and assert the
/// collapse, the retention, and both sides of the boundary. The title now claims what the
/// fixture establishes (`§O-280`).
#[tokio::test]
async fn the_peer_ip_is_one_series_key_not_one_per_request() {
    let server = Server::start().await;

    server
        .request("GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;

    // The key is the peer address, and it is **one** key rather than one per request.
    let addr_key =
        server.metrics.bytes_out_for("127.0.0.1") > 0 || server.metrics.bytes_out_for("::1") > 0;
    assert!(
        addr_key,
        "the request must be recorded under the peer address"
    );
    assert_eq!(
        server.metrics.series_count(),
        1,
        "one client must not produce a series per request"
    );
}

/// **Latency is recorded, and it is plausible rather than zero.**
///
/// A histogram that recorded nothing would report `None`; one that recorded a constant
/// would pass a `is_some` check. This asserts a real measurement happened.
#[tokio::test]
async fn latency_is_recorded() {
    let server = Server::start().await;
    assert_eq!(server.metrics.latency().count(), 0);

    server
        .request("GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;

    assert_eq!(server.metrics.latency().count(), 1);
    assert!(
        server.metrics.latency().sum_micros() > 0,
        "a real request takes a non-zero time"
    );
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

/// **One connection is one open and one close.**
///
/// The control for both counters: an implementation that incremented `open` per *request*
/// or never decremented would show a growing count, and a server that leaked connections
/// would look identical to one that was busy.
#[tokio::test]
async fn a_connection_opens_and_closes_once() {
    let server = Server::start().await;

    server
        .request("GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;

    // The close is recorded after the ledger releases, so give the task a moment to finish.
    for _ in 0..100 {
        if server.metrics.connections_for(Outcome::Ok) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(
        server.metrics.open_connections(),
        0,
        "the connection must not still be counted as open"
    );
    assert_eq!(
        server.metrics.connections_for(Outcome::Ok),
        1,
        "and it must be counted exactly once as closed"
    );
}

/// A client that disconnects gets `ClientClosed`, not `Ok`.
#[tokio::test]
async fn a_client_disconnect_is_recorded_as_such() {
    let server = Server::start().await;

    // **Settle the baseline before measuring a delta.** `Server::start`'s readiness probe
    // opens and closes a connection of its own, and that close is recorded
    // **asynchronously** — so a baseline read immediately after `start` returns is taken
    // *before* the probe's own `ClientClosed` lands, and the next increase is the probe's
    // rather than this test's.
    //
    // That is not a hypothesis: the first version of this fix read the baseline once and
    // compared, and the fault injection below — *delete the test's connection entirely* —
    // still **passed**. A delta against an unsettled baseline attributes nothing, and only
    // running the injection says so (`§O-280`). So the baseline waits for the count to stop
    // moving, which is the only way to know the probe is accounted for.
    let mut baseline = server.metrics.connections_for(Outcome::ClientClosed);
    for _ in 0..100 {
        let before = server.metrics.connections_for(Outcome::ClientClosed);
        tokio::time::sleep(Duration::from_millis(10)).await;
        baseline = server.metrics.connections_for(Outcome::ClientClosed);
        if baseline == before {
            break;
        }
    }

    // Connect and close without sending anything.
    let stream = TcpStream::connect(server.addr).await.expect("connect");
    drop(stream);

    let mut after = baseline;
    for _ in 0..100 {
        after = server.metrics.connections_for(Outcome::ClientClosed);
        if after > baseline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The absolute count is not the assertion — the readiness probe is a connection too.
    // What matters is the **classification**, measured as a delta from the settled
    // baseline: the vanished client is a `ClientClosed` and never an `Ok`, because a
    // connection that served no request must not be counted as a success.
    assert!(
        after > baseline,
        "the vanished client must add a `ClientClosed` on top of the settled {baseline}; \
         the count is still {after}"
    );
    assert_eq!(
        server.metrics.connections_for(Outcome::Ok),
        0,
        "no connection served a request, so none is a success"
    );
}

// ---------------------------------------------------------------------------
// Off by default
// ---------------------------------------------------------------------------

/// **A server with no registry records nothing and does not fail.**
///
/// `ServerConfig::metrics` defaults to `None`, and the recording sites are `Option`-checked
/// so that absence is free. This is the control that the wiring did not make a registry
/// mandatory.
#[tokio::test]
async fn a_server_with_no_registry_serves_normally() {
    let addr = free_addr();
    let listen = ListenAddr::parse(&addr.to_string()).expect("parses");
    let shutdown = Shutdown::new();
    let config = ServerConfig::for_addr(listen);
    assert!(config.metrics.is_none(), "off by default");
    let local = shutdown.clone();

    tokio::spawn(async move {
        let _ = serve(
            config,
            table(),
            Dispatch::flat(handler()),
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
        .write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    client.flush().await.expect("flush");
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut out)).await;
    let text = String::from_utf8_lossy(&out);

    assert!(
        text.contains("200 OK"),
        "the server must still work: {text}"
    );
    shutdown.signal();
}
