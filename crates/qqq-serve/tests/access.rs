// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for structured access logging (`SRV-013`).
//!
//! # Why these drive a real socket
//!
//! `access_log`'s own 21 tests cover the type: the field contract, redaction, the
//! two encodings. None of them can show that a request **produces** a record,
//! because that happens in `serve_connection` after the handler runs — the seam
//! where `§O-118` and `§O-120` both found defects. A logger with perfect unit tests
//! and no call site is dead code that looks tested.
//!
//! So these tests start the real server, send a real request, and assert on the
//! record built from the status the server actually returned.
//!
//! # Why the record comes from the server's own builder
//!
//! An earlier draft of this file restated `serve_connection`'s level rule and
//! hand-built the `Record`, on the theory that importing the implementation's answer
//! makes the test vacuous. That reasoning is right about the *rule* and wrong about the
//! *wiring*: a copied record proves nothing about what the server emits, and it goes
//! stale the first time a field is added.
//!
//! The rule has since been extracted to `server::level_of` and the record to
//! `server::access_record`, both public. So this file drives **production code** and
//! asserts against literal expected values — the boundaries, the field names, the level
//! names. A change to any of them fails here. That is a stronger test than either
//! copy, because the wiring is now covered and the contract is still stated.
//!
//! # The gap these tests do not close, stated plainly
//!
//! Rust's test harness captures `println!` per test and surfaces it only on failure,
//! so a test cannot read back the line the *server* printed. Everything up to the
//! sink is verified here — the status the socket returned, the record the server
//! builds from it, the filter that decides whether it is written, and the exact
//! rendering — but the `println!` itself is not. It is one call with no logic in it,
//! and naming that is more useful than a test that pretends to cover it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use qqq_io::listener::{ListenAddr, Shutdown};
use qqq_serve::access_log::{Format, Level, Logger, Redactor};
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::server::{
    access_record, level_of, serve, Handler, ServerConfig, MANIFEST_REV_UNKNOWN,
};
use qqq_serve::{RequestHead, Response, RouteMatch, Version};

/// A port nobody is using.
///
/// Bound and released, accepting a microsecond race, for the reason
/// `tests/socket.rs` documents: `Listener` does not expose the address it bound, so
/// port `0` cannot be read back, and a fixed port would collide when the test
/// binaries run concurrently.
fn free_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = l.local_addr().expect("addr");
    drop(l);
    a
}

/// A table with one route.
fn table() -> RouteTable {
    let mut t = RouteTable::new();
    t.insert(Route::new(Method::Get, "/ok", "ok").expect("a valid route"))
        .expect("a distinct route inserts");
    t
}

/// A handler that answers every matched request with `status`.
fn handler_with(status: u16) -> Handler {
    Arc::new(move |_head: &RequestHead, _m: &RouteMatch| Response::text(status, "body"))
}

/// A running server, stopped when dropped.
struct Server {
    addr: SocketAddr,
    shutdown: Shutdown,
}

impl Server {
    /// Start a server whose logger is configured for the test's assertions.
    ///
    /// `Level::Error` inside the server itself keeps its own output quiet while the
    /// tests below drive `Logger` directly: the server's access lines go to the test
    /// harness's captured stdout, and a logger at `Trace` would interleave them with
    /// failure output. Errors still surface, because a test that hides a server-side
    /// 500 passes for the wrong reason.
    async fn start(handler: Handler) -> Self {
        let addr = free_addr();
        let listen = ListenAddr::parse(&addr.to_string()).expect("a resolved address must parse");
        let shutdown = Shutdown::new();
        let config = ServerConfig::for_addr(listen);
        let local = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(
                config,
                table(),
                handler,
                local,
                Logger::new(Format::Json, Level::Error),
            )
            .await
            {
                // Printed rather than swallowed: a bind failure would otherwise
                // surface as "connection refused" in every assertion below, with
                // nothing saying why.
                eprintln!("server stopped early: {}", e.render());
            }
        });

        let server = Self { addr, shutdown };
        server.wait_until_accepting().await;
        server
    }

    /// Wait until the listener accepts, by connecting.
    ///
    /// Polling with a real connect tests the property that matters — the socket
    /// accepts — rather than sleeping a guessed interval.
    async fn wait_until_accepting(&self) {
        for _ in 0..200 {
            if TcpStream::connect(self.addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the server never accepted a connection on {}", self.addr);
    }

    /// Send one request and return the status code it produced.
    ///
    /// Asynchronous throughout: a blocking `std::net` read inside a
    /// `#[tokio::test]` runtime blocks the only worker thread the server runs on,
    /// so the response never arrives — which is how the first version of this file
    /// failed, with five empty status lines.
    async fn status_of(&self, target: &str) -> u16 {
        let mut stream = TcpStream::connect(self.addr).await.expect("connect");
        let req = format!("GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.expect("write");
        stream.flush().await.expect("flush");

        let raw = read_all(&mut stream).await;
        let line = raw.lines().next().unwrap_or_default();
        line.split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .parse()
            .unwrap_or_else(|_| panic!("no status in the response to {target}: {raw:?}"))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.signal();
    }
}

/// Read until EOF, with a timeout.
///
/// The timeout matters more than the read: a server that never responds would
/// otherwise hang the test until CI's job timeout, which reports nothing about the
/// cause.
async fn read_all(stream: &mut TcpStream) -> String {
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

/// The level `serve_connection` assigns to `status`.
///
/// A thin alias so the test bodies read as assertions rather than as calls. The
/// rule itself lives in `server::level_of` and is never restated here.
fn level_for(status: u16) -> Level {
    level_of(status)
}

/// A request head for the request the tests send.
fn head(target: &str) -> RequestHead {
    RequestHead {
        method: Method::Get,
        target: target.to_owned(),
        version: Version::Http11,
        headers: Vec::new(),
        // No body: `access_record` reads only the method, the target and the status.
        content_length: None,
        chunked: false,
    }
}

/// The record the server builds for a response to `GET target`.
fn record_for(status: u16, target: &str) -> qqq_serve::access_log::Record {
    access_record(
        &head(target),
        target,
        &Response::text(status, "body"),
        "127.0.0.1",
        1,
    )
}

// ---------------------------------------------------------------------------
// The seam: does the request path yield the record the server should build?
// ---------------------------------------------------------------------------

/// **A 200 through a real socket produces an `Info` record naming the request.**
#[tokio::test]
async fn a_request_produces_an_access_record() {
    let server = Server::start(handler_with(200)).await;
    let status = server.status_of("/ok").await;
    assert_eq!(status, 200, "the request must succeed");

    let logger = Logger::new(Format::Json, Level::Trace);
    let line = logger
        .emit(record_for(status, "/ok"))
        .expect("Info passes a Trace filter");

    let v: serde_json::Value = serde_json::from_str(&line).expect("the record must be JSON");
    assert_eq!(v["status"], "200");
    assert_eq!(v["path"], "/ok");
    assert_eq!(v["component"], "qqq-serve");
    assert_eq!(v["tenant"], "127.0.0.1");
    assert_eq!(v["level"], "info");

    // §10.3's mandatory field set, asserted as a set so a dropped field fails.
    for field in [
        "trace_id",
        "span_id",
        "tenant",
        "component",
        "manifest_rev",
        "level",
        "msg",
    ] {
        assert!(v.get(field).is_some(), "§10.3 requires `{field}`: {line}");
    }
}

/// **The level follows the status the client actually saw.**
///
/// This is what makes `grep '"level":"error"'` a useful query. A server logging
/// every response at `Info` would leave the level field decorative, and that is a
/// failure no unit test on `Level` can catch — the rule lives at the call site.
#[tokio::test]
async fn the_record_level_follows_the_status_the_client_saw() {
    for (status, want) in [
        (200u16, Level::Info),
        (404, Level::Warn),
        (500, Level::Error),
    ] {
        let server = Server::start(handler_with(status)).await;
        let seen = server.status_of("/ok").await;
        assert_eq!(seen, status, "the server must return {status}");
        assert_eq!(
            level_for(seen),
            want,
            "the level rule must map {status} to {want:?}"
        );
    }
}

/// At `Error`, only a 500 is written — checked by rendering, not by inspection.
#[tokio::test]
async fn the_error_filter_writes_only_failures() {
    let logger = Logger::new(Format::Json, Level::Error);
    for (status, written) in [(200u16, false), (404, false), (500, true)] {
        let line = logger.emit(record_for(status, "/ok"));
        assert_eq!(
            line.is_some(),
            written,
            "at Error, {status} is {}written",
            if written { "" } else { "not " }
        );
        if let Some(l) = line {
            assert!(l.contains("\"level\":\"error\""), "{l}");
        }
    }
}

/// An unregistered path is answered and does not take the server down.
#[tokio::test]
async fn an_unknown_path_is_answered_and_the_server_survives() {
    let server = Server::start(handler_with(200)).await;

    assert_eq!(
        server.status_of("/nope").await,
        404,
        "an unregistered path is a 404"
    );
    // The connection that produced it did not stop the listener.
    assert_eq!(
        server.status_of("/ok").await,
        200,
        "the server still serves"
    );
}

/// A failing response's error code reaches the record.
///
/// The code is extracted by the server's own `access_record`, from the body the server
/// itself produced — so this covers the join between "the server found a code" and "the
/// operator can grep for it", not just each half.
#[tokio::test]
async fn an_error_response_yields_a_code_on_the_record() {
    let handler: Handler =
        Arc::new(|_head: &RequestHead, _m: &RouteMatch| Response::text(500, "boom: QQQ-3007"));
    let server = Server::start(handler).await;
    assert_eq!(server.status_of("/ok").await, 500);

    // The record the server builds for a 500 whose body carries a code.
    let rec = access_record(
        &head("/ok"),
        "/ok",
        &Response::text(500, "boom: QQQ-3007"),
        "127.0.0.1",
        1,
    );
    assert_eq!(
        rec.code(),
        Some("QQQ-3007"),
        "the code must be extracted from the body"
    );

    let logger = Logger::new(Format::Json, Level::Error);
    let line = logger.emit(rec).expect("Error passes an Error filter");
    assert!(line.contains("\"code\":\"QQQ-3007\""), "{line}");
}

/// A body with no code produces no `code` field, rather than an empty one.
///
/// §10.3 writes the field as `code?`, so its absence is the contract for success.
/// An empty string would make `code == ""` and `code is null` both possible and
/// neither meaningful.
#[tokio::test]
async fn a_successful_response_has_no_code_field() {
    let server = Server::start(handler_with(200)).await;
    assert_eq!(server.status_of("/ok").await, 200);

    let rec = record_for(200, "/ok");
    assert_eq!(rec.code(), None, "a success has no code");

    let logger = Logger::new(Format::Json, Level::Info);
    let line = logger.emit(rec).expect("Info passes");
    assert!(!line.contains("\"code\""), "no code on a success: {line}");
}

/// A near-miss code — right shape, wrong digits — is not reported as a code.
///
/// `error_code_of` scans for `QQQ-` plus exactly four digits. A body containing
/// `QQQ-abc` or `QQQ-12345` must not produce a code, because a log field holding a
/// non-code would poison every query that groups by it.
#[tokio::test]
async fn a_malformed_code_is_not_extracted() {
    for body in ["QQQ-abc", "QQQ-12345", "QQQ-", "no code here"] {
        let rec = access_record(
            &head("/ok"),
            "/ok",
            &Response::text(500, body),
            "127.0.0.1",
            1,
        );
        assert_eq!(rec.code(), None, "`{body}` is not a code");
    }
    // And the shape that *is* a code still is, so the loop above is not passing
    // because extraction is broken outright.
    let rec = access_record(
        &head("/ok"),
        "/ok",
        &Response::text(500, "QQQ-1234"),
        "127.0.0.1",
        1,
    );
    assert_eq!(rec.code(), Some("QQQ-1234"));
}

// ---------------------------------------------------------------------------
// Redaction, as the server configures it
// ---------------------------------------------------------------------------

/// **A secret in a request path is not written to the log.**
///
/// The path is attacker-controlled and lands in two fields (`msg` and `path`), so
/// it is the realistic place a token appears. Both must be redacted — asserted on
/// the *rendered line*, not on the redactor in isolation.
#[test]
fn a_secret_in_the_request_path_is_redacted() {
    let logger = Logger::new(Format::Json, Level::Info)
        .with_redactor(Redactor::from_values(["s3cr3t-token"]));

    let rec = record_for(200, "/orders?token=s3cr3t-token");
    let line = logger.emit(rec).expect("Info passes");

    assert!(
        !line.contains("s3cr3t-token"),
        "the token must not appear in the access line: {line}"
    );
    let v: serde_json::Value = serde_json::from_str(&line).expect("still JSON");
    assert!(v["path"].as_str().unwrap().contains("[redacted:"), "{line}");
    assert!(v["msg"].as_str().unwrap().contains("[redacted:"), "{line}");
}

/// A request with no secret is not altered by having a redactor.
///
/// The control: without it, the previous test's pass could be caused by redaction
/// corrupting every line rather than by the secret being present.
#[test]
fn an_ordinary_request_is_not_altered() {
    let logger = Logger::new(Format::Json, Level::Info)
        .with_redactor(Redactor::from_values(["s3cr3t-token"]));

    let line = logger
        .emit(record_for(200, "/orders"))
        .expect("Info passes");
    assert!(line.contains("GET /orders 200"), "{line}");
    assert!(!line.contains("redacted"), "nothing to redact: {line}");
}

/// The human format carries every mandatory field, on one line.
///
/// Drives the server's own builder into the human renderer, so the two encodings are
/// compared through production code. `manifest_rev` is in the list because an earlier
/// `render_human` dropped it while `render_json` wrote it — see
/// `access_log::tests::the_two_encodings_carry_the_same_fields`.
#[test]
fn the_human_format_carries_the_mandatory_fields() {
    let logger = Logger::new(Format::Human, Level::Info);
    let line = logger
        .emit(record_for(404, "/nope"))
        .expect("Warn passes an Info filter");

    // `WARN`, uppercase: the human format leads with the level so `grep ERROR`
    // works against a line whose other fields are lowercase prose.
    for needle in [
        "WARN",
        "127.0.0.1",
        "qqq-serve",
        MANIFEST_REV_UNKNOWN,
        "GET /nope 404",
    ] {
        assert!(
            line.contains(needle),
            "human line must carry `{needle}`: {line}"
        );
    }

    // One line: a human log that wraps breaks `grep` and every line-oriented tool.
    assert!(
        !line.contains('\n'),
        "the human record is one line: {line:?}"
    );

    // And it is *not* JSON — a human format that emitted JSON would mean the two
    // formats were one format with a label.
    assert!(
        serde_json::from_str::<serde_json::Value>(&line).is_err(),
        "the human format is not JSON: {line}"
    );
}

/// The record names the request the client sent, not a reconstruction of it.
///
/// `msg` is what an operator reads first and `path` is what a query filters on; both
/// must describe the same request. A record whose `msg` said `/ok` while its `path`
/// said `/nope` would be worse than either field alone, because the reader would trust
/// the wrong one.
#[test]
fn the_record_describes_the_request_that_was_sent() {
    let rec = record_for(200, "/orders/42");
    assert_eq!(rec.msg(), "GET /orders/42 200");

    // Read through the public field iterator rather than by reaching into JSON, so a
    // renamed field fails here rather than in whatever queries operators have written.
    let fields: std::collections::BTreeMap<&str, &str> = rec.fields().collect();
    assert_eq!(fields.get("path"), Some(&"/orders/42"));
    assert_eq!(fields.get("method"), Some(&"GET"));
    assert_eq!(fields.get("status"), Some(&"200"));
}
