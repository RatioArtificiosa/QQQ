// SPDX-License-Identifier: Apache-2.0

//! A streaming route served through `serve` (`SRV-004`).
//!
//! # Why this test did not exist until now
//!
//! `tests/stream.rs` drove `StreamWriter` directly, because `serve_connection` had no
//! way to dispatch a streaming route: `serve` took a `Handler`, and a `Handler` returns a
//! complete `Response` with a `Content-Length`. So the writer was tested and unwired, and
//! the two tests said so rather than implying otherwise.
//!
//! `Dispatch` closes that. These tests go through the **real accept loop** — `serve`,
//! a bound socket, a live client — and prove that an event stream reaches a client with
//! no buffering anywhere in the path.
//!
//! # What "no buffering" means here, concretely
//!
//! The handler writes an event and **awaits a signal** before writing the next. The
//! client must receive the first event while the handler is still parked. If any layer
//! buffered the body until the handler returned, the client would see nothing until the
//! signal fired — and the test would deadlock rather than fail, so the signal is sent by
//! the client's read completing. That is the strongest available statement that the
//! bytes are not being held.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::server::{serve, Dispatch, Handler, RouteMatch, ServerConfig};
use qqq_serve::stream::{StreamError, StreamWriter};
use qqq_serve::{RequestHead, Response};

use qqq_io::listener::{ListenAddr, Shutdown};

/// A port nobody is using, for the reason `tests/socket.rs` documents.
fn free_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = l.local_addr().expect("addr");
    drop(l);
    a
}

/// A table with one `GET /events` route whose handler is named `stream`.
fn table() -> RouteTable {
    let mut t = RouteTable::new();
    t.insert(Route::new(Method::Get, "/events", "stream").expect("valid route"))
        .expect("distinct route");
    t
}

/// A running server, stopped when dropped.
struct Server {
    addr: SocketAddr,
    shutdown: Shutdown,
}

impl Server {
    async fn start(dispatch: Dispatch) -> Self {
        let addr = free_addr();
        let listen = ListenAddr::parse(&addr.to_string()).expect("parses");
        let shutdown = Shutdown::new();
        let config = ServerConfig::for_addr(listen);
        let local = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(
                config,
                table(),
                dispatch,
                local,
                // Errors only: an `Info` logger would interleave access lines with the
                // test harness's own output.
                Logger::new(Format::Json, Level::Error),
            )
            .await
            {
                eprintln!("server stopped early: {}", e.render());
            }
        });

        let server = Self { addr, shutdown };
        server.wait_until_accepting().await;
        server
    }

    async fn wait_until_accepting(&self) {
        for _ in 0..200 {
            if TcpStream::connect(self.addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the server never accepted a connection on {}", self.addr);
    }

    /// Connect and send a request, returning the live stream so a test can read
    /// incrementally rather than waiting for EOF.
    async fn open(&self, target: &str) -> TcpStream {
        let mut stream = TcpStream::connect(self.addr).await.expect("connect");
        let req = format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n");
        stream
            .write_all(req.as_bytes())
            .await
            .expect("write request");
        stream.flush().await.expect("flush");
        stream
    }

    /// Connect and send a request that **declares** `declared` body bytes, sending none.
    ///
    /// The declaration is the whole instrument. A server that reads the body before
    /// dispatching must block waiting for bytes that never arrive, so a response that
    /// still arrives is proof the body was not read — and no timing threshold is
    /// involved, because a blocking read never completes rather than completing slowly.
    async fn open_declaring(&self, target: &str, declared: u64) -> TcpStream {
        let mut stream = TcpStream::connect(self.addr).await.expect("connect");
        let req = format!("GET {target} HTTP/1.1\r\nHost: x\r\nContent-Length: {declared}\r\n\r\n");
        stream
            .write_all(req.as_bytes())
            .await
            .expect("write request");
        stream.flush().await.expect("flush");
        stream
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.signal();
    }
}

/// Read until `needle` appears or the timeout expires.
async fn read_until(stream: &mut TcpStream, needle: &str) -> String {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let mut chunk = [0u8; 1024];
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

/// Read whatever arrives within `window`, then return it.
///
/// Used by the control test below, which asserts on **absence**: the only way to show a
/// server is waiting is to wait a bounded time and find nothing.
async fn read_within(stream: &mut TcpStream, window: Duration) -> String {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(window, async {
        let mut chunk = [0u8; 1024];
        while let Ok(n) = stream.read(&mut chunk).await {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
        }
    })
    .await;
    String::from_utf8_lossy(&out).into_owned()
}

/// A streaming handler that writes one event, waits for a signal, then writes another.
///
/// The signal is what makes this a *streaming* test rather than a buffering one: the
/// harness only fires it after the client has already read the first event, so if any
/// layer held the body until the handler returned, the handler would never return.
///
/// # The counter, and why `tx.send(()).is_ok()` was not enough
///
/// The 404 test below asserts this handler never ran, and it used to prove that with
/// `tx.send(()).is_ok()` — *"the gate must still be pending"*. **That argument does not
/// hold.** `send` succeeds whenever the receiver has not been **dropped**, which includes
/// the case where the handler already took the receiver, parked on it, and is about to
/// complete. So the assertion passes whether or not the handler ran, which is the one
/// thing it was there to distinguish.
///
/// `invocations` is incremented as the handler's first instruction, so the 404 test can
/// assert **zero** — a claim about what happened rather than a claim about a channel's
/// state (`§O-279`).
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
                // Park until the client has seen the first event.
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

/// A handler used for the flat path, so a non-streaming route still works.
fn flat_handler() -> Handler {
    Arc::new(|_head: &RequestHead, _m: &RouteMatch| Response::text(200, "flat"))
}

// ---------------------------------------------------------------------------
// The wiring
// ---------------------------------------------------------------------------

/// **A streaming route delivers its first event before the handler finishes.**
///
/// The property the whole item exists for. The handler is parked awaiting a signal that
/// the test only sends after reading the first event, so a buffered path could not pass:
/// it would deadlock, not merely fail.
#[tokio::test]
async fn a_streaming_route_delivers_an_event_before_the_handler_returns() {
    let (tx, rx) = oneshot::channel();
    let invocations = Arc::new(AtomicUsize::new(0));
    let dispatch = Dispatch::flat(flat_handler())
        .with_streaming("stream", gated_handler(rx, Arc::clone(&invocations)));
    let server = Server::start(dispatch).await;

    let mut client = server.open("/events").await;

    // Read the head and the first event. The handler is still parked.
    let got = read_until(&mut client, "data: first").await;
    assert!(
        got.contains("data: first"),
        "the first event must arrive while the handler is still running: {got:?}"
    );

    // **The positive control for the 404 test's counter.** That test asserts the handler
    // was invoked zero times; this asserts it was invoked once on the path that matches.
    // Two assertions on one instrument, and the pair is what makes it an instrument: a
    // counter that always read zero would satisfy the 404 test and prove nothing there.
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        1,
        "the matching route must have invoked the handler exactly once"
    );
    assert!(
        got.contains("Transfer-Encoding: chunked"),
        "a streamed response is chunked: {got:?}"
    );
    assert!(
        !got.contains("Content-Length"),
        "a streamed response must not declare a length: {got:?}"
    );

    // Now let the handler finish.
    let _ = tx.send(());
    let rest = read_until(&mut client, "data: second").await;
    assert!(
        rest.contains("data: second"),
        "the second event must arrive after the gate opens: {rest:?}"
    );
}

/// **A streaming route must not read the request body.**
///
/// # The defect this test exists for
///
/// `drain_body` documented that *"a route with a `StreamingHandler` is dispatched
/// **before** this function runs, so a streaming route never buffers"* — while the call to
/// `serve_special_route` sat **below** the call to `drain_body`. So a streaming route's
/// body was read into memory and then handed to a handler that has no body parameter and
/// could not read it if it wanted to. Nothing failed: the response was correct and only
/// the cost was wrong, which is why no test noticed.
///
/// # Why the declaration is the instrument
///
/// The request declares `Content-Length: 4096` and sends **none** of those bytes. A server
/// that reads the body first blocks in `read` forever, so the first event never arrives
/// and `read_until`'s timeout finds nothing. A server that dispatches first streams the
/// event immediately. There is no timing threshold to tune: a blocking read does not
/// complete late, it does not complete.
#[tokio::test]
async fn a_streaming_route_does_not_read_the_request_body() {
    let (tx, rx) = oneshot::channel();
    let dispatch = Dispatch::flat(flat_handler())
        .with_streaming("stream", gated_handler(rx, Arc::new(AtomicUsize::new(0))));
    let server = Server::start(dispatch).await;

    let mut client = server.open_declaring("/events", 4096).await;
    let got = read_until(&mut client, "data: first").await;

    assert!(
        got.contains("data: first"),
        "the stream must start without the declared body: the handler was dispatched \
         before the body was read, or the server is blocked waiting for 4096 bytes that \
         will never arrive. Got: {got:?}"
    );

    let _ = tx.send(());
}

/// **The control: a flat route does read the declared body.**
///
/// Without this, `a_streaming_route_does_not_read_the_request_body` would also pass on a
/// server that ignored `Content-Length` entirely — which would be a far worse defect than
/// the one it is checking for, and this test is what tells the two apart.
#[tokio::test]
async fn a_flat_route_does_read_the_declared_body() {
    let dispatch = Dispatch::flat(flat_handler());
    let server = Server::start(dispatch).await;

    let mut client = server.open_declaring("/events", 11).await;

    // Nothing yet: the server is waiting for the eleven bytes it was promised.
    let early = read_within(&mut client, Duration::from_millis(300)).await;
    assert!(
        early.is_empty(),
        "a flat route must not answer before its declared body arrives, so the server \
         does honour Content-Length. Got: {early:?}"
    );

    client
        .write_all(b"hello world")
        .await
        .expect("write the promised body");
    client.flush().await.expect("flush");

    let got = read_until(&mut client, "flat").await;
    assert!(
        got.contains("200 OK") && got.ends_with("flat"),
        "once the body arrives the flat handler runs: {got:?}"
    );
}

/// A route with no streaming handler falls through to the flat one.
///
/// The reason `Dispatch` keys by name rather than putting a flag on `Route`: a server
/// that registers no streaming handlers must behave exactly as it did before.
#[tokio::test]
async fn a_route_without_a_streaming_handler_uses_the_flat_one() {
    let dispatch = Dispatch::flat(flat_handler());
    let server = Server::start(dispatch).await;

    let mut client = server.open("/events").await;
    let got = read_until(&mut client, "flat").await;

    assert!(got.contains("200 OK"), "{got:?}");
    assert!(
        got.contains("Content-Length: 4"),
        "a flat response has a length: {got:?}"
    );
    assert!(
        got.ends_with("flat"),
        "the body must be the flat handler's: {got:?}"
    );
}

/// An unknown path is still a 404 when streaming is configured.
///
/// The control for the two tests above: `Dispatch` must not change routing, only
/// dispatch.
#[tokio::test]
async fn an_unknown_path_is_still_a_404_with_streaming_configured() {
    let (tx, rx) = oneshot::channel();
    let invocations = Arc::new(AtomicUsize::new(0));
    let dispatch = Dispatch::flat(flat_handler())
        .with_streaming("stream", gated_handler(rx, Arc::clone(&invocations)));
    let server = Server::start(dispatch).await;

    let mut client = server.open("/nope").await;
    let got = read_until(&mut client, "\r\n\r\n").await;

    assert!(got.contains("404"), "{got:?}");
    // **The handler never ran**, asserted on a counter rather than on the channel.
    //
    // `assert!(tx.send(()).is_ok())` used to stand here, documented as *"the gate was never
    // consumed, because the streaming handler never ran"*. The conclusion does not follow
    // from the premise: `send` succeeds whenever the receiver has **not been dropped**,
    // which is also true when the handler took the receiver and parked on it. So the
    // assertion passes in the very case it was written to exclude. The counter is
    // incremented at the handler's first instruction, so zero invocations means zero
    // invocations (`§O-279`).
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "the streaming handler must not run for a path that matched no route"
    );
    // The gate is still open. A weaker signal than the counter, kept because it is the
    // property the other two tests depend on.
    assert!(tx.send(()).is_ok(), "the gate must still be pending");
}

/// **A streaming handler that fails mid-body leaves the client a truncated body, not a
/// fabricated error.**
///
/// The status is already on the wire and cannot be changed, so the only honest signal
/// left is the log. This drives a handler that returns `Handler` after one write and
/// asserts the client got what was sent.
///
/// # What this test does *not* observe, and where that is covered instead
///
/// It used to be titled *"A streaming handler that fails mid-body is recorded as
/// `HandlerFailed`"* — and it never observed that. `StreamOutcome::HandlerFailed` is
/// produced inside the server's dispatch loop (`server.rs`) and is **not reachable from an
/// integration test**: no public handle exposes it. It is verified where it can be —
/// `stream.rs`'s own unit tests assert that `HandlerFailed`'s level is `Error` and its
/// label is `handler_failed` — and the **consequence** a caller can see, that a failed
/// stream is classified `ClientClosed` rather than `Ok`, is asserted in
/// `metrics_wiring.rs`.
///
/// A claim in a title that the test cannot check is the defect `§O-125` names. The title
/// now states the property this test actually establishes, and the unobservable outcome is
/// named with its real home rather than left as an implied assertion (`§O-279`).
#[tokio::test]
async fn a_handler_that_fails_mid_body_truncates_rather_than_lies() {
    let handler: qqq_serve::stream::StreamingHandler = Arc::new(
        |_head: &RequestHead,
         _m: &RouteMatch,
         w: &mut StreamWriter<'_>|
         -> Pin<Box<dyn std::future::Future<Output = Result<(), StreamError>> + Send + '_>> {
            Box::pin(async move {
                w.write_now(b"data: partial\n\n")
                    .await
                    .map_err(|e| StreamError::Transport(e.to_string()))?;
                Err(StreamError::Handler("the data source went away".to_owned()))
            })
        },
    );
    let dispatch = Dispatch::flat(flat_handler()).with_streaming("stream", handler);
    let server = Server::start(dispatch).await;

    let mut client = server.open("/events").await;
    let got = read_until(&mut client, "data: partial").await;

    assert!(
        got.contains("data: partial"),
        "what the handler wrote must reach the client: {got:?}"
    );
    assert!(
        got.contains("200 OK"),
        "the status was already sent and cannot be revised: {got:?}"
    );
}
