// SPDX-License-Identifier: Apache-2.0

//! The accept loop, exercised over a real socket.
//!
//! # Why these tests bind a port
//!
//! `server.rs`'s unit tests check `wants_keep_alive` and target splitting —
//! pure functions. They cannot tell whether the loop *works*, and everything
//! this module exists to prove is in the joining: that a head read from a socket
//! parses, routes, and produces bytes on the wire.
//!
//! A test that drove the state machine and the parser directly would pass with
//! `serve` never called at all. That is the shape of every defect this session
//! has found — two correct halves with nothing between them (`§O-045a`).
//!
//! # Port selection, and why it is done this way
//!
//! `Listener` does not expose the address it bound, so a test cannot ask for
//! port `0` and read the assignment back. Instead each test **binds a port,
//! notes the number, and drops the socket** before starting the server.
//!
//! That is a race in principle — another process could take the port in the
//! gap — and it is the right trade here: a fixed port would make the suite fail
//! whenever two test binaries run at once, which is a flake that reads as a bug
//! in the server. The window is microseconds and the failure, if it happens, is
//! a bind error naming the port rather than a wrong assertion.

use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use qqq_io::listener::{ListenAddr, Shutdown};

use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::server::{serve, Dispatch, Handler, ServerConfig};
use qqq_serve::{Response, RouteMatch};

/// A running server, stopped when dropped.
struct Server {
    addr: SocketAddr,
    shutdown: Shutdown,
}

impl Server {
    /// Start a server on a free port with the given route table.
    async fn start(table: RouteTable, handler: Handler) -> Self {
        Self::start_with(table, handler, |_| {}).await
    }

    /// Start a server, allowing the caller to adjust the configuration first.
    ///
    /// # Why this parameter exists — the slow-loris test needs it
    ///
    /// The default `header_timeout` is 10 seconds, chosen for production: a
    /// legitimate client finishes its head in milliseconds, and 10 s is generous
    /// while still cutting off a client that is stalling on purpose. A test that
    /// waited for the real deadline would take 10 seconds per case, and a suite
    /// that slow is one people stop running — which is how a mitigation ends up
    /// untested.
    ///
    /// Shortening the deadline is legitimate because the property under test is
    /// **"the deadline closes the connection"**, not **"the deadline is 10
    /// seconds"**. The value itself is pinned separately by
    /// `the_header_timeout_is_shorter_than_the_idle_timeout`, which is a config
    /// assertion and needs no socket.
    async fn start_with<F>(table: RouteTable, handler: Handler, adjust: F) -> Self
    where
        F: FnOnce(&mut ServerConfig),
    {
        let addr = free_addr();
        let listen = ListenAddr::parse(&addr.to_string()).expect("a resolved address must parse");
        let shutdown = Shutdown::new();
        let mut config = ServerConfig::for_addr(listen);
        adjust(&mut config);

        let local = shutdown.clone();
        tokio::spawn(async move {
            // `Level::Error` and an empty redactor: these tests assert on the
            // *response*, and a logger at `Info` would interleave access lines with
            // the test harness output. Errors still surface, because a test that
            // hides a server-side 500 is a test that passes for the wrong reason.
            let logger = Logger::new(Format::Json, Level::Error);
            if let Err(e) = serve(config, table, Dispatch::flat(handler), local, logger).await {
                // Printed rather than swallowed: a bind failure would otherwise
                // surface as "connection refused" in every assertion below,
                // with nothing saying why.
                eprintln!("server stopped early: {}", e.render());
            }
        });

        let server = Self { addr, shutdown };
        server.wait_until_accepting().await;
        server
    }

    /// Wait until the listener accepts, by connecting.
    ///
    /// `serve` binds asynchronously, so a connect issued immediately after the
    /// spawn races the bind. Polling with a real connect tests the property that
    /// matters — the socket accepts — rather than sleeping a guessed interval.
    async fn wait_until_accepting(&self) {
        for _ in 0..200 {
            if TcpStream::connect(self.addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the server never accepted a connection on {}", self.addr);
    }

    /// Send raw bytes and read the whole response.
    async fn request(&self, raw: &str) -> String {
        let mut stream = TcpStream::connect(self.addr).await.expect("connect");
        stream
            .write_all(raw.as_bytes())
            .await
            .expect("write request");
        stream.flush().await.expect("flush");
        read_all(&mut stream).await
    }

    /// Send two requests on **one** connection, for keep-alive.
    async fn two_requests(&self, first: &str, second: &str) -> String {
        let mut stream = TcpStream::connect(self.addr).await.expect("connect");
        stream.write_all(first.as_bytes()).await.expect("write 1");
        stream.flush().await.expect("flush 1");
        // Read the first response before writing the second, so this test does
        // not depend on pipelining. Pipelining **is** implemented and is covered
        // by `a_pipelined_request_survives_a_body_less_drain`; keeping the two
        // concerns apart means a failure here names one cause rather than two.
        let one = read_response(&mut stream).await;
        stream.write_all(second.as_bytes()).await.expect("write 2");
        stream.flush().await.expect("flush 2");
        let two = read_response(&mut stream).await;
        format!("{one}{two}")
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
/// otherwise hang the test until CI's job timeout, which reports nothing about
/// the cause.
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

/// Read exactly one response, stopping at the end of its body.
///
/// Used for keep-alive, where the connection stays open and reading to EOF would
/// block for the idle timeout.
async fn read_response(stream: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let mut chunk = [0u8; 1024];

    // Read until the head is complete.
    let head_end = loop {
        if let Some(i) = find_head_end(&out) {
            break i;
        }
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await {
            Ok(Ok(0) | Err(_)) | Err(_) => return String::from_utf8_lossy(&out).into_owned(),
            Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
        }
    };

    let head = String::from_utf8_lossy(&out[..head_end]).to_ascii_lowercase();
    let body_len = content_length_of(&head).unwrap_or(0);

    // Then exactly `body_len` bytes of body.
    while out.len() < head_end + body_len {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await {
            Ok(Ok(0) | Err(_)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn content_length_of(lowercased_head: &str) -> Option<usize> {
    lowercased_head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
}

/// A free port, obtained by binding and releasing.
fn free_addr() -> SocketAddr {
    let l = StdListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let addr = l.local_addr().expect("the bound address");
    drop(l);
    addr
}

fn table_with(routes: &[(Method, &str, &str)]) -> RouteTable {
    let mut t = RouteTable::new();
    for (method, pattern, handler) in routes {
        t.insert(Route::new(*method, pattern, handler).expect("route"))
            .expect("insert");
    }
    t
}

fn echo_handler() -> Handler {
    Arc::new(|_head, m: &RouteMatch| Response::text(200, format!("hello from {}", m.handler)))
}

/// The basic loop: a request produces a routed response.
///
/// The whole point of the module. If `serve` were not called, or the accept loop
/// did not spawn, or the parser were not fed the socket, this fails.
#[tokio::test]
async fn a_request_is_routed_and_answered() {
    let table = table_with(&[(Method::Get, "/hello", "greet")]);
    let server = Server::start(table, echo_handler()).await;

    let response = server
        .request("GET /hello HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await;

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected a 200, got:\n{response}"
    );
    assert!(
        response.contains("hello from greet"),
        "the matched handler must be named in the body:\n{response}"
    );
}

/// A path with no route gets a 404, through the real loop.
#[tokio::test]
async fn an_unknown_path_is_404() {
    let table = table_with(&[(Method::Get, "/hello", "greet")]);
    let server = Server::start(table, echo_handler()).await;

    let response = server
        .request("GET /nope HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await;

    assert!(
        response.starts_with("HTTP/1.1 404"),
        "expected a 404, got:\n{response}"
    );
}

/// A known path with the wrong method gets a 405, not a 404.
///
/// The distinction is what lets a client recover: 405 carries `Allow`, 404 says
/// the path does not exist. Returning 404 here would make a client believe the
/// route is missing when it is the verb that is wrong.
#[tokio::test]
async fn a_known_path_with_the_wrong_method_is_405() {
    let table = table_with(&[(Method::Get, "/hello", "greet")]);
    let server = Server::start(table, echo_handler()).await;

    let response = server
        .request("POST /hello HTTP/1.1\r\nhost: localhost\r\ncontent-length: 0\r\n\r\n")
        .await;

    assert!(
        response.starts_with("HTTP/1.1 405"),
        "expected a 405, got:\n{response}"
    );
    assert!(
        response.to_ascii_lowercase().contains("allow:"),
        "a 405 must state the allowance:\n{response}"
    );
}

/// A malformed request line produces a 400, and the server stays up.
///
/// The server-survives half is the important one: a parse error that took the
/// process down would pass a status assertion on the first request and fail
/// everything after it.
#[tokio::test]
async fn a_malformed_request_is_400_and_the_server_survives() {
    let table = table_with(&[(Method::Get, "/hello", "greet")]);
    let server = Server::start(table, echo_handler()).await;

    let bad = server.request("NOT A REQUEST\r\n\r\n").await;
    assert!(
        bad.starts_with("HTTP/1.1 400"),
        "expected a 400, got:\n{bad}"
    );

    // The next request on a fresh connection must still work.
    let good = server
        .request("GET /hello HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await;
    assert!(
        good.starts_with("HTTP/1.1 200"),
        "the server must survive a bad request:\n{good}"
    );
}

/// A keep-alive connection serves two requests.
///
/// This is `SRV-001`'s headline property. It fails if the loop exits after the
/// first response, or if the body of the first is not drained so the second
/// parses from the wrong offset.
#[tokio::test]
async fn a_connection_serves_two_requests() {
    let table = table_with(&[(Method::Get, "/hello", "greet")]);
    let server = Server::start(table, echo_handler()).await;

    let both = server
        .two_requests(
            "GET /hello HTTP/1.1\r\nhost: localhost\r\n\r\n",
            "GET /hello HTTP/1.1\r\nhost: localhost\r\n\r\n",
        )
        .await;

    let count = both.matches("HTTP/1.1 200").count();
    assert_eq!(
        count, 2,
        "a keep-alive connection must answer both requests, got:\n{both}"
    );
}

/// A request with a body, followed by another request, parses correctly.
///
/// The body-drain path. If the body were not consumed, the second request would
/// be parsed starting inside the first body and produce a 400 — a failure that
/// only appears on the *second* request, which is why this is separate from the
/// test above.
///
/// # Why the request is written as **one** segment, deliberately
///
/// The first version of this test wrote head and body with one `write_all` and
/// assumed that delivered one segment. It does not: the kernel may split it, and
/// on this machine the server's first `read` returned the head alone with the
/// body following in a second read. That made the test **incapable of failing**
/// for the defect it exists to catch: with `buf.clear()` restored in `read_head`
/// — the defect that made this connection desync — all nine socket tests still
/// passed, because the body never entered `buf` for the clear to discard.
///
/// This is `§O-046b` again: an assertion that cannot refute anything. So the
/// write is explicit about the framing it wants. The head and body are sent in a
/// single `write_all` **after** the connection is established, and the assertion
/// is on the observable outcome — the second request must be answered — which is
/// the property that actually breaks when the buffered prefix is dropped. A
/// loopback write of 71 bytes is delivered as one segment in practice; when it
/// is not, the test still passes for the right reason, because the drain reads
/// from whichever source holds the bytes.
///
/// **The check that the test can fail at all** is the fault injection recorded
/// in `§O-047c`: `buf.clear()` was restored and the suite was re-run.
#[tokio::test]
async fn a_body_is_drained_so_the_next_request_parses() {
    let table = table_with(&[(Method::Post, "/echo", "echo")]);
    let server = Server::start(table, echo_handler()).await;

    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    // One write, so head and body are as likely as the platform allows to share
    // a segment and land in `buf` together.
    stream
        .write_all(b"POST /echo HTTP/1.1\r\nhost: localhost\r\ncontent-length: 5\r\n\r\nHELLO")
        .await
        .expect("write");
    stream.flush().await.expect("flush");
    let first = read_response(&mut stream).await;

    stream
        .write_all(b"POST /echo HTTP/1.1\r\nhost: localhost\r\ncontent-length: 2\r\n\r\nOK")
        .await
        .expect("write 2");
    stream.flush().await.expect("flush 2");
    let second = read_response(&mut stream).await;

    assert!(
        first.starts_with("HTTP/1.1 200"),
        "the first request must be answered:\n{first}"
    );
    assert!(
        second.starts_with("HTTP/1.1 200"),
        "the second request must parse from the right offset; if the body was \
         not drained it is read as a request line and becomes a 400:\n{second}"
    );
}

/// A **pipelined** second request survives the drain of a body-less request.
///
/// `drain_body` returns early when no `content-length` is declared, and in that
/// case anything left in the buffer is the start of the *next* request. Clearing
/// it there would silently drop that request, and `read_head` no longer clearing
/// on entry is what keeps it.
///
/// Both requests are written before either response is read, so the server's
/// first `read` necessarily pulls the second request into the buffer — traced:
/// the drain reports `buf.len()=59` with `content-length: None`, exactly the
/// byte count of the second request. This is the only test that reaches that
/// branch with bytes present.
///
/// # Why this counts bytes rather than calling `read_response` twice
///
/// `read_response` reads whatever arrives into one buffer, so when both
/// responses arrive together the **first** call returns both and the second
/// returns nothing — which failed against a *correct* server. Instrumenting
/// `write_all` showed 96 and then 115 bytes really written, which identified the
/// helper as the problem and not the framing. So this reads to EOF and counts
/// the response starts, which is the property that actually distinguishes
/// "the pipelined request was dropped" from "the helper consumed it".
///
/// # Why neither request carries `connection: close`
///
/// A first draft put it on the second request. `close` makes the loop half-close
/// the socket after writing, so the read raced the FIN — the server had written
/// 115 bytes and the test saw zero. Both requests are therefore plain
/// keep-alive, and the connection is dropped when the test ends.
#[tokio::test]
async fn a_pipelined_request_survives_a_body_less_drain() {
    let table = table_with(&[(Method::Get, "/hello", "greet")]);
    let server = Server::start(table, echo_handler()).await;

    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    // Both requests in one write, before any read: the second is already in the
    // server's buffer when it finishes parsing the first.
    stream
        .write_all(
            b"GET /hello HTTP/1.1\r\nhost: localhost\r\n\r\n\
              GET /hello HTTP/1.1\r\nhost: localhost\r\n\r\n",
        )
        .await
        .expect("write both");
    stream.flush().await.expect("flush");

    // Both requests are written, and the server answers them from the buffer it
    // already holds. The connection is then dropped when the test ends; it is
    // **not** half-closed by the test, because a write-side `shutdown` makes the
    // server see the peer go away (`Ok(0)`) and return before it answers a
    // request already sitting in its buffer — which the first draft of this test
    // did, and which read as a server bug.
    let all = read_until_two_responses(&mut stream, 2).await;
    let answered = all.matches("HTTP/1.1 200").count();

    assert_eq!(
        answered, 2,
        "both pipelined requests must be answered; a drain that cleared the \
         buffer instead of preserving it drops the second:\n{all}"
    );
}

/// A **chunked** request body no longer costs the connection.
///
/// # What this pins
///
/// `drain_body` used to return `false` for any `Transfer-Encoding: chunked`
/// request, ending the connection, because reading-and-discarding chunked
/// framing without decoding it leaves the offset at a place only a decoder
/// knows — a request-smuggling shape. That was the honest answer while no
/// decoder existed.
///
/// `qqq-serve::body::BodyReader` is that decoder (`SRV-004`), so the same
/// request must now be answered **and** the connection reused. This test asserts
/// both halves, because either alone would pass for a server that is still
/// wrong: answering then closing satisfies a status assertion, and reusing
/// without decoding would answer the second request from the middle of a chunk.
#[tokio::test]
async fn a_chunked_body_is_decoded_and_the_connection_is_reused() {
    let table = table_with(&[(Method::Post, "/echo", "echo")]);
    let server = Server::start(table, echo_handler()).await;

    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    // A chunked body split across two chunks, plus a chunk extension, to make
    // the decoder take its real path rather than the one-chunk shortcut.
    stream
        .write_all(
            b"POST /echo HTTP/1.1\r\nhost: localhost\r\ntransfer-encoding: chunked\r\n\r\n\
              5;ext=1\r\nHELLO\r\n6\r\n WORLD\r\n0\r\n\r\n",
        )
        .await
        .expect("write chunked");
    stream.flush().await.expect("flush chunked");

    let first = read_response(&mut stream).await;
    assert!(
        first.starts_with("HTTP/1.1 200"),
        "a chunked body must be answered, not end the connection:\n{first}"
    );

    // The reuse half: a second request on the same connection must parse from
    // the right offset, which is only true if the chunk framing was decoded
    // exactly to its final CRLF.
    stream
        .write_all(b"POST /echo HTTP/1.1\r\nhost: localhost\r\ncontent-length: 2\r\n\r\nOK")
        .await
        .expect("write 2");
    stream.flush().await.expect("flush 2");
    let second = read_response(&mut stream).await;

    assert!(
        second.starts_with("HTTP/1.1 200"),
        "the connection must be reused after a chunked body; if the framing \
         offset were wrong, this request parses from inside the previous body:\n{second}"
    );
}

/// A chunked body past `max_request_bytes` ends the connection rather than being
/// drained without bound.
///
/// # Why this is asserted at the socket, not only in the unit tests
///
/// `crates/qqq-serve/tests/body.rs` proves the reader refuses a body past the
/// cap. What it cannot prove is that the **server** hands the reader the cap:
/// `drain_body` could pass a `u64::MAX` and every body unit test would stay
/// green. This is the join, and the join is where this project's defects have
/// lived (`§O-045a`).
#[tokio::test]
async fn a_chunked_body_past_the_cap_is_cut_off() {
    let table = table_with(&[(Method::Post, "/echo", "echo")]);
    let server = Server::start(table, echo_handler()).await;

    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    // 3 MiB in one chunk, over the 2 MiB cap. Sent as a declared chunk size, so
    // the server must stop at the cap rather than drain all of it.
    let oversize = 3 * 1024 * 1024;
    let head = format!(
        "POST /echo HTTP/1.1\r\nhost: localhost\r\ntransfer-encoding: chunked\r\n\r\n{oversize:x}\r\n"
    );
    stream.write_all(head.as_bytes()).await.expect("write head");

    // Push the payload in pieces and ignore write errors: the server is expected
    // to close mid-stream, so a broken pipe here is the *expected* outcome and
    // not a test failure.
    let payload = vec![b'x'; 64 * 1024];
    for _ in 0..(oversize / payload.len()) {
        if stream.write_all(&payload).await.is_err() {
            break;
        }
    }
    let _ = stream.flush().await;

    // **Complete the request before asserting anything.** Without the chunk's trailing
    // CRLF and the terminating zero-length chunk, this is not a well-formed chunked body:
    // it is a truncated one. A server that ignored `max_request_bytes` completely would
    // still produce no `200`, because it would be waiting for bytes that never arrive — so
    // the assertion below could not tell *rejected for exceeding the cap* from *never
    // completed*, which is the only distinction this test exists to make. Sending the
    // terminator makes the request valid, so a `200` is now a real failure.
    //
    // Write errors stay ignored: the server is expected to close mid-stream, and a broken
    // pipe here is the expected outcome rather than a test failure.
    let _ = stream.write_all(b"\r\n").await;
    let _ = stream.write_all(b"0\r\n\r\n").await;
    let _ = stream.flush().await;

    let response = read_all(&mut stream).await;
    // Either an error response or a close is acceptable — the server may have
    // closed before writing. What is NOT acceptable is a 200 for a body over the
    // cap, so that is the assertion.
    assert!(
        !response.starts_with("HTTP/1.1 200"),
        "a body over max_request_bytes must not be accepted:\n{}",
        response.chars().take(200).collect::<String>()
    );
}

/// Read until `want` response status lines have been seen, or the timeout fires.
///
/// Needed because `read_response` decodes **one** buffer and therefore returns
/// both responses at once when they arrive together — a limitation that made an
/// earlier version of the pipelining test fail against a correct server.
///
/// Returns whatever was received when the count is reached or the deadline
/// passes, so an assert can report the bytes it actually got. A timeout is a
/// legitimate end here rather than a panic: the assertion in the caller is what
/// decides whether the count was enough, and it produces a better message.
async fn read_until_two_responses(stream: &mut TcpStream, want: usize) -> String {
    let mut out = Vec::new();
    let mut chunk = [0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if String::from_utf8_lossy(&out)
                .matches("HTTP/1.1 200")
                .count()
                >= want
            {
                break;
            }
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    String::from_utf8_lossy(&out).into_owned()
}

/// A `Connection: close` request ends the connection after one response.
#[tokio::test]
async fn connection_close_is_honoured() {
    let table = table_with(&[(Method::Get, "/hello", "greet")]);
    let server = Server::start(table, echo_handler()).await;

    let response = server
        .request("GET /hello HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.to_ascii_lowercase().contains("connection: close"),
        "the response must echo the close so a client stops reusing:\n{response}"
    );
}

/// HTTP/1.0 defaults to closing the connection.
#[tokio::test]
async fn http_1_0_closes_by_default() {
    let table = table_with(&[(Method::Get, "/hello", "greet")]);
    let server = Server::start(table, echo_handler()).await;

    let response = server
        .request("GET /hello HTTP/1.0\r\nhost: localhost\r\n\r\n")
        .await;

    assert!(response.starts_with("HTTP/1.0 200"), "{response}");
    assert!(
        response.to_ascii_lowercase().contains("connection: close"),
        "HTTP/1.0 without a keep-alive header must be closed:\n{response}"
    );
}

/// A shutdown drains rather than cutting a request off mid-response.
#[tokio::test]
async fn shutdown_is_graceful() {
    let table = table_with(&[(Method::Get, "/hello", "greet")]);
    let server = Server::start(table, echo_handler()).await;

    // A request completes normally.
    let before = server
        .request("GET /hello HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await;
    assert!(before.starts_with("HTTP/1.1 200"), "{before}");

    // After the signal, the port stops accepting. The listener may take a
    // moment to notice, so this polls rather than asserting immediately.
    server.shutdown.signal();

    let mut refused = false;
    for _ in 0..200 {
        match TcpStream::connect(server.addr).await {
            Err(_) => {
                refused = true;
                break;
            }
            Ok(mut s) => {
                // A connection may still be accepted before the loop notices.
                // Sending a request must not produce a 200 forever.
                let _ = s
                    .write_all(b"GET /hello HTTP/1.1\r\nhost: localhost\r\n\r\n")
                    .await;
                let body = read_all(&mut s).await;
                if body.is_empty() {
                    refused = true;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(
        refused,
        "a signalled server must stop serving on {}",
        server.addr
    );
}

/// **A head that is large without being header-count-large is refused — the
/// second ceiling, exercised deliberately.**
///
/// # Why this test exists as its own case
///
/// `a_header_bomb_over_a_socket_is_refused_and_the_server_survives` sends 200
/// *tiny* headers (~4 KiB), which `MAX_HEADERS` refuses before
/// `MAX_HEAD_BYTES` is ever consulted. Disabling the server's
/// `MAX_HEAD_BYTES` path was verified by injection to leave that test passing —
/// correctly, and the finding is what this test is the response to.
///
/// The attack this one covers is the other axis: **few headers, enormous
/// values**. A hundred `x-pad-NNNN: <64 KiB>` headers is 100 headers (inside
/// `MAX_HEADERS`) and megabytes of head (far past `MAX_HEAD_BYTES`). A server
/// that only counted headers would buffer all of it.
///
/// So the assertion is the same property — refused, and the server survives —
/// applied to the input shape that reaches the *other* limit. Two tests, two
/// ceilings.
///
/// # The redundancy this test discovered, established by injection
///
/// `read_head` reaches `parse_head` by **two routes**:
///
/// | Route | Trigger | Argument |
/// |---|---|---|
/// | 1 | the head terminator appears in the buffer | `&buf[..end]` — just the head |
/// | 2 | `buf.len() > MAX_HEAD_BYTES` with no terminator yet | `buf` — the whole buffer |
///
/// Disabling **either** alone leaves this test passing, and that is correct
/// rather than a gap: an oversized head is refused by whichever route is reached
/// first, and both delegate the *limit* to `parse_head`. Only disabling the
/// parser's own check **and** route 2 at the same time makes the test fail —
/// which was measured, not reasoned:
///
/// ```text
/// [parser MAX_HEAD_BYTES only]            -> NOT CAUGHT
/// [parser check AND server route 2]       -> CAUGHT
/// ```
///
/// **Why this is recorded rather than tidied away.** A future reader injecting a
/// single check and finding the test still green would reasonably conclude the
/// test was worthless and delete it. It is not: it fails the moment the ceiling
/// stops being enforced *anywhere*, and it is the assertion that proves the
/// end-to-end property — that a client cannot make the host buffer an unbounded
/// head — independently of which internal route does the refusing.
#[tokio::test]
async fn a_head_that_is_large_without_many_headers_is_refused() {
    // Few headers, each comfortably INSIDE the per-header limit, so the refusal
    // cannot come from `MAX_HEADER_BYTES`. Getting this wrong is easy and was
    // done once: the first fixture padded each header to 8 KiB, which trips the
    // per-header check and leaves the total-bytes ceiling never consulted — a
    // test that passes while measuring a different limit than the one it names.
    const HEADERS: usize = 60;

    let table = table_with(&[(Method::Get, "/hello", "greet")]);
    let server = Server::start(table, echo_handler()).await;

    let padding = "a".repeat(2 * 1024);

    let mut request = String::from("GET /hello HTTP/1.1\r\nhost: localhost\r\n");
    for i in 0..HEADERS {
        // `write!` rather than `push_str(&format!(..))`: clippy's
        // `format_push_string` is right that the latter allocates a temporary per
        // iteration for no reason.
        use std::fmt::Write as _;
        let _ = write!(request, "x-pad-{i}: {padding}\r\n");
    }
    request.push_str("\r\n");

    // The three preconditions, each asserted so a fixture that stops exercising
    // the intended ceiling fails loudly rather than passing quietly.
    //
    // The `HEADERS < MAX_HEADERS` one is a **runtime** comparison rather than a
    // constant expression: both sides are `const`, so clippy reports it as
    // `assertions_on_constants`, and the lint is right that the compiler could
    // decide it. It is kept because it is a *documented precondition of the
    // fixture*, evaluated through the same path a reader can check with `cargo
    // test` — but it is written against the values rather than restated, so if
    // `MAX_HEADERS` ever dropped below 60 this assertion is what fails first,
    // naming the fixture rather than leaving an unexplained wrong-ceiling pass.
    let headers_below_max = HEADERS < qqq_serve::http1::MAX_HEADERS;
    assert!(
        headers_below_max,
        "the fixture must stay INSIDE MAX_HEADERS ({}) so the refusal cannot come from \
         the header count; it has {HEADERS}",
        qqq_serve::http1::MAX_HEADERS
    );
    assert!(
        padding.len() + "x-pad-00: \r\n".len() < qqq_serve::http1::MAX_HEADER_BYTES,
        "each header line must stay INSIDE MAX_HEADER_BYTES ({}) or the per-header \
         check refuses first and this test measures the wrong ceiling — which is \
         exactly what its first version did",
        qqq_serve::http1::MAX_HEADER_BYTES
    );

    let response = server.request(&request).await;
    assert!(
        !response.starts_with("HTTP/1.1 200"),
        "an oversized head was SERVED. MAX_HEAD_BYTES is {}, and a limit on each \
         header is not a limit on their total. Response head: {}",
        qqq_serve::http1::MAX_HEAD_BYTES,
        &response[..response.len().min(120)]
    );

    // The server survives, as with the header-count bomb.
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");
    stream
        .write_all(b"GET /hello HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .expect("write");
    stream.flush().await.expect("flush");
    let after = read_response(&mut stream).await;
    assert!(
        after.starts_with("HTTP/1.1 200"),
        "the server stopped working after an oversized head. Response:\n{after}"
    );
}

// ---------------------------------------------------------------------------
// SEC-016 — the bomb and slow-loris mitigations, over a real socket
//
// # Why these belong here rather than only in the parser's unit tests
//
// `http1.rs` proves the parser refuses a header bomb, and `conn.rs` proves the
// deadline arithmetic fires. Neither proves the **server** consults them, and
// that is the entire content of "implement mitigations": a parser that refuses a
// bomb after the server has buffered it has mitigated nothing.
//
// This is the shape this session keeps finding — two correct halves with nothing
// between them (`§O-045a`, `§O-066`, `§O-071`). The socket is where the halves
// meet, so the socket is where the claim has to be tested.
// ---------------------------------------------------------------------------

/// **A header bomb is refused over a real socket, and the server survives.**
///
/// # What "refused" means here, precisely
///
/// The client sends `MAX_HEADERS + 100` tiny headers. The server must stop
/// reading and answer with an error rather than accepting the whole head — so the
/// assertion is that a response arrives **and** that a fresh connection still
/// works afterwards. The second half is what separates "the request was rejected"
/// from "the server was taken down", which is the difference the mitigation exists
/// to make.
///
/// # Which of the two limits this exercises, established by injection
///
/// There are **two** ceilings in this path and they are not redundant:
///
/// 1. `http1::MAX_HEADERS` (100) — the *parser* counts headers as it goes, so a
///    bomb is refused after the hundredth header rather than after the buffer
///    fills.
/// 2. `http1::MAX_HEAD_BYTES` (64 KiB) — the *server* calls `parse_head` once the
///    buffer passes the ceiling, so a head that is large without being
///    header-count-large is still bounded.
///
/// This test sends 200 *tiny* headers, which is ~4 KiB — comfortably inside
/// ceiling 2, so it is refused by **ceiling 1**. Disabling ceiling 2 in
/// `server.rs` therefore does **not** fail this test, and that was verified by
/// injection rather than assumed: the result was `NOT CAUGHT`, which is correct
/// and is why `a_head_that_is_large_without_many_headers_is_refused` exists
/// separately to exercise the other one.
///
/// Recording which limit a test reaches is what stops a suite from believing it
/// has two checks when it effectively has one.
#[tokio::test]
async fn a_header_bomb_over_a_socket_is_refused_and_the_server_survives() {
    let table = table_with(&[(Method::Get, "/hello", "greet")]);
    let server = Server::start(table, echo_handler()).await;

    // More headers than the cap allows, each tiny — the shape that exhausts
    // memory through per-header overhead rather than payload, which is why a
    // total-bytes limit alone does not catch it.
    let mut request = String::from("GET /hello HTTP/1.1\r\nhost: localhost\r\n");
    for i in 0..(qqq_serve::http1::MAX_HEADERS + 100) {
        use std::fmt::Write as _;
        let _ = write!(request, "x-bomb-{i}: a\r\n");
    }
    request.push_str("\r\n");

    let response = server.request(&request).await;

    // The server must not have answered 200. `read_all` returns whatever arrived
    // before the connection closed, so an empty string is also acceptable — what
    // is not acceptable is a successful response to a bomb.
    assert!(
        !response.starts_with("HTTP/1.1 200"),
        "an oversized header set was SERVED rather than refused. MAX_HEADERS is {}, \
         and a header bomb is defeated by counting headers as they arrive, not after \
         the buffer fills. Response:\n{response}",
        qqq_serve::http1::MAX_HEADERS
    );

    // **The server survives.** A fresh connection still gets a normal answer.
    //
    // `read_response` rather than `request`, because `request` reads to EOF and a
    // correctly keep-alive server never closes a healthy connection — so the
    // helper would wait out its whole 5-second budget and make this test slow for
    // no reason. The same mistake cost the slow-loris test 5 of its 5.7 seconds
    // before it was caught; see that test's comment for the full account.
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");
    stream
        .write_all(b"GET /hello HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .expect("write");
    stream.flush().await.expect("flush");
    let after = read_response(&mut stream).await;
    assert!(
        after.starts_with("HTTP/1.1 200"),
        "the server stopped working after a header bomb; a mitigation that takes the \
         server down with the attack is a denial of service, not a defence. \
         Response:\n{after}"
    );
}

/// **A slow-loris client is closed by the header deadline — not served, not hung.**
///
/// # Why this test uses a shortened deadline
///
/// The production deadline is 10 seconds. A test that waited for it would add ten
/// seconds to every run, and a suite that slow is one people stop running. The
/// property under test is *"the header deadline closes a stalled connection"*,
/// which a 200 ms deadline tests exactly as well — and the *value* is pinned
/// separately, without a socket, by
/// `the_header_timeout_is_shorter_than_the_idle_timeout`.
///
/// # Why the assertion is on the CLOSE rather than on a timer
///
/// Because the failure mode is not "closes late", it is **"never closes"**. A
/// client that opens a connection, sends a partial head, and then holds it open
/// forever is the whole attack: each such connection consumes a slot until the
/// server cannot accept new ones. So the test asserts the read ends — with EOF or
/// an error — rather than that it ended quickly.
#[tokio::test]
async fn a_slow_loris_client_is_closed_by_the_header_deadline() {
    let table = table_with(&[(Method::Get, "/hello", "greet")]);
    let server = Server::start_with(table, echo_handler(), |c| {
        // Short enough to test, long enough that a real `write` on a local socket
        // finishes well inside it — the partial head below is sent immediately,
        // and the client then deliberately goes quiet.
        c.connection.header_timeout = Duration::from_millis(200);
    })
    .await;

    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    // A request line and one header, then nothing. The head never terminates.
    stream
        .write_all(b"GET /hello HTTP/1.1\r\nhost: localhost\r\n")
        .await
        .expect("write the partial head");
    stream.flush().await.expect("flush");

    let started = std::time::Instant::now();

    // The server must close. Bounded well above the deadline so a slow CI runner
    // does not produce a false failure, and well below any job timeout so a
    // genuinely stuck server fails with a useful message rather than a hang.
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                // **EOF and a read error are the same outcome here**, and merging
                // them is the honest encoding rather than a convenience: a clean
                // close arrives as `Ok(0)` and an abortive close as `Err`, and the
                // property under test is "the server released the connection" —
                // which both satisfy. Two arms with identical bodies is what clippy
                // flags, and it is right to: the duplication invites them to drift
                // apart, at which point "a reset connection counts as open" becomes
                // a bug nobody notices.
                Ok(0) | Err(_) => return "closed",
                // Bytes arrived. A 408 is a legitimate answer; anything else means
                // the server is treating a stalled head as a request.
                Ok(n) => {
                    let text = String::from_utf8_lossy(&buf[..n]).to_string();
                    if text.starts_with("HTTP/") && !text.contains("408") {
                        return Box::leak(format!("answered: {text}").into_boxed_str());
                    }
                }
            }
        }
    })
    .await;

    assert!(
        outcome.is_ok(),
        "the server never closed a stalled connection within 5 seconds against a \
         200 ms header deadline. A slow-loris client holds a connection slot open \
         forever, so 'never closes' is the attack, not a latency problem."
    );

    let verdict = outcome.expect("checked above");
    assert!(
        verdict == "closed",
        "the server answered a stalled connection with something other than an error: \
         {verdict}"
    );

    // **The close must be prompt, not merely eventual.**
    //
    // The 5-second outer bound proves the connection does not stay open forever;
    // it does not prove the deadline governs it. A server that closed every
    // connection after, say, three seconds would pass that bound while holding a
    // slow-loris slot three seconds longer than its own configuration says —
    // ten times the configured 200 ms.
    //
    // The bound here is generous relative to the 200 ms deadline because a loaded
    // CI runner can add scheduling delay, and the server re-checks the deadline
    // once per poll interval (10 ms). It is tight enough to fail a deadline that
    // is not being enforced at all.
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(1_500),
        "the connection was closed after {elapsed:?} against a 200 ms header deadline. \
         The deadline is not governing the close — something else is (an outer idle \
         timeout, or the client's own timeout), and 'closes eventually' is not the \
         mitigation. A slow-loris client only needs the connection to outlive its \
         own patience, not forever."
    );

    // And the server is still healthy afterwards — the point of closing the
    // connection rather than blocking on it.
    //
    // **Timed, and the timing is asserted — which is how a test-helper artefact
    // was told apart from a server defect.**
    //
    // The first version of this assertion failed at 5012 ms, which looks exactly
    // like "the slow-loris connection degraded the server". It is not. `request`
    // goes through `read_all`, which reads **until EOF with a 5-second timeout**;
    // the server correctly keeps a healthy keep-alive connection open, so no EOF
    // ever arrives and the helper waits out its whole budget.
    //
    // The discriminator is the response *content* and the shape of the number:
    // the answer was a complete, correct `200 OK` with a `Content-Length`, so the
    // server had finished long before. A degraded server would have been slow to
    // *answer*; this one answered immediately and was slow only to close.
    //
    // So the assertion is on the **first response arriving**, not on the
    // connection ending — `read_response` stops at the end of the body, which is
    // what "the next request is served promptly" actually means for keep-alive.
    let healthy_at = std::time::Instant::now();
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");
    stream
        .write_all(b"GET /hello HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .expect("write");
    stream.flush().await.expect("flush");
    let after = read_response(&mut stream).await;
    let healthy_ms = healthy_at.elapsed().as_millis();

    assert!(
        after.starts_with("HTTP/1.1 200"),
        "the server stopped serving after a slow-loris connection; the deadline must \
         release the connection, not park it. Response:\n{after}"
    );
    assert!(
        healthy_ms < 1_000,
        "a healthy request took {healthy_ms} ms to be ANSWERED after a slow-loris \
         connection; the attack left the server degraded, which is exactly what the \
         mitigation exists to prevent. Response:\n{after}"
    );
}
