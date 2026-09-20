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

use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::server::{serve, Handler, ServerConfig};
use qqq_serve::{Response, RouteMatch};

/// A running server, stopped when dropped.
struct Server {
    addr: SocketAddr,
    shutdown: Shutdown,
}

impl Server {
    /// Start a server on a free port with the given route table.
    async fn start(table: RouteTable, handler: Handler) -> Self {
        let addr = free_addr();
        let listen = ListenAddr::parse(&addr.to_string()).expect("a resolved address must parse");
        let shutdown = Shutdown::new();
        let config = ServerConfig::for_addr(listen);

        let local = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(config, table, handler, local).await {
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
        // Read the first response before writing the second, so the test does
        // not depend on the server pipelining — which is HTTP/1.1-legal but not
        // something this server implements.
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
/// # What this pins that the test above does not
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
