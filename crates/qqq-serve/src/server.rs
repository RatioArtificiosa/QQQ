//! The accept loop: joining the socket layer to the connection state machine.
//!
//! Implements `SRV-001` (HTTP/1.1 with keep-alive, timeouts and connection
//! limits); Proposal §6.4, §4.4.
//!
//! # What existed before this module, and what did not
//!
//! Every piece of the request path was already built and individually tested:
//!
//! | Piece | Module |
//! |---|---|
//! | route table (radix trie) | `route` |
//! | head parser, header limits | `http1` |
//! | response writer, error mapping | `response` |
//! | connection lifetime, keep-alive, drain | `conn` |
//! | listener, shards, shutdown | `qqq-io` |
//!
//! Nothing joined them. That is worth stating plainly, because "the pieces
//! exist" reads like progress and is not: a router with no socket is a data
//! structure, and a parser with no loop is a function. This module is the loop.
//!
//! # The loop, and why it is structured this way
//!
//! ```text
//! accept ──> admit (per-tenant ceiling) ──┐
//!                                         v
//!              read head ──> parse ──> route ──> respond
//!                    │                    │
//!                    └── timeout/limit ───┘
//! ```
//!
//! Three decisions shape it:
//!
//! 1. **Timeouts are enforced by the connection state machine**, not by
//!    `tokio::time::timeout` around a read. `Connection::poll(now)` already
//!    knows the idle and header deadlines, and wrapping reads as well would
//!    give two authorities on one answer — they would disagree eventually, and
//!    the disagreement would be a connection that hangs.
//! 2. **The ledger is checked before the first byte is read.** A tenant at its
//!    ceiling is closed rather than served-then-rejected, because reading a
//!    request the server will not answer spends the attacker's cost on the
//!    defender.
//! 3. **A handler that traps closes the connection**, rather than keeping it
//!    alive. The connection state machine decides that through
//!    `server_wants_close`, so the policy lives in one place.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use qqq_core::{Error, ErrorCode, Result};
use qqq_io::listener::{AcceptError, ListenAddr, Listener, ListenerConfig, Shutdown};

use crate::conn::{Action, CloseReason, Connection, ConnectionConfig, ConnectionLedger};
use crate::http1::{self, ParseError, RequestHead, Version};
use crate::response::{self, Response};
use crate::route::RouteTable;

/// How the server behaves.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Where to listen.
    pub addr: ListenAddr,
    /// Connection lifetime rules.
    pub connection: ConnectionConfig,
    /// Per-tenant connection ceiling.
    pub connections_per_tenant: u32,
    /// Shards to bind.
    ///
    /// `None` uses the shard count `qqq-io` derives from the machine. An
    /// explicit value is for testing and for deployments that have measured a
    /// different number.
    pub shards: Option<usize>,
}

impl ServerConfig {
    /// A configuration for an address, with the documented defaults.
    #[must_use]
    pub fn for_addr(addr: ListenAddr) -> Self {
        Self {
            addr,
            connection: ConnectionConfig::default(),
            connections_per_tenant: 10_000,
            shards: None,
        }
    }
}

/// What a handler returns.
///
/// A handler is a **pure function of the request** in V1: it receives the parsed
/// head and produces a response. It does not touch the socket, which keeps the
/// routing and encoding testable without a listener and means a handler cannot
/// hold a connection open by accident.
pub type Handler = Arc<dyn Fn(&RequestHead, &RouteMatch) -> Response + Send + Sync>;

/// The route decision a handler is given.
///
/// Carries the matched handler name and the captured parameters, so a handler
/// does not re-parse the target — the router already did, and doing it twice is
/// how the two disagree about a path with an encoded separator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMatch {
    /// The handler name from the matched route.
    pub handler: String,
    /// The pattern that matched.
    pub pattern: String,
    /// Captured parameters, in pattern order.
    pub params: Vec<(String, String)>,
}

/// The outcomes a single connection can end with, for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// The client closed cleanly between requests.
    ClientClosed,
    /// The connection reached its request ceiling.
    RequestLimit,
    /// The connection was idle past its deadline.
    IdleTimeout,
    /// The client sent no complete head within its deadline.
    HeaderTimeout,
    /// A parse error ended the connection.
    BadRequest,
    /// The server is draining and closed it.
    Drained,
    /// The handler asked to close.
    HandlerClosed,
}

/// Serve requests on an address until shutdown.
///
/// # Errors
///
/// * `QQQ-6002` — the listener could not bind. The error names the address and
///   the OS error, because "could not bind" without the address sends an
///   operator to the wrong config file.
/// * `QQQ-6004` — an internal invariant. Always a bug in QQQ.
pub async fn serve(
    config: ServerConfig,
    table: RouteTable,
    handler: Handler,
    shutdown: Shutdown,
) -> Result<()> {
    let listener_config = ListenerConfig::for_addr(config.addr.clone());
    let listener = Listener::bind(listener_config).await.map_err(|e| {
        Error::new(
            ErrorCode::ListenerBindFailed,
            format!("could not bind `{}`", config.addr.render()),
        )
        .with_cause(e.to_string())
        .with_remediation(
            "check the address is free and the port is above 1024, or that the \
             process may bind it",
        )
    })?;

    let table = Arc::new(table);
    let ledger = Arc::new(tokio::sync::Mutex::new(ConnectionLedger::new(
        config.connections_per_tenant,
    )));
    // Wrapped in an `Arc` so each connection task shares one immutable config
    // rather than cloning it per connection. `ConnectionConfig` is four small
    // fields, so this is not about size — it is about the closure being `FnMut`
    // and therefore unable to move a captured value out on each call.
    let connection_config = Arc::new(config.connection.clone());

    // A clone for the closure, so the acceptor's own borrow of `shutdown` is a
    // different value from the one each connection task carries. Sharing one
    // would mean the tasks and the acceptor contend on the same borrow, which
    // the compiler refuses — correctly, because it would be a clone of a
    // handle whose lifetime the tasks outlive.
    let task_shutdown = shutdown.clone();

    // The accept loop hands each connection to a task. `accept_stream` takes a
    // synchronous callback, so the spawn happens here rather than inside it —
    // and the callback must not block, because it runs on the acceptor.
    let result = listener
        .accept_stream(&shutdown, move |stream, peer| {
            let table = Arc::clone(&table);
            let handler = Arc::clone(&handler);
            let ledger = Arc::clone(&ledger);
            let connection_config = Arc::clone(&connection_config);
            let local_shutdown = task_shutdown.clone();

            tokio::spawn(async move {
                let tenant = tenant_of(peer);
                {
                    let mut l = ledger.lock().await;
                    if !l.admit(&tenant) {
                        // Refused before reading a byte. Reading a request the
                        // server will not answer spends the attacker's cost on
                        // the defender, which is the wrong way round.
                        drop(l);
                        let _ = close_immediately(stream, 503).await;
                        return;
                    }
                }

                let served = serve_connection(
                    stream,
                    &table,
                    &handler,
                    // Dereferenced from the `Arc`: the function borrows the
                    // config, and passing the `Arc` would force it to know about
                    // how the caller shares it.
                    connection_config.as_ref(),
                    &local_shutdown,
                )
                .await;

                let mut l = ledger.lock().await;
                l.release(&tenant);
                let _ = served;
            });
        })
        .await;

    result.map_err(|e: AcceptError| {
        Error::new(
            ErrorCode::ListenerBindFailed,
            "the accept loop stopped with an error",
        )
        .with_cause(e.to_string())
    })
}

/// The tenant a peer address belongs to.
///
/// The peer's IP, because there is no authentication at this layer. Named as a
/// function rather than inlined so that when `default_auth` arrives (`SRV-008`),
/// the change is here and every caller inherits it.
fn tenant_of(peer: SocketAddr) -> String {
    peer.ip().to_string()
}

/// Serve one connection until it closes, for any reason.
///
/// The config is taken by reference and cloned into the `Connection`, which owns
/// it: the shared `Arc` cannot be moved into a value that outlives the borrow,
/// and `ConnectionConfig` is four small fields, so the clone costs less than the
/// indirection that would avoid it.
async fn serve_connection(
    mut stream: TcpStream,
    table: &RouteTable,
    handler: &Handler,
    config: &ConnectionConfig,
    shutdown: &Shutdown,
) -> Served {
    let mut conn = Connection::new(config.clone());
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);

    loop {
        // --- Which action does the state machine want? ---------------------
        //
        // **This is the only authority on the deadlines.** `poll` decides
        // whether the connection is idle, past its header deadline, at its
        // request ceiling or draining — and it is re-evaluated every iteration
        // and on every read timeout inside `read_head`.
        //
        // An earlier draft threaded a `last_activity` instant into `read_head`
        // as well, which made the read loop a *second* authority on the idle
        // deadline. The compiler reported the duplication as an unused
        // assignment, which is the correct diagnosis: two places deciding the
        // same thing is how a connection ends up held past its deadline by one
        // and closed early by the other.
        let now = Instant::now();
        match conn.poll(now) {
            Action::Close(reason) => return outcome_of(reason),
            // `WriteResponse` here means the previous iteration wrote and the
            // machine is ready for the next read; both it and `ReadRequest` lead
            // to reading, and the distinction matters only to a caller that
            // interleaves other work between them.
            Action::ReadRequest | Action::WriteResponse => {}
        }

        if shutdown.is_signalled() {
            // Begin a graceful drain and stop reading. The in-flight request
            // above has already been answered, so a client is not cut off
            // mid-response.
            conn.begin_drain(Instant::now());
            if let Action::Close(reason) = conn.poll(Instant::now()) {
                return outcome_of(reason);
            }
        }

        conn.begin_request(now);

        // --- Read a complete head -----------------------------------------
        let head = match read_head(&mut stream, &mut buf, config).await {
            Ok(h) => h,
            Err(ReadOutcome::ClientClosed) => return Served::ClientClosed,
            Err(ReadOutcome::HeaderTimeout) => return Served::HeaderTimeout,
            Err(ReadOutcome::BadRequest(err)) => {
                conn.on_parse_error(&err);
                // `parse_error_response`, not `error_response`: a malformed
                // request has no truthful `ErrorCode`, and routing it through
                // `ParseError::to_error` produced `ManifestSchemaViolation` and
                // a **500** for a client's bad request line. The taxonomy had no
                // client-error class at all until this test found that.
                let body = response::write_response(
                    &response::from_error(&response::parse_error_response(&err.to_string())),
                    Version::Http11,
                    false,
                );
                let _ = stream.write_all(&body).await;
                let _ = stream.flush().await;
                return Served::BadRequest;
            }
        };

        // --- Route and respond --------------------------------------------
        //
        // The idle clock starts **after** the head is read, not before it: the
        // time spent waiting for a client to send a request is what the idle
        // deadline measures, and the time spent parsing and answering is not.
        // Starting it earlier would cut off a slow-but-progressing client for
        // the server's own think time.
        let (path, _query) = split_target(&head.target);
        let client_wants_keep_alive = wants_keep_alive(&head);
        conn.on_request_parsed(client_wants_keep_alive);

        let response = if let Some(m) = table.match_route(head.method, path) {
            handler(
                &head,
                &RouteMatch {
                    handler: m.handler.clone(),
                    pattern: m.pattern.clone(),
                    params: m
                        .params
                        .iter()
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect(),
                },
            )
        } else {
            // A path with no route but a known method set gets a 405 with the
            // allowance, which is what a client needs to recover; a genuinely
            // unknown path gets 404.
            let allowed = table.allows(path);
            if allowed.is_empty() {
                response::not_found()
            } else {
                response::method_not_allowed(&allowed)
            }
        };

        // Whether the connection may be reused is the **state machine's**
        // decision, and the question to ask it is `will_keep_alive`, not
        // `is_open`.
        //
        // `is_open` answers "has this connection been closed?" — `true` for the
        // whole of a request that is about to be the last one. Using it here
        // advertised `Connection: keep-alive` on the very response that closed
        // the connection, which is how an HTTP/1.0 request came back with
        // keep-alive after a correct encoder and a correct state machine.
        //
        // The response carries no opinion of its own: a `keep_alive` flag on
        // `Response` would be a second authority on the same answer, and the two
        // would eventually disagree in exactly this way.
        let keep_alive = conn.will_keep_alive(false);
        let bytes = response::write_response(&response, head.version, keep_alive);
        if stream.write_all(&bytes).await.is_err() || stream.flush().await.is_err() {
            // A write failure is the client's problem, not the server's: it
            // disconnected before reading the response.
            return Served::ClientClosed;
        }

        conn.on_response_sent(Instant::now(), !keep_alive);
        if !keep_alive {
            // Half-close rather than dropping the socket, so the FIN follows the
            // response instead of a RST discarding data the client has not read.
            let _ = stream.shutdown().await;
            return Served::HandlerClosed;
        }

        // Consume the body if there is one, so the next request on this
        // connection starts at the right offset. A keep-alive connection that
        // skipped the body would parse the body as a request line.
        if !drain_body(&mut stream, &mut buf, &head).await {
            return Served::ClientClosed;
        }
    }
}

/// Why a head read stopped.
///
/// There is deliberately **no `IdleTimeout` variant**. An idle connection is
/// closed by `Connection::poll` before this function is entered, so a variant
/// for it here would be unreachable — and an unreachable variant is how a second
/// authority on the idle deadline would start: someone constructs it, the two
/// checks disagree, and a connection is held past its deadline by one path while
/// the other closes it early.
///
/// The compiler reported it as a dead variant, which is the correct diagnosis.
enum ReadOutcome {
    /// The client closed between requests, which is normal for HTTP/1.0.
    ClientClosed,
    /// Bytes arrived but the head did not complete within its deadline.
    ///
    /// Kept here rather than in `Connection` because it is a property of the
    /// *read* rather than of the connection: the state machine does not know how
    /// many bytes have arrived.
    HeaderTimeout,
    /// The request was malformed.
    BadRequest(ParseError),
}

/// How long to sleep between timeout checks while waiting for bytes.
///
/// A poll interval rather than a `select!` on a timer, because the deadlines
/// live in `Connection` and this must not become a second authority on them.
/// 10 ms is well below the smallest documented deadline (10 s) and costs one
/// wakeup per idle connection per interval.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Read until a complete request head is available.
///
/// # Why the read is incremental
///
/// A single `read` may return any prefix: half a request line, a header split
/// across two TCP segments, or everything plus the start of the body. The parser
/// is asked only once `head_end` finds the terminator, so `parse_head` never has
/// to handle a truncated buffer — and it is the parser that owns the decision
/// about what a complete head is, so the check lives in one place.
///
/// # Why this does **not** clear the buffer on entry
///
/// It did, and that was a real defect — caught by
/// `tests/socket.rs::a_body_is_drained_so_the_next_request_parses`, which is the
/// only test that sends a second request behind a body.
///
/// The parser keeps the bytes after the head, because they are the start of the
/// body and the kernel has already delivered them (`buf.drain(..end)` below).
/// `buf` is owned by the connection loop and outlives one call to this function,
/// so a `buf.clear()` here threw that retained prefix away — **making the
/// preservation above pointless.** `drain_body` then read the body from the
/// *socket*, but those bytes were no longer there: they had been consumed by the
/// first `read` into `buf` and then discarded. The connection was left five
/// bytes ahead of where it believed it was, so the next request line began
/// mid-body and parsed as `400 Bad Request`.
///
/// The failure is worth the paragraph because of where it hid: every unit test
/// passed, the first request on the connection was answered correctly, and the
/// damage appeared only on the second request — one layer away from the code
/// that caused it. Two individually correct halves, the preserve and the drain,
/// disagreed about **who owns the buffered bytes**, which is `§O-045a`'s shape
/// again.
///
/// The buffer is now cleared exactly once, by `drain_body`, at the point where
/// its remaining contents are genuinely consumed. That is the only place that
/// knows how many bytes the body still owes.
async fn read_head(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    config: &ConnectionConfig,
) -> std::result::Result<RequestHead, ReadOutcome> {
    let mut header_started: Option<Instant> = None;

    loop {
        if let Some(end) = http1::head_end(buf) {
            return match http1::parse_head(&buf[..end]) {
                Ok((head, _consumed)) => {
                    // Keep the remainder: it is the start of the body and must
                    // not be discarded, or the next read would re-fetch bytes
                    // the kernel has already delivered.
                    buf.drain(..end);
                    Ok(head)
                }
                Err(e) => Err(ReadOutcome::BadRequest(e)),
            };
        }

        // Two deadlines, and they measure different failures — but only one of
        // them is checked here.
        //
        //   * Past `idle_timeout` with nothing read — decided by
        //     `Connection::poll`, which the caller runs before entering this
        //     function and this loop runs again on each poll tick. Not
        //     re-checked here, because a second authority on the same deadline
        //     is how one path holds a connection past it while the other closes
        //     early.
        //   * Past `header_timeout` with bytes read — a client mid-request that
        //     stalled. `Connection` does not model this, because it is a
        //     property of the *read* rather than of the connection, so the
        //     deadline is kept here.
        if let Some(started) = header_started {
            if Instant::now().duration_since(started) >= config.header_timeout {
                return Err(ReadOutcome::HeaderTimeout);
            }
        }

        let mut chunk = [0u8; 8192];
        let read = tokio::select! {
            biased;
            // The poll interval lets the deadlines above be re-checked while a
            // read is pending. It is far below the smallest documented timeout,
            // so it costs one wakeup per idle connection per interval and never
            // fires early enough to matter.
            () = tokio::time::sleep(POLL_INTERVAL) => continue,
            r = stream.read(&mut chunk) => r,
        };

        match read {
            // A zero-length read and a read error both mean the peer is gone.
            // Merged rather than kept apart because the handling is identical,
            // and two arms that must stay in step are two places to forget.
            Ok(0) | Err(_) => return Err(ReadOutcome::ClientClosed),
            Ok(n) => {
                header_started.get_or_insert(Instant::now());
                buf.extend_from_slice(&chunk[..n]);
                // The head ceiling is enforced by the *parser*, not here: it is
                // the parser that knows the limit and that a body may legally
                // exceed it. Duplicating the check would give two limits, and a
                // smuggled request is what the gap between two limits looks
                // like.
                if buf.len() > http1::MAX_HEAD_BYTES + 1 {
                    return match http1::parse_head(buf) {
                        Ok((head, _)) => Ok(head),
                        Err(e) => Err(ReadOutcome::BadRequest(e)),
                    };
                }
            }
        }
    }
}

/// Consume a declared body so the next request parses from the right offset.
///
/// Returns `false` when the body could not be consumed, which means the
/// connection cannot be reused.
///
/// # Why this takes `buf`
///
/// The body may be **partly or wholly already in the buffer**: `read_head` stops
/// at the head terminator and keeps whatever followed it, and a client that
/// wrote a small request in one segment delivers head and body together. Reading
/// only from the socket would therefore skip those bytes and leave the
/// connection advanced past the body by exactly the amount already buffered —
/// the desync that produced a 400 on the second request.
///
/// So the buffered remainder is consumed **first**, and the socket is read only
/// for what is still owed. At the end the buffer is empty: whatever it held was
/// either body (consumed here) or, on a body-less request, nothing.
///
/// # Why a chunked body ends the connection
///
/// De-chunking is `SRV-004`'s job and is not built. Reading-and-discarding a
/// chunked body without decoding it would leave the connection at an offset only
/// the decoder knows, so the honest choice is to close. A keep-alive connection
/// whose framing is wrong turns one bad request into a stream of misparsed ones,
/// which is a request-smuggling shape.
async fn drain_body(stream: &mut TcpStream, buf: &mut Vec<u8>, head: &RequestHead) -> bool {
    /// Drop `n` bytes of buffered body, if any are buffered.
    ///
    /// Returns how many were taken, so the caller's count of what is still owed
    /// stays honest rather than assuming the buffer was non-empty.
    fn take_buffered(buf: &mut Vec<u8>, n: u64) -> u64 {
        let available = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        let taken = n.min(available);
        let taken_usize = usize::try_from(taken).unwrap_or(buf.len());
        buf.drain(..taken_usize);
        taken
    }

    if head.chunked {
        return false;
    }
    let Some(len) = head.content_length else {
        // No body is declared, so anything buffered is the start of the **next**
        // request — a pipelined one. It must be preserved, not cleared, or a
        // client that pipelines loses its second request.
        return true;
    };
    if len == 0 {
        return true;
    }

    // Whatever the head read already pulled in is body, and it is consumed here
    // rather than refetched from a socket that no longer holds it.
    let mut remaining = len - take_buffered(buf, len);
    if remaining == 0 {
        return true;
    }

    // The parser already refused a body over `MAX_REQUEST_BYTES`, so this
    // cannot read unbounded bytes — the bound is enforced where the length is
    // parsed rather than twice.
    let mut sink = [0u8; 8192];
    while remaining > 0 {
        let want = usize::try_from(remaining.min(sink.len() as u64)).unwrap_or(sink.len());
        match stream.read(&mut sink[..want]).await {
            // The peer closed mid-body, or the read failed. Either way the
            // connection cannot be reused: the framing offset is unknown.
            Ok(0) | Err(_) => return false,
            Ok(n) => remaining -= u64::try_from(n).unwrap_or(remaining),
        }
    }
    true
}

/// Split a request target into path and query.
///
/// The query is returned but unused today: routing matches on the path, and a
/// handler that wants the query reads it from `RequestHead::target`. Splitting
/// here rather than in the router keeps the router's contract — "match a path" —
/// honest, since a route pattern never contains a query.
fn split_target(target: &str) -> (&str, Option<&str>) {
    match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    }
}

/// Whether the client asked to keep the connection open.
///
/// HTTP/1.1 defaults to keep-alive; HTTP/1.0 does not. Getting this backwards
/// either closes every connection after one request — making HTTP/1.1 slower
/// than 1.0 — or keeps a 1.0 connection alive that the client will not reuse,
/// holding a slot until the idle timeout.
fn wants_keep_alive(head: &RequestHead) -> bool {
    let connection_header = head
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .map(|(_, value)| value.to_ascii_lowercase());

    match connection_header.as_deref() {
        Some(v) if v.contains("close") => false,
        Some(v) if v.contains("keep-alive") => true,
        // No header: the version decides.
        _ => head.version == Version::Http11,
    }
}

/// Close a connection immediately with a status and no body.
///
/// Used when the ledger refuses a connection: sending a full error response
/// would spend more of the server's budget on a peer that is already over it.
async fn close_immediately(mut stream: TcpStream, status: u16) -> std::io::Result<()> {
    let text = format!(
        "HTTP/1.1 {status} {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        if status == 503 {
            "Service Unavailable"
        } else {
            "Error"
        }
    );
    stream.write_all(text.as_bytes()).await?;
    stream.flush().await
}

/// Map a close reason to the reported outcome.
///
/// `ClientRequested` and `ServerRequested` collapse to `ClientClosed` and
/// `HandlerClosed`, because who *asked* is not what an operator needs — what
/// they need is whether the server chose to close or the peer did.
const fn outcome_of(reason: CloseReason) -> Served {
    match reason {
        CloseReason::IdleTimeout => Served::IdleTimeout,
        CloseReason::HeaderTimeout => Served::HeaderTimeout,
        CloseReason::RequestLimit => Served::RequestLimit,
        // A protocol error and a drain deadline both end in a closed
        // connection; they are reported as the bad request and the drain they
        // were, rather than as "something closed".
        CloseReason::ProtocolError => Served::BadRequest,
        CloseReason::DrainDeadline | CloseReason::ShutdownIdle => Served::Drained,
        CloseReason::ClientRequested => Served::ClientClosed,
        CloseReason::ServerRequested => Served::HandlerClosed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::Method;

    fn head(version: Version, headers: &[(&str, &str)]) -> RequestHead {
        RequestHead {
            method: Method::Get,
            target: "/".to_owned(),
            version,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            content_length: None,
            chunked: false,
        }
    }

    /// HTTP/1.1 keeps alive by default; HTTP/1.0 does not.
    ///
    /// Getting this backwards either closes every 1.1 connection after one
    /// request, or holds a 1.0 connection open that the client will never reuse.
    #[test]
    fn the_version_decides_keep_alive_when_no_header_is_present() {
        assert!(wants_keep_alive(&head(Version::Http11, &[])));
        assert!(
            !wants_keep_alive(&head(Version::Http10, &[])),
            "HTTP/1.0 defaults to close"
        );
    }

    /// An explicit `Connection` header overrides the version, both ways.
    #[test]
    fn an_explicit_connection_header_overrides_the_version() {
        assert!(!wants_keep_alive(&head(
            Version::Http11,
            &[("Connection", "close")]
        )));
        assert!(wants_keep_alive(&head(
            Version::Http10,
            &[("Connection", "keep-alive")]
        )));
    }

    /// The header name and value are matched case-insensitively.
    ///
    /// A client sending `CONNECTION: Close` is stating the same thing, and a
    /// case-sensitive match would keep the connection alive against its wish.
    #[test]
    fn connection_header_matching_is_case_insensitive() {
        assert!(!wants_keep_alive(&head(
            Version::Http11,
            &[("CONNECTION", "Close")]
        )));
        assert!(wants_keep_alive(&head(
            Version::Http10,
            &[("connection", "Keep-Alive")]
        )));
    }

    #[test]
    fn a_target_splits_into_path_and_query() {
        assert_eq!(split_target("/a/b"), ("/a/b", None));
        assert_eq!(split_target("/a/b?x=1"), ("/a/b", Some("x=1")));
        // An empty query is present, not absent. `/a?` and `/a` differ, and
        // collapsing them loses what the client actually sent.
        assert_eq!(split_target("/a?"), ("/a", Some("")));
    }

    #[test]
    fn a_target_with_no_leading_slash_is_returned_as_is() {
        // Not a valid origin-form target, and normalising it here would hide
        // that from the parser that should reject it.
        assert_eq!(split_target("a/b"), ("a/b", None));
    }

    #[test]
    fn a_tenant_is_the_peer_ip() {
        let peer: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        assert_eq!(tenant_of(peer), "203.0.113.7");
    }
}
