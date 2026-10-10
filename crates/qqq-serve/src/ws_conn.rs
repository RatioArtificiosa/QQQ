// SPDX-License-Identifier: Apache-2.0

//! A live WebSocket connection: the loop between the handshake and the guest.
//!
//! This is what closes `SRV-009`. The three layers below it — the handshake
//! ([`crate::ws`]), the frame codec ([`crate::ws_frame`]) and message assembly
//! ([`crate::ws_message`]) — were each complete and tested, and **none was reachable**
//! from `serve`. This module is the wiring.
//!
//! # What the loop does, and the two things it must never do
//!
//! It reads frames, assembles messages, hands them to the guest, and writes what the
//! guest sends back. Two rules from RFC 6455 are the loop's responsibility rather than
//! either codec's, because both need the *conversation*:
//!
//! 1. **A `Ping` must be answered with a `Pong` carrying the same payload** (§5.5.3). The
//!    frame codec sees the ping and has nowhere to send the answer. A connection that
//!    silently ignored pings is disconnected by every intermediary that uses them as a
//!    liveness probe — and the failure looks like "the connection drops after 60
//!    seconds", with nothing in the logs.
//!
//! 2. **A `Close` must be echoed before the connection is torn down** (§5.5.1). A server
//!    that closes the TCP connection without echoing leaves the client unable to
//!    distinguish a clean close from a network fault, and a client that cannot tell will
//!    *reconnect* — turning a deliberate shutdown into a reconnect storm.
//!
//! 3. **A close the peer cannot read is a silent close.** Every refusal and the
//!    close echo drain the peer first (see `refuse_with`): tearing down a socket
//!    that still holds unread peer bytes sends RST, and on some stacks an RST
//!    discards even bytes already buffered at the peer — so the close frame
//!    never arrives and a refusal the server meant to explain looks like a
//!    network fault. (The shutdown and idle paths in `run_frames` use
//!    `close_with` without a drain: there the server is ending the connection
//!    on its own behalf rather than answering the peer, so no explanation is
//!    owed one.)
//!
//! # Why the read side and the write side are separate tasks
//!
//! Because a WebSocket is full-duplex: a guest that is computing may still need to answer
//! a ping, and a guest that is idle must still see an incoming message. A single
//! `select!` over both directions is the smallest correct shape, and it is what this does
//! rather than two independent loops that would each need their own half of the socket.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::access_log::{Level, Logger, Record, TraceId};
use crate::http1::{RequestHead, Version};
use qqq_io::listener::Shutdown;

use crate::ws::{self, Handshake};
use crate::ws_frame::{self, Frame, Opcode};
use crate::ws_message::{Assembler, Message, Progress};

/// The largest number of bytes the read buffer will hold before compaction.
///
/// Frames are decoded from a growable buffer, and a peer that sends a large frame in small
/// pieces grows it. Compacted after each consumed frame so a long-lived connection does
/// not hold the high-water mark of its largest message forever.
const READ_BUFFER: usize = 16 * 1024;

/// What a WebSocket connection ended as, for the access log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsOutcome {
    /// The client sent a close and the server echoed it.
    Closed,
    /// The client disconnected without a close frame.
    ClientGone,
    /// The peer violated the protocol; the server closed with a code.
    ProtocolError,
    /// The guest's handler returned.
    HandlerDone,
}

impl WsOutcome {
    /// The access-log level.
    ///
    /// `Closed` and `ClientGone` are `Info`: a WebSocket ending is the normal outcome, and
    /// logging it as a failure would make the failure count useless. Only a protocol
    /// violation is `Error`.
    #[must_use]
    pub const fn level(self) -> Level {
        match self {
            Self::ProtocolError => Level::Error,
            _ => Level::Info,
        }
    }

    /// The name recorded in the log.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::ClientGone => "client_gone",
            Self::ProtocolError => "protocol_error",
            Self::HandlerDone => "handler_done",
        }
    }
}

/// What a guest handler is given for each message, and what it may send back.
///
/// A trait rather than a closure because a handler needs to *send* while receiving, and a
/// `Fn(&Message) -> Vec<Message>` cannot express that: a chat server broadcasts to other
/// connections, which is a send to a socket this handler does not own.
pub trait WebSocketHandler: Send + Sync {
    /// Handle one message from the client.
    ///
    /// `send` writes to this connection. It is `async` and takes `&mut` because two
    /// sends must not interleave their frames — a frame written in two pieces by two
    /// tasks is the one way to corrupt the stream that no codec can prevent.
    fn on_message<'a>(
        &'a self,
        message: &'a Message,
        send: &'a mut WsSender<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;

    /// Called once when the connection closes.
    ///
    /// Not given a sender: the socket is going away, and a handler that could write here
    /// would be writing frames after the close echo.
    fn on_close(&self, _outcome: WsOutcome) {}
}

/// A handler that echoes every message, for tests and for `qqqai dev`.
///
/// Provided rather than left to callers because it is the smallest thing that proves the
/// whole path works, and because an echo server is what a developer reaches for first.
pub struct Echo;

impl WebSocketHandler for Echo {
    fn on_message<'a>(
        &'a self,
        message: &'a Message,
        send: &'a mut WsSender<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            send.send(message.kind, &message.payload).await;
        })
    }
}

/// The write half, handed to handlers.
///
/// # Why `&mut` and not `&`
///
/// Two concurrent `send` calls could interleave their frames — one writing a header and
/// another its payload — and that is the one corruption no codec can detect, because the
/// resulting bytes are individually well-formed. The borrow makes it impossible rather
/// than documented.
pub struct WsSender<'a> {
    stream: &'a mut TcpStream,
}

impl WsSender<'_> {
    /// Send one message.
    pub async fn send(&mut self, kind: Opcode, payload: &[u8]) {
        let frame = Frame {
            opcode: kind,
            fin: true,
            payload: payload.to_vec(),
        };
        let _ = self.stream.write_all(&ws_frame::encode(&frame)).await;
        let _ = self.stream.flush().await;
    }

    /// Send a text message.
    pub async fn send_text(&mut self, text: &str) {
        self.send(Opcode::Text, text.as_bytes()).await;
    }

    /// Send a binary message.
    pub async fn send_binary(&mut self, bytes: &[u8]) {
        self.send(Opcode::Binary, bytes).await;
    }

    /// Send one frame, without framing it as a message.
    ///
    /// Public because a handler may need to fragment deliberately, and because a test
    /// needs to send a malformed frame to prove the loop refuses it.
    pub async fn send_frame(&mut self, frame: &Frame) {
        let _ = self.stream.write_all(&ws_frame::encode(frame)).await;
        let _ = self.stream.flush().await;
    }
}

/// The context a WebSocket connection is served in.
///
/// The same grouping the streaming path uses: identity, logger and the request head all
/// belong to the connection, and threading them separately pushed every function past
/// clippy's argument limit.
pub struct WsContext<'a> {
    /// The peer's address, for the log.
    pub peer: SocketAddr,
    /// The tenant the peer belongs to.
    pub tenant: &'a str,
    /// Where records go.
    pub logger: &'a Logger,
    /// The process-wide trace id.
    pub trace: u64,
    /// The per-connection span.
    pub span: u64,
    /// The accept loop's shutdown signal.
    ///
    /// An upgraded connection must still observe this. A WebSocket that ignored it would
    /// keep the process alive past `Shutdown::signal()` -- and since a WebSocket has no
    /// natural end, a single idle client would make a graceful restart **hang forever**,
    /// which in production is a deploy that never completes.
    pub shutdown: &'a Shutdown,
    /// How long the connection may be idle before the server closes it.
    ///
    /// `None` means no idle limit, which is what a WebSocket expecting heartbeats wants:
    /// the peer sends a ping on its own schedule and the server answers it.
    pub idle_timeout: Option<std::time::Duration>,
    /// This connection's buffer caps: one frame, one message.
    pub limits: crate::ws::WsLimits,
    /// The process-wide buffered-bytes budget, in bytes.
    ///
    /// Shared by every connection: `connections × message size` cannot exceed
    /// the configured total no matter how many peers fragment at once.
    pub buffer: std::sync::Arc<tokio::sync::Semaphore>,
}

/// Perform the handshake and, if it succeeds, run the connection until either side closes.
///
/// # Errors
///
/// Returns the outcome rather than an error: every way a WebSocket ends is a normal
/// result, and a caller distinguishing "the client closed" from "the peer broke the
/// protocol" needs the value rather than a bool.
pub async fn serve_websocket(
    stream: &mut TcpStream,
    head: &RequestHead,
    handler: &dyn WebSocketHandler,
    protocol: Option<&str>,
    prefix: Vec<u8>,
    ctx: &WsContext<'_>,
) -> WsOutcome {
    // --- The handshake ---------------------------------------------------
    let handshake = match Handshake::parse(head.method.as_str(), |name| {
        head.header(name).map(str::to_owned)
    }) {
        Ok(h) => h,
        Err(e) => {
            // A refused handshake is an HTTP response, not a WebSocket one: the
            // connection never became a WebSocket, so it is answered and closed.
            let _ = stream.write_all(&ws::write_refusal(&e)).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
            return WsOutcome::ProtocolError;
        }
    };

    if stream
        .write_all(&ws::write_upgrade(&handshake, protocol))
        .await
        .is_err()
        || stream.flush().await.is_err()
    {
        return WsOutcome::ClientGone;
    }

    // --- The frame loop --------------------------------------------------
    //
    // `prefix` is what the connection buffer held **past the request head**. A client may
    // coalesce its first frame with the handshake -- §4.1 makes the connection a WebSocket
    // as soon as the server's `101` is *sent*, not when the client has read it -- and
    // starting the loop from an empty buffer would silently discard that frame.
    let outcome = run_frames(stream, handler, prefix, ctx).await;

    // --- One record, with the outcome ------------------------------------
    emit_ws_record(ctx, head, outcome);
    handler.on_close(outcome);

    let _ = stream.shutdown().await;
    outcome
}

/// One connection's share of the process-wide buffer budget.
///
/// Permits are exact bytes, acquired per data frame and released when the
/// frame's message completes or is refused. The `Drop` backstop returns any
/// remainder when the connection ends — stranded fragments from a dead
/// assembly, or a path that returned early — so every permit returns exactly
/// once: `release` subtracts what it returns, and `Drop` returns only what
/// is left.
struct BufferBudget {
    /// The shared budget.
    sem: std::sync::Arc<tokio::sync::Semaphore>,
    /// Bytes currently charged to this connection.
    held: usize,
}

impl BufferBudget {
    /// Hold nothing yet against a shared budget.
    fn new(sem: std::sync::Arc<tokio::sync::Semaphore>) -> Self {
        Self { sem, held: 0 }
    }

    /// Try to charge `n` bytes. `false` sheds rather than waits: waiting on
    /// a shared budget is head-of-line blocking across connections.
    fn acquire(&mut self, n: usize) -> bool {
        let Ok(permit) = self
            .sem
            .try_acquire_many(u32::try_from(n).unwrap_or(u32::MAX))
        else {
            return false;
        };
        // Held, not dropped: the permit lives as `held` bytes until released.
        std::mem::forget(permit);
        self.held = self.held.saturating_add(n);
        true
    }

    /// Return `n` bytes, clamping to what is held: releasing more than held
    /// would mint permits the budget never issued.
    fn release(&mut self, n: usize) {
        let n = n.min(self.held);
        self.held -= n;
        self.sem.add_permits(n);
    }
}

impl Drop for BufferBudget {
    fn drop(&mut self) {
        self.sem.add_permits(self.held);
    }
}

/// A byte count as `usize`.
///
/// All values here are bounded by the configured caps (at most 64 MiB), so
/// the fallback is unreachable by construction — it names zero rather than
/// failing, because every call site already enforces the cap first.
fn u64_to_usize(n: u64) -> usize {
    usize::try_from(n).unwrap_or(0)
}

/// The read/assemble/dispatch loop.
async fn run_frames(
    stream: &mut TcpStream,
    handler: &dyn WebSocketHandler,
    prefix: Vec<u8>,
    ctx: &WsContext<'_>,
) -> WsOutcome {
    let mut assembler = Assembler::with_limit(ctx.limits.max_message_bytes);
    // Seeded with the leftover bytes rather than empty: see `serve_websocket`.
    let mut buf: Vec<u8> = prefix;
    // The process-wide budget this connection currently holds. Acquired per
    // data frame, released when its message completes or is refused, and any
    // remainder returned when the connection ends — permits are exact, so
    // every path must settle its account exactly once.
    let mut budget = BufferBudget::new(std::sync::Arc::clone(&ctx.buffer));

    loop {
        // Decode as many whole frames as the buffer holds. A single read can carry
        // several, and decoding only one per read would leave the rest until the next
        // syscall — which for a peer that has stopped sending never comes.
        loop {
            match ws_frame::decode_server_frame_with_limit(&buf, ctx.limits.max_frame_bytes) {
                Ok(Some((frame, used))) => {
                    buf.drain(..used);
                    if !frame.opcode.is_control() && !budget.acquire(frame.payload.len()) {
                        // The process is full: shed this connection's bytes with
                        // 1009 rather than waiting, because waiting on a shared
                        // budget is head-of-line blocking across connections —
                        // and a slow consumer could hold it deliberately.
                        refuse_with(
                            stream,
                            1009,
                            "the server's WebSocket buffer budget is exhausted",
                        )
                        .await;
                        return WsOutcome::ProtocolError;
                    }
                    if let Some(outcome) =
                        dispatch_frame(stream, handler, &mut assembler, frame, &mut budget).await
                    {
                        return outcome;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    // §7.4.1: the server must say *why* it is closing. A silent close is
                    // indistinguishable from a network fault, and a client that cannot
                    // tell the difference retries.
                    refuse_with(stream, e.close_code(), &e.to_string()).await;
                    return WsOutcome::ProtocolError;
                }
            }
        }

        // Compact so a long-lived connection does not hold the high-water mark of its
        // largest message forever.
        if buf.is_empty() && buf.capacity() > READ_BUFFER {
            buf.shrink_to(READ_BUFFER);
        }

        // --- Wait for bytes, a shutdown, or the idle deadline ---------------
        //
        // A WebSocket has no natural end, so every lifecycle bound the HTTP connection
        // state machine enforces has to be re-established here. Without this:
        //
        //   - `Shutdown::signal()` never reaches an upgraded connection, and because the
        //     read blocks forever, **one idle client makes a graceful restart hang** --
        //     a deploy that never completes;
        //   - the configured idle deadline silently stops applying the moment a connection
        //     upgrades, so a half-open socket is held for the process's life.
        //
        // `select!` rather than a timeout wrapper on the read: shutdown must be observed
        // *while* a read is in flight, and a timeout around the read would only be
        // evaluated between reads.
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk);
        tokio::pin!(read);

        let n = if let Some(idle) = ctx.idle_timeout {
            tokio::select! {
                r = &mut read => r.unwrap_or(0),
                () = ctx.shutdown.wait() => {
                    close_with(stream, 1001, "server shutting down").await;
                    return WsOutcome::Closed;
                }
                () = tokio::time::sleep(idle) => {
                    // 1001 as well: the *server* is ending the connection, and a code that
                    // blamed the client would make it retry with the same idle behaviour
                    // and be closed again.
                    close_with(stream, 1001, "idle timeout").await;
                    return WsOutcome::Closed;
                }
            }
        } else {
            tokio::select! {
                r = &mut read => r.unwrap_or(0),
                () = ctx.shutdown.wait() => {
                    close_with(stream, 1001, "server shutting down").await;
                    return WsOutcome::Closed;
                }
            }
        };

        if n == 0 {
            // A client that vanishes without a close frame. This is not an error: a
            // browser closing a tab sends nothing.
            return WsOutcome::ClientGone;
        }
        // Bound on a `let`: `read` returns at most the buffer length by contract.
        #[expect(clippy::expect_used, reason = "read returns at most chunk len")]
        let fresh: &[u8] = chunk.get(..n).expect("read returns at most chunk len");
        buf.extend_from_slice(fresh);
    }
}

/// How long a refused connection waits for the peer to go away after the
/// server sent its close frame.
///
/// Long enough for the peer to read the close and answer with its own (one
/// round trip plus slack); short enough that a peer holding the connection
/// open on purpose only parks one task briefly. Hitting it is not an error —
/// the close was already delivered, and the teardown below is identical.
const REFUSAL_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// How many peer bytes a closing connection drains at most.
///
/// The timeout above bounds the drain in time; this bounds it in space, so a
/// peer flooding bytes post-refusal cannot turn the drain into unbounded
/// read work. 8 MiB is eight times the largest refusal that motivated the
/// drain (an over-cap frame refuses on its length, leaving ~1 MiB unread),
/// so a legitimate peer never reaches it — and reaching it falls back to the
/// same immediate teardown the timeout uses, never to buffering.
const REFUSAL_DRAIN_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Send a close frame and drain the peer before tearing down.
///
/// A close frame the peer cannot read is a silent close, and §7.1.1 requires
/// better: the server must deliver the code. Sending the frame is not enough
/// on its own — after it the connection is dropped while the peer's bytes may
/// still sit unread in the receive buffer (an over-cap frame refuses on its
/// length alone, so ~1 MiB is still in flight), and closing a socket with
/// unread received data sends RST. On some stacks an RST discards even bytes
/// already buffered at the peer, so the close frame never arrives and the
/// client reports a network fault for a refusal the server meant to explain.
/// Draining first — half-close, read-and-discard until the peer's FIN, close,
/// the byte cap, or this timeout — means the final close finds an empty
/// buffer and goes out as FIN, which no stack reorders ahead of the data.
async fn refuse_with(stream: &mut TcpStream, code: u16, reason: &str) {
    let mut sender = WsSender { stream };
    sender.send_frame(&Frame::close(code, reason)).await;
    // Half-close: the write side is done, but the read side must stay open to
    // consume what the peer already sent — that is what keeps the teardown
    // below from becoming a reset.
    let _ = stream.shutdown().await;
    let deadline = tokio::time::Instant::now() + REFUSAL_DRAIN_TIMEOUT;
    let mut chunk = [0u8; 4096];
    let mut drained = 0usize;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline || drained >= REFUSAL_DRAIN_MAX_BYTES {
            break;
        }
        match tokio::time::timeout(deadline - now, stream.read(&mut chunk)).await {
            // Bytes already in flight: discarded, and the loop keeps draining.
            Ok(Ok(n)) if n > 0 => {
                drained = drained.saturating_add(n);
            }
            // The peer went away (EOF), reset, or the wait ran out: the close
            // frame was already sent, so there is nothing more this path owes.
            Ok(_) | Err(_) => break,
        }
    }
}

/// Send a close frame with a code and reason, ignoring a write failure.
///
/// A close is the last thing written on a connection that is already ending, so a failure
/// to send it is not actionable -- the peer is gone or the socket is closed, and both mean
/// the same thing to the caller.
async fn close_with(stream: &mut TcpStream, code: u16, reason: &str) {
    let mut sender = WsSender { stream };
    sender.send_frame(&Frame::close(code, reason)).await;
}

/// Handle one decoded frame, returning an outcome when the connection should end.
///
/// `budget` holds this connection's share of the process-wide buffer budget:
/// data frames arrived pre-charged by the caller, and this settles the
/// account — released when the message completes or is refused, so permits
/// track buffered bytes rather than leaking per frame.
async fn dispatch_frame(
    stream: &mut TcpStream,
    handler: &dyn WebSocketHandler,
    assembler: &mut Assembler,
    frame: Frame,
    budget: &mut BufferBudget,
) -> Option<WsOutcome> {
    if frame.opcode == Opcode::Ping {
        // §5.5.3: a pong carries **the same payload** as the ping. An empty pong is a
        // legal frame and useless: a peer using pings as a liveness probe with a nonce
        // cannot tell its own ping from anyone else's.
        let mut sender = WsSender { stream };
        sender.send_frame(&Frame::pong(frame.payload)).await;
        return None;
    }

    if frame.opcode == Opcode::Close {
        // §5.5.1: echo the close before tearing down. A client that does not receive the
        // echo cannot distinguish a clean close from a fault and will reconnect — which
        // turns a deliberate shutdown into a reconnect storm.
        //
        // The echo carries the peer's own code, or 1000 when it sent none, which §7.1.5
        // permits: a close with no status means "no status", and replying with 1000 is
        // the defined way to say "normal closure". The drain inside is the same one
        // every refusal uses: the peer may have pipelined messages behind its close,
        // and they must not turn this clean ending into a reset.
        let code = frame.close_code().unwrap_or(1000);
        refuse_with(stream, code, "").await;
        return Some(WsOutcome::Closed);
    }

    // Data frames arrive pre-charged against the process budget (see
    // `run_frames`); control frames bypass it, so only these settle an
    // account below. Captured before `push` consumes the frame.
    let data_len = (!frame.opcode.is_control()).then_some(frame.payload.len());
    match assembler.push(frame) {
        // A control frame passed through (`Ping`/`Close` were handled above, so this is a
        // `Pong` from the peer) and a fragment was accumulated: in both cases the
        // connection continues and nothing is dispatched. A pong was never
        // charged (control frames bypass the budget), so there is nothing to
        // settle here; an accumulated fragment stays charged until its message
        // completes.
        Ok(Progress::Control(_) | Progress::Accumulating) => None,
        Ok(Progress::Complete(message)) => {
            budget.release(message.payload.len());
            let mut sender = WsSender { stream };
            handler.on_message(&message, &mut sender).await;
            None
        }
        Err(e) => {
            // The refused bytes return too: a refusal that kept its permits
            // would let a peer drain the process budget with messages the
            // server never buffered. A cap refusal returns the whole attempted
            // total (it covers every fragment acquired so far); any other
            // error returns just this frame, and stranded fragments from a
            // dead assembly return with the connection (see `BufferBudget`).
            match (e.refused_bytes(), data_len) {
                (Some(total), _) => budget.release(u64_to_usize(total)),
                (None, Some(n)) => budget.release(n),
                (None, None) => {}
            }
            refuse_with(stream, e.close_code(), &e.to_string()).await;
            Some(WsOutcome::ProtocolError)
        }
    }
}

/// Write one access record for a WebSocket connection.
fn emit_ws_record(ctx: &WsContext<'_>, head: &RequestHead, outcome: WsOutcome) {
    let rec = Record::new(
        outcome.level(),
        TraceId::from_counter(ctx.trace),
        TraceId::span(&format!("{:016x}", ctx.span))
            .unwrap_or_else(|_| TraceId::from_counter(ctx.span)),
        ctx.tenant,
        "qqq-serve",
        crate::server::MANIFEST_REV_UNKNOWN,
        format!(
            "{} {} websocket ({})",
            head.method.as_str(),
            head.target,
            outcome.as_str()
        ),
    )
    .with_field("method", head.method.as_str())
    .with_field("path", head.target.clone())
    .with_field("websocket", outcome.as_str())
    .with_field("peer", ctx.peer.ip().to_string());

    if let Some(line) = ctx.logger.emit(rec) {
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout().lock(), "{line}");
    }
}

/// The response a non-upgrade request to a WebSocket route gets.
///
/// §4.2.1: a request that is not an upgrade is an ordinary HTTP request, and the honest
/// answer is `400` with the reason. A `101` would put the connection into frame mode for a
/// client that is still speaking HTTP.
#[must_use]
pub fn not_an_upgrade() -> Vec<u8> {
    ws::write_refusal(&crate::ws::HandshakeError::NotAnUpgrade)
}

/// Whether a request is asking to upgrade to WebSocket.
///
/// Checked **before** routing, so a `GET` to a WebSocket route with no upgrade header is
/// answered as an ordinary request rather than hijacked. The check is deliberately
/// shallow — the full validation is `Handshake::parse`, which produces the reasons.
#[must_use]
pub fn is_upgrade_request(head: &RequestHead) -> bool {
    head.header("upgrade").is_some_and(|v| {
        v.split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
    }) && head.header("sec-websocket-key").is_some()
}

/// The HTTP version a WebSocket is being requested over.
///
/// A `101` is an HTTP/1.1 response, and the version is here rather than read from the head
/// because a caller upgrading must know it cannot be HTTP/2's extended CONNECT yet.
#[must_use]
pub const fn supported_version() -> Version {
    Version::Http11
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The normal endings are `Info`; only a protocol violation is `Error`.
    #[test]
    fn only_a_protocol_error_is_an_error() {
        assert_eq!(WsOutcome::Closed.level(), Level::Info);
        assert_eq!(WsOutcome::ClientGone.level(), Level::Info);
        assert_eq!(WsOutcome::HandlerDone.level(), Level::Info);
        assert_eq!(WsOutcome::ProtocolError.level(), Level::Error);
    }

    /// Every outcome has a distinct log name.
    #[test]
    fn outcome_names_are_distinct() {
        let names = [
            WsOutcome::Closed.as_str(),
            WsOutcome::ClientGone.as_str(),
            WsOutcome::ProtocolError.as_str(),
            WsOutcome::HandlerDone.as_str(),
        ];
        let unique: std::collections::BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len());
    }

    /// A non-upgrade response is a refusal with a body, not a `101`.
    #[test]
    fn a_non_upgrade_gets_a_refusal() {
        let raw = not_an_upgrade();
        let text = String::from_utf8(raw).expect("ascii");
        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{text}");
        assert!(
            !text.contains("101"),
            "a request without an upgrade must never be answered with a 101: {text}"
        );
    }
}
