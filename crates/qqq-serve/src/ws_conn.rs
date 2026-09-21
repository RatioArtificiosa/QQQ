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

/// The read/assemble/dispatch loop.
async fn run_frames(
    stream: &mut TcpStream,
    handler: &dyn WebSocketHandler,
    prefix: Vec<u8>,
    ctx: &WsContext<'_>,
) -> WsOutcome {
    let mut assembler = Assembler::new();
    // Seeded with the leftover bytes rather than empty: see `serve_websocket`.
    let mut buf: Vec<u8> = prefix;

    loop {
        // Decode as many whole frames as the buffer holds. A single read can carry
        // several, and decoding only one per read would leave the rest until the next
        // syscall — which for a peer that has stopped sending never comes.
        loop {
            match ws_frame::decode_server_frame(&buf) {
                Ok(Some((frame, used))) => {
                    buf.drain(..used);
                    if let Some(outcome) =
                        dispatch_frame(stream, handler, &mut assembler, frame).await
                    {
                        return outcome;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    // §7.4.1: the server must say *why* it is closing. A silent close is
                    // indistinguishable from a network fault, and a client that cannot
                    // tell the difference retries.
                    let mut sender = WsSender { stream };
                    sender
                        .send_frame(&Frame::close(e.close_code(), &e.to_string()))
                        .await;
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
        buf.extend_from_slice(&chunk[..n]);
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
async fn dispatch_frame(
    stream: &mut TcpStream,
    handler: &dyn WebSocketHandler,
    assembler: &mut Assembler,
    frame: Frame,
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
        // the defined way to say "normal closure".
        let code = frame.close_code().unwrap_or(1000);
        let mut sender = WsSender { stream };
        sender.send_frame(&Frame::close(code, "")).await;
        return Some(WsOutcome::Closed);
    }

    match assembler.push(frame) {
        // A control frame passed through (`Ping`/`Close` were handled above, so this is a
        // `Pong` from the peer) and a fragment was accumulated: in both cases the
        // connection continues and nothing is dispatched.
        Ok(Progress::Control(_) | Progress::Accumulating) => None,
        Ok(Progress::Complete(message)) => {
            let mut sender = WsSender { stream };
            handler.on_message(&message, &mut sender).await;
            None
        }
        Err(e) => {
            let mut sender = WsSender { stream };
            sender
                .send_frame(&Frame::close(e.close_code(), &e.to_string()))
                .await;
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
