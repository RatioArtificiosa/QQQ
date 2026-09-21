// SPDX-License-Identifier: Apache-2.0

//! Streaming responses: writing a body in pieces, after the head.
//!
//! # Why this is separate from [`crate::Handler`], and not a change to it
//!
//! `Handler` is `Fn(&RequestHead, &RouteMatch) -> Response` and its doc comment states
//! the property that buys:
//!
//! > A handler is a **pure function of the request** in V1 [...] It does not touch the
//! > socket, which keeps the routing and encoding testable without a listener and means
//! > a handler cannot hold a connection open by accident.
//!
//! Every word of that is still true and still worth having. A streaming handler
//! violates all of it by necessity: it must await, it must write, and it *does* hold the
//! connection open — that is the point of an event stream. Making `Handler` async to
//! accommodate both would trade a real guarantee for a feature, and every existing
//! caller would inherit the ability to hang a connection whether it wanted it or not.
//!
//! So there are two, and the difference is visible at the call site rather than implied
//! by a flag. `SRV-004`'s own note in `response.rs` predicted this shape for the writer
//! ("a *different* function, not a flag on this one, because the failure modes are
//! different"); this is the same argument one level up, for the handler.
//!
//! # What a streaming handler is given
//!
//! A [`StreamWriter`] that owns the socket for the duration. The handler writes the head
//! and then as many pieces as it likes, flushing when it wants a piece to *arrive*
//! rather than merely be queued. When it returns, the body is terminated correctly for
//! the protocol version — a zero-length chunk for HTTP/1.1, or a plain close for
//! HTTP/1.0, which has no chunked encoding.
//!
//! # The three ways this goes wrong, and what is done about each
//!
//! 1. **The head is written but never flushed.** The client sees a connected socket
//!    producing nothing and cannot distinguish it from a slow server. [`StreamWriter::begin`]
//!    flushes, so a handler cannot forget.
//! 2. **A zero-length write ends the body.** [`crate::response::write_chunk`] returns no
//!    bytes for an empty piece precisely because a zero-length *chunk* terminates the
//!    stream — and an idle moment is normal for an event stream.
//! 3. **The handler returns an error after the head is sent.** The status is already on
//!    the wire and cannot be changed; the only honest signal left is to stop writing and
//!    close, which is what [`StreamOutcome`] records so an access log can say so.

use std::net::SocketAddr;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::access_log::{Level, Logger, Record, TraceId};
use crate::http1::{RequestHead, Version};
use crate::response::{self, Response};

/// What a streaming handler did, for the access log and for the connection state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamOutcome {
    /// The handler finished and the body was terminated correctly.
    Completed,
    /// The client disconnected before the handler finished. The **normal** end of an
    /// event stream, not an error.
    ClientClosed,
    /// The handler returned an error after the head was sent.
    ///
    /// A distinct outcome rather than `Completed`, because the response on the wire is
    /// incomplete and a reader of the log needs to know the client received a truncated
    /// body. There is no way to signal this to the client — the status is already sent —
    /// which is exactly why it must be recorded.
    HandlerFailed,
}

impl StreamOutcome {
    /// The access-log level this outcome is recorded at.
    ///
    /// `ClientClosed` is `Info`: a client closing an event stream is the normal end of
    /// one, and logging it as a failure would make the failure count meaningless.
    /// `HandlerFailed` is `Error`, because a truncated response is a real defect.
    #[must_use]
    pub const fn level(self) -> Level {
        match self {
            Self::Completed | Self::ClientClosed => Level::Info,
            Self::HandlerFailed => Level::Error,
        }
    }

    /// The name recorded in the access log.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::ClientClosed => "client_closed",
            Self::HandlerFailed => "handler_failed",
        }
    }
}

/// The socket, for the duration of a streaming handler.
///
/// # Why the handler does not get the `TcpStream`
///
/// Because then it could write a malformed response, and the framing rules —
/// `Content-Length` never, `Transfer-Encoding: chunked` on HTTP/1.1 only, `Connection:
/// close` forced on HTTP/1.0 — would be the handler's problem to remember. Wrapping the
/// socket means those rules are applied once, here, and a handler that writes nothing at
/// all still produces a valid empty stream.
pub struct StreamWriter<'a> {
    stream: &'a mut TcpStream,
    version: Version,
    /// Whether the body has been terminated, so `finish` is idempotent.
    finished: bool,
    /// How many bytes of body were written, for the access log.
    written: u64,
}

impl<'a> StreamWriter<'a> {
    /// Write the response head and flush it.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the head could not be written — the client is already gone, or
    /// the socket failed. The caller must **not** retry with a different status: nothing
    /// has been committed if this returns an error, and something has if it does not.
    pub async fn begin(
        stream: &'a mut TcpStream,
        response: &Response,
        version: Version,
    ) -> std::io::Result<Self> {
        // `keep_alive` is `false` for a streaming response on **both** versions, and the
        // reason differs:
        //
        // - HTTP/1.0: the body is delimited by EOF, so the connection must close.
        // - HTTP/1.1: the body is chunked and *could* be followed by another request,
        //   but a stream that ends by client disconnect leaves the connection in an
        //   indeterminate state, and a handler that returned has no way to have
        //   consumed the next request's head. Closing is the honest answer.
        let head = response::write_stream_head(response, version, false);
        stream.write_all(&head).await?;
        // Flushed **here**, not left to the handler: a head that sits in the buffer
        // looks to the client exactly like a server that has not answered.
        stream.flush().await?;
        Ok(Self {
            stream,
            version,
            finished: false,
            written: 0,
        })
    }

    /// Write one piece of the body.
    ///
    /// An empty piece writes nothing and is **not** an error — an idle moment is normal
    /// for an event stream. The body is terminated by [`Self::finish`], never by a write
    /// of zero bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the client disconnected or the socket failed. The caller
    /// should stop and return rather than retrying.
    pub async fn write(&mut self, piece: &[u8]) -> std::io::Result<()> {
        if piece.is_empty() {
            return Ok(());
        }
        // **Framing is version-dependent**, and getting this wrong puts the chunk length
        // on the wire as body data. HTTP/1.1 frames each piece with a hex length so the
        // client can delimit it; HTTP/1.0 has no chunked encoding, so the piece is
        // written raw and the body is delimited by the connection close that follows
        // `finish`.
        //
        // A first version of this function called `write_chunk` unconditionally, gating
        // only the *terminator* on the version. A test caught it: an HTTP/1.0 client
        // received `13\r\nraw-body-for-http10\r\n` — the length prefix as content.
        // **Framing is version-dependent**, and getting this wrong puts the chunk length
        // on the wire as body data. HTTP/1.1 frames each piece with a hex length so the
        // client can delimit it; HTTP/1.0 has no chunked encoding, so the piece is
        // written raw and the body is delimited by the connection close that follows
        // `finish`.
        //
        // A first version of this function called `write_chunk` unconditionally, gating
        // only the *terminator* on the version. A test caught it: an HTTP/1.0 client
        // received `13\r\nraw-body-for-http10\r\n` -- the length prefix as content.
        let framed = if self.version == Version::Http11 {
            response::write_chunk(piece)
        } else {
            piece.to_vec()
        };
        self.stream.write_all(&framed).await?;
        self.written += piece.len() as u64;
        Ok(())
    }

    /// Write one piece and flush it, so it reaches the client now.
    ///
    /// # Why flushing is not automatic on every write
    ///
    /// Because the caller knows what a "piece" means and this type does not. An
    /// event-stream handler flushes per event, so a client sees each one immediately; a
    /// handler emitting a large body in chunks flushes every few writes, because a
    /// syscall per chunk costs more than the latency it saves. Making every write flush
    /// would remove the second choice, and making none of them flush would remove the
    /// first.
    ///
    /// # Errors
    ///
    /// As [`Self::write`].
    pub async fn write_now(&mut self, piece: &[u8]) -> std::io::Result<()> {
        self.write(piece).await?;
        self.stream.flush().await
    }

    /// Terminate the body.
    ///
    /// For HTTP/1.1 this writes the zero-length chunk and the empty trailer; for
    /// HTTP/1.0 it writes nothing, because there the body ends at EOF and the connection
    /// close that follows is the terminator. Doing it the other way round — sending a
    /// chunk terminator to an HTTP/1.0 client — would put `0\r\n\r\n` in the body as
    /// data.
    ///
    /// Idempotent: calling it twice writes one terminator.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the terminator could not be written. The body is already
    /// truncated in that case, so the caller's only action is to close — but it still
    /// needs to know, so it can report `HandlerFailed` rather than `Completed`.
    pub async fn finish(&mut self) -> std::io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        if self.version == Version::Http11 {
            self.stream.write_all(&response::write_last_chunk()).await?;
        }
        self.stream.flush().await
    }

    /// How many bytes of body were written, excluding framing.
    #[must_use]
    pub const fn written(&self) -> u64 {
        self.written
    }
}

/// A handler that streams its response.
///
/// Takes `&mut StreamWriter` rather than returning one, for the reason `Handler` takes
/// `&RequestHead` rather than owning it: the writer belongs to the connection, and a
/// handler that owned it could drop it mid-body.
pub type StreamingHandler = std::sync::Arc<
    dyn for<'a> Fn(
            &'a RequestHead,
            &'a crate::server::RouteMatch,
            &'a mut StreamWriter<'a>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), StreamError>> + Send + 'a>,
        > + Send
        + Sync,
>;

/// Why a streaming handler stopped.
///
/// Deliberately not `std::io::Error`: a handler failing to produce its *data* and a
/// socket failing to accept it are different facts, and only the first is the handler's
/// fault. Both end the body early, and the outcome records which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// The handler could not produce the body — its data source failed, or its own
    /// logic did. The socket is still healthy.
    Handler(String),
    /// The socket failed or the client disconnected. The **normal** end of an event
    /// stream when the client is the one who closed.
    Transport(String),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handler(why) => write!(f, "the streaming handler failed: {why}"),
            Self::Transport(why) => write!(f, "the connection failed: {why}"),
        }
    }
}

impl std::error::Error for StreamError {}

/// What a completed streaming request needs recording.
///
/// # Why a struct rather than the ten parameters this started as
///
/// Clippy's `too_many_arguments` fired at ten, and it was right for the reason it
/// usually is not: the values are not ten independent facts. Five of them — trace,
/// span, tenant, peer and the head — answer **"which request, and whose?"**, and the
/// other five are the answer to **"how did it end?"**. Grouping them means a caller
/// cannot pass the trace of one request with the span of another, which is the kind of
/// mistake a positional parameter list invites and a named field does not.
///
/// It also makes the signature readable at the call site, where ten positional
/// arguments had become a block a reader had to count.
#[derive(Debug)]
pub struct StreamRecord<'a> {
    /// The request head, for the method and target.
    pub head: &'a RequestHead,
    /// The matched path, for the `path` field.
    pub path: &'a str,
    /// The status already sent on the wire.
    pub status: u16,
    /// How the stream ended.
    pub outcome: StreamOutcome,
    /// Body bytes written, excluding framing.
    pub written: u64,
    /// The tenant the peer belongs to.
    pub tenant: &'a str,
    /// The client address.
    pub peer: SocketAddr,
    /// The process-wide trace id.
    pub trace: u64,
    /// The per-connection span.
    pub span: u64,
}

/// Write one access record for a streaming request.
///
/// # Why this is separate from `server::emit_record`
///
/// A streaming response has no body length at the time the record is built — that is
/// what "streaming" means — so the record carries what *is* known: the outcome, the
/// bytes actually written so far, and the same trace and span as any other request.
/// Reusing the non-streaming record shape would mean a field that is always zero or
/// always wrong.
pub fn emit_stream_record(logger: &Logger, rec: &StreamRecord<'_>) {
    let record = Record::new(
        rec.outcome.level(),
        TraceId::from_counter(rec.trace),
        TraceId::span(&format!("{:016x}", rec.span))
            .unwrap_or_else(|_| TraceId::from_counter(rec.span)),
        rec.tenant,
        "qqq-serve",
        crate::server::MANIFEST_REV_UNKNOWN,
        format!(
            "{} {} {} (streamed)",
            rec.head.method.as_str(),
            rec.head.target,
            rec.status
        ),
    )
    .with_field("method", rec.head.method.as_str())
    .with_field("path", rec.path)
    .with_field("status", rec.status.to_string())
    .with_field("stream", rec.outcome.as_str())
    .with_field("body_bytes", rec.written.to_string())
    .with_field("peer", rec.peer.ip().to_string());

    if let Some(line) = logger.emit(record) {
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout().lock(), "{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two normal endings are `Info`, and only a truncated body is `Error`.
    ///
    /// The distinction is operational: an event stream ends when the *client* goes away,
    /// so logging that as a failure would make the failure count useless.
    #[test]
    fn only_a_truncated_body_is_an_error() {
        assert_eq!(StreamOutcome::Completed.level(), Level::Info);
        assert_eq!(
            StreamOutcome::ClientClosed.level(),
            Level::Info,
            "a client closing an event stream is the normal end of one"
        );
        assert_eq!(StreamOutcome::HandlerFailed.level(), Level::Error);
    }

    /// Every outcome has a distinct name for the log.
    #[test]
    fn outcomes_have_distinct_names() {
        let names = [
            StreamOutcome::Completed.as_str(),
            StreamOutcome::ClientClosed.as_str(),
            StreamOutcome::HandlerFailed.as_str(),
        ];
        let unique: std::collections::BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len(), "outcome names must be distinct");
    }

    /// A handler failure and a transport failure are different facts.
    #[test]
    fn the_two_error_kinds_are_distinguishable() {
        let handler = StreamError::Handler("the data source closed".to_owned());
        let transport = StreamError::Transport("broken pipe".to_owned());
        assert_ne!(handler, transport);
        assert!(handler.to_string().contains("handler"));
        assert!(transport.to_string().contains("connection"));
    }
}
