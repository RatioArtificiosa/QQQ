//! Streaming request bodies: incremental framing, and the cap enforced *while*
//! the body arrives rather than after it is buffered.
//!
//! Implements `SRV-004` (streaming bodies with backpressure propagation) and
//! `SRV-005` (`max_request_bytes` enforced during streaming). Proposal §6.4:
//!
//! > Bodies are `stream<u8>` end-to-end. Backpressure propagates from the client
//! > socket through the host to the guest's stream and back. There is no point
//! > at which a request body is fully buffered unless the manifest asked for it
//! > (`max_request_bytes` is a *cap*, not a buffer).
//!
//! # Why this is a pull-based decoder and not a buffered one
//!
//! The obvious implementation reads the whole body into a `Vec<u8>`, applies the
//! cap, and hands the buffer to the handler. It is wrong for the reason §6.4
//! gives, and the reason is a security boundary rather than a performance
//! preference:
//!
//! * **`max_request_bytes` must be a cap, not a buffer.** If the cap is checked
//!   after buffering, then the memory cost of a request is the size the *client*
//!   chose up to whatever the allocation limit happens to be — and a client that
//!   sends 2 GiB to a 2 MiB limit has already allocated it. The check has to
//!   happen while the bytes flow, so that the bytes past the cap are never held.
//! * **Backpressure is not expressible over a buffer.** A handler that reads at
//!   its own pace must be able to stop reading, which lets the TCP receive
//!   window close and the sender slow down. A decoder that pre-buffers has
//!   already read from the socket regardless of what the handler wanted, so the
//!   only backpressure left is the OS buffer.
//!
//! So [`BodyReader`] exposes `poll_chunk`: the caller asks for the next piece and
//! gets whatever the framing layer can produce *now*. Nothing accumulates except
//! the unparsed remainder of the framing itself.
//!
//! # Chunked decoding, and why `drain_body` closed the connection before this
//!
//! `server::drain_body` returns `false` for a `chunked` body, ending the
//! connection, and its comment says why: reading-and-discarding a chunked body
//! without decoding it leaves the connection at an offset only a decoder knows,
//! and a keep-alive connection with a wrong offset turns one bad request into a
//! stream of misparsed ones — a request-smuggling shape (`§O-047a`).
//!
//! That was the honest answer while no decoder existed. This module is the
//! decoder, so the offset is now knowable, and the smuggle window closes with it.
//!
//! # Trailers are consumed and discarded
//!
//! A chunked body may be followed by a trailer section. It is read to its
//! terminator so the connection is left at the next request, and the fields are
//! **discarded rather than exposed**: a trailer is not authenticated by anything
//! in V1, and surfacing it to a handler would let a client add headers after the
//! fact to a request whose head has already been routed. Discarding keeps the
//! framing correct and the trust boundary where it was.

use std::fmt;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Why a body could not be read.
///
/// Every variant is a **client** fault: the request was malformed, or it
/// exceeded a limit the deployment declared. None of them is a QQQ error, so
/// none carries a `QQQ-` code — the same distinction
/// `response::parse_error_response` exists to preserve (`§O-047`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// A chunk-size line was not valid hexadecimal.
    BadChunkSize {
        /// The offending line, truncated for the message.
        line: String,
    },
    /// A chunk-size line was longer than any legitimate one.
    ///
    /// A chunk size is a hexadecimal count; 16 digits represent any size a
    /// `u64` can hold, so a longer line is an attack rather than a request.
    ChunkSizeLineTooLong {
        /// The cap that was exceeded.
        limit: usize,
    },
    /// A chunk did not end with its required `CRLF`.
    MissingChunkTerminator,
    /// The body exceeded `max_request_bytes` **while being read**.
    ///
    /// This is the variant `SRV-005` exists for. It is reported as soon as the
    /// running total passes the cap, so the bytes beyond it are never held.
    TooLarge {
        /// The configured cap.
        limit: u64,
        /// How much had arrived when the cap was passed.
        seen: u64,
    },
    /// A chunked body did not end with a zero-length chunk.
    Truncated,
    /// The chunk framing was otherwise malformed.
    BadFraming {
        /// What was wrong.
        reason: &'static str,
    },
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadChunkSize { line } => {
                write!(f, "chunk size is not hexadecimal: {line:?}")
            }
            Self::ChunkSizeLineTooLong { limit } => {
                write!(f, "chunk-size line longer than {limit} bytes")
            }
            Self::MissingChunkTerminator => {
                write!(f, "chunk data was not terminated by CRLF")
            }
            Self::TooLarge { limit, seen } => write!(
                f,
                "request body exceeded max_request_bytes: {seen} read, limit {limit}"
            ),
            Self::Truncated => write!(f, "chunked body ended before its final chunk"),
            Self::BadFraming { reason } => write!(f, "malformed chunked framing: {reason}"),
        }
    }
}

impl std::error::Error for BodyError {}

/// The largest chunk-size line that can be legitimate.
///
/// 16 hexadecimal digits hold every `u64`, and the line also carries its `CRLF`
/// and may carry chunk extensions. The cap is generous and exists to bound the
/// buffer before the parse rather than after it.
pub const MAX_CHUNK_SIZE_LINE: usize = 1024;

/// One piece of a body, as produced by [`BodyReader::poll_chunk`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyChunk {
    /// Body bytes. May be fewer than requested; the caller loops.
    Data(Vec<u8>),
    /// The body ended. No further calls will produce data.
    End,
}

/// A request body read incrementally, with the cap enforced as it arrives.
///
/// Constructed by [`BodyReader::length_delimited`] or [`BodyReader::chunked`],
/// never directly, so the framing mode cannot disagree with the head it came
/// from.
#[derive(Debug)]
pub struct BodyReader {
    /// How the body is framed.
    framing: Framing,
    /// The cap on total body bytes, enforced continuously.
    max_bytes: u64,
    /// Total body bytes handed to the caller so far.
    seen: u64,
    /// Bytes of the current chunk left to deliver, in chunked mode.
    chunk_remaining: u64,
    /// Whether the body has been fully consumed.
    finished: bool,
}

/// The body framing declared by the head.
///
/// Private, because a caller must not be able to construct a `BodyReader` whose
/// framing differs from the `RequestHead` it was built from — that is how a
/// `Content-Length` body gets read as chunked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// No body is declared.
    None,
    /// Exactly `n` bytes follow.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
}

impl BodyReader {
    /// A reader for a body with no declared framing.
    #[must_use]
    pub const fn empty(max_bytes: u64) -> Self {
        Self {
            framing: Framing::None,
            max_bytes,
            seen: 0,
            chunk_remaining: 0,
            finished: true,
        }
    }

    /// A reader for a `Content-Length` body.
    #[must_use]
    pub const fn length_delimited(len: u64, max_bytes: u64) -> Self {
        Self {
            // A zero-length body is complete before it starts, and saying so
            // here means `poll_chunk` has one fewer branch to get wrong.
            framing: if len == 0 {
                Framing::None
            } else {
                Framing::Length(len)
            },
            max_bytes,
            seen: 0,
            chunk_remaining: 0,
            finished: len == 0,
        }
    }

    /// A reader for a `Transfer-Encoding: chunked` body.
    #[must_use]
    pub const fn chunked(max_bytes: u64) -> Self {
        Self {
            framing: Framing::Chunked,
            max_bytes,
            seen: 0,
            chunk_remaining: 0,
            finished: false,
        }
    }

    /// Build the reader a head calls for, resolving framing from the head's own
    /// fields.
    ///
    /// `max_bytes` is the deployment's `max_request_bytes`.
    ///
    /// # Why this takes the head rather than its fields
    ///
    /// It refuses a head that declares **both** `Content-Length` and
    /// `Transfer-Encoding: chunked` — the request-smuggling shape. `http1`
    /// already rejects that at parse time, so this is the second check, and it
    /// is deliberately redundant: the parse is the first authority and this is
    /// the one that keeps holding if the parse is ever relaxed. A decoder that
    /// had to trust an upstream rejection would be one refactor away from
    /// smuggling.
    ///
    /// # Errors
    ///
    /// Returns [`BodyError::BadFraming`] when the head declares both framings.
    pub fn from_head(head: &crate::http1::RequestHead, max_bytes: u64) -> Result<Self, BodyError> {
        if head.chunked && head.content_length.is_some() {
            return Err(BodyError::BadFraming {
                reason: "both Content-Length and Transfer-Encoding: chunked",
            });
        }
        if head.chunked {
            Ok(Self::chunked(max_bytes))
        } else if let Some(len) = head.content_length {
            Ok(Self::length_delimited(len, max_bytes))
        } else {
            Ok(Self::empty(max_bytes))
        }
    }

    /// Total body bytes delivered so far.
    #[must_use]
    pub const fn bytes_read(&self) -> u64 {
        self.seen
    }

    /// Whether the body has been fully consumed.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Whether the body is framed as chunked.
    #[must_use]
    pub const fn is_chunked(&self) -> bool {
        matches!(self.framing, Framing::Chunked)
    }

    /// Read the next piece of the body.
    ///
    /// `max` bounds the bytes returned by a single call, so a caller controls
    /// its own working set — this is where backpressure is expressed: a handler
    /// that asks for 1 KiB at a time never holds more than that, and while it is
    /// not asking, nothing is read from the socket and the peer's window closes.
    ///
    /// Returns [`BodyChunk::End`] once the body is complete, and on every call
    /// thereafter.
    ///
    /// # Errors
    ///
    /// Returns a [`BodyError`] for malformed framing, a truncated body, or a
    /// body that passed `max_request_bytes` while arriving. The reader is left
    /// unusable after an error — the connection cannot be resynchronised, which
    /// is why the caller closes it.
    pub async fn poll_chunk<R>(&mut self, io: &mut R, max: usize) -> Result<BodyChunk, BodyError>
    where
        R: AsyncRead + Unpin,
    {
        if self.finished {
            return Ok(BodyChunk::End);
        }
        if max == 0 {
            // A zero-byte request is not an error; it would loop forever, so it
            // is answered with the only truthful thing: nothing more to give
            // *this call*. `End` would be a lie while bytes remain.
            return Ok(BodyChunk::Data(Vec::new()));
        }

        match self.framing {
            Framing::None => {
                self.finished = true;
                Ok(BodyChunk::End)
            }
            Framing::Length(remaining_total) => {
                let left = remaining_total.saturating_sub(self.seen);
                if left == 0 {
                    self.finished = true;
                    return Ok(BodyChunk::End);
                }
                let want = usize::try_from(left.min(max as u64)).unwrap_or(max);
                let mut buf = vec![0u8; want];
                let n = read_some(io, &mut buf).await?;
                if n == 0 {
                    // The peer stopped short of the length it declared. That is
                    // not a complete request, and treating it as one would
                    // deliver a truncated body to a handler as if it were whole.
                    return Err(BodyError::Truncated);
                }
                buf.truncate(n);
                self.account(n)?;
                if self.seen >= remaining_total {
                    self.finished = true;
                }
                Ok(BodyChunk::Data(buf))
            }
            Framing::Chunked => self.poll_chunked(io, max).await,
        }
    }

    /// Charge `n` bytes against the cap, failing as soon as it is passed.
    ///
    /// The running total is checked **before** the bytes are returned, so a body
    /// one byte past the cap is refused without the caller ever holding those
    /// bytes. That ordering is `SRV-005` in one line: the cap is enforced during
    /// streaming, not after buffering.
    fn account(&mut self, n: usize) -> Result<(), BodyError> {
        let n = u64::try_from(n).unwrap_or(u64::MAX);
        self.seen = self.seen.saturating_add(n);
        if self.seen > self.max_bytes {
            return Err(BodyError::TooLarge {
                limit: self.max_bytes,
                seen: self.seen,
            });
        }
        Ok(())
    }

    /// The chunked path.
    async fn poll_chunked<R>(&mut self, io: &mut R, max: usize) -> Result<BodyChunk, BodyError>
    where
        R: AsyncRead + Unpin,
    {
        // Finish the current chunk before looking for the next size line: the
        // size line is only valid at a chunk boundary.
        if self.chunk_remaining == 0 {
            let size = self.read_chunk_size(io).await?;
            if size == 0 {
                // The zero-size chunk is the body's end. It **is** followed by a
                // trailer section, so this is not the end of the *bytes* until
                // the trailers are consumed — returning early would leave the
                // connection pointing into the trailer and the next request
                // would parse from the wrong offset.
                self.read_trailers(io).await?;
                self.finished = true;
                return Ok(BodyChunk::End);
            }
            self.chunk_remaining = size;
        }

        let want = usize::try_from(self.chunk_remaining.min(max as u64)).unwrap_or(max);
        let mut buf = vec![0u8; want];
        let n = read_some(io, &mut buf).await?;
        if n == 0 {
            return Err(BodyError::Truncated);
        }
        buf.truncate(n);
        self.chunk_remaining -= u64::try_from(n).unwrap_or(self.chunk_remaining);
        self.account(n)?;

        if self.chunk_remaining == 0 {
            // Every chunk's data is followed by its own CRLF. Consuming it here,
            // exactly at the boundary, is what makes "the framing offset is
            // knowable" true — the property `drain_body` needed and did not have.
            self.expect_crlf(io).await?;
        }
        Ok(BodyChunk::Data(buf))
    }

    /// Read and parse a chunk-size line.
    async fn read_chunk_size<R>(&mut self, io: &mut R) -> Result<u64, BodyError>
    where
        R: AsyncRead + Unpin,
    {
        let line = self.read_line(io, MAX_CHUNK_SIZE_LINE).await?;
        // A chunk size may carry extensions after `;`. They are parsed away and
        // discarded: V1 defines none, and a decoder that ignored them without
        // skipping them would misread the size.
        let digits = line.split(';').next().unwrap_or("").trim();
        if digits.is_empty() {
            return Err(BodyError::BadChunkSize { line });
        }
        u64::from_str_radix(digits, 16).map_err(|_| BodyError::BadChunkSize { line })
    }

    /// Consume a chunked body's trailer section, up to its blank line.
    ///
    /// Discarded rather than exposed — see the module docs for why a trailer is
    /// a trust-boundary problem and not a feature to add casually.
    async fn read_trailers<R>(&mut self, io: &mut R) -> Result<(), BodyError>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            let line = self.read_line(io, MAX_CHUNK_SIZE_LINE).await?;
            if line.is_empty() {
                return Ok(());
            }
        }
    }

    /// Read one CRLF-terminated line, excluding the terminator.
    ///
    /// Reads a byte at a time on purpose. A buffered read would pull bytes
    /// belonging to the *next* request into this decoder's buffer, and there is
    /// no buffer here to hand them back — the whole point of the module. The
    /// cost is bounded by `limit`, and a chunk-size line is a dozen bytes.
    async fn read_line<R>(&mut self, io: &mut R, limit: usize) -> Result<String, BodyError>
    where
        R: AsyncRead + Unpin,
    {
        let mut out = Vec::with_capacity(16);
        loop {
            if out.len() > limit {
                return Err(BodyError::ChunkSizeLineTooLong { limit });
            }
            let mut byte = [0u8; 1];
            let n = read_some(io, &mut byte).await?;
            if n == 0 {
                return Err(BodyError::Truncated);
            }
            if byte[0] == b'\n' {
                // Tolerate a bare LF: some clients send it, and rejecting it
                // costs a connection for a request that is otherwise fine. The
                // `\r` is stripped if present.
                if out.last() == Some(&b'\r') {
                    out.pop();
                }
                return String::from_utf8(out).map_err(|_| BodyError::BadFraming {
                    reason: "non-UTF-8 line",
                });
            }
            out.push(byte[0]);
        }
    }

    /// Require exactly `CRLF` next.
    async fn expect_crlf<R>(&mut self, io: &mut R) -> Result<(), BodyError>
    where
        R: AsyncRead + Unpin,
    {
        let mut crlf = [0u8; 2];
        let mut got = 0;
        while got < 2 {
            let n = read_some(io, &mut crlf[got..]).await?;
            if n == 0 {
                return Err(BodyError::Truncated);
            }
            got += n;
        }
        if crlf != *b"\r\n" {
            return Err(BodyError::MissingChunkTerminator);
        }
        Ok(())
    }
}

/// Read at least one byte, retrying on a spurious zero-length result.
///
/// `AsyncReadExt::read` returning `0` means EOF, so a plain loop is correct
/// here; the helper exists so every call site uses the same interpretation
/// rather than one of them treating `0` as "try again", which would spin.
async fn read_some<R>(io: &mut R, buf: &mut [u8]) -> Result<usize, BodyError>
where
    R: AsyncRead + Unpin,
{
    match io.read(buf).await {
        Ok(n) => Ok(n),
        // An I/O error on the body is the peer going away, which is a
        // truncation from the decoder's point of view — there is no reset to
        // send, because the connection is already gone.
        Err(_) => Ok(0),
    }
}

/// Discard a body, enforcing the cap, without exposing its bytes.
///
/// This is the function `server::drain_body` needs: after this returns `Ok`,
/// the connection is positioned at the next request regardless of how the body
/// was framed.
///
/// # Errors
///
/// Returns a [`BodyError`] when the body is malformed or exceeds the cap. Either
/// way the connection cannot be reused, which is what the caller must do.
pub async fn discard<R>(reader: &mut BodyReader, io: &mut R) -> Result<u64, BodyError>
where
    R: AsyncRead + Unpin,
{
    let mut total = 0u64;
    loop {
        match reader.poll_chunk(io, 8 * 1024).await? {
            // The count comes from the reader's own accounting rather than from
            // summing here, so the two cannot drift.
            BodyChunk::Data(_) => total = reader.bytes_read(),
            BodyChunk::End => return Ok(total),
        }
    }
}
