// SPDX-License-Identifier: Apache-2.0

//! One connection's byte stream: cleartext or TLS-decrypted (`SRV-021`).
//!
//! A home of its own because two modules need the name: `server` serves it
//! and `stream` writes streaming bodies into it, and neither may own what
//! the other names — the topology this crate keeps is that transport types
//! live beside the handlers, not inside one handler's module.

use tokio::net::TcpStream;

/// The byte stream under one connection: the accepted socket, or its
/// TLS-decrypted form.
///
/// An enum rather than a generic so the seventeen handlers name one type:
/// generics would add a parameter to every one of them for a choice with
/// exactly two inhabitants, and a `Box<dyn ...>` would allocate per
/// connection to hide the same choice. Both variants are `Unpin`, so
/// delegation needs no pin projection — `Pin::new` on the inner stream is
/// sound because neither variant moves through the borrow.
///
/// Public because `StreamWriter::begin` takes it: a public function cannot
/// name a private type, and embedders driving streaming responses need the
/// same wrapper the accept loop builds.
pub enum ConnStream {
    /// Cleartext: the accepted socket as it arrived.
    Plain(TcpStream),
    /// Terminated TLS: the handshake the accept loop performed.
    ///
    /// Boxed: the TLS session state is ~1.2 KiB against the socket's ~50 B,
    /// and one pointer per connection keeps the enum small. The allocation
    /// is per TLS connection, where the handshake already allocates far
    /// more — it is not a per-request cost.
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl tokio::io::AsyncRead for ConnStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ConnStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            ConnStream::Tls(s) => std::pin::Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for ConnStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ConnStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            ConnStream::Tls(s) => std::pin::Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ConnStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            ConnStream::Tls(s) => std::pin::Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ConnStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            // A TLS `close_notify` before the TCP FIN: without it a client
            // cannot distinguish "response complete" from "connection cut",
            // which is a truncation an attacker can produce.
            ConnStream::Tls(s) => std::pin::Pin::new(&mut **s).poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            ConnStream::Plain(s) => s.is_write_vectored(),
            ConnStream::Tls(s) => s.as_ref().is_write_vectored(),
        }
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Overridden alongside `is_write_vectored`, which claims `true`:
        // the default impl would loop over `poll_write`, which is correct
        // but unvectored — the claim and the path would disagree.
        match self.get_mut() {
            ConnStream::Plain(s) => std::pin::Pin::new(s).poll_write_vectored(cx, bufs),
            ConnStream::Tls(s) => std::pin::Pin::new(&mut **s).poll_write_vectored(cx, bufs),
        }
    }
}
