// SPDX-License-Identifier: Apache-2.0

//! Streaming responses over a real socket (`SRV-004`).
//!
//! # Why this drives a socket
//!
//! `stream.rs`'s own tests cover the three outcomes and the error kinds -- pure values.
//! They cannot show that `StreamWriter` **writes what it is given, in order, flushed**,
//! which is the entire property a streaming handler depends on and which no unit test
//! can reach: `begin` takes a `&mut TcpStream`.
//!
//! # What these prove that the SSE integration tests could not
//!
//! `tests/sse.rs` spoke the protocol over a raw socket, because nothing in the crate
//! could stream. `StreamWriter` is that missing piece, so these tests drive **it** --
//! the type a handler actually receives -- rather than re-implementing its framing.
//!
//! # Why there is no test that goes through `serve`
//!
//! `serve` takes a `Handler`, and `StreamWriter` is given to a `StreamingHandler`. The
//! two are separate on purpose (see `stream.rs`'s module docs), and `serve_connection`
//! does not yet dispatch a streaming route -- that requires the route table to say which
//! handler kind a route wants, which is the next step rather than this one. Saying so
//! here is the discipline the observations call for: a test suite that implied otherwise
//! would be aimed at the wrong artifact.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use qqq_serve::sse::{self, Event};
use qqq_serve::stream::{StreamOutcome, StreamWriter};
use qqq_serve::{Response, Version};

/// A port nobody is using, for the reason `tests/socket.rs` documents.
fn free_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = l.local_addr().expect("addr");
    drop(l);
    a
}

/// An SSE response, as a streaming handler would build it.
fn sse_response() -> Response {
    let mut resp = Response::status(200);
    for (name, value) in sse::headers() {
        resp.set_header(name, value);
    }
    resp
}

/// Read a whole response with a timeout.
async fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    raw
}

/// Split a response into status line, headers and decoded body.
fn parse(raw: &[u8]) -> (String, Vec<(String, String)>, Vec<u8>) {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no header terminator in {}", text.escape_debug()));
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default().to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    (status, headers, decode_chunks(body.as_bytes()))
}

fn decode_chunks(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or_else(|| panic!("no chunk header in {:?}", String::from_utf8_lossy(body)));
        let len = usize::from_str_radix(
            std::str::from_utf8(&body[..end]).expect("hex length is ascii"),
            16,
        )
        .expect("hex length");
        body = &body[end + 2..];
        if len == 0 {
            return out;
        }
        assert!(body.len() >= len + 2, "chunk shorter than declared");
        out.extend_from_slice(&body[..len]);
        body = &body[len + 2..];
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

// ---------------------------------------------------------------------------
// The writer
// ---------------------------------------------------------------------------

/// **A streaming handler writes a valid chunked response over a real socket.**
#[tokio::test]
async fn a_streaming_writer_produces_a_valid_chunked_response() {
    let addr = free_addr();
    let listener = TcpListener::bind(addr).await.expect("bind");

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf).await;

        let mut writer = StreamWriter::begin(&mut sock, &sse_response(), Version::Http11)
            .await
            .expect("the head must write");
        for event in [
            Event::data("first"),
            Event::keep_alive("ping"),
            Event::data("second"),
        ] {
            writer
                .write_now(&event.encode())
                .await
                .expect("each event must reach the client");
        }
        let written = writer.written();
        writer.finish().await.expect("the terminator must write");
        (written, StreamOutcome::Completed)
    });

    let mut client = TcpStream::connect(addr).await.expect("connect");
    client
        .write_all(b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("request");
    client.flush().await.expect("flush");
    let raw = read_all(&mut client).await;

    let (written, outcome) = server.await.expect("server task");
    assert_eq!(outcome, StreamOutcome::Completed);
    assert!(written > 0, "the writer must have counted body bytes");

    let (status, headers, body) = parse(&raw);
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert_eq!(header(&headers, "Transfer-Encoding"), Some("chunked"));
    assert_eq!(
        header(&headers, "Content-Length"),
        None,
        "a streamed body has no length"
    );
    assert_eq!(
        header(&headers, "Content-Type"),
        Some("text/event-stream"),
        "the handler's own headers must survive"
    );

    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("data:first"), "{text:?}");
    assert!(text.contains(":ping"), "{text:?}");
    assert!(text.contains("data:second"), "{text:?}");
}

/// **`begin` flushes the head, so the client sees it before any body.**
#[tokio::test]
async fn the_head_reaches_the_client_before_any_body() {
    let addr = free_addr();
    let listener = TcpListener::bind(addr).await.expect("bind");

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf).await;
        // Scoped so the borrow of `sock` ends here. No `drop(writer)`: the type has no
        // `Drop` implementation, so dropping it explicitly would say nothing — clippy
        // rejects it, and a scope states the same intent without the pretence.
        {
            let _writer = StreamWriter::begin(&mut sock, &sse_response(), Version::Http11)
                .await
                .expect("head");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    let mut client = TcpStream::connect(addr).await.expect("connect");
    client
        .write_all(b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("request");
    client.flush().await.expect("flush");

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("the head must arrive without waiting for the body")
        .expect("read");
    let got = String::from_utf8_lossy(&buf[..n]);
    assert!(
        got.starts_with("HTTP/1.1 200"),
        "the head must be on the wire; an unflushed buffer is the bug: {got:?}"
    );

    let _ = server.await;
}

/// **An empty write sends nothing, and the body is ended only by `finish`.**
#[tokio::test]
async fn an_empty_write_does_not_end_the_body() {
    let addr = free_addr();
    let listener = TcpListener::bind(addr).await.expect("bind");

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf).await;

        let mut writer = StreamWriter::begin(&mut sock, &sse_response(), Version::Http11)
            .await
            .expect("head");
        writer.write_now(b"before").await.expect("first");
        writer.write_now(b"").await.expect("empty is not an error");
        writer.write(b"").await.expect("empty is not an error");
        writer
            .write_now(b"after")
            .await
            .expect("after the idle moment");
        writer.finish().await.expect("terminator");
    });

    let mut client = TcpStream::connect(addr).await.expect("connect");
    client
        .write_all(b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("request");
    client.flush().await.expect("flush");
    let raw = read_all(&mut client).await;

    server.await.expect("server task");
    let (_, _, body) = parse(&raw);
    assert_eq!(
        String::from_utf8_lossy(&body),
        "beforeafter",
        "an empty write must send no bytes and end nothing"
    );
}

/// **An HTTP/1.0 streaming response is delimited by EOF, not by a chunk terminator.**
#[tokio::test]
async fn an_http10_stream_writes_no_chunk_terminator() {
    let addr = free_addr();
    let listener = TcpListener::bind(addr).await.expect("bind");

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf).await;

        let mut writer = StreamWriter::begin(&mut sock, &sse_response(), Version::Http10)
            .await
            .expect("head");
        writer.write(b"raw-body-for-http10").await.expect("body");
        writer.finish().await.expect("finish");
        let _ = sock.shutdown().await;
    });

    let mut client = TcpStream::connect(addr).await.expect("connect");
    client
        .write_all(b"GET /events HTTP/1.0\r\nHost: x\r\n\r\n")
        .await
        .expect("request");
    client.flush().await.expect("flush");
    let raw = read_all(&mut client).await;

    server.await.expect("server task");
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no terminator in {text:?}"));

    assert!(head.starts_with("HTTP/1.0 200"), "{head}");
    assert!(
        head.contains("Connection: close"),
        "HTTP/1.0 must close to delimit the body: {head}"
    );
    assert!(
        !head.contains("Transfer-Encoding"),
        "HTTP/1.0 has no chunked encoding: {head}"
    );
    assert_eq!(body, "raw-body-for-http10", "{body:?}");
}

/// **A client disconnect is reported, not panicked on.**
#[tokio::test]
async fn a_client_disconnect_is_an_error_the_handler_can_see() {
    let addr = free_addr();
    let listener = TcpListener::bind(addr).await.expect("bind");

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf).await;

        let mut writer = StreamWriter::begin(&mut sock, &sse_response(), Version::Http11)
            .await
            .expect("head");
        for i in 0..100_000u32 {
            if writer
                .write_now(&Event::data(format!("n{i}")).encode())
                .await
                .is_err()
            {
                return StreamOutcome::ClientClosed;
            }
        }
        StreamOutcome::Completed
    });

    {
        let mut client = TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect("request");
        let mut buf = [0u8; 64];
        let _ = client.read(&mut buf).await;
    }

    let outcome = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the server task must not hang")
        .expect("the server task must not panic");

    assert_eq!(
        outcome,
        StreamOutcome::ClientClosed,
        "a disconnect must be reported as the normal end of a stream"
    );
}

/// `finish` is idempotent, so a handler that calls it twice writes one terminator.
#[tokio::test]
async fn finish_is_idempotent() {
    let addr = free_addr();
    let listener = TcpListener::bind(addr).await.expect("bind");

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf).await;

        let mut writer = StreamWriter::begin(&mut sock, &sse_response(), Version::Http11)
            .await
            .expect("head");
        writer.write_now(b"x").await.expect("body");
        writer.finish().await.expect("first finish");
        writer.finish().await.expect("second finish is a no-op");
        let _ = sock.shutdown().await;
    });

    let mut client = TcpStream::connect(addr).await.expect("connect");
    client
        .write_all(b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("request");
    client.flush().await.expect("flush");
    let raw = read_all(&mut client).await;

    server.await.expect("server task");
    let text = String::from_utf8_lossy(&raw);
    let occurrences = text.matches("0\r\n\r\n").count();
    assert_eq!(occurrences, 1, "exactly one terminator, not two: {text:?}");
}
