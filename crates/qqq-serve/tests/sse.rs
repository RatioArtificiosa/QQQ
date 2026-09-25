// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for Server-Sent Events (`SRV-010`) over a real socket.
//!
//! # What these prove, and what they cannot
//!
//! The `sse` module's own 24 tests cover the framing: every field, every line-break
//! form, the leading-space rule, the reserved-id rule. None of them can show the bytes
//! reach a client, because that needs a socket.
//!
//! These tests drive the **actual primitives a streaming handler must use** —
//! `write_stream_head`, `write_chunk`, `write_last_chunk` and `Event::encode` — and
//! decode the result with an SSE parser written to the specification's algorithm. So
//! they prove the composition works, which is the seam where this project has found
//! most of its defects.
//!
//! # The wiring gap, stated rather than hidden
//!
//! `qqq-serve`'s `Handler` is `Fn(&RequestHead, &RouteMatch) -> Response` — synchronous,
//! returning a complete `Response` whose body is a `Vec<u8>`. A handler therefore
//! **cannot** stream: by the time it returns, its body is finished, and the server's
//! write path calls `write_response`, which emits `Content-Length`.
//!
//! So these tests speak the protocol over a raw socket rather than through `serve`.
//! That is a real limitation and it is named rather than papered over: SSE is complete
//! at the framing and framing-level integration, and reaching it through `serve`
//! requires `Handler` to gain an async streaming variant — the same change `SRV-004`
//! (streaming bodies with backpressure) needs, because both are blocked on one
//! interface decision. Writing these against `serve` instead would mean lying about
//! what `serve` does.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use qqq_serve::response::{write_chunk, write_last_chunk, write_stream_head};
use qqq_serve::sse::{self, Event};
use qqq_serve::{Response, Version};

/// A port nobody is using, for the reason `tests/socket.rs` documents.
fn free_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = l.local_addr().expect("addr");
    drop(l);
    a
}

/// An SSE response head, as a handler would build it.
fn head() -> Vec<u8> {
    let mut resp = Response::status(200);
    for (name, value) in sse::headers() {
        resp.set_header(name, value);
    }
    write_stream_head(&resp, Version::Http11, true)
}

/// Encode a full SSE response — head, events, terminator — as the client would read
/// it.
///
/// This is what a streaming handler performs. The `write`/`flush` per event in the
/// socket tests below is the point: a stream that buffered and flushed once at the end
/// would never deliver anything, because an SSE stream does not end.
fn serve_events(events: &[Event]) -> Vec<u8> {
    let mut wire = head();
    for event in events {
        wire.extend_from_slice(&write_chunk(&event.encode()));
    }
    wire.extend_from_slice(&write_last_chunk());
    wire
}

// ---------------------------------------------------------------------------
// A client, written to the specification's parsing algorithm
// ---------------------------------------------------------------------------

/// One parsed event, as a client's `EventSource` would hand it to a listener.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Received {
    event: Option<String>,
    data: String,
    id: Option<String>,
    retry: Option<u64>,
}

/// Parse a `text/event-stream` body the way the specification describes.
///
/// Written from the specification's algorithm rather than by splitting on `\n\n`,
/// because the difference is the whole point of these tests: the spec strips **one**
/// space after the colon, joins multiple `data:` lines with `\n`, and removes the last
/// one. A naive parser would agree with a naive encoder and both would be wrong
/// together, which is why the parser here is written independently of the encoder's
/// implementation.
fn parse(body: &str) -> Vec<Received> {
    let mut events = Vec::new();
    let mut current = Received::default();
    let mut data_lines: Vec<String> = Vec::new();
    let mut saw_data = false;

    for line in body.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            if saw_data || current.event.is_some() || current.id.is_some() {
                // The specification's final step: join the data lines, then remove the
                // trailing line break from the result.
                let mut joined = data_lines.join("\n");
                // `pop` on the owned `String` rather than slicing and cloning: the
                // slice form is what `clippy::assigning_clones` flags, and it is a
                // genuine second allocation for a one-byte trim.
                if joined.ends_with('\n') {
                    joined.pop();
                }
                current.data = joined;
                events.push(current.clone());
            }
            current = Received::default();
            data_lines.clear();
            saw_data = false;
            continue;
        }
        if line.starts_with(':') {
            // A comment is discarded by the client, exactly as the specification says.
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        match field {
            "event" => current.event = Some(value.to_owned()),
            "data" => {
                data_lines.push(value.to_owned());
                saw_data = true;
            }
            "id" => {
                if !value.contains('\u{0}') {
                    current.id = Some(value.to_owned());
                }
            }
            "retry" => {
                if let Ok(n) = value.parse() {
                    current.retry = Some(n);
                }
            }
            _ => {}
        }
    }
    events
}

/// Split an HTTP response into its head and its decoded body.
fn split_response(raw: &[u8]) -> (String, Vec<(String, String)>, Vec<u8>) {
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
// The framing
// ---------------------------------------------------------------------------

/// **A complete SSE exchange is well-framed.**
#[test]
fn a_sse_body_is_chunked_and_carries_the_three_headers() {
    let wire = serve_events(&[Event::data("hello")]);
    let (status, headers, body) = split_response(&wire);

    assert_eq!(status, "HTTP/1.1 200 OK");
    assert_eq!(header(&headers, "Transfer-Encoding"), Some("chunked"));
    assert_eq!(
        header(&headers, "Content-Length"),
        None,
        "an event stream has no length"
    );
    for (name, value) in sse::headers() {
        assert_eq!(header(&headers, name), Some(*value), "missing {name}");
    }
    assert_eq!(String::from_utf8_lossy(&body), "data:hello\n\n");
}

/// A multi-line payload survives the whole path: encode, chunk, decode, parse.
#[test]
fn a_multiline_payload_round_trips_through_the_client_parser() {
    let payload = "{\n  \"a\": 1,\n  \"b\": 2\n}";
    let wire = serve_events(&[Event::data(payload)]);
    let (_, _, body) = split_response(&wire);
    let events = parse(&String::from_utf8_lossy(&body));

    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(
        events[0].data, payload,
        "pretty-printed JSON is the common case and it must not be truncated"
    );
}

/// A leading space in a payload survives encode and parse.
///
/// The end-to-end form of the `data:  x` rule: the encoder adds a second space and the
/// parser the specification describes strips exactly one, so the payload arrives
/// unchanged. Only testing an encoder and a *specification-derived* parser against each
/// other catches this — a matching pair of bugs would agree and pass.
#[test]
fn a_leading_space_survives_encode_and_parse() {
    for payload in [" leading", "  two spaces", "no-space", "", " ", "a\n", "\n"] {
        let wire = serve_events(&[Event::data(payload)]);
        let (_, _, body) = split_response(&wire);
        let events = parse(&String::from_utf8_lossy(&body));
        assert_eq!(events.len(), 1, "payload {payload:?}");
        assert_eq!(events[0].data, payload, "payload {payload:?} was mangled");
    }
}

/// A comment produces no event but does produce bytes.
///
/// The keep-alive property: the client receives bytes and dispatches nothing. If a
/// keep-alive dispatched, every idle connection would wake its listeners once per
/// interval — the opposite of what a keep-alive is for.
#[test]
fn a_keep_alive_delivers_bytes_and_dispatches_nothing() {
    let wire = serve_events(&[Event::keep_alive("ping"), Event::data("real")]);
    let (_, _, body) = split_response(&wire);
    let text = String::from_utf8_lossy(&body);

    assert!(
        text.contains(":ping"),
        "the bytes must be on the wire: {text:?}"
    );
    let events = parse(&text);
    assert_eq!(
        events.len(),
        1,
        "only the real event dispatches: {events:?}"
    );
    assert_eq!(events[0].data, "real");
}

/// Every field of a full event arrives.
#[test]
fn a_full_event_round_trips() {
    let event = Event::data("payload")
        .with_event("update")
        .with_id("42")
        .with_retry(3000);
    let wire = serve_events(&[event]);
    let (_, _, body) = split_response(&wire);
    let events = parse(&String::from_utf8_lossy(&body));

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.as_deref(), Some("update"));
    assert_eq!(events[0].data, "payload");
    assert_eq!(events[0].id.as_deref(), Some("42"));
    assert_eq!(events[0].retry, Some(3000));
}

/// Many events arrive in order, and the count is exact.
///
/// Ordering and count are what a client's state machine depends on; a framing bug that
/// merged two events or dropped one is invisible in a single-event test.
#[test]
fn many_events_arrive_in_order() {
    let events: Vec<Event> = (0..100).map(|i| Event::data(format!("n{i}"))).collect();
    let wire = serve_events(&events);
    let (_, _, body) = split_response(&wire);
    let parsed = parse(&String::from_utf8_lossy(&body));

    assert_eq!(parsed.len(), 100, "every event must dispatch exactly once");
    for (i, got) in parsed.iter().enumerate() {
        assert_eq!(got.data, format!("n{i}"), "event {i} out of order");
    }
}

/// An id containing NUL is dropped, so a client never adopts an id it must ignore.
#[test]
fn an_id_with_nul_never_reaches_the_client() {
    let wire = serve_events(&[Event::data("x").with_id("a\u{0}b")]);
    let (_, _, body) = split_response(&wire);
    let events = parse(&String::from_utf8_lossy(&body));

    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].id, None,
        "the spec says a client ignores such an id, so emitting it loses the position"
    );
}

// ---------------------------------------------------------------------------
// Over a real socket
// ---------------------------------------------------------------------------

/// **The bytes reach a real TCP client, flushed per event.**
///
/// The point of the socket: a client reads the head and the events while the server is
/// still running, which is what streaming means and what a buffered response cannot do.
#[tokio::test]
async fn a_client_receives_the_head_and_events_incrementally() {
    let addr = free_addr();
    let listener = TcpListener::bind(addr).await.expect("bind");
    let events = [
        Event::data("first"),
        Event::keep_alive("ping"),
        Event::data("second"),
    ];

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        // Read the request head, so this is a real HTTP exchange rather than a
        // one-way write.
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf).await;
        sock.write_all(&head()).await.expect("head");
        sock.flush().await.expect("flush head");
        for event in &events {
            sock.write_all(&write_chunk(&event.encode()))
                .await
                .expect("event");
            // Flushed per event: without it the client sees nothing until the socket
            // buffer fills, which for a slow stream is never.
            sock.flush().await.expect("flush event");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        sock.write_all(&write_last_chunk()).await.expect("end");
        sock.flush().await.expect("flush end");
    });

    let mut client = TcpStream::connect(addr).await.expect("connect");
    client
        .write_all(b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("request");
    client.flush().await.expect("flush");

    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let mut chunk = [0u8; 4096];
        loop {
            match client.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;

    server.await.expect("server task");
    let (status, headers, body) = split_response(&raw);
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert_eq!(header(&headers, "Content-Type"), Some("text/event-stream"));

    let parsed = parse(&String::from_utf8_lossy(&body));
    assert_eq!(parsed.len(), 2, "two events and a comment: {parsed:?}");
    assert_eq!(parsed[0].data, "first");
    assert_eq!(parsed[1].data, "second");
}

/// A client that disconnects mid-stream is an error the writer can act on, not a panic.
///
/// A client closing an SSE stream is the **normal** end of one, so the server side must
/// treat the write error as an outcome rather than a failure. This asserts the shape the
/// caller must handle: `write_all` returns `Err`, and nothing panics.
#[tokio::test]
async fn a_client_disconnect_mid_stream_is_an_error_not_a_panic() {
    let addr = free_addr();
    let listener = TcpListener::bind(addr).await.expect("bind");

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf).await;
        sock.write_all(&head()).await.expect("head");
        // Write until the peer is gone. The error is the expected outcome, and the loop
        // is bounded so a failure to notice the disconnect cannot hang the test.
        let mut errored = false;
        for i in 0..100_000u32 {
            if sock
                .write_all(&write_chunk(&Event::data(format!("n{i}")).encode()))
                .await
                .is_err()
            {
                errored = true;
                break;
            }
        }
        errored
    });

    {
        let mut client = TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect("request");
        // Read a little, then vanish without terminating the body.
        let mut buf = [0u8; 64];
        let _ = client.read(&mut buf).await;
    }

    let errored = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the server task must not hang")
        .expect("the server task must not panic");
    assert!(
        errored,
        "writing to a closed socket must report an error the caller can act on"
    );
}
