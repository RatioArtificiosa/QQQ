// SPDX-License-Identifier: Apache-2.0

//! Streaming request bodies over real bytes: chunked decoding, the size cap
//! enforced while the body arrives, and the framing offset left exact.
//!
//! Implements `SRV-004` and `SRV-005`; Proposal §6.4.
//!
//! # Why these drive a `Cursor` rather than a socket
//!
//! The body decoder's contract is about **bytes and offsets**, and a `Cursor`
//! over a byte slice makes the offset assertion exact: after a body is
//! consumed, the remaining slice *is* the next request's first byte. A socket
//! test can show that a following request parses, which is weaker — it cannot
//! show that nothing was over- or under-read when the following bytes happen to
//! be tolerant of both.
//!
//! `crates/qqq-serve/tests/socket.rs` covers the end-to-end path; these cover
//! the decoder, including malformed inputs a real client would never send.

use std::io::Cursor;

use qqq_serve::body::{discard, BodyChunk, BodyError, BodyReader, MAX_CHUNK_SIZE_LINE};
use qqq_serve::http1::{RequestHead, Version};
use qqq_serve::route::Method;

/// A head with the given framing, for `BodyReader::from_head`.
fn head(content_length: Option<u64>, chunked: bool) -> RequestHead {
    RequestHead {
        method: Method::Post,
        target: "/upload".to_owned(),
        version: Version::Http11,
        headers: Vec::new(),
        content_length,
        chunked,
    }
}

/// Read a whole body into a `Vec`, one small piece at a time.
///
/// The small piece size is deliberate: it is what makes the reader take multiple
/// iterations through its framing loop rather than one, so chunk-boundary bugs
/// are reachable. A single large `max` would complete most bodies in one call and
/// leave the boundary logic unexercised.
async fn read_all(reader: &mut BodyReader, input: &[u8]) -> Result<(Vec<u8>, usize), BodyError> {
    let mut io = Cursor::new(input.to_vec());
    let mut out = Vec::new();
    while let BodyChunk::Data(d) = reader.poll_chunk(&mut io, 3).await? {
        out.extend_from_slice(&d);
    }
    let position = usize::try_from(io.position()).expect("position fits in usize");
    Ok((out, position))
}

// ---------------------------------------------------------------------------
// Content-Length bodies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_length_delimited_body_is_delivered_and_stops_exactly() {
    let mut r = BodyReader::length_delimited(5, 1024);
    let (body, pos) = read_all(&mut r, b"HELLOrest").await.expect("read");

    assert_eq!(body, b"HELLO");
    // The offset assertion, and the reason a Cursor is used: the decoder must
    // stop precisely after five bytes, leaving `rest` for the next request.
    assert_eq!(pos, 5, "the reader consumed past the declared length");
    assert_eq!(r.bytes_read(), 5);
    assert!(r.is_finished());
}

#[tokio::test]
async fn a_body_short_of_its_declared_length_is_truncated_not_accepted() {
    // Three bytes declared, two sent. Accepting this would hand a handler a
    // body that is not what the client claimed.
    let mut r = BodyReader::length_delimited(3, 1024);
    let mut io = Cursor::new(b"AB".to_vec());
    let err = loop {
        match r.poll_chunk(&mut io, 3).await {
            Ok(BodyChunk::End) => panic!("a short body must not report End"),
            Ok(BodyChunk::Data(_)) => {}
            Err(e) => break e,
        }
    };
    assert_eq!(err, BodyError::Truncated);
}

#[tokio::test]
async fn a_zero_length_body_is_finished_before_any_read() {
    let mut r = BodyReader::length_delimited(0, 1024);
    assert!(r.is_finished(), "a zero-length body is complete at once");
    let mut io = Cursor::new(b"next request".to_vec());
    assert_eq!(
        r.poll_chunk(&mut io, 16).await.expect("read"),
        BodyChunk::End
    );
    assert_eq!(io.position(), 0, "nothing must be read for an empty body");
}

// ---------------------------------------------------------------------------
// The cap (SRV-005): enforced during streaming
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_length_delimited_body_past_the_cap_fails_without_reading_it_all() {
    // 100 bytes available, cap 10, requested 3 at a time. The failure must come
    // at the byte that passes the cap, not after the body is drained.
    let input = vec![b'x'; 100];
    let mut r = BodyReader::length_delimited(100, 10);
    let mut io = Cursor::new(input);

    // A `delivered` counter lived here and clippy removed its only use: it was
    // assigned and then discarded, so it asserted nothing. The claim worth making
    // about this defect is the one below, on the consumed offset — a variable
    // that merely tracked progress was decoration.
    let err = loop {
        match r.poll_chunk(&mut io, 3).await {
            Ok(BodyChunk::End) => panic!("a body past the cap must not succeed"),
            Ok(BodyChunk::Data(_)) => {}
            Err(e) => break e,
        }
    };

    match err {
        BodyError::TooLarge { limit, seen } => {
            assert_eq!(limit, 10);
            assert!(
                seen > 10,
                "the cap must be detected as it is passed: {seen}"
            );
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }

    // **This is the SRV-005 assertion.** The reader stopped near the cap rather
    // than consuming the 100 bytes available. If the cap were applied after
    // buffering, this position would be 100.
    assert!(
        io.position() <= 12,
        "the cap must stop the read near the limit, not buffer the whole body; \
         consumed {} of 100 bytes",
        io.position()
    );
}

#[tokio::test]
async fn a_chunked_body_past_the_cap_is_refused() {
    // Chunks of 4 bytes each, cap 5: the second chunk must trip it.
    let mut r = BodyReader::chunked(5);
    let input = b"4\r\nAAAA\r\n4\r\nBBBB\r\n0\r\n\r\n";
    let mut io = Cursor::new(input.to_vec());

    let err = loop {
        match r.poll_chunk(&mut io, 8).await {
            Ok(BodyChunk::End) => panic!("a body past the cap must not succeed"),
            Ok(BodyChunk::Data(_)) => {}
            Err(e) => break e,
        }
    };
    assert!(
        matches!(err, BodyError::TooLarge { .. }),
        "expected TooLarge, got {err:?}"
    );
}

#[tokio::test]
async fn a_body_exactly_at_the_cap_is_accepted() {
    // The boundary, and it is the one an off-by-one lives on: `>` not `>=`.
    let mut r = BodyReader::length_delimited(10, 10);
    let (body, _) = read_all(&mut r, &[b'a'; 10]).await.expect("read");
    assert_eq!(body.len(), 10);
    assert!(r.is_finished());
}

// ---------------------------------------------------------------------------
// Chunked decoding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_chunked_body_is_decoded_and_the_offset_lands_on_the_next_request() {
    let mut r = BodyReader::chunked(1024);
    let input = b"5\r\nHELLO\r\n6\r\n WORLD\r\n0\r\n\r\nGET /x HTTP/1.1\r\n";
    let (body, pos) = read_all(&mut r, input).await.expect("read");

    assert_eq!(body, b"HELLO WORLD");
    // The framing offset is knowable — the property `drain_body` closed the
    // connection for want of (§O-047a). `pos` must be exactly the start of the
    // next request.
    assert_eq!(
        pos,
        input.len() - b"GET /x HTTP/1.1\r\n".len(),
        "the decoder must stop after the final CRLF of the body, at the next request"
    );
    assert_eq!(&input[pos..], b"GET /x HTTP/1.1\r\n");
}

#[tokio::test]
async fn chunk_extensions_are_skipped_not_misread() {
    // A size line with an extension: the size is still 5. A decoder that parsed
    // the whole line as hex would fail here.
    //
    // The expected offset is derived from the input rather than written as a
    // constant: an earlier version hardcoded 20 and was simply miscounted by
    // hand (the real framed length is 26). Asserting against the input means the
    // test cannot be wrong about its own fixture.
    let mut r = BodyReader::chunked(1024);
    let input = b"5;name=value\r\nHELLO\r\n0\r\n\r\n";
    let (body, pos) = read_all(&mut r, input).await.expect("read");
    assert_eq!(body, b"HELLO");
    assert_eq!(pos, input.len());
}

#[tokio::test]
async fn a_chunked_body_with_trailers_leaves_the_offset_after_them() {
    // Trailers are discarded, but they must be *consumed*, or the next request
    // would be parsed starting at `X-Trailer:`.
    let mut r = BodyReader::chunked(1024);
    let input = b"3\r\nEND\r\n0\r\nx-trailer: v\r\n\r\nGET / HTTP/1.1\r\n";
    let (body, pos) = read_all(&mut r, input).await.expect("read");
    assert_eq!(body, b"END");
    assert_eq!(&input[pos..], b"GET / HTTP/1.1\r\n");
}

#[tokio::test]
async fn an_uppercase_hex_chunk_size_is_accepted() {
    // `from_str_radix` is case-insensitive, but the property is worth pinning:
    // RFC 9112 permits either case and some clients send uppercase.
    let mut r = BodyReader::chunked(1024);
    let (body, _) = read_all(&mut r, b"A\r\n0123456789\r\n0\r\n\r\n")
        .await
        .expect("read");
    assert_eq!(body, b"0123456789");
}

#[tokio::test]
async fn a_non_hexadecimal_chunk_size_is_refused() {
    let mut r = BodyReader::chunked(1024);
    let err = read_all(&mut r, b"zz\r\nAA\r\n0\r\n\r\n")
        .await
        .expect_err("must fail");
    assert!(
        matches!(err, BodyError::BadChunkSize { .. }),
        "expected BadChunkSize, got {err:?}"
    );
}

#[tokio::test]
async fn a_chunk_without_its_crlf_is_refused() {
    // The chunk's data is present but not its terminator. Accepting this leaves
    // the framing offset wrong, which is the smuggle shape.
    let mut r = BodyReader::chunked(1024);
    let err = read_all(&mut r, b"3\r\nABCXX0\r\n\r\n")
        .await
        .expect_err("must fail");
    assert_eq!(err, BodyError::MissingChunkTerminator);
}

#[tokio::test]
async fn a_chunked_body_without_its_final_chunk_is_truncated() {
    let mut r = BodyReader::chunked(1024);
    let err = read_all(&mut r, b"3\r\nABC\r\n")
        .await
        .expect_err("must fail");
    assert_eq!(err, BodyError::Truncated);
}

#[tokio::test]
async fn an_oversized_chunk_size_line_is_refused_before_buffering_it() {
    // A client that never sends a newline must not make the decoder allocate
    // without bound. The cap is checked as the line grows.
    let mut r = BodyReader::chunked(1024 * 1024);
    let input = vec![b'a'; MAX_CHUNK_SIZE_LINE + 10];
    let err = read_all(&mut r, &input).await.expect_err("must fail");
    assert_eq!(
        err,
        BodyError::ChunkSizeLineTooLong {
            limit: MAX_CHUNK_SIZE_LINE
        }
    );
}

#[tokio::test]
async fn an_empty_chunked_body_is_just_the_terminator() {
    let mut r = BodyReader::chunked(1024);
    let (body, pos) = read_all(&mut r, b"0\r\n\r\nNEXT").await.expect("read");
    assert!(body.is_empty());
    assert_eq!(pos, 5);
}

// ---------------------------------------------------------------------------
// Head-derived framing, and the smuggling check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_head_declaring_both_framings_is_refused() {
    // The request-smuggling shape. `http1` rejects this at parse time, so this
    // is the redundant second check — deliberately redundant, because a decoder
    // that trusted an upstream rejection would be one refactor from smuggling.
    let err = BodyReader::from_head(&head(Some(5), true), 1024).expect_err("must refuse");
    assert_eq!(
        err,
        BodyError::BadFraming {
            reason: "both Content-Length and Transfer-Encoding: chunked"
        }
    );
}

#[tokio::test]
async fn from_head_selects_the_framing_the_head_declares() {
    let none = BodyReader::from_head(&head(None, false), 1024).expect("ok");
    assert!(none.is_finished() && !none.is_chunked());

    let len = BodyReader::from_head(&head(Some(7), false), 1024).expect("ok");
    assert!(!len.is_chunked() && !len.is_finished());

    let chunked = BodyReader::from_head(&head(None, true), 1024).expect("ok");
    assert!(chunked.is_chunked() && !chunked.is_finished());
}

// ---------------------------------------------------------------------------
// discard: what the connection loop needs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discard_consumes_a_length_delimited_body_and_returns_its_size() {
    let mut r = BodyReader::from_head(&head(Some(5), false), 1024).expect("ok");
    let mut io = Cursor::new(b"HELLOrest".to_vec());
    let total = discard(&mut r, &mut io).await.expect("discard");
    assert_eq!(total, 5);
    assert_eq!(
        io.position(),
        5,
        "the connection is left at the next request"
    );
}

#[tokio::test]
async fn discard_consumes_a_chunked_body_and_returns_its_decoded_size() {
    let mut r = BodyReader::from_head(&head(None, true), 1024).expect("ok");
    let input = b"5\r\nHELLO\r\n5\r\nWORLD\r\n0\r\n\r\nNEXT";
    let mut io = Cursor::new(input.to_vec());
    let total = discard(&mut r, &mut io).await.expect("discard");
    assert_eq!(total, 10, "the decoded size, not the framed size");
    assert_eq!(&input[usize::try_from(io.position()).unwrap()..], b"NEXT");
}

#[tokio::test]
async fn discard_refuses_a_body_past_the_cap() {
    let mut r = BodyReader::from_head(&head(Some(50), false), 8).expect("ok");
    let mut io = Cursor::new(vec![b'x'; 50]);
    let err = discard(&mut r, &mut io).await.expect_err("must fail");
    assert!(matches!(err, BodyError::TooLarge { .. }), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Backpressure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_reader_never_reads_more_than_the_caller_asked_for() {
    // This is backpressure in its testable form: the caller's `max` is respected
    // exactly, so a handler that asks for little never causes a large read and
    // the peer's window stays closed while it is not asking.
    let mut r = BodyReader::length_delimited(100, 1000);
    let mut io = Cursor::new(vec![b'z'; 100]);

    for _ in 0..5 {
        match r.poll_chunk(&mut io, 4).await.expect("read") {
            BodyChunk::Data(d) => assert!(
                d.len() <= 4,
                "the reader returned {} bytes for a max of 4",
                d.len()
            ),
            BodyChunk::End => panic!("the body is not finished"),
        }
    }
    assert_eq!(io.position(), 20, "exactly five requests of four bytes");
}

#[tokio::test]
async fn a_zero_max_returns_no_data_and_reads_nothing() {
    // Not an error, and emphatically not `End` — the body has not ended. A
    // decoder that returned `End` here would truncate every body for a caller
    // that computed a zero-sized buffer.
    let mut r = BodyReader::length_delimited(10, 1000);
    let mut io = Cursor::new(vec![b'q'; 10]);
    assert_eq!(
        r.poll_chunk(&mut io, 0).await.expect("read"),
        BodyChunk::Data(Vec::new())
    );
    assert_eq!(io.position(), 0);
    assert!(
        !r.is_finished(),
        "a zero-size request must not finish the body"
    );
}
