// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! The serve-side regression corpus — the always-on half of `I-07`.
//!
//! # Why this file exists beside the fuzzer
//!
//! `fuzz/fuzz_targets/http1_diff.rs` explores randomly on nightly with
//! libFuzzer; this file pins the **known** shapes on stable Rust in every
//! `cargo test`. The two are complements: a crash the fuzzer finds is
//! promoted here as a row (see `fuzz.yml`'s follow-up text), and from that
//! moment the shape is checked on the commit that would reintroduce it.
//!
//! # Why QQQ-side expectations only, never httparse's
//!
//! `httparse` is a dependency of the fuzz crate only (`I-07` keeps the
//! reference parser out of the shipped tree). A regression entry therefore
//! asserts what QQQ does with the bytes — accepts with these fields, or
//! refuses — and the differential property itself is re-proven by the
//! nightly differential run, not duplicated here.

use qqq_serve::http1::{Version, parse_head};
use qqq_serve::route::Method;

/// The rows `F-04` accepts, with the fields each must parse to.
///
/// Every row here is also a seed file under `fuzz/corpus/http1_diff/`, so
/// the nightly run starts from the shapes the unit tests pin rather than
/// from empty bytes.
#[test]
fn f04_accept_rows_parse_to_their_fields() {
    let rows: &[(&str, Method, &str, Version)] = &[
        (
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            Method::Get,
            "/",
            Version::Http11,
        ),
        (
            "GET / HTTP/1.1\r\nhOsT: Example.COM\r\n\r\n",
            Method::Get,
            "/",
            Version::Http11,
        ),
        (
            "POST /o HTTP/1.1\r\nHost: x\r\ncOnTeNt-LeNgTh: 3\r\n\r\n",
            Method::Post,
            "/o",
            Version::Http11,
        ),
        (
            "POST /o HTTP/1.1\r\nHost: x\r\ntRansfer-ENCoding: chunked\r\n\r\n",
            Method::Post,
            "/o",
            Version::Http11,
        ),
        (
            "GET / HTTP/1.1\r\n123456789: v\r\nHost: x\r\n\r\n",
            Method::Get,
            "/",
            Version::Http11,
        ),
        (
            "GET / HTTP/1.1\r\nX-Empty:\r\nHost: x\r\n\r\n",
            Method::Get,
            "/",
            Version::Http11,
        ),
        (
            "GET /search?q=1 HTTP/1.0\r\nHost: x\r\n\r\n",
            Method::Get,
            "/search?q=1",
            Version::Http10,
        ),
    ];
    for (raw, method, target, version) in rows {
        let (head, _) = parse_head(raw.as_bytes()).expect("F-04 accept row must parse");
        assert_eq!(head.method, *method, "method for {raw:?}");
        assert_eq!(head.target, *target, "target for {raw:?}");
        assert_eq!(head.version, *version, "version for {raw:?}");
    }

    let cl = parse_head(b"POST /o HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n")
        .expect("content-length row must parse");
    assert_eq!(cl.0.content_length, Some(3));
    assert!(!cl.0.chunked);
    let chunked = parse_head(b"POST /o HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
        .expect("chunked row must parse");
    assert!(chunked.0.chunked);
    assert_eq!(chunked.0.content_length, None);
    // QQQ normalises the method's case and surrounding space (`Method::parse`
    // trims and uppercases); the differential harness compares methods
    // case-insensitively for exactly this documented reason.
    let lower = parse_head(b"get / HTTP/1.1\r\nHost: x\r\n\r\n").expect("lowercase method parses");
    assert_eq!(lower.0.method, Method::Get);
}

/// The rows `F-04` refuses. Any one of these parsing is a regression —
/// and, through the differential target, a candidate smuggling shape.
#[test]
fn f04_reject_rows_are_refused() {
    let rows: &[&[u8]] = &[
        // Obs-fold continuation.
        b"GET / HTTP/1.1\r\nHost: x\r\n folded: yes\r\n\r\n",
        // Two Hosts.
        b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        // Tab separator and tab inside the target (`F-23`).
        b"GET\t/\tHTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /a\tb HTTP/1.1\r\nHost: x\r\n\r\n",
        // Non-ASCII target.
        "GET /caf\u{e9} HTTP/1.1\r\nHost: x\r\n\r\n".as_bytes(),
        // Whitespace in the name, colonless line, over-long unusable line.
        b"GET / HTTP/1.1\r\nHost : x\r\n\r\n",
        b"GET / HTTP/1.1\r\nX Bad: v\r\n\r\n",
        b"GET / HTTP/1.1\r\nNoColonHere\r\n\r\n",
        // Invalid UTF-8.
        b"GET / HTTP/1.1\r\nX-Bin: \xff\xfe\r\n\r\n",
        // Unknown method, relative target, bad version.
        b"FOO / HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET / HTTP/2.0\r\nHost: x\r\n\r\n",
        // Smuggling shapes: double framing and conflicting framing.
        b"POST /o HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n",
        b"POST /o HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"POST /o HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n",
    ];
    for raw in rows {
        assert!(
            parse_head(raw).is_err(),
            "must be refused: {:?}",
            String::from_utf8_lossy(raw)
        );
    }
}

/// The header-count boundary: exactly `MAX_HEADERS` parses, one more does not.
#[test]
fn header_count_boundary() {
    use std::fmt::Write as _;
    let mut many = String::from("GET / HTTP/1.1\r\n");
    for i in 0..qqq_serve::http1::MAX_HEADERS {
        let _ = write!(many, "X-Pad-{i}: v\r\n");
    }
    many.push_str("\r\n");
    assert!(parse_head(many.as_bytes()).is_ok());
    let mut too_many = String::from("GET / HTTP/1.1\r\n");
    for i in 0..=qqq_serve::http1::MAX_HEADERS {
        let _ = write!(too_many, "X-Pad-{i}: v\r\n");
    }
    too_many.push_str("\r\n");
    assert!(parse_head(too_many.as_bytes()).is_err());
}
