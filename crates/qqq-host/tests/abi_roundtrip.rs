// SPDX-License-Identifier: Apache-2.0

//! The `qqq:http` ABI types, checked against the **WIT source**.
//!
//! # What this proves that the unit tests cannot
//!
//! `abi.rs`'s own tests pin the variant order against a literal list written by
//! hand — a second description of the same fact, and a second description can
//! drift. This file reads `wit/qqq-http.wit` itself and compares, which is the
//! difference `§O-141` records: a test and an implementation that share a wrong
//! assumption cannot correct each other.
//!
//! The variant order is load-bearing because a WIT `enum` lowers to a **case
//! index**. Reordering the Rust variants renumbers the wire encoding, and the
//! failure — `POST` arriving as `PUT` — is invisible to a type checker.
//!
//! # The gap this file used to have, and what closed it
//!
//! The first version compared `Method::ALL` against the WIT. `ALL` is a hand-
//! written array, so it is a *third* description of the same fact — and a fault
//! injection that reordered the enum's **declaration** (the thing the compiler
//! actually numbers) was not caught by anything. `the_all_array_matches_the_
//! declaration_order` below parses the source and closes that gap: the chain is
//! now WIT → declaration → `ALL`, with a check at each link.

use qqq_host::abi::{Header, HttpError, Method, Request, Response};

/// The WIT source, as text, read at test time.
fn wit_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../wit/qqq-http.wit");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("`{}`: {e}", path.display()))
}

/// The bare variant names in a WIT `enum`/`variant` block, in order.
///
/// Doc comments are filtered out — they are prose, not variants — and a variant
/// must be lower-case kebab (the WIT naming rule), so a comment line ending in a
/// comma cannot be mistaken for one.
fn variants_of(wit: &str, header: &str) -> Vec<String> {
    let block = wit
        .split(header)
        .nth(1)
        .unwrap_or_else(|| panic!("the WIT must declare `{header}`"));
    let body = block.split('}').next().expect("the block is closed");
    body.lines()
        .map(|l| l.trim().trim_end_matches(','))
        .filter(|l| !l.is_empty() && !l.starts_with("//"))
        .filter(|l| l.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_method_order_matches_the_wit() {
    let wit = wit_source();
    let from_wit = variants_of(&wit, "enum method {");
    let from_rust: Vec<&str> = Method::ALL.iter().map(|m| m.as_wit_str()).collect();

    assert!(!from_wit.is_empty(), "the WIT parse found no methods");
    assert_eq!(
        from_wit, from_rust,
        "the Rust `Method` order must be the WIT's, because it is the wire encoding"
    );
}

#[test]
fn the_error_order_matches_the_wit() {
    let wit = wit_source();
    let from_wit = variants_of(&wit, "variant http-error {");
    let from_rust: Vec<&str> = HttpError::ALL.iter().map(|e| e.as_wit_str()).collect();

    assert!(!from_wit.is_empty(), "the WIT parse found no errors");
    assert_eq!(
        from_wit, from_rust,
        "the Rust `HttpError` order must be the WIT's"
    );
}

#[test]
fn the_all_array_matches_the_declaration_order() {
    // Why this exists, measured: a fault injection that swapped two variants in
    // the **enum declaration** -- the order the compiler numbers -- was not caught
    // by any test, because every test went through `ALL`. `ALL` is hand-written,
    // so it is a third description that can drift from the declaration.
    //
    // The chain is now WIT -> declaration -> ALL, with a check at each link.
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/abi.rs"),
    )
    .expect("the ABI source must be readable");

    let declared = |enum_name: &str| -> Vec<String> {
        let block = source
            .split(&format!("pub enum {enum_name} {{"))
            .nth(1)
            .unwrap_or_else(|| panic!("`{enum_name}` must be declared"));
        let body = block.split("\n}").next().expect("the block is closed");
        body.lines()
            .map(str::trim)
            // A variant line is exactly `Name,` -- doc comments and attributes
            // are filtered because they are not variants.
            .filter(|l| l.ends_with(',') && !l.starts_with("//") && !l.starts_with('#'))
            .map(|l| l.trim_end_matches(',').to_owned())
            .collect()
    };

    // `Method`: the declared names, and the ones `ALL` lists, must agree.
    let method_declared = declared("Method");
    let method_all: Vec<String> = Method::ALL.iter().map(|m| format!("{m:?}")).collect();
    assert!(!method_declared.is_empty(), "the parse found no variants");
    assert_eq!(
        method_declared, method_all,
        "`Method::ALL` must list the variants in their declared order, because the \
         declaration is what the compiler numbers"
    );

    // And the `#[component(name = "...")]` attribute above each variant must agree
    // with what `as_wit_str` returns. Without this the wire name could be changed
    // on one side only: `as_wit_str` is hand-written and the attribute is what the
    // canonical ABI actually uses, so a mismatch would send `patch` while this
    // crate believed it sent `patched`.
    //
    // This is the third link in the chain (WIT -> declaration -> ALL -> attribute),
    // and it exists because a fault injection renamed the attribute and nothing
    // noticed.
    let attr_of = |enum_name: &str, variant: &str| -> Option<String> {
        let block = source
            .split(&format!("pub enum {enum_name} {{"))
            .nth(1)
            .expect("declared");
        let body = block.split("\n}").next().expect("closed");
        let mut pending: Option<String> = None;
        for line in body.lines().map(str::trim) {
            if let Some(rest) = line.strip_prefix("#[component(name = \"") {
                pending = Some(rest.trim_end_matches("\")]").to_owned());
            } else if line == format!("{variant},") {
                return pending;
            }
        }
        None
    };

    for m in Method::ALL {
        let attr = attr_of("Method", &format!("{m:?}"));
        assert_eq!(
            attr.as_deref(),
            Some(m.as_wit_str()),
            "`Method::{m:?}` must carry `#[component(name = \"{}\")]`, because that \
             attribute -- not `as_wit_str` -- is what the canonical ABI encodes",
            m.as_wit_str()
        );
    }
    for e in HttpError::ALL {
        let attr = attr_of("HttpError", &format!("{e:?}"));
        assert_eq!(
            attr.as_deref(),
            Some(e.as_wit_str()),
            "`HttpError::{e:?}` must carry `#[component(name = \"{}\")]`",
            e.as_wit_str()
        );
    }

    let error_declared = declared("HttpError");
    let error_all: Vec<String> = HttpError::ALL.iter().map(|e| format!("{e:?}")).collect();
    assert!(!error_declared.is_empty(), "the parse found no variants");
    assert_eq!(
        error_declared, error_all,
        "`HttpError::ALL` must list the variants in their declared order"
    );
}

#[test]
fn the_request_and_response_fields_match_the_wit() {
    let wit = wit_source();

    let request_block = wit
        .split("record request {")
        .nth(1)
        .expect("the WIT declares `record request`")
        .split('}')
        .next()
        .expect("closed");
    let response_block = wit
        .split("record response {")
        .nth(1)
        .expect("the WIT declares `record response`")
        .split('}')
        .next()
        .expect("closed");

    for field in ["method", "url", "headers", "body"] {
        assert!(
            request_block.contains(&format!("{field}:")),
            "`qqq:http/request` must declare `{field}`; block was:\n{request_block}"
        );
    }
    for field in ["status", "headers", "body"] {
        assert!(
            response_block.contains(&format!("{field}:")),
            "`qqq:http/response` must declare `{field}`; block was:\n{response_block}"
        );
    }

    // The Rust types are constructed with exactly those fields, so a rename is a
    // compile error rather than a silent ABI drift.
    let req = Request {
        method: Method::Post,
        url: "/orders".to_owned(),
        headers: vec![],
        body: None,
    };
    let res = Response {
        status: 201,
        headers: vec![Header {
            name: "location".to_owned(),
            value: b"/orders/42".to_vec(),
        }],
        body: b"created".to_vec(),
    };
    assert_eq!(req.method, Method::Post);
    assert_eq!(res.status, 201);
}

#[test]
fn an_absent_body_is_distinct_from_an_empty_one() {
    // `option<list<u8>>` lowers `None` and `Some(vec![])` differently, and the
    // distinction carries meaning: a `POST` with no body and one with an empty
    // body are different requests.
    let absent = Request {
        method: Method::Post,
        url: "/orders".to_owned(),
        headers: vec![],
        body: None,
    };
    let empty = Request {
        body: Some(vec![]),
        ..absent.clone()
    };
    assert_ne!(absent, empty, "None and Some(empty) must not compare equal");
}

#[test]
fn a_header_value_is_bytes_not_a_string() {
    // A header value is not guaranteed UTF-8, and a host that forced it would
    // mangle a valid request. The field's type is the assertion.
    let h = Header {
        name: "x-bytes".to_owned(),
        value: vec![0xff, 0xfe, 0x00],
    };
    assert_eq!(h.value.len(), 3);
    assert_eq!(h.value[0], 0xff);
}
