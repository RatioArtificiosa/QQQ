// SPDX-License-Identifier: Apache-2.0

//! The bridge from a served request to a guest call: `qqq-serve` + `qqq-abi` +
//! `qqq-host`, joined.
//!
//! # Why this lives in `qqq-run`
//!
//! The same reason [`crate::serve_routes`] does. `qqq-serve` owns the HTTP types
//! and must not depend on `qqq-host`; `qqq-host` owns the engine and must not
//! depend on the server. Proposal §4.3's order puts `qqq-run` above both, so this
//! is the only crate where a `RequestHead` can meet an `abi::Request`.
//!
//! # What this module is, and is not
//!
//! It is the **pure translation** between the two vocabularies, plus the call.
//! It is not `qqqai serve` (`CLI-011`): it has no listener, no `--workers` and no
//! config loading. Keeping it separate means the mapping is testable without a
//! socket, which is where the bugs in a mapping actually live.
//!
//! # The asymmetry this module refuses to hide
//!
//! `qqq-serve::Method` has **ten** variants; `abi::Method` has **nine**. The tenth
//! is `Extension`, which the router carries so an extension method cannot be
//! silently routed to the wrong handler. WIT's `qqq:http/method` has no case for
//! it, so an extension method **cannot be expressed to a guest at all**.
//!
//! [`to_guest`] therefore refuses it by name rather than folding it into `Get`.
//! Folding would be the "value that looks like an identifier and is not" defect:
//! a `PROPFIND` would reach the guest as a `GET`, and the guest would answer a
//! question nobody asked while every log line said the request was served.

use qqq_core::{Error, ErrorCode, Result};
use qqq_host::abi;
use qqq_serve::http1::RequestHead;
use qqq_serve::route::Method as ServeMethod;

/// Translate a served method into the guest's vocabulary.
///
/// # Errors
///
/// `QQQ-6004` for `Extension`. See the module documentation: the guest's `method`
/// enum has no case for an extension method, and a default would be a lie.
pub fn to_guest(method: ServeMethod) -> Result<abi::Method> {
    Ok(match method {
        ServeMethod::Get => abi::Method::Get,
        ServeMethod::Head => abi::Method::Head,
        ServeMethod::Post => abi::Method::Post,
        ServeMethod::Put => abi::Method::Put,
        ServeMethod::Patch => abi::Method::Patch,
        ServeMethod::Delete => abi::Method::Delete,
        ServeMethod::Options => abi::Method::Options,
        ServeMethod::Trace => abi::Method::Trace,
        ServeMethod::Connect => abi::Method::Connect,
        // Not representable, and refusing beats guessing. `Extension` also carries
        // no name of its own in this type -- the serve side matches it by its wire
        // text -- so even a "best effort" mapping would have nothing to send.
        ServeMethod::Extension => {
            return Err(Error::new(
                ErrorCode::InternalInvariantViolated,
                "an extension HTTP method cannot be expressed to a guest, because \
                 `qqq:http/method` has no case for one",
            )
            .with_context("method", "extension")
            .with_remediation(
                "declare the method in the manifest's route table using one of the \
                 nine methods `qqq:http` defines, or handle it in the host",
            ))
        }
    })
}

/// Build the guest-side request from a served one.
///
/// # Why the body is an argument rather than read from the head
///
/// [`RequestHead`] carries `content_length` and `chunked`, not the bytes: the
/// server streams a body and a head is parsed before the body arrives. So the
/// caller passes what it actually read.
///
/// # Why `content_length: Some(0)` becomes `Some(vec![])` and not `None`
///
/// The distinction is observable and the WIT makes it: `option<list<u8>>` lowers
/// `None` and `Some(vec![])` differently. A request that *declared* a zero-length
/// body sent a body that happens to be empty; a request with no `Content-Length`
/// and no chunking sent none. Collapsing them would tell a guest that a `POST`
/// with `Content-Length: 0` had no body, which is not what the client said.
///
/// # The URL is reconstructed, and that is a deliberate limit
///
/// The WIT's `request.url` is a **full** URL, but `RequestHead::target` is an
/// origin-form target (`/orders?x=1`) with no scheme or authority. The host knows
/// what it is serving on; a head alone does not. So the caller supplies the
/// authority, and this function refuses an empty one rather than emitting
/// `http:///orders` — a malformed URL the guest would reject for a reason that
/// named the wrong cause.
///
/// # Errors
///
/// As [`to_guest`], plus `QQQ-6004` when the authority is empty.
pub fn request_from_head(
    head: &RequestHead,
    authority: &str,
    body: Option<Vec<u8>>,
) -> Result<abi::Request> {
    if authority.is_empty() {
        return Err(Error::new(
            ErrorCode::InternalInvariantViolated,
            "the guest's request wants an absolute URL, and no authority was given",
        )
        .with_remediation(
            "pass the host authority the server is bound to, for example `127.0.0.1:8080`",
        ));
    }

    // The target is kept verbatim, including any query, because a guest routing on
    // it needs the whole thing and re-joining would lose `/a?` versus `/a`.
    let url = format!("http://{authority}{}", head.target);

    Ok(abi::Request {
        method: to_guest(head.method)?,
        url,
        headers: head
            .headers
            .iter()
            .map(|(name, value)| abi::Header {
                name: name.clone(),
                // A served header value is a `String` because the parser validated
                // it as one; the guest's type is bytes because not every header is
                // UTF-8. Widening is lossless and narrowing would not be.
                value: value.as_bytes().to_vec(),
            })
            .collect(),
        // `Some(vec![])` when the head declared a zero-length body, `None` when it
        // declared none. See the doc comment: the two are different facts.
        body: match (body, head.content_length, head.chunked) {
            (Some(b), _, _) => Some(b),
            (None, Some(0), _) => Some(Vec::new()),
            (None, _, _) => None,
        },
    })
}

/// Translate a guest's method back into the server's vocabulary.
///
/// Every `abi::Method` has a `qqq-serve::Method`, so this direction is total and
/// cannot fail. It exists as a function rather than an inline `match` so the
/// round-trip below can be tested for **all nine** — and so a future tenth guest
/// method cannot be added without this failing to compile.
#[must_use]
pub fn from_guest(method: abi::Method) -> ServeMethod {
    match method {
        abi::Method::Get => ServeMethod::Get,
        abi::Method::Head => ServeMethod::Head,
        abi::Method::Post => ServeMethod::Post,
        abi::Method::Put => ServeMethod::Put,
        abi::Method::Patch => ServeMethod::Patch,
        abi::Method::Delete => ServeMethod::Delete,
        abi::Method::Options => ServeMethod::Options,
        abi::Method::Trace => ServeMethod::Trace,
        abi::Method::Connect => ServeMethod::Connect,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_serve::http1::Version;

    fn head(method: ServeMethod, target: &str) -> RequestHead {
        RequestHead {
            method,
            target: target.to_owned(),
            version: Version::Http11,
            headers: vec![],
            content_length: None,
            chunked: false,
        }
    }

    #[test]
    fn every_served_method_maps_to_the_guest_except_extension() {
        // `ALL` on the serve side is every method it knows by name -- nine of them.
        // Each must map, because a method the server can route and the guest
        // cannot receive is a route that can never be served.
        for m in ServeMethod::ALL {
            assert!(
                to_guest(m).is_ok(),
                "`{}` must map into the guest's vocabulary",
                m.as_str()
            );
        }
    }

    #[test]
    fn an_extension_method_is_refused_by_name_rather_than_defaulted() {
        let err =
            to_guest(ServeMethod::Extension).expect_err("an extension method must be refused");

        assert!(
            err.message.contains("extension HTTP method"),
            "the message must name what cannot be expressed: {}",
            err.message
        );
        assert!(
            err.remediation.is_some(),
            "the refusal must say what to do instead: {err:?}"
        );
        // The critical property: it must NOT have been folded into anything.
        assert!(
            !err.message.contains("GET"),
            "the refusal must not imply a substitution: {}",
            err.message
        );
    }

    #[test]
    fn the_round_trip_is_identity_for_every_guest_method() {
        for m in abi::Method::ALL {
            assert_eq!(
                to_guest(from_guest(m)),
                Ok(m),
                "`{}` must round-trip",
                m.as_wit_str()
            );
        }
    }

    #[test]
    fn a_bodyless_request_has_no_body_and_an_empty_one_has_an_empty_body() {
        // The distinction is observable and the WIT encodes it. Collapsing them
        // would misreport what the client sent.
        let mut no_body = head(ServeMethod::Post, "/orders");
        no_body.content_length = None;
        let r = request_from_head(&no_body, "127.0.0.1:8080", None).expect("ok");
        assert_eq!(r.body, None, "a request that declared no body has none");

        let mut empty = head(ServeMethod::Post, "/orders");
        empty.content_length = Some(0);
        let r = request_from_head(&empty, "127.0.0.1:8080", None).expect("ok");
        assert_eq!(
            r.body,
            Some(Vec::new()),
            "`Content-Length: 0` declared a body, and it is empty"
        );

        // And an explicitly-passed body wins over the head, because the caller
        // read it.
        let mut with = head(ServeMethod::Post, "/orders");
        with.content_length = Some(3);
        let r = request_from_head(&with, "127.0.0.1:8080", Some(b"abc".to_vec())).expect("ok");
        assert_eq!(r.body, Some(b"abc".to_vec()));
    }

    #[test]
    fn the_url_is_absolute_and_keeps_the_query_verbatim() {
        let h = head(ServeMethod::Get, "/orders?status=open&limit=10");
        let r = request_from_head(&h, "api.example.com:443", None).expect("ok");
        assert_eq!(
            r.url,
            "http://api.example.com:443/orders?status=open&limit=10"
        );
    }

    #[test]
    fn an_empty_authority_is_refused_rather_than_producing_a_malformed_url() {
        // `http:///orders` is a URL a guest would reject for a reason that names
        // the wrong cause -- "invalid URL" when the real problem is a missing
        // authority the host forgot to supply.
        let h = head(ServeMethod::Get, "/orders");
        let err = request_from_head(&h, "", None).expect_err("an empty authority must be refused");
        assert!(
            err.remediation
                .as_deref()
                .is_some_and(|r| r.contains("authority")),
            "the remediation must name what is missing: {err:?}"
        );
    }

    #[test]
    fn headers_cross_as_bytes_without_loss() {
        let mut h = head(ServeMethod::Get, "/");
        h.headers = vec![
            ("accept".to_owned(), "application/json".to_owned()),
            ("x-empty".to_owned(), String::new()),
        ];
        let r = request_from_head(&h, "h", None).expect("ok");
        assert_eq!(r.headers.len(), 2);
        assert_eq!(r.headers[0].name, "accept");
        assert_eq!(r.headers[0].value, b"application/json");
        assert_eq!(
            r.headers[1].value,
            Vec::<u8>::new(),
            "an empty value stays empty"
        );
    }
}
