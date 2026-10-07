// SPDX-License-Identifier: Apache-2.0

//! Calling a guest's handler: the request in, the response out.
//!
//! # What this adds to `invoke`
//!
//! [`crate::invoke`] resolves *which* function to call. This module performs the
//! call: it sends an [`abi::Request`] through the typed API Wasmtime wants,
//! calls the guest, and reads the answer back.
//!
//! # Why the typed API on the hot path, and the dynamic `Val` form kept
//!
//! The HTTP interface is known at host build time — `validate_interface`
//! proves the exact same types — so the dynamic form's per-byte `Val::U8`
//! allocation (48 bytes per payload byte, measured) is pure overhead on the
//! request path. The dynamic form survives for diagnostics
//! ([`call_handler_raw`]) and its shape tests, where its honest type-checking
//! (a runtime check that names the problem rather than silently
//! reinterpreting a field) is worth more than speed, and where a 64 KiB cap
//! per byte list keeps inspection from becoming amplification.
//!
//! # The shape of the call, measured
//!
//! The guest's `handle: func(req: request) -> result<response, http-error>` has one
//! parameter and one result. The dynamic diagnostic form builds:
//!
//! ```text
//!   params[0]  = Val::Record([("method", Val::Enum("get")), ("url", Val::String(..)), …])
//!   results[0] = Val::Result(Ok(Some(Box::new(response_record))))
//!              | Val::Result(Err(Some(Box::new(Val::Enum("invalid-url")))))
//! ```
//!
//! Note the double wrapping on a refusal: the `http-error` **case** is the value,
//! because `http-error` is a plain variant with no payload. Reading it as
//! `Err(None)` — which also type-checks — would lose the guest's actual reason, so
//! [`decode_response`] treats that shape as malformed rather than guessing.

use wasmtime::component::Val;
use wasmtime::Store;

use qqq_core::{Error, ErrorCode, Result};

use crate::abi::{self, HttpError};
use crate::invoke::HandlerHandle;
use crate::linker::StoreData;

/// Encode a request as the guest's parameter.
///
/// # Why the field order is not load-bearing, unlike an enum's
///
/// A component-model record lowers **by name**, which is what the
/// `Vec<(String, Val)>` form encodes. Reordering these entries would not change
/// the wire — the opposite of the `enum` case, where the order *is* the encoding.
/// The field **names** are what must match, and a typo is reported by Wasmtime's
/// type check at the call site rather than silently misread.
///
/// # Diagnostic-only, capped at 64 KiB per byte list
///
/// The production path calls through [`call_handler`] with the typed API and
/// never builds these `Val`s. This encoder serves the diagnostic path
/// ([`call_handler_raw`]) and its own shape tests only, so any byte list
/// over 64 KiB is refused before the 48-bytes-per-byte amplification can
/// run: diagnostics must not become the denial of service the production
/// path just stopped being.
///
/// # Errors
///
/// `QQQ-2005` when a header value or the body exceeds 64 KiB.
pub fn encode_request(req: &abi::Request) -> Result<Val> {
    const DIAGNOSTIC_CAP: usize = 64 * 1024;
    fn capped_list(bytes: &[u8], what: &str) -> Result<Val> {
        if bytes.len() > DIAGNOSTIC_CAP {
            return Err(Error::new(
                ErrorCode::LimitOutOfRange,
                format!("diagnostic encode refuses {what} over 64 KiB"),
            )
            .with_remediation(
                "the typed production path has no such cap; the dynamic \
                 diagnostic path exists for inspection, not bulk transfer",
            ));
        }
        Ok(Val::List(bytes.iter().copied().map(Val::U8).collect()))
    }
    let mut headers = Vec::with_capacity(req.headers.len());
    for h in &req.headers {
        headers.push(Val::Record(vec![
            ("name".to_owned(), Val::String(h.name.clone())),
            ("value".to_owned(), capped_list(&h.value, "a header value")?),
        ]));
    }
    Ok(Val::Record(vec![
        (
            "method".to_owned(),
            Val::Enum(req.method.as_wit_str().to_owned()),
        ),
        ("url".to_owned(), Val::String(req.url.clone())),
        ("headers".to_owned(), Val::List(headers)),
        (
            "body".to_owned(),
            // `option<list<u8>>`. `Val::Option(None)` and `Val::Option(Some(empty))`
            // are different values, which is the distinction `guest_bridge`
            // preserves from the HTTP side.
            Val::Option(match &req.body {
                None => None,
                Some(b) => Some(Box::new(capped_list(b, "a request body")?)),
            }),
        ),
    ]))
}

/// Why a guest's returned value could not be read as a response.
///
/// Each variant is a distinct thing to fix, and collapsing them into one message
/// would send an operator to the wrong place — the same argument
/// [`crate::invoke::Failure`] makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeFailure {
    /// The result was an error the guest chose to return.
    ///
    /// Not a host failure: the guest answered, and its answer was "I could not do
    /// this". Carries the guest's own [`HttpError`].
    GuestRefused(HttpError),
    /// The result was `Ok` but carried no response.
    ///
    /// The double-wrapping trap: `result<response, http-error>` in the dynamic
    /// form is `Ok(Some(response))`. An `Ok(None)` type-checks and reads as "the
    /// guest returned nothing", so it is named rather than defaulted.
    OkWithoutResponse,
    /// A value had the wrong shape for its declared type.
    ///
    /// Carries what was found, because "malformed" without the actual shape is a
    /// riddle.
    Malformed(String),
}

impl DecodeFailure {
    /// A stable, machine-readable name.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::GuestRefused(_) => "guest_refused",
            Self::OkWithoutResponse => "ok_without_response",
            Self::Malformed(_) => "malformed",
        }
    }

    /// The error a caller reports.
    #[must_use]
    pub fn to_error(&self, component: &str) -> Error {
        let (message, fix) = match self {
            Self::GuestRefused(e) => (
                format!("`{component}` refused the request: {}", e.human_message()),
                "this is the guest's own answer, not a host failure: the request was \
                 understood and declined",
            ),
            Self::OkWithoutResponse => (
                format!("`{component}`'s handler returned `ok` with no response"),
                "this is a QQQ bug: `result<response, http-error>` cannot produce `ok` \
                 without a response, so the value was misread",
            ),
            Self::Malformed(what) => (
                format!("`{component}`'s handler returned a value that is not a response: {what}"),
                "the component and this host disagree about `qqq:http/response`",
            ),
        };
        Error::new(ErrorCode::InternalInvariantViolated, message)
            .with_context("component", component.to_owned())
            .with_remediation(fix)
    }
}

/// Read a guest's returned value as a response.
///
/// # Errors
///
/// [`DecodeFailure`] converted to an [`Error`], naming which shape was wrong.
pub fn decode_response(value: &Val, component: &str) -> Result<abi::Response> {
    let Val::Result(inner) = value else {
        return Err(
            DecodeFailure::Malformed(format!("found {}", kind_of(value))).to_error(component),
        );
    };

    match inner {
        Err(payload) => {
            // The refusal case travels as the payload, because `http-error` is a
            // variant whose *case* is the whole value. `Err(None)` would lose the
            // reason, so it is refused rather than guessed at.
            let e = payload
                .as_deref()
                .and_then(decode_http_error)
                .ok_or_else(|| {
                    DecodeFailure::Malformed(
                        "an error result with no `http-error` case; the case is the value"
                            .to_owned(),
                    )
                    .to_error(component)
                })?;
            Err(DecodeFailure::GuestRefused(e).to_error(component))
        }
        Ok(None) => Err(DecodeFailure::OkWithoutResponse.to_error(component)),
        Ok(Some(payload)) => decode_record(payload).ok_or_else(|| {
            DecodeFailure::Malformed(format!("found {}", kind_of(payload))).to_error(component)
        }),
    }
}

/// The `http-error` case a guest returned, if the value names one.
#[must_use]
pub fn decode_http_error(value: &Val) -> Option<HttpError> {
    let name = match value {
        // Wasmtime produces `Enum` for a WIT `enum` and `Variant` for a `variant`.
        // `http-error` is declared `variant`, but both are accepted: refusing one
        // would reject a correct guest over a representation detail.
        Val::Enum(name) | Val::Variant(name, _) => name.as_str(),
        _ => return None,
    };
    HttpError::ALL.into_iter().find(|e| e.as_wit_str() == name)
}

/// Read a `qqq:http/response` record.
fn decode_record(value: &Val) -> Option<abi::Response> {
    let Val::Record(fields) = value else {
        return None;
    };

    let mut status = None;
    let mut headers = Vec::new();
    let mut body = Vec::new();

    for (name, v) in fields {
        match name.as_str() {
            "status" => status = u16::try_from(as_u64(v)?).ok(),
            "headers" => headers = decode_headers(v)?,
            "body" => body = decode_bytes(v)?,
            // An unknown field is not an error: a future `qqq:http` could add one,
            // and refusing a guest for being newer than its host is the opposite of
            // what a versioned interface is for.
            _ => {}
        }
    }

    Some(abi::Response {
        status: status?,
        headers,
        body,
    })
}

fn decode_headers(value: &Val) -> Option<Vec<abi::Header>> {
    let Val::List(items) = value else {
        return None;
    };
    items
        .iter()
        .map(|item| {
            let Val::Record(fields) = item else {
                return None;
            };
            let mut name = None;
            let mut value = None;
            for (k, v) in fields {
                match k.as_str() {
                    "name" => name = as_str(v),
                    "value" => value = decode_bytes(v),
                    _ => {}
                }
            }
            Some(abi::Header {
                name: name?,
                value: value?,
            })
        })
        .collect()
}

fn decode_bytes(value: &Val) -> Option<Vec<u8>> {
    let Val::List(items) = value else {
        return None;
    };
    items
        .iter()
        .map(|v| match v {
            Val::U8(b) => Some(*b),
            _ => None,
        })
        .collect()
}

fn as_str(value: &Val) -> Option<String> {
    match value {
        Val::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn as_u64(value: &Val) -> Option<u64> {
    match value {
        Val::U16(n) => Some(u64::from(*n)),
        Val::U32(n) => Some(u64::from(*n)),
        Val::U64(n) => Some(*n),
        _ => None,
    }
}

/// A human name for a value's shape, for an error message.
fn kind_of(value: &Val) -> &'static str {
    match value {
        Val::Bool(_) => "a bool",
        Val::S8(_) | Val::S16(_) | Val::S32(_) | Val::S64(_) => "a signed integer",
        Val::U8(_) | Val::U16(_) | Val::U32(_) | Val::U64(_) => "an unsigned integer",
        Val::Float32(_) | Val::Float64(_) => "a float",
        Val::Char(_) => "a char",
        Val::String(_) => "a string",
        Val::List(_) | Val::FixedLengthList(_) => "a list",
        Val::Map(_) => "a map",
        Val::Record(_) => "a record",
        Val::Tuple(_) => "a tuple",
        Val::Variant(..) => "a variant",
        Val::Enum(_) => "an enum",
        Val::Option(_) => "an option",
        Val::Result(_) => "a result",
        Val::Flags(_) => "flags",
        Val::Resource(_) => "a resource",
        Val::Future(_) => "a future",
        Val::Stream(_) => "a stream",
        Val::ErrorContext(_) => "an error context",
    }
}

/// Call the guest's handler with a request.
///
/// The composition of everything else in this area: `invoke` resolved the export,
/// `abi` gave the types, and this performs the call and reads the answer.
///
/// # Typed hot path, dynamic diagnostics
///
/// The HTTP interface is known at host build time — `validate_interface`
/// proves the exact same types — so the request travels by value through
/// the typed API and Wasmtime lowers and lifts the byte lists with bulk
/// copies (~1x host memory) instead of one 48-byte `Val` per payload byte.
/// The dynamic `Val` form survives only for the diagnostic path
/// ([`call_handler_raw`]) and its shape tests. Errors map through the
/// identical constructor as before, so trap and mismatch codes are unchanged
/// by construction: `typed()` failures and call failures both report through
/// [`signature_mismatch`], and a guest refusal reports through
/// [`DecodeFailure::GuestRefused`] exactly as [`decode_response`] does.
///
/// # Errors
///
/// * A trap, or fuel/epoch exhaustion, from the guest's execution.
/// * A guest refusal, as [`DecodeFailure::GuestRefused`].
/// * `QQQ-6004` when the guest's signature does not match what was sent — which is
///   what turns a field-name typo into a *reported* error
///   rather than a silent misread.
pub fn call_handler(
    store: &mut Store<StoreData>,
    wasm: &wasmtime::component::Instance,
    handle: &HandlerHandle,
    request: abi::Request,
) -> Result<abi::Response> {
    let func = handle.func(store, wasm)?;

    let typed = func
        .typed::<(abi::Request,), (std::result::Result<abi::Response, abi::HttpError>,)>(
            &mut *store,
        )
        .map_err(|e| signature_mismatch(handle, &e))?;
    let (result,) = typed
        .call(&mut *store, (request,))
        .map_err(|e| signature_mismatch(handle, &e))?;
    result.map_err(|e| DecodeFailure::GuestRefused(e).to_error(handle.component()))
}

/// Call the handler and return the raw result value.
///
/// For a caller that wants to inspect what the guest actually returned — a future
/// `qqqai run` showing the value when a decode fails, and the tests here.
/// Diagnostic-only: byte lists over 64 KiB are refused before the `Val`
/// amplification (see [`encode_request`]).
///
/// # Errors
///
/// A trap, a signature mismatch as [`call_handler`], or an over-cap byte list.
pub fn call_handler_raw(
    store: &mut Store<StoreData>,
    wasm: &wasmtime::component::Instance,
    handle: &HandlerHandle,
    request: &abi::Request,
) -> Result<Val> {
    let func = handle.func(store, wasm)?;
    let params = [encode_request(request)?];
    let mut results = [Val::Bool(false)];
    func.call(&mut *store, &params, &mut results)
        .map_err(|e| signature_mismatch(handle, &e))?;
    Ok(results[0].clone())
}

/// The error for a call Wasmtime refused before the guest ran.
///
/// Named separately because this is the **only** place a wrong field name is
/// caught, and the message must say so: "the call was refused" alone sends an
/// operator to the guest, when the fault is in the host's encoding.
fn signature_mismatch(handle: &HandlerHandle, e: &wasmtime::Error) -> Error {
    Error::new(
        ErrorCode::InternalInvariantViolated,
        format!("the call to `{handle}` was refused before the guest ran: {e}"),
    )
    .with_context("component", handle.component().to_owned())
    .with_remediation(
        "this is a mismatch between the host's encoding and the component's declared \
         type; check the field names against `wit/qqq-http.wit`",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only the tests name a method directly; the module itself never does,
    // which is why this import is here and not at the top of the file.
    use crate::abi::Method;

    /// **F-03: `Val` is orders of magnitude wider than one byte.**
    ///
    /// This documents why `list<u8>` must never be marshalled as
    /// `Vec<Val::U8>` on the production path: every payload byte becomes a
    /// separately allocated enum value sized for the largest variant. The
    /// number below is what the 2 MiB request ceiling multiplies into tens
    /// of MiB of transient host heap.
    #[test]
    fn f03_val_is_much_wider_than_one_byte() {
        assert!(
            std::mem::size_of::<wasmtime::component::Val>() >= 16,
            "Val shrank: re-evaluate whether the dynamic path is still the amplification it was"
        );
    }

    fn a_request() -> abi::Request {
        abi::Request {
            method: Method::Post,
            url: "http://h/orders".to_owned(),
            headers: vec![abi::Header {
                name: "accept".to_owned(),
                value: b"application/json".to_vec(),
            }],
            body: Some(b"{}".to_vec()),
        }
    }

    #[test]
    fn a_request_encodes_with_the_field_names_the_wit_declares() {
        // The record lowers by NAME, so these strings are the contract. A typo is
        // caught by Wasmtime's type check rather than silently misread -- but it is
        // still a typo, and this makes it visible here instead.
        let Val::Record(fields) = encode_request(&a_request()).expect("small request encodes")
        else {
            panic!("a request must encode as a record");
        };
        let names: Vec<&str> = fields.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["method", "url", "headers", "body"]);
    }

    #[test]
    fn an_absent_body_encodes_as_none_and_an_empty_one_as_some() {
        // The distinction `guest_bridge` preserves from the HTTP side must survive
        // this far, or it is lost at the last step.
        let mut absent = a_request();
        absent.body = None;
        let Val::Record(f) = encode_request(&absent).expect("encodes") else {
            panic!("record")
        };
        let body = &f.iter().find(|(n, _)| n == "body").expect("body").1;
        assert!(matches!(body, Val::Option(None)), "got {body:?}");

        let mut empty = a_request();
        empty.body = Some(Vec::new());
        let Val::Record(f) = encode_request(&empty).expect("encodes") else {
            panic!("record")
        };
        let body = &f.iter().find(|(n, _)| n == "body").expect("body").1;
        assert!(
            matches!(body, Val::Option(Some(_))),
            "an empty body is still a body: got {body:?}"
        );
    }

    #[test]
    fn each_header_encodes_as_a_named_record_with_byte_values() {
        let Val::Record(f) = encode_request(&a_request()).expect("encodes") else {
            panic!("record")
        };
        let headers = &f.iter().find(|(n, _)| n == "headers").expect("headers").1;
        let Val::List(items) = headers else {
            panic!("headers must be a list")
        };
        assert_eq!(items.len(), 1);
        let Val::Record(h) = &items[0] else {
            panic!("each header is a record")
        };
        let names: Vec<&str> = h.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["name", "value"]);
        // The value is a list of bytes, not a string.
        let value = &h.iter().find(|(n, _)| n == "value").expect("value").1;
        assert!(matches!(value, Val::List(_)), "got {value:?}");
    }

    /// **F-03: the diagnostic encoder refuses byte lists over 64 KiB.**
    ///
    /// The cap that keeps inspection from becoming amplification. A 65 KiB
    /// body and a 65 KiB header value are each refused; exactly 64 KiB
    /// encodes. The production typed path has no such cap.
    #[test]
    fn f03_diagnostic_encode_refuses_byte_lists_over_64_kib() {
        let mut big_body = a_request();
        big_body.body = Some(vec![0xA5; 65 * 1024]);
        let err = encode_request(&big_body).expect_err("65 KiB body must be refused");
        assert_eq!(err.code, ErrorCode::LimitOutOfRange);

        let mut big_header = a_request();
        big_header.headers[0].value = vec![0xA5; 65 * 1024];
        let err = encode_request(&big_header).expect_err("65 KiB header must be refused");
        assert_eq!(err.code, ErrorCode::LimitOutOfRange);

        let mut exact = a_request();
        exact.body = Some(vec![0xA5; 64 * 1024]);
        assert!(
            encode_request(&exact).is_ok(),
            "exactly 64 KiB must still encode"
        );
    }

    #[test]
    fn a_refusal_decodes_from_either_enum_or_variant_form() {
        for e in HttpError::ALL {
            let as_enum = Val::Enum(e.as_wit_str().to_owned());
            let as_variant = Val::Variant(e.as_wit_str().to_owned(), None);
            assert_eq!(decode_http_error(&as_enum), Some(e));
            assert_eq!(decode_http_error(&as_variant), Some(e));
        }
        assert_eq!(decode_http_error(&Val::Enum("no-such".to_owned())), None);
    }

    #[test]
    fn a_guest_refusal_is_not_reported_as_a_host_failure() {
        let value = Val::Result(Err(Some(Box::new(Val::Enum(
            HttpError::HostNotAllowed.as_wit_str().to_owned(),
        )))));
        let err = decode_response(&value, "app.wasm").expect_err("a refusal is an error");

        assert!(
            err.message.contains("refused the request"),
            "the message must attribute the refusal to the guest: {}",
            err.message
        );
        assert!(
            err.remediation
                .as_deref()
                .is_some_and(|r| r.contains("not a host failure")),
            "the remediation must say it is the guest's own answer: {err:?}"
        );
    }

    #[test]
    fn an_error_result_without_a_case_is_refused_rather_than_guessed() {
        // `Err(None)` type-checks and produces no reason. Guessing a reason would
        // report a refusal the guest never gave.
        let value = Val::Result(Err(None));
        let err = decode_response(&value, "app.wasm").expect_err("must be refused");
        assert!(
            err.message.contains("no `http-error` case"),
            "the message must name the missing case: {}",
            err.message
        );
    }

    #[test]
    fn an_ok_without_a_response_is_named_rather_than_read_as_empty() {
        let value = Val::Result(Ok(None));
        let err = decode_response(&value, "app.wasm").expect_err("must be named");
        assert!(
            err.message.contains("`ok` with no response"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn a_well_formed_response_decodes() {
        let value = Val::Result(Ok(Some(Box::new(Val::Record(vec![
            ("status".to_owned(), Val::U16(201)),
            (
                "headers".to_owned(),
                Val::List(vec![Val::Record(vec![
                    ("name".to_owned(), Val::String("location".to_owned())),
                    (
                        "value".to_owned(),
                        Val::List(b"/orders/42".iter().copied().map(Val::U8).collect()),
                    ),
                ])]),
            ),
            (
                "body".to_owned(),
                Val::List(b"ok".iter().copied().map(Val::U8).collect()),
            ),
        ])))));

        let r = decode_response(&value, "app.wasm").expect("decodes");
        assert_eq!(r.status, 201);
        assert_eq!(r.headers.len(), 1);
        assert_eq!(r.headers[0].name, "location");
        assert_eq!(r.headers[0].value, b"/orders/42");
        assert_eq!(r.body, b"ok");
    }

    #[test]
    fn an_unknown_record_field_does_not_fail_the_decode() {
        // A future `qqq:http` could add one. Refusing a guest for being newer than
        // its host is the opposite of what a versioned interface is for.
        let value = Val::Result(Ok(Some(Box::new(Val::Record(vec![
            ("status".to_owned(), Val::U16(200)),
            ("headers".to_owned(), Val::List(vec![])),
            ("body".to_owned(), Val::List(vec![])),
            ("trailers".to_owned(), Val::List(vec![])),
        ])))));
        let r = decode_response(&value, "app.wasm").expect("must still decode");
        assert_eq!(r.status, 200);
    }

    #[test]
    fn a_non_result_value_is_malformed_rather_than_a_panic() {
        let err = decode_response(&Val::String("nope".to_owned()), "app.wasm")
            .expect_err("must be refused");
        assert!(
            err.message.contains("not a response"),
            "got: {}",
            err.message
        );
        assert!(
            err.message.contains("a string"),
            "the message must name what was found: {}",
            err.message
        );
    }

    #[test]
    fn a_response_missing_its_status_is_malformed_rather_than_defaulted() {
        // Defaulting a status would invent a result the guest did not give.
        let value = Val::Result(Ok(Some(Box::new(Val::Record(vec![
            ("headers".to_owned(), Val::List(vec![])),
            ("body".to_owned(), Val::List(vec![])),
        ])))));
        assert!(
            decode_response(&value, "app.wasm").is_err(),
            "a response with no status must not decode to a default"
        );
    }

    #[test]
    fn every_decode_failure_has_a_distinct_name() {
        let names = [
            DecodeFailure::GuestRefused(HttpError::InvalidUrl).as_str(),
            DecodeFailure::OkWithoutResponse.as_str(),
            DecodeFailure::Malformed("x".to_owned()).as_str(),
        ];
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "duplicate: {names:?}");
    }
}
