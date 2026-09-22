// SPDX-License-Identifier: Apache-2.0

//! The guest handler a `Dispatch` can call: everything in this area, composed.
//!
//! # What this module is
//!
//! [`crate::guest_bridge`] maps HTTP to the ABI and `qqq_host::call` performs the
//! call. This module joins them into the shape `qqq-serve::Dispatch` wants — a
//! `Fn(&RequestHead, &RouteMatch) -> Response` — so a manifest's routes can be
//! served by a real guest.
//!
//! # Why a handler and not just a function
//!
//! `Dispatch::flat` takes `Arc<dyn Fn(..)>`, so the guest has to be captured in a
//! closure. The pieces that must travel with it are the **engine**, the compiled
//! component and the resolved [`HandlerHandle`] — and the handle is what makes this
//! cheap: it is resolved once here, not per request (`invoke`'s own documentation
//! gives the reason).
//!
//! # The authority problem, stated rather than hidden
//!
//! The guest's `request.url` is a **full** URL, and `RequestHead` carries only an
//! origin-form target. The host has to supply the authority, and this module takes
//! it as a parameter rather than inventing one, because:
//!
//! * `Host` from the request is **client-controlled**. Trusting it would let a
//!   client decide what the guest believes it is serving, which is a host-header
//!   injection into the guest's own routing logic.
//! * The bound authority is **configuration**, so it is what the server actually
//!   answers on.
//!
//! So the authority is configured at construction and used for every request.
//! That is the same choice a reverse proxy makes, and for the same reason.

use std::sync::Arc;

use qqq_cap::resolve::GrantSet;
use qqq_core::{Error, ErrorCode, Result};
use qqq_host::abi;
use qqq_host::call::call_handler;
use qqq_host::instance::Instance;
use qqq_host::invoke::HandlerHandle;
use qqq_host::{LimitSet, PreparedComponent};
use qqq_serve::http1::RequestHead;
use qqq_serve::response::Response;

use crate::guest_bridge;

/// A compiled guest, ready to answer requests.
///
/// Holds the three things every request needs and none of the per-request state:
/// the engine, the compiled component, and the resolved handle. An
/// `Instance` is created per request, which is the §4.2 isolation model — the
/// expensive work (compilation) happens once and the cheap work (instantiation)
/// happens per request.
pub struct GuestApp {
    engine: wasmtime::Engine,
    prepared: PreparedComponent,
    handle: HandlerHandle,
    grants: GrantSet,
    limits: LimitSet,
    /// The authority every guest-visible URL is built from. See the module docs.
    authority: String,
}

impl std::fmt::Debug for GuestApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestApp")
            .field("handle", &self.handle.to_string())
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

impl GuestApp {
    /// Prepare a guest from compiled bytes.
    ///
    /// # Why the handle is resolved here and not per request
    ///
    /// [`HandlerHandle::resolve`] needs a live instance, so one is created and
    /// discarded during preparation. That means **a component that is not a QQQ
    /// application is refused at start-up** rather than after a request has been
    /// read — which is the difference between a server that refuses to start and
    /// one that 500s on every request with a message nobody reads.
    ///
    /// # Errors
    ///
    /// * The component does not compile.
    /// * The component is not a QQQ application ([`qqq_host::invoke::Failure`]).
    /// * The authority is empty.
    pub fn new(
        engine: wasmtime::Engine,
        bytes: &[u8],
        grants: GrantSet,
        limits: LimitSet,
        authority: impl Into<String>,
    ) -> Result<Self> {
        let authority = authority.into();
        if authority.is_empty() {
            return Err(Error::new(
                ErrorCode::InternalInvariantViolated,
                "a guest app needs the authority its URLs are built from",
            )
            .with_remediation(
                "pass the host and port the server binds, for example `127.0.0.1:8080`",
            ));
        }

        let prepared = PreparedComponent::compile(&engine, bytes)?;

        // A throwaway instance, purely to resolve the export. Creating one here is
        // what turns "not a QQQ application" into a start-up failure.
        let handle = {
            let instance = Instance::create(&engine, &prepared, &grants, limits)?;
            instance.run(|store, wasm| {
                HandlerHandle::resolve(&mut *store, wasm, "guest")
                    .map_err(|e| wasmtime::Error::msg(e.message.clone()))
            })
        }
        .map_err(|e| {
            // `Instance::run` classifies a closure error as a trap, so the reason is
            // in the message. Re-wrapped here so the caller gets a QQQ error rather
            // than a trap summary -- the same shape `invoke`'s own tests document.
            Error::new(
                ErrorCode::InvalidComponentArtifact,
                format!("this component cannot serve requests: {e}"),
            )
            .with_remediation("build the app against `wit/app/app.wit`")
        })?;

        Ok(Self {
            engine,
            prepared,
            handle,
            grants,
            limits,
            authority,
        })
    }

    /// The authority guest-visible URLs are built from.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The resolved handler, for diagnostics.
    #[must_use]
    pub fn handle(&self) -> &HandlerHandle {
        &self.handle
    }

    /// Answer one request by calling the guest.
    ///
    /// # Errors
    ///
    /// * The instance could not be created (a grant or limit problem).
    /// * The method cannot be expressed to a guest (`guest_bridge::to_guest`).
    /// * The guest trapped, or returned a value that is not a response.
    pub fn handle_request(&self, head: &RequestHead, body: Option<Vec<u8>>) -> Result<Response> {
        // The body is what the caller read; the head only declares its length.
        let request = guest_bridge::request_from_head(head, &self.authority, body)?;

        let instance = Instance::create(&self.engine, &self.prepared, &self.grants, self.limits)?;

        // The guest's answer travels out of the closure in a slot: `Instance::run`
        // treats any closure error as a trap, which would replace the guest's own
        // reason with a trap summary. `call`'s own tests document that shape.
        let mut outcome: Option<Result<abi::Response>> = None;
        instance.run(|store, wasm| {
            outcome = Some(call_handler(&mut *store, wasm, &self.handle, &request));
            // The closure itself succeeds: the trap machinery is for the *guest's*
            // execution, and a host-side decode failure is not one.
            Ok(())
        })?;

        let response = outcome.ok_or_else(|| {
            Error::new(
                ErrorCode::InternalInvariantViolated,
                "the guest call produced no outcome",
            )
            .with_remediation("this is a QQQ bug; please report it")
        })??;

        Ok(to_served(&response))
    }

    /// Build a `Dispatch` handler that calls this guest.
    ///
    /// The shape `qqq-serve::server::Dispatch::flat` wants. Kept as a method so
    /// the `Arc` and the closure are built once rather than at every call site.
    ///
    /// # Why a failure becomes a 502 and not a 500
    ///
    /// A guest failure is **the upstream failing**, which is what 502 means, and a
    /// trap is a guest that misbehaved rather than the server being broken. A 500
    /// would tell an operator to look at QQQ; a 502 tells them to look at the app.
    ///
    /// # Why this ignores the body, and what to use instead
    ///
    /// A flat handler has nowhere to put a body, so this passes `None`. It remains
    /// correct for a route that declares no body and for the tests that only exercise
    /// the head path -- and it is what the type system permits, not an oversight.
    /// [`Self::dispatch_with_body`] is the one a write route needs.
    #[must_use]
    pub fn dispatch(self: &Arc<Self>) -> qqq_serve::Handler {
        let app = Arc::clone(self);
        Arc::new(
            move |head: &RequestHead, _matched: &qqq_serve::RouteMatch| match app
                .handle_request(head, None)
            {
                Ok(response) => response,
                Err(e) => failure_response(&e),
            },
        )
    }

    /// Build a **body-aware** `Dispatch` handler that calls this guest.
    ///
    /// # Why this is separate from [`Self::dispatch`]
    ///
    /// Because `qqq-serve` keeps the two kinds apart for the same reason it separates
    /// flat, streaming and WebSocket handlers: they are registered by name, and a route
    /// with no entry falls back. A caller that wants bodies registers this one.
    ///
    /// # Which body the guest sees
    ///
    /// [`qqq_serve::BodyBytes::Absent`] becomes `None` on the guest's `request.body`;
    /// every other variant becomes `Some(bytes)`. That preserves the distinction the
    /// guest's own routing relies on -- a `POST` with no body and a `POST` with an empty
    /// body are different requests -- so the bridge does not quietly collapse a fact the
    /// application can act on.
    ///
    /// `TooLarge` carries no bytes by construction, so a guest cannot receive a body it
    /// believes is complete when it is not: it sees `Some([])`, which its own required-
    /// field checks then reject. That is the right outcome -- `SRV-005` already refuses
    /// an over-cap body before a handler runs, so this path is reachable only through a
    /// per-tenant cap stricter than the global one, and refusing beats truncating.
    #[must_use]
    pub fn dispatch_with_body(self: &Arc<Self>) -> qqq_serve::BodyHandler {
        let app = Arc::clone(self);
        Arc::new(move |head: &RequestHead, body: &qqq_serve::BodyBytes| {
            let carried = match body {
                qqq_serve::BodyBytes::Absent => None,
                other => Some(other.as_slice().to_vec()),
            };
            match app.handle_request(head, carried) {
                Ok(response) => response,
                Err(e) => failure_response(&e),
            }
        })
    }
}

/// Convert a guest's response into the one the server writes.
///
/// # Why a non-UTF-8 header value is refused rather than lossily converted
///
/// The guest's header value is `list<u8>`; the server's is a `String`. A lossy
/// conversion would replace invalid bytes with `U+FFFD`, producing a **valid**
/// response carrying a header the guest never sent — a silent corruption. So a
/// value that is not UTF-8 is dropped, and the reason is recorded here rather
/// than in a comment nobody reads: a header the guest sent and the client did not
/// receive is a fact worth knowing, and the alternative is worse.
#[must_use]
pub fn to_served(response: &abi::Response) -> Response {
    Response {
        status: response.status,
        headers: response
            .headers
            .iter()
            .filter_map(|h| {
                std::str::from_utf8(&h.value)
                    .ok()
                    .map(|v| (h.name.clone(), v.to_owned()))
            })
            .collect(),
        body: response.body.clone(),
    }
}

/// The response for a failed guest call.
///
/// The message is the guest's own where there is one, because an operator
/// debugging an app wants the app's reason rather than QQQ's.
fn failure_response(e: &Error) -> Response {
    let mut r = Response::text(502, format!("the application failed: {}", e.message));
    r.set_header("X-QQQ-Error", &format!("{:?}", e.code));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guest_response_maps_status_headers_and_body() {
        let guest = abi::Response {
            status: 201,
            headers: vec![abi::Header {
                name: "Location".to_owned(),
                value: b"/orders/42".to_vec(),
            }],
            body: b"created".to_vec(),
        };
        let served = to_served(&guest);
        assert_eq!(served.status, 201);
        assert_eq!(served.headers.len(), 1);
        assert_eq!(served.headers[0].0, "Location");
        assert_eq!(served.headers[0].1, "/orders/42");
        assert_eq!(served.body, b"created");
    }

    #[test]
    fn a_non_utf8_header_is_dropped_rather_than_corrupted() {
        // A lossy conversion would emit U+FFFD and produce a valid response
        // carrying a header the guest never sent.
        let guest = abi::Response {
            status: 200,
            headers: vec![
                abi::Header {
                    name: "good".to_owned(),
                    value: b"fine".to_vec(),
                },
                abi::Header {
                    name: "bad".to_owned(),
                    value: vec![0xff, 0xfe],
                },
            ],
            body: Vec::new(),
        };
        let served = to_served(&guest);
        assert_eq!(
            served.headers.len(),
            1,
            "the invalid header must be dropped, not replaced"
        );
        assert_eq!(served.headers[0].0, "good");
        assert!(
            served.header("bad").is_none(),
            "a dropped header must not appear with a substituted value"
        );
    }

    #[test]
    fn a_valid_utf8_header_with_multibyte_characters_survives() {
        // The refusal is about *validity*, not about being ASCII.
        let guest = abi::Response {
            status: 200,
            headers: vec![abi::Header {
                name: "x-note".to_owned(),
                value: "café".as_bytes().to_vec(),
            }],
            body: Vec::new(),
        };
        let served = to_served(&guest);
        assert_eq!(served.headers.len(), 1);
        assert_eq!(served.headers[0].1, "café");
    }
}
