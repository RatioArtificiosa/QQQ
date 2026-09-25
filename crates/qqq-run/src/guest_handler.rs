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
use qqq_host::pool::Pool;
use qqq_host::{LimitSet, PreparedComponent};
use qqq_serve::http1::RequestHead;
use qqq_serve::response::Response;

use crate::guest_bridge;

/// A compiled guest, ready to answer requests.
///
/// Holds the four things every request needs and none of the per-request state:
/// the engine, the compiled component, the resolved handle, and the **pool**.
/// An `Instance` is created per request, which is the §4.2 isolation model — the
/// expensive work (compilation) happens once and the cheap work (instantiation)
/// happens per request.
///
/// # Why the pool is here, and what it bounds
///
/// `qqqai serve --workers <n>` sizes this pool. Before it did, `--workers` was a
/// number the command validated, capped and **reported without acting on** — the
/// module doc in `serve.rs` described its "honest meaning in V1" as the
/// instance-pool capacity, which was a description of a pool that did not exist
/// on this path.
///
/// What the capacity bounds is **concurrent live instances**, not threads. V1 runs
/// async-single-threaded with one task per connection (§4.7), so a "worker" is not
/// a thread that owns connections; the quantity the operator is reaching for when
/// they raise it is *how many requests may hold a guest instance at once*. That is
/// a bound this pool enforces and can report, which is what makes the flag's effect
/// observable rather than nominal.
///
/// The isolation model is unchanged: acquiring a slot does not reuse a guest's
/// state, because `Instance::create` still runs per request. The pool bounds
/// *concurrency*, and reuse is the optimisation a later tier adds.
pub struct GuestApp {
    engine: wasmtime::Engine,
    prepared: PreparedComponent,
    handle: HandlerHandle,
    grants: GrantSet,
    limits: LimitSet,
    /// The authority every guest-visible URL is built from. See the module docs.
    authority: String,
    /// Bounds how many requests may hold an instance at once.
    pool: Pool,
    /// Completed requests per second, for the pool's `Retry-After` estimate.
    ///
    /// Kept at `0.0`, which the pool reads as "no rate known" and answers with its
    /// floor. Measured throughput is `qqq-serve`'s metric and inventing a number
    /// here would be a second, disagreeing estimate of the same quantity.
    completion_rate: f64,
}

impl std::fmt::Debug for GuestApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestApp")
            .field("handle", &self.handle.to_string())
            .field("authority", &self.authority)
            .field("pool_capacity", &self.pool.capacity())
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
        Self::with_capacity(engine, bytes, grants, limits, authority, 1)
    }

    /// Prepare a guest whose request concurrency is bounded to `workers` instances.
    ///
    /// # Why `workers` and not `max_instances`
    ///
    /// They are different quantities and the distinction is what `--workers` was
    /// missing. `[limits] max_instances` is the manifest's **per-store** ceiling:
    /// how many Wasmtime instances one instantiation may create, which is a property
    /// of the artifact (`§O-154` measured three core modules and four instantiation
    /// sites in the reference application). This capacity is how many **requests may
    /// hold a guest at once** across the process.
    ///
    /// Conflating them was the first fix's mistake in `§O-154`, and it is the same
    /// conflation the refusal text used to make by pointing `--workers` at
    /// `max_instances`. Both are real; neither substitutes for the other.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn with_capacity(
        engine: wasmtime::Engine,
        bytes: &[u8],
        grants: GrantSet,
        limits: LimitSet,
        authority: impl Into<String>,
        workers: u32,
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
            // `Pool::new` treats 0 as 1 and says why: a pool that can hand nothing out
            // is a deadlock rather than a configuration. `serve::options` already
            // refuses `--workers 0`, so this is a second line of defence rather than
            // the check.
            pool: Pool::new(u64::from(workers)),
            completion_rate: 0.0,
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
    /// * Every slot is busy, or the pool is draining — `QQQ-6001` from
    ///   [`Pool::acquire`], carrying the capacity and a `retry-after`. This is the
    ///   refusal `--workers` now produces, and it is a **capacity** fact rather than
    ///   a guest fault, which is why it is distinguishable by code.
    /// * The instance could not be created (a grant or limit problem).
    /// * The method cannot be expressed to a guest (`guest_bridge::to_guest`).
    /// * The guest trapped, or returned a value that is not a response.
    pub fn handle_request(&self, head: &RequestHead, body: Option<Vec<u8>>) -> Result<Response> {
        // The body is what the caller read; the head only declares its length.
        let request = guest_bridge::request_from_head(head, &self.authority, body)?;

        // --- The capacity gate ------------------------------------------------
        //
        // Acquired **before** the instance is created, which is the whole point: the
        // expensive thing this bounds is instantiation, so a check after it had
        // happened would have already paid the cost the bound exists to prevent. That
        // ordering is the same rule `qqq-serve`'s `refuse_before_reading` states for
        // request bodies, applied one layer down.
        //
        // # What `pooled` means, and the assertion that was wrong about it
        //
        // `Acquired::pooled` is true when the pool's **idle count was above zero** at
        // acquisition — not when a guest instance was reused. Nothing in V1 reuses an
        // instance: `serve_one` calls `Instance::create` on every request, so isolation is
        // structural rather than promised here.
        //
        // The first version of this code asserted `!acquired.pooled`, on the reasoning that a
        // pooled hit would mean reuse had landed without its isolation test. That premise was
        // false and the assertion **panicked the server on the second request**, because
        // `release()` increments the idle count and so every subsequent acquire reports
        // `pooled: true`. Measured: `qqqai serve --workers 4` answered the first request `200`
        // and died on the second with
        // `V1 instantiates per request; a pooled hit would mean reuse landed without its
        // isolation test`.
        //
        // A `debug_assert` that fires on correct behaviour is worse than none: it kills the
        // process in debug builds, which is where every test runs. The field is now read for the
        // one thing it is true of, and the absence of reuse is stated where a reader looks for it
        // — in `serve_one`'s own doc, next to the `Instance::create` that makes it so.
        let acquired = self.pool.acquire(self.completion_rate)?;
        debug_assert!(
            acquired.capacity >= 1,
            "a pool hands out at least one slot or refuses"
        );

        // Released on every exit path, including the error ones. `Instance::create` and
        // `run` both return `Result`, and a slot leaked on failure would shrink the
        // capacity monotonically — a server that gets slower the more it errors is a
        // worse failure than the error itself.
        let outcome = self.serve_one(&request);
        self.pool.release();

        Ok(to_served(&outcome?))
    }

    /// Create an instance for `request`, call the guest, and return its answer.
    ///
    /// Extracted so [`Self::handle_request`] can hold the pool slot across exactly this
    /// work with one release site rather than one per early return — the ordering rule
    /// `§O-184` records for `serve_special_route` and `drain_body`.
    fn serve_one(&self, request: &abi::Request) -> Result<abi::Response> {
        let instance = Instance::create(&self.engine, &self.prepared, &self.grants, self.limits)?;

        // The guest's answer travels out of the closure in a slot: `Instance::run`
        // treats any closure error as a trap, which would replace the guest's own
        // reason with a trap summary. `call`'s own tests document that shape.
        let mut outcome: Option<Result<abi::Response>> = None;
        instance.run(|store, wasm| {
            outcome = Some(call_handler(&mut *store, wasm, &self.handle, request));
            // The closure itself succeeds: the trap machinery is for the *guest's*
            // execution, and a host-side decode failure is not one.
            Ok(())
        })?;

        outcome.ok_or_else(|| {
            Error::new(
                ErrorCode::InternalInvariantViolated,
                "the guest call produced no outcome",
            )
            .with_remediation("this is a QQQ bug; please report it")
        })?
    }

    /// How many requests may hold a guest instance at once.
    ///
    /// Public so `qqqai serve` can report the capacity it actually installed rather
    /// than the number the operator typed. Those are the same number today, and
    /// reporting the pool's own value is what keeps them the same if a clamp is ever
    /// added — a report that echoes the flag cannot notice a clamp.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.pool.capacity()
    }

    /// Requests currently holding an instance.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.pool.in_use()
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
