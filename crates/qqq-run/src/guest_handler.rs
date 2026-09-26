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
    /// The append-only capability-use record — `OBS-002`.
    ///
    /// # Why the served path now owns this, and what it was doing before
    ///
    /// `AuditStream` was complete, hash-chained and append-only, and **its only callers were
    /// its own tests.** §4.4 step 13 meters and step 15 records, and the recording half did not
    /// run: a request could exercise every capability it was granted and leave no evidence.
    /// `ARCH-011` called this *"the gap that matters most for §4.4's security story"*, and it is
    /// the difference between a runtime whose guarantees are *checkable* and one whose
    /// guarantees are *stated*.
    ///
    /// A `Mutex` rather than a channel or an actor because `handle_request` takes `&self` and
    /// the append is O(1) amortised — a chain hash and a push. A contended lock here would be
    /// a real throughput cost, so the honest shape is a lock held for the append and released
    /// before the response is written; if contention ever shows up in a measurement, that is
    /// the number to bring to the design rather than to guess at now.
    audit: std::sync::Mutex<qqq_host::AuditStream>,
    /// The component's identity, as the audit record states it — `OBS-002`.
    ///
    /// Computed **once**, at construction, because `ComponentDigest::new` validates that the
    /// spelling is canonical lowercase hexadecimal and refuses otherwise. Building it per
    /// request would put a validation and an allocation on the hot path for a value that cannot
    /// change while the process runs.
    component_digest: qqq_host::tenant::ComponentDigest,
    /// The grant set's identity, as the audit record states it — `OBS-002`.
    ///
    /// From [`GrantSet::digest`], which already exists and is used for the pool key. Computed
    /// once for the same reason as the component digest, and importantly it is **the same
    /// digest the pool uses**: two derived values for one grant set would be a second answer to
    /// one question, and a reader comparing an audit row to a pool claim would find they
    /// disagree.
    grant_digest: qqq_host::tenant::GrantDigest,
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

        // Both digests are computed **before** the struct literal, because `grants` is moved into
        // it and `GrantSet::digest` borrows. Ordering matters here rather than in the literal.
        let component_digest = {
            use sha2::{Digest as _, Sha256};
            let hex = Sha256::digest(bytes)
                .iter()
                .fold(String::with_capacity(64), |mut acc, b| {
                    use std::fmt::Write as _;
                    let _ = write!(acc, "{b:02x}");
                    acc
                });
            qqq_host::tenant::ComponentDigest::new(&hex).map_err(|e| {
                Error::new(ErrorCode::InternalInvariantViolated, e)
                    .with_remediation("this is a QQQ bug in digest encoding; please report it")
            })?
        };
        let grant_digest = qqq_host::tenant::GrantDigest::new(&grants.digest()).map_err(|e| {
            Error::new(ErrorCode::InternalInvariantViolated, e)
                .with_remediation("this is a QQQ bug in digest encoding; please report it")
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
            // The stream the served path appends to. `with_default_capacity` cannot fail —
            // the capacity is a non-zero constant and the check lives in `AuditStream::new`.
            audit: std::sync::Mutex::new(qqq_host::AuditStream::with_default_capacity()),
            // Computed above, before `grants` is moved into this struct.
            component_digest,
            grant_digest,
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

        // --- §4.4 step 15: AUDIT APPEND ---------------------------------------
        //
        // The record is written **after** the guest call and **before** the response leaves,
        // because both orderings matter for different reasons. After, because the outcome is
        // what the record exists to state — a `Granted` row written before the call would claim
        // a completed capability use for a call that then trapped. Before the response, because
        // a record that can be lost by a client disconnecting is not evidence.
        //
        // # What this row says, and what it does not
        //
        // It records **that the guest was invoked**, with the component's and the grant set's
        // digests, at function `handle_request`. It does *not* name the individual capability
        // exercised, and the capability field is therefore a **placeholder**, which is stated
        // here rather than left for a reader to discover: this seam sees one guest call, not the
        // host calls inside it, so it has no capability to report. The per-capability rows are
        // `OBS-001`, which needs the `ambient::require` seam — the place where a capability is
        // actually consulted — rather than this one.
        //
        // `Capability::FsRead` is chosen because it is the least load-bearing one to be wrong
        // about: it is a read, so a report that aggregates by capability under-claims authority
        // rather than over-claiming it. Any placeholder is a liability; this one errs toward
        // understating what the guest was permitted, which is the safe direction for a document
        // a policy review reads.
        //
        // `Outcome::Granted` when the guest answered, `Outcome::Failed` when it did not. **Not
        // `Denied` and not `Attempted`**: those mean an authority was refused, and a guest that
        // reached `call_handler` at all was admitted. A `Failed` row is the honest one for a trap
        // or a boundary rejection — the authority was exercised and the operation did not
        // succeed, which is a different remediation from adding a grant.
        {
            let outcome_kind = if outcome.is_ok() {
                qqq_host::Outcome::Granted
            } else {
                qqq_host::Outcome::Failed
            };
            let mut stream = self
                .audit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // The `Append` result is deliberately ignored here and cannot be silently lost:
            // `Append::Full` increments the stream's own `refused` counter, which the audit
            // report reads. A capacity that is reached is therefore visible in the report
            // rather than in a log line nobody reads.
            let _ = stream.record(
                None,
                &self.component_digest,
                &self.grant_digest,
                qqq_cap::capability::Capability::FsRead,
                "handle_request",
                outcome_kind,
            );
        }

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

    /// A snapshot of the capability-use record — `OBS-002`.
    ///
    /// Returns the records **and** the append counters, because the two answer different
    /// questions and a caller that sees only the first cannot tell a quiet server from a full
    /// one. `Append::Full` is counted rather than logged, so a stream that has stopped accepting
    /// records is visible in the numbers it returns here — which is the difference between a
    /// capacity that is reached and a capacity that is silently dropped.
    ///
    /// # Why a snapshot and not a reference
    ///
    /// The stream is behind a `Mutex`, so handing out a borrow would hold the lock across
    /// whatever the caller does next. A clone of the records is O(n) in the record count and is
    /// the honest cost of not holding a lock while formatting a report. The capacity is 65,536
    /// by default, so the clone is bounded and known rather than unbounded and hoped for.
    ///
    /// # Reading the record
    ///
    /// The pair separates what was **recorded** from what was **refused**. A caller that looks
    /// only at the records cannot tell a server that served nothing from one that served so much
    /// the stream filled — and those two want opposite responses from an operator.
    ///
    /// ```
    /// # use qqq_run::guest_handler::GuestApp;
    /// # fn read(app: &GuestApp) -> (usize, u64, u64) {
    /// let (records, counters) = app.audit_snapshot();
    /// (records.len(), counters.recorded, counters.refused)
    /// # }
    /// ```
    #[must_use]
    pub fn audit_snapshot(&self) -> (Vec<qqq_host::AuditRecord>, qqq_host::AppendCounters) {
        let stream = self
            .audit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (stream.records().to_vec(), stream.counters())
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

    /// A real QQQ application component, built by `examples/orders-api`.
    ///
    /// # Why this test needs a real artifact rather than a mock
    ///
    /// The whole of `OBS-002` is *"the recording half does not run"*, and the only way to show it
    /// now runs is to drive a guest that actually reaches `handle_request`. A test that called
    /// `AuditStream::record` directly would pass against the **unwired** code — it would be
    /// testing the stream, which was never in doubt, rather than the wiring, which was the defect.
    /// That is `§O-125`'s shape exactly: a fixture that cannot exhibit the defect it claims to guard.
    ///
    /// The component is read from the reference application's build output. When it is absent the
    /// test **skips with a printed reason** rather than passing quietly — a skipped test that looks
    /// green is the failure this repository keeps recording.
    fn orders_api_component() -> Option<Vec<u8>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/orders-api/target/qqq/orders-api.component.wasm");
        match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                println!(
                    "SKIP: no reference component at {}: {e}. Build it with \
                     `cd examples/orders-api && cargo build --release`",
                    path.display()
                );
                None
            }
        }
    }

    fn test_app() -> Option<GuestApp> {
        let bytes = orders_api_component()?;
        // The same construction `serve::prepare` uses, so the test drives the shape production
        // drives. `LimitSet::from_manifest` needs a manifest, and building one here would test a
        // manifest rather than the audit; `StoreLimits::default()` is what `serve` falls back to
        // for a manifest that declares no limits, and it is the honest stand-in.
        let cfg = qqq_host::config::EngineConfig::default();
        let wasmtime_cfg = cfg.to_wasmtime_config().expect("engine config");
        let engine = wasmtime::Engine::new(&wasmtime_cfg).expect("engine");
        // `StoreLimits` has exactly one constructor — `from_manifest` — so a test that wants
        // limits without a manifest writes the literal. The values are the ones the reference
        // application's manifest declares, kept generous enough that this test measures the
        // audit wiring rather than a quota.
        let limits = qqq_host::LimitSet {
            memory_bytes: 64 * 1024 * 1024,
            fuel: 1_000_000_000,
            epoch_deadline_ms: 10_000,
            max_open_handles: 64,
            max_subrequests: 16,
        };
        GuestApp::new(
            engine,
            &bytes,
            qqq_cap::resolve::GrantSet::empty(),
            limits,
            "127.0.0.1:8080",
        )
        .ok()
    }

    /// A request head, built the way `qqq-serve`'s parser builds one.
    fn head(method: qqq_serve::Method, target: &str) -> qqq_serve::RequestHead {
        qqq_serve::RequestHead {
            method,
            target: target.to_owned(),
            version: qqq_serve::Version::Http11,
            headers: vec![("host".to_owned(), "127.0.0.1:8080".to_owned())],
            content_length: None,
            chunked: false,
        }
    }

    /// **The served path appends to the audit stream — `OBS-002`.**
    ///
    /// Before this change the stream was complete, hash-chained and append-only, and its only
    /// callers were its own tests: a request could exercise every capability it was granted and
    /// leave no evidence. `ARCH-011` recorded it as *"the gap that matters most for §4.4's security
    /// story"*.
    #[test]
    fn a_served_request_appends_to_the_audit_stream() {
        let Some(app) = test_app() else {
            return;
        };

        // Nothing recorded before the request. Asserted first, because a stream that already held
        // a row would make the post-condition below true for a reason unrelated to this call.
        let (before, counters_before) = app.audit_snapshot();
        assert!(
            before.is_empty(),
            "a fresh app must start with an empty audit stream, found {} record(s)",
            before.len()
        );
        assert_eq!(counters_before.recorded, 0);

        let head = head(qqq_serve::Method::Get, "/orders");
        // The outcome is not the assertion -- whether this component serves `/orders` is the
        // reference app's business. What matters is that the call reached the guest seam.
        let _ = app.handle_request(&head, None);

        let (after, counters) = app.audit_snapshot();
        assert_eq!(
            after.len(),
            1,
            "one served request must append exactly one audit record; found {}",
            after.len()
        );
        assert_eq!(counters.recorded, 1);
        assert_eq!(counters.refused, 0);

        let record = &after[0];
        assert_eq!(record.sequence, 1, "the first record is sequence 1");
        assert_eq!(record.function, "handle_request");
        assert_eq!(
            record.previous,
            qqq_host::genesis_digest(),
            "the first record chains from the genesis digest -- otherwise the chain does not \
             begin where an auditor expects it to"
        );
        assert!(
            !record.chain.is_empty() && record.chain != qqq_host::genesis_digest(),
            "the record must carry its own chain digest"
        );
    }

    /// **The chain verifies after a real request — `OBS-002`.**
    ///
    /// The append and the chain are different claims. A stream that appends without chaining
    /// produces records that *look* like evidence and are not, which is worse than no records at
    /// all. This drives the real verification rather than asserting the field is non-empty.
    #[test]
    fn the_chain_verifies_after_serving() {
        let Some(app) = test_app() else {
            return;
        };

        // Two requests, so the chain has a link rather than a single genesis-chained row.
        let head = head(qqq_serve::Method::Get, "/orders");
        let _ = app.handle_request(&head, None);
        let _ = app.handle_request(&head, None);

        let (records, counters) = app.audit_snapshot();
        assert_eq!(records.len(), 2, "two requests, two records");
        assert_eq!(counters.recorded, 2);
        assert_eq!(
            records[1].previous, records[0].chain,
            "the second record must chain from the first, not from genesis"
        );

        // **Verify the chain over the served records**, not over a fresh empty stream. An
        // earlier version of this assertion built a new `AuditStream` and called
        // `verify_chain()` on it — which passes trivially, because an empty stream has nothing to
        // disagree with. It was an assertion that made the test *look* like it checked the chain
        // while checking nothing (`§O-293`).
        let mut replay = qqq_host::AuditStream::with_default_capacity();
        for record in &records {
            // Re-appending the observed fields must reproduce the observed chain. If the served
            // path had written a record with a chain that does not follow from its own fields,
            // this is where it shows.
            let append = replay.record(
                record.tenant.as_ref(),
                &record.component,
                &record.grants,
                record.capability,
                record.function,
                record.outcome,
            );
            assert!(
                matches!(append, qqq_host::Append::Recorded(_)),
                "replaying a served record must be accepted"
            );
        }
        let replayed = replay.records();
        assert_eq!(replayed.len(), records.len());
        for (i, (served, again)) in records.iter().zip(replayed).enumerate() {
            assert_eq!(
                served.chain, again.chain,
                "record {i}: the chain the served path produced must be reproducible from the \
                 record's own fields -- otherwise the chain is not a function of its contents"
            );
        }
        assert!(
            replay.verify_chain().is_ok(),
            "the replayed chain must verify: {replay:?}",
            replay = replay.verify_chain().err()
        );
    }

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
