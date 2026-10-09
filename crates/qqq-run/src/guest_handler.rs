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

use std::fmt::Write as _;
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
    ticker: Arc<EpochTicker>,
    prepared: PreparedComponent,
    handle: HandlerHandle,
    grants: GrantSet,
    limits: LimitSet,
    /// The authority every guest-visible URL is built from. See the module docs.
    authority: String,
    /// Bounds how many requests may hold an instance at once.
    pool: Arc<Pool>,
    /// Bounds host heap held for request and response bodies (`F-03`).
    ///
    /// Permits are bytes; 256 MiB total across the app. Admission's RSS math
    /// bounds what guests may hold, but the host heap that carries bodies in
    /// flight — request bytes read before the guest runs, the lifted
    /// response after — is outside every Wasmtime limiter. When the budget is
    /// exhausted the request is shed with 503 + `Retry-After`, never queued:
    /// an unbounded queue is how a slow consumer turns heap pressure into an
    /// OOM kill. Shared across replacements like the pool, for the same
    /// reason: a rotation must not double the budget.
    ///
    /// # Window boundary, stated exactly
    ///
    /// The permits cover the guest-processing window (entry through return).
    /// The socket-write window after return holds the bounded response under
    /// connection backpressure — unchanged from the pre-semaphore baseline,
    /// whose transient the split writes reduced. Carrying a permit to the
    /// socket would cross the `Handler` boundary (`live.dispatch` →
    /// `Dispatch::flat` → `server.write_flat_response`) with signature churn
    /// across three crates for the last mile of an optional item; that is
    /// server write-backpressure work, named as follow-up, not smuggled in
    /// here.
    buffer_budget: Arc<tokio::sync::Semaphore>,
    /// The per-tenant output budgets for this app's requests.
    ///
    /// One registry per app, matching the pool: each deployed component bounds
    /// its own tenants, exactly as each bounds its own instance slots.
    tenant_outputs: qqq_host::guest_output::TenantOutputBudgets,
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
    audit: std::sync::Arc<std::sync::Mutex<qqq_host::AuditStream>>,
    /// Where the record is persisted, when the operator asked for a file — `OBS-002`.
    ///
    /// `None` means the stream is in memory only, which is the honest default: a server that wrote
    /// an evidence file the operator did not ask for would be a surprise, and a *silent* one
    /// because nothing in the response says a file was created.
    ///
    /// # Why a bounded worker rather than a synchronous write
    ///
    /// The synchronous path serialized every audit-enabled request on the file
    /// mutex and paid a flush per record on the request's own thread, so a slow
    /// disk became slow requests — `PERF-AUDIT-001`. The appender hands each
    /// record to a bounded queue with one writing thread: producers block only
    /// when the disk cannot keep up (backpressure, never a dropped row), and
    /// the default durability still flushes per record, so the crash promise
    /// the synchronous path gave is kept, not traded away.
    audit_appender: Option<Arc<qqq_host::audit_sink::AuditAppender>>,
    /// What a request does when its evidence cannot be made durable (`F-09`).
    ///
    /// `FailClosed` by default whenever a sink is configured: a served
    /// request whose row never lands is a hole shaped exactly like a
    /// request that never happened. Carried on the app (not the appender)
    /// because the pre-flight check runs before any worker contact, and
    /// because a replacement must inherit the operator's choice with the
    /// stream (`replacement` clones it below).
    audit_policy: qqq_host::audit_sink::AuditFailurePolicy,
    /// Rows dropped under `FailOpenWithAlarm`, and restores that found a
    /// torn tail (`F-09`).
    ///
    /// Atomics with getters, matching the `AppenderStats` precedent: the
    /// counts are asserted in-tree, and every occurrence also logs, so an
    /// operator learns of a drop from the log line and audits the total
    /// from the counter. Prometheus surfacing for these two is follow-up
    /// work, named here rather than smuggled into dispatch signatures.
    audit_drops: std::sync::Arc<std::sync::atomic::AtomicU64>,
    audit_quarantines: std::sync::Arc<std::sync::atomic::AtomicU64>,
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
    /// Whether guest instances run deterministically — `F-20`.
    ///
    /// Set post-construction by `qqqai serve --deterministic` (after the
    /// loopback-or-explicit gate), never by the manifest: a manifest that
    /// could opt its own server into reproducible randomness would be a
    /// guest-controlled predictability switch. Defaults off, so every
    /// existing constructor — including the integration tests' — serves
    /// real-time randomness unless serve says otherwise.
    deterministic: bool,
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
    /// Give independently constructed applications dedicated engines: this app
    /// owns the engine's millisecond epoch clock. Use [`Self::replacement`] to
    /// share its clock, quota and audit history across code generations.
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
        Self::with_context(
            engine,
            bytes,
            grants,
            limits,
            authority.into(),
            (workers, None),
        )
    }

    fn with_context(
        engine: wasmtime::Engine,
        bytes: &[u8],
        grants: GrantSet,
        limits: LimitSet,
        authority: String,
        context: (u32, Option<Arc<EpochTicker>>),
    ) -> Result<Self> {
        let (workers, ticker) = context;
        let ticker = match ticker {
            Some(ticker) => ticker,
            None => Arc::new(EpochTicker::start(engine.clone())?),
        };

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
            let instance = Instance::create_with(
                &engine,
                &prepared,
                &grants,
                limits,
                &timed_options(limits, false),
            )?;
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

        // `Pool::new` treats 0 as 1 and says why: a pool that can hand nothing out
        // is a deadlock rather than a configuration. `serve::options` already
        // refuses `--workers 0`, so this is a second line of defence rather than
        // the check.
        let pool = Arc::new(Pool::new(u64::from(workers)));
        // One registry per app, matching the pool: tenants are not global
        // identities here, so each deployed component bounds its own tenants,
        // exactly as each bounds its own instance slots. The registry meters
        // tenant-ceiling refusals into the pool's recorder, so operators see
        // them where every other operational counter lives.
        let tenant_outputs = qqq_host::guest_output::TenantOutputBudgets::new(
            qqq_host::guest_output::TENANT_OUTPUT_BYTES,
        );
        tenant_outputs.set_meter(pool.metrics_arc());

        Ok(Self {
            engine,
            ticker,
            prepared,
            handle,
            grants,
            limits,
            authority,
            pool,
            // One budget per app, matching the pool: the heap that carries
            // bodies is per deployed component like its instance slots.
            buffer_budget: Arc::new(tokio::sync::Semaphore::new(BUFFER_BUDGET_BYTES)),
            tenant_outputs,
            // The stream the served path appends to. `with_default_capacity` cannot fail —
            // the capacity is a non-zero constant and the check lives in `AuditStream::new`.
            audit: std::sync::Arc::new(std::sync::Mutex::new(
                qqq_host::AuditStream::with_default_capacity(),
            )),
            audit_appender: None,
            audit_policy: qqq_host::audit_sink::AuditFailurePolicy::FailClosed,
            audit_drops: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            audit_quarantines: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            // Computed above, before `grants` is moved into this struct.
            component_digest,
            grant_digest,
            completion_rate: 0.0,
            deterministic: false,
        })
    }

    /// Run guest instances deterministically — `F-20`.
    ///
    /// Crate-visible rather than public: only `serve` sets this, after its
    /// listener gate, and an external caller with a setter would be a second
    /// path to deterministic serving that bypasses the gate. Must be called
    /// before serving; instances created afterwards read it.
    pub(crate) fn set_deterministic(&mut self, deterministic: bool) {
        self.deterministic = deterministic;
    }

    /// Whether this app runs guest instances deterministically.
    ///
    /// Crate-visible for the same reason: reported so `serve` can state the
    /// mode it installed rather than the flag it parsed — a report that
    /// echoes the flag cannot notice a setter that was never called.
    #[must_use]
    pub(crate) fn is_deterministic(&self) -> bool {
        self.deterministic
    }

    /// Prepare a replacement under the same authority and aggregate resource limits.
    /// Compilation and admission finish before a caller publishes this value.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// # fn update(app: &qqq_run::guest_handler::GuestApp, wasm: &[u8]) -> qqq_core::Result<()> {
    /// let next = app.replacement(wasm)?;
    /// assert_eq!(app.capacity(), next.capacity());
    /// # Ok(())
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Refuses compilation, instantiation and HTTP signature failures.
    pub fn replacement(&self, bytes: &[u8]) -> Result<Self> {
        let mut next = Self::with_context(
            self.engine.clone(),
            bytes,
            self.grants.clone(),
            self.limits,
            self.authority.clone(),
            (1, Some(Arc::clone(&self.ticker))),
        )?;
        next.validate_interface()?;
        next.pool = Arc::clone(&self.pool);
        next.buffer_budget = Arc::clone(&self.buffer_budget);
        next.audit = Arc::clone(&self.audit);
        next.audit_appender.clone_from(&self.audit_appender);
        next.audit_policy = self.audit_policy;
        next.audit_drops = std::sync::Arc::clone(&self.audit_drops);
        next.audit_quarantines = std::sync::Arc::clone(&self.audit_quarantines);
        // The tenant budgets roll with the replacement, like the pool and the
        // audit stream: a rotation must not double a tenant's ceiling by
        // accident, and must not forgive an over-budget tenant either.
        next.tenant_outputs = self.tenant_outputs.clone();
        // The clock mode rolls with it too: a deterministic server that
        // served real-time randomness after a rotation would be neither.
        next.deterministic = self.deterministic;
        Ok(next)
    }

    /// Validate the entire HTTP function signature before live activation.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// # fn validate(app: &qqq_run::guest_handler::GuestApp) -> qqq_core::Result<()> {
    /// app.validate_interface()?;
    /// # Ok(())
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Refuses failed instantiation and any mismatch with the declared HTTP handler signature.
    pub fn validate_interface(&self) -> Result<()> {
        let instance = Instance::create_with(
            &self.engine,
            &self.prepared,
            &self.grants,
            self.limits,
            &timed_options(self.limits, self.deterministic),
        )?;
        instance.run(|store, wasm| {
            let func = self.handle.func(store, wasm)
                .map_err(|e| wasmtime::Error::msg(e.to_string()))?;
            func.typed::<(abi::Request,), (std::result::Result<abi::Response, abi::HttpError>,)>(&*store)?;
            Ok(())
        }).map_err(|e| Error::new(ErrorCode::InvalidComponentArtifact,
            format!("HTTP interface validation failed: {e}")))
    }

    /// Digest used by the active-generation registry and audit records.
    #[must_use]
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// # fn inspect(app: &qqq_run::guest_handler::GuestApp) {
    /// assert_eq!(app.digest().len(), 64);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn digest(&self) -> &str {
        self.prepared.digest()
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
    /// The `tenant` is the serve layer's name for the caller — the peer address
    /// today — and it selects the shared output budget this request accounts
    /// into. It travels as an explicit parameter rather than inside the head
    /// because the head is client-controlled: a tenant identity the client
    /// could set would let a guest's heaviest tenant bill its bytes to
    /// another.
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
    /// * The guest answered but the answer failed boundary validation —
    ///   `QQQ-3009` from [`to_served`], rendered as 502 by the caller and
    ///   recorded as a `Failed` (not `Granted`) audit row.
    pub fn handle_request(
        &self,
        head: &RequestHead,
        body: Option<Vec<u8>>,
        tenant: &str,
    ) -> Result<Response> {
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
        // # What `slot_reused` means, and the assertion that was wrong about it
        //
        // `Acquired::slot_reused` is true when the pool's **idle count was above zero** at
        // acquisition — not when a guest instance was reused. Nothing in V1 reuses an
        // instance: `serve_one` calls `Instance::create` on every request, so isolation is
        // structural rather than promised here.
        //
        // The first version of this code asserted `!acquired.slot_reused`, on the reasoning that a
        // slot hit would mean reuse had landed without its isolation test. That premise was
        // false and the assertion **panicked the server on the second request**, because
        // `release()` increments the idle count and so every subsequent acquire reports
        // `slot_reused: true`. Measured: `qqqai serve --workers 4` answered the first request `200`
        // and died on the second with
        // `V1 instantiates per request; a pooled hit would mean reuse landed without its
        // isolation test`.
        //
        // A `debug_assert` that fires on correct behaviour is worse than none: it kills the
        // process in debug builds, which is where every test runs. The field is now read for the
        // one thing it is true of, and the absence of reuse is stated where a reader looks for it
        // — in `serve_one`'s own doc, next to the `Instance::create` that makes it so.
        // --- The buffer budget ------------------------------------------------
        //
        // Host heap for this request's body, held across the guest call: the
        // request bytes are already in heap here, and the lifted response
        // will join them. `try_acquire` never waits — an exhausted budget
        // sheds with 503 + `Retry-After` rather than queueing, because a
        // queue of large bodies is the OOM this budget exists to prevent.
        // Released on every exit path by the guards' drops. This runs BEFORE
        // the pool gate below so a shed request consumes no slot: the reverse
        // order leaked `in_use` on every shed (the permit that would release
        // the slot is only created afterwards).
        let request_len =
            u32::try_from(request.body.as_ref().map_or(0, Vec::len)).unwrap_or(u32::MAX);
        let Ok(_request_permit) = self.buffer_budget.try_acquire_many(request_len) else {
            return Ok(buffer_overload(&self.pool, self.completion_rate));
        };

        let acquired = self.pool.acquire(self.completion_rate)?;
        debug_assert!(
            acquired.capacity >= 1,
            "a pool hands out at least one slot or refuses"
        );

        // Released on every exit path, including the error ones. `Instance::create` and
        // `run` both return `Result`, and a slot leaked on failure would shrink the
        // capacity monotonically — a server that gets slower the more it errors is a
        // worse failure than the error itself.
        let permit = RequestPermit::clean(&self.pool);
        // This request's audit rows live in its own handle, buffered
        // unsequenced until the commit below — never sliced out of the
        // shared stream, so a persist set holds exactly this request's
        // rows regardless of concurrency (`F-09`: the old floor-slice
        // copied every row appended since the request started, growing
        // with concurrency and interleaving other requests' rows).
        let audit_handle = qqq_host::audit::AuditHandle::new(
            std::sync::Arc::clone(&self.audit),
            self.component_digest.clone(),
            self.grant_digest.clone(),
            None,
        );
        // FailClosed pre-flight (`F-09`): a dead persist path refuses
        // BEFORE the guest runs, so no request executes that its evidence
        // could never cover. FailOpenWithAlarm counts the refusal loudly
        // and serves anyway — the operator chose availability over
        // auditability, in one visible call.
        if let Some(appender) = self.audit_appender.as_ref() {
            if appender.is_failed() {
                match self.audit_policy {
                    qqq_host::audit_sink::AuditFailurePolicy::FailClosed => {
                        return Ok(audit_unavailable(
                            &self.pool,
                            self.completion_rate,
                            "the audit worker cannot persist",
                        ));
                    }
                    qqq_host::audit_sink::AuditFailurePolicy::FailOpenWithAlarm => {
                        self.note_audit_drop("pre-flight: worker already failed");
                    }
                }
            }
        }
        let outcome = self.serve_one(request, tenant, &audit_handle);

        // The response body joins the heap here: budget it too, or a flood
        // of large answers bypasses the entry check above. On exhaustion the
        // lifted response is dropped and the request shed with 503 — but
        // through `settle` below, not around it: the guest already ran, so
        // the shed is a `Failed` exercise with an audit row, while the slot
        // is released (the instance did nothing wrong — only served what did
        // not fit). An early return here would skip the row, the taint
        // bookkeeping, and the persist.
        let mut shed = None;
        let (outcome, _response_permit) = match outcome {
            Ok(response) => {
                let response_len = u32::try_from(response.body.len()).unwrap_or(u32::MAX);
                if let Ok(permit) = self.buffer_budget.try_acquire_many(response_len) {
                    (Ok(response), Some(permit))
                } else {
                    shed = Some(buffer_overload(&self.pool, self.completion_rate));
                    (
                        Err(buffer_overload_error(&self.pool, self.completion_rate)),
                        None,
                    )
                }
            }
            Err(error) => (Err(error), None),
        };

        // Settled **before** the audit row, so the row states the outcome the
        // caller acts on: a guest answer the boundary refuses (`QQQ-3009`) is
        // a `Failed` exercise of the authority, not a `Granted` one. Settling
        // after the row recorded such answers as granted while the caller
        // rendered their 502.
        let (converted, outcome_kind) = self.settle(outcome);

        // The slot follows the SETTLED outcome, not the raw one (`F-01`,
        // review): a boundary-refused answer (illegal status, host-controlled
        // header, breached cap) means the instance produced protocol-violating
        // output, so its slot is discarded like a trap's — only a converted,
        // servable answer hands its slot back. A shed response is the
        // exception that proves the shape: it converts to `Err` for the
        // `Failed` row below, but the permit stays untainted (the instance
        // behaved; the host is full), so the slot is released. V1 builds a
        // fresh instance per request regardless, so `slot_reused` describes
        // accounting, never a reused instance.
        if converted.is_err() && shed.is_none() {
            permit.taint();
        }
        drop(permit);

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
        // It records **that the app served a request**, at function `handle_request`, under the
        // capability `HttpServer` — which is the authority a QQQ application exercises by being
        // served at all.
        //
        // # Why this replaced a placeholder, and what the placeholder was
        //
        // This row used to carry `Capability::FsRead` as a **stated placeholder**, because the seam
        // sees one guest call and not the host calls inside it. A report that aggregates by
        // capability was therefore aggregating a *constant*: every request appeared to read a file.
        // `OBS-001` is now closed at the seam where a capability is actually consulted —
        // `ambient::require`, which appends its own row naming the capability it read — so this row
        // no longer has to guess, and `HttpServer` is not a guess: it is the authority the served
        // path exercises.
        //
        // # Why `Attempted` and not `Denied` when the grant is absent
        //
        // Because that is the distinction `Outcome::Attempted`'s own documentation draws: it is
        // *"the guest attempted the call and the capability was absent, so the attempt was refused
        // before policy was consulted"*, and it exists precisely so that *"a component was deployed
        // that needs authority the manifest does not grant"* leaves a record. `Denied` means the
        // call-time re-check refused an instance that was built with the capability present, which
        // is a different and much more alarming event.
        //
        // `Outcome::Granted` when the app is granted `HttpServer` and the converted
        // answer succeeded, `Outcome::Failed` when it is granted and the call did not
        // succeed. The row reads the **settled** result (`settle` converts with
        // `to_served` before the row), so a `Failed` row is the honest one for a trap or a boundary
        // rejection: the authority was exercised and the operation did not succeed,
        // which is a different remediation from adding a grant.
        {
            // The handle row joins the buffered ambient rows, and the commit
            // assigns every sequence under ONE lock hold: the returned set
            // is exactly this request's rows, in commit order. No floor
            // index, no shared slice, no concurrent rows riding along.
            audit_handle.record(
                qqq_cap::capability::Capability::HttpServer,
                "handle_request",
                outcome_kind,
            );
            let rows = audit_handle.commit();

            if let Some(appender) = self.audit_appender.as_ref() {
                // Waited, not fire-and-forget: the barrier keeps the
                // synchronous path's promise that a returned request has its
                // evidence durable, while the shared worker still batches
                // concurrent requests into fewer disk passes.
                //
                // The timeout comes from the attached appender, not the default:
                // `attach_audit_file` derives it from the epoch deadline, and a
                // call site that re-defaulted it would silently shorten the
                // tripwire the attach chose.
                if let Err(error) = appender.persist(&rows, appender.config().persist_timeout) {
                    match self.audit_policy {
                        qqq_host::audit_sink::AuditFailurePolicy::FailClosed => {
                            return Ok(audit_unavailable(
                                &self.pool,
                                self.completion_rate,
                                &error.to_string(),
                            ));
                        }
                        qqq_host::audit_sink::AuditFailurePolicy::FailOpenWithAlarm => {
                            self.note_audit_drop(&format!(
                                "persist of {} records failed: {error}",
                                rows.len()
                            ));
                        }
                    }
                }
            }
        }

        // A shed response replaces the (failed) conversion: the bookkeeping
        // above ran on the error, but the client gets the 503 that names the
        // real condition rather than a 502 that would blame the guest.
        match shed {
            Some(response) => Ok(response),
            None => converted,
        }
    }

    /// Convert a guest answer and classify the audit row for it.
    ///
    /// The two steps [`Self::handle_request`] performs between the guest call
    /// and the audit block, extracted so tests can drive a `to_served`-rejected
    /// answer through the real ordering without a guest that misbehaves on
    /// demand. Conversion precedes classification: a boundary refusal
    /// (`QQQ-3009`) classifies as `Failed`, and the grant check decides before
    /// either, because an ungranted call is an attempt however it ended.
    fn settle(&self, outcome: Result<abi::Response>) -> (Result<Response>, qqq_host::Outcome) {
        let converted: Result<Response> =
            outcome.and_then(|raw| to_served(raw, self.response_body_cap()));
        let serves = self
            .grants
            .grants(qqq_cap::capability::Capability::HttpServer);
        let kind = audit_outcome(serves, converted.is_ok());
        (converted, kind)
    }

    /// The effective guest-response body cap: the smaller of the response
    /// constant and the instance's memory ceiling (`F-03`, `F-10`).
    ///
    /// One number, never two: the constant bounds responses below the
    /// ceiling, and the ceiling binds deployments with small memories. A
    /// body larger than either is refused by [`to_served`] before anything
    /// downstream can buffer it.
    fn response_body_cap(&self) -> u64 {
        MAX_GUEST_RESPONSE_BODY_BYTES.min(self.limits.memory_bytes)
    }

    /// Create an instance for `request`, call the guest, and return its answer.
    ///
    /// Extracted so [`Self::handle_request`] can hold the pool slot across exactly this
    /// work with one release site rather than one per early return — the ordering rule
    /// `§O-184` records for `serve_special_route` and `drain_body`.
    ///
    /// Takes the request BY VALUE (`F-03`): the typed call lowers it with bulk
    /// copies, and a borrow here would force the caller to clone the body to
    /// satisfy the move — the exact copy this phase exists to remove.
    fn serve_one(
        &self,
        request: abi::Request,
        tenant: &str,
        audit: &qqq_host::audit::AuditHandle,
    ) -> Result<abi::Response> {
        // The handle arrives from `handle_request`, which keeps its own
        // copy for the commit: rows buffer request-locally either way, and
        // the store behind the instance sees the same chain through the
        // shared stream. Cloned, not rebuilt, so the commit sees every row
        // the guest call recorded.
        let handle = audit.clone();
        // Held for exactly this request: dropping it at the end releases the
        // tenant entry when no request of this tenant remains, which is the
        // reset boundary. The budget outlives concurrent requests through the
        // registry, never through this local.
        let tenant_output = self.tenant_outputs.acquire(tenant);
        let mut options = timed_options(self.limits, self.deterministic);
        options.audit = Some(handle);
        options.tenant_output = Some(tenant_output);
        let instance = Instance::create_with(
            &self.engine,
            &self.prepared,
            &self.grants,
            self.limits,
            &options,
        )?;

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

    /// Persist the capability-use record to `path`, resuming any history already there — `OBS-002`.
    ///
    /// # Errors
    ///
    /// When the file cannot be read, when its records do not form a stream, or when it cannot be
    /// opened for appending. **Every one of these refuses rather than falling back to memory-only**:
    /// an operator who asked for a persistent record and silently got an in-memory one would
    /// believe they had evidence they do not have, and would discover it at the worst moment.
    ///
    /// # Why this is a method and not a constructor argument
    ///
    /// Because attaching is the *decision to persist*, and it carries a load that can fail. A
    /// constructor argument would make every existing caller pass `None` for a feature it does not
    /// use, and would put a fallible file read inside the path that compiles a component — so a
    /// malformed audit file would be reported as a component that cannot serve.
    ///
    /// # Example
    ///
    /// The file is read and verified **before** a single request is served, so a chain that is
    /// already broken refuses the start rather than being extended:
    ///
    /// ```
    /// # use qqq_run::guest_handler::GuestApp;
    /// # use std::path::Path;
    /// # fn attach(app: &mut GuestApp, path: &Path) -> Result<(), String> {
    /// app.attach_audit_file(path).map_err(|e| e.message.clone())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn attach_audit_file(&mut self, path: &std::path::Path) -> Result<()> {
        self.attach_audit_file_with_key(path, None)
    }

    /// Attach a file sink with an explicit v2 chain key (`F-09`).
    ///
    /// The key comes from the operator as a file (`--audit-hmac-key-file`
    /// in `serve`): rows are HMAC-SHA-256 chained and unforgable without
    /// it. Without a key the chain is plain SHA-256 — corruption-evident,
    /// not tamper-evident — and the attach says so loudly rather than
    /// letting the deployment believe it has a guarantee it does not.
    ///
    /// # Errors
    ///
    /// The same unwritable-path and broken-history refusals as
    /// [`Self::attach_audit_file`].
    pub fn attach_audit_file_with_key(
        &mut self,
        path: &std::path::Path,
        key: Option<qqq_host::audit::ChainKey>,
    ) -> Result<()> {
        let keyed = key.is_some();
        let (stream, loaded) = qqq_host::audit_sink::resume_or_start_ring(
            path,
            qqq_host::audit::DEFAULT_RING_CAPACITY,
            key,
        )
        .map_err(|e| {
            Error::new(ErrorCode::InternalInvariantViolated, e.to_string()).with_remediation(
                "point `--audit-log` at a writable path, or remove the flag to keep the record in \
                 memory only",
            )
        })?;

        // A dropped partial line means the previous process did not shut down cleanly. Reported
        // here rather than swallowed: the records alone cannot state it, and an operator reading
        // the record later has no other way to learn it.
        if loaded.dropped_partial_line {
            self.audit_quarantines
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            eprintln!(
                "warning: the audit file {} ended mid-record; the torn tail was quarantined to {} \
                 before truncation. The process that wrote it did not shut down cleanly.",
                path.display(),
                loaded
                    .quarantined_to
                    .as_ref()
                    .map_or("<unknown>".to_owned(), |p| p.display().to_string()),
            );
        }

        // No key, no tamper evidence: the chain still detects accidents, but
        // anyone with write access to the file can recompute it. Said loudly
        // at the one moment the operator can still act on it, not buried in
        // a document they read after the breach.
        if !keyed {
            eprintln!(
                "warning: the audit log {} is chained without an HMAC key; rows are \
                 tamper-evident against accidents, not attackers. Pass \
                 `--audit-hmac-key-file` with 64 hex characters to key the chain.",
                path.display(),
            );
        }

        let file =
            qqq_host::audit_sink::AuditFile::open(path, loaded.records.len()).map_err(|e| {
                Error::new(ErrorCode::InternalInvariantViolated, e.to_string()).with_remediation(
                "point `--audit-log` at a writable path, or remove the flag to keep the record in \
                 memory only",
            )
            })?;

        // The worker owns the file from here: one queue, one writing thread, rows
        // in sequence order. The default durability flushes per record, which is
        // the crash promise the synchronous path gave — kept, not traded away
        // for the throughput the worker adds. The stall timeout derives from
        // the epoch deadline: ambient rows are recorded during guest
        // execution, which preemption bounds, so a gap that outlives twice
        // that bound plus a margin is a dead producer rather than a slow
        // request — and skipping it early would drop a legitimate slow row.
        // The persist tripwire stays ordered after it, so a wedged worker
        // still fails loudly instead of hanging requests.
        let stall_timeout = std::time::Duration::from_millis(self.limits.epoch_deadline_ms)
            + std::time::Duration::from_secs(10);
        let appender = qqq_host::audit_sink::AuditAppender::spawn(
            file,
            qqq_host::audit_sink::AppenderConfig {
                stall_timeout,
                persist_timeout: stall_timeout + std::time::Duration::from_secs(30),
                ..qqq_host::audit_sink::AppenderConfig::default()
            },
        )
        .map_err(|e| {
            Error::new(ErrorCode::InternalInvariantViolated, e.to_string()).with_remediation(
                "the host could not start its audit worker thread; the process cannot create \
                 threads",
            )
        })?;

        self.audit = std::sync::Arc::new(std::sync::Mutex::new(stream));
        self.audit_appender = Some(Arc::new(appender));
        Ok(())
    }

    /// Choose what a request does when its evidence cannot persist (`F-09`).
    ///
    /// `FailClosed` is already the default; this exists for the operator
    /// who has decided availability beats auditability and wants that
    /// decision visible in one call rather than inferred from silence.
    pub fn set_audit_failure_policy(&mut self, policy: qqq_host::audit_sink::AuditFailurePolicy) {
        self.audit_policy = policy;
    }

    /// Rows dropped under `FailOpenWithAlarm`.
    ///
    /// Every drop also logs, so the counter audits the total while the
    /// log line carries the instance. A counter nobody reads is a wish;
    /// the `FailOpen` test below reads this one.
    #[must_use]
    pub fn audit_drops(&self) -> u64 {
        self.audit_drops.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Restores that quarantined a torn tail.
    ///
    /// Bumped wherever the warning above fires, so the count and the log
    /// agree and neither can drift from the other unnoticed.
    #[must_use]
    pub fn audit_quarantines(&self) -> u64 {
        self.audit_quarantines
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Count one alarm drop and say so out loud.
    ///
    /// The counter audits the total while the log line carries the
    /// instance: neither alone is the alarm, and the two are bumped
    /// together so they cannot disagree.
    fn note_audit_drop(&self, detail: &str) {
        self.audit_drops
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        eprintln!("error: audit evidence dropped ({detail})");
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
    ///
    /// # Why the tenant here is the route name
    ///
    /// The flat handler type carries no tenant: changing it would break every flat
    /// route in the workspace for callers with no interest in accounting. Production
    /// registers [`Self::dispatch_with_body`] for every declared route, so guest
    /// traffic through this closure is test and development traffic, attributed to
    /// the route rather than to a tenant. A deployment serving guests through flat
    /// handlers alone gets per-route budgets, stated here rather than discovered.
    #[must_use]
    pub fn dispatch(self: &Arc<Self>) -> qqq_serve::Handler {
        let app = Arc::clone(self);
        Arc::new(move |head: &RequestHead, matched: &qqq_serve::RouteMatch| {
            match app.handle_request(head, None, &matched.handler) {
                Ok(response) => response,
                Err(e) => failure_response(&e),
            }
        })
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
        Arc::new(
            move |head: &RequestHead, body: &qqq_serve::BodyBytes, tenant: &str| {
                let carried = match body {
                    qqq_serve::BodyBytes::Absent => None,
                    other => Some(other.as_slice().to_vec()),
                };
                match app.handle_request(head, carried, tenant) {
                    Ok(response) => response,
                    Err(e) => failure_response(&e),
                }
            },
        )
    }
}

/// Maximum guest response headers: 128.
///
/// Mirrors the request side's count discipline at twice the request cap — a
/// guest builds responses programmatically, so legitimate use clusters higher
/// than hand-written requests, but unbounded is how a compromised guest turns
/// the serializer into an allocator.
const MAX_RESPONSE_HEADERS: usize = 128;

/// Host-heap budget for bodies in flight, in bytes (`F-03`).
///
/// Sized so a full 2 MiB request plus a full 8 MiB response cap still leaves
/// headroom for dozens of concurrent small requests: exhaustion means an
/// actual flood of large bodies, not one big one.
const BUFFER_BUDGET_BYTES: usize = 256 * 1024 * 1024;

/// Maximum guest response body in bytes: 8 MiB.
///
/// The post-lift bound on what a guest may return. The effective cap is the
/// smaller of this and the instance's memory ceiling (F-10's bound: a
/// response larger than the instance's total memory cannot exist), computed
/// by [`GuestApp::response_body_cap`]. A manifest field was considered and
/// refused: `max_response_bytes` is a historically rejected manifest field
/// (DOC-SCHEMA-001 pins its rejection), and resurrecting it here would trade
/// a two-line const for schema, validation, and cookbook churn with no new
/// information — the ceiling already configures the bound per deployment.
const MAX_GUEST_RESPONSE_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum bytes of one guest response header (name plus value).
///
/// Mirrors the 8 KiB request-side line cap: a header that does not fit in the
/// same budget going out as coming in is either a bug or an exfiltration
/// attempt chunked across headers.
const MAX_RESPONSE_HEADER_BYTES: usize = 8 * 1024;

/// Whether a status code has meaning on the wire: `100`–`599`.
///
/// Anything else — `99`, `600`, let alone wider integers — has no reason
/// phrase and no defined client behavior. Serializing it anyway would emit a
/// status line no client can interpret.
///
/// ```rust
/// use qqq_run::guest_handler::is_valid_guest_status;
///
/// assert!(is_valid_guest_status(200));
/// assert!(is_valid_guest_status(599));
/// assert!(!is_valid_guest_status(99));
/// assert!(!is_valid_guest_status(600));
/// ```
#[must_use]
pub fn is_valid_guest_status(status: u16) -> bool {
    (100..=599).contains(&status)
}

/// Whether a header is the serializer's to write, never the guest's.
///
/// `Content-Length`, `Connection`, and `Transfer-Encoding` define the
/// framing, and `write_response` skips them when present — so a guest setting
/// them is either confused or attempting to desynchronize the stream. Either
/// way the answer is refusal, not silent dropping: dropping would hide the
/// attempt from everyone reading the audit trail.
///
/// ```rust
/// use qqq_run::guest_handler::is_host_controlled_header;
///
/// assert!(is_host_controlled_header("content-length"));
/// assert!(is_host_controlled_header("Connection"));
/// assert!(!is_host_controlled_header("x-tenant"));
/// ```
#[must_use]
pub fn is_host_controlled_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("transfer-encoding")
}

/// Escape a guest header value for the wire.
///
/// Trims OWS, then percent-encodes `%` first and every ASCII control except
/// tab after — so `%0D` in input becomes `%250D` rather than decoding back
/// into a split, and NUL or DEL cannot ride through where only `\r` and `\n`
/// were expected. Tab passes through: it is legal field whitespace, and the
/// trim already removed it from the edges. The result never contains a raw
/// control byte, which is the property that matters: a value that cannot
/// terminate its own line cannot inject the next one.
///
/// ```rust
/// use qqq_run::guest_handler::escape_header_value;
///
/// assert_eq!(escape_header_value("a\r\nEvil: x"), "a%0D%0AEvil: x");
/// assert_eq!(escape_header_value("%0D"), "%250D");
/// assert_eq!(escape_header_value("  padded  "), "padded");
/// assert_eq!(escape_header_value("nul\x00del\x7f"), "nul%00del%7F");
/// ```
#[must_use]
pub fn escape_header_value(value: &str) -> String {
    let trimmed = value.trim();
    let mut out = String::with_capacity(trimmed.len());
    for c in trimmed.chars() {
        match c {
            '%' => out.push_str("%25"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            // Tab passes through: it is legal field whitespace, and the trim
            // above already removed it from the edges. This arm must precede
            // the control guard below — `\t` IS an ASCII control.
            '\t' => out.push('\t'),
            c if c.is_ascii_control() => {
                let _ = write!(out, "%{c:02X}", c = c as u8);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Derive the audit [`Outcome`](qqq_host::Outcome) from the grant state and the
/// **converted** result.
///
/// `handle_request` converts the guest answer with [`to_served`] *before* it
/// records the row, so a boundary rejection (`QQQ-3009`) lands as `Failed`:
/// the authority was exercised and the operation did not succeed. Deriving
/// from the raw guest result instead recorded such answers as `Granted`
/// while the caller rendered their 502 — the mismatch the `Failed` variant
/// exists to prevent. A missing grant decides before anything else, because
/// an ungranted call is an attempt however it ended.
fn audit_outcome(serves_http: bool, converted_ok: bool) -> qqq_host::Outcome {
    match (serves_http, converted_ok) {
        (false, _) => qqq_host::Outcome::Attempted,
        (true, true) => qqq_host::Outcome::Granted,
        (true, false) => qqq_host::Outcome::Failed,
    }
}

/// Convert a guest's response into the one the server writes.
///
/// Takes the response BY VALUE (`F-24`): the body and header strings are
/// moved, not cloned — the caller already owns them, so a second copy is
/// pure waste on the hot path. The `body_cap_bytes` bound is enforced here,
/// immediately after lifting, so an over-cap body is refused before any
/// downstream code can buffer it again.
///
/// # Why refusal replaces silent repair here
///
/// An earlier version dropped non-UTF-8 header *values* (kept: a lossy
/// conversion would emit a header the guest never sent). `F-02` extends the
/// same principle to the whole response: a status with no wire meaning, a
/// framing header the serializer owns, or an oversized header set fails the
/// conversion, and the caller renders its 502 instead. Nothing guest-controlled
/// reaches serialization unvalidated — the serializer writes what it is
/// given, so this boundary is the only place the check can live.
///
/// # Errors
///
/// `QQQ-3009` when the status, a header, or the sizes fail validation. The
/// file (and its tests) that define the wire contract live in `qqq-serve`;
/// this function enforces the guest side of it.
pub fn to_served(
    response: abi::Response,
    body_cap_bytes: u64,
) -> std::result::Result<Response, Error> {
    if !is_valid_guest_status(response.status) {
        return Err(Error::new(
            ErrorCode::GuestResponseRefused,
            format!(
                "guest status {} has no meaning on the wire (100-599 only)",
                response.status
            ),
        ));
    }
    if response.headers.len() > MAX_RESPONSE_HEADERS {
        return Err(Error::new(
            ErrorCode::GuestResponseRefused,
            format!(
                "guest sent {} headers, over the {MAX_RESPONSE_HEADERS} cap",
                response.headers.len()
            ),
        ));
    }
    let mut headers = Vec::with_capacity(response.headers.len());
    for h in &response.headers {
        // Names are validated before values are decoded: a host-controlled
        // name is refused even when its value is non-UTF-8. Decoding first
        // would `continue` past the framing header and hide the attempt —
        // the drop below is for values, never for names.
        // Names are trimmed here, unlike on the parse path: parsing must not
        // repair (`Host : x` hides smuggling), but emitting normalizes — the
        // wire always carries the trimmed form either way, so nothing is
        // hidden from anyone reading the response.
        let name = h.name.trim();
        if !qqq_serve::http1::is_valid_header_name(name) {
            return Err(Error::new(
                ErrorCode::GuestResponseRefused,
                format!("guest header name `{name}` is not a valid token"),
            ));
        }
        if is_host_controlled_header(name) {
            return Err(Error::new(
                ErrorCode::GuestResponseRefused,
                format!("guest must not set host-controlled header `{name}`"),
            ));
        }
        // Non-UTF-8 values keep the historical drop: a lossy conversion would
        // emit U+FFFD, producing a valid response carrying a header the guest
        // never sent — a silent corruption. Pinned by
        // `a_non_utf8_header_is_dropped_rather_than_corrupted`; F-02 deliberately
        // does not change it, because dropping a single header is fail-safe
        // while refusing the whole response over one bad value would turn a
        // logging header into a denial of service on the happy path.
        let Ok(value) = std::str::from_utf8(&h.value) else {
            continue;
        };
        let value = escape_header_value(value.trim());
        if name.len() + value.len() > MAX_RESPONSE_HEADER_BYTES {
            return Err(Error::new(
                ErrorCode::GuestResponseRefused,
                format!("guest header `{name}` exceeds {MAX_RESPONSE_HEADER_BYTES} bytes"),
            ));
        }
        headers.push((name.to_owned(), value));
    }
    // The body cap is checked after the headers so a response that violates
    // both reports the headers first — matching the order the checks are
    // documented in, and keeping every existing header-first test green.
    // The comparison is against the caller's bound (the smaller of the
    // response constant and the instance ceiling), not a second number.
    let body_len = u64::try_from(response.body.len()).unwrap_or(u64::MAX);
    if body_len > body_cap_bytes {
        return Err(Error::new(
            ErrorCode::GuestResponseRefused,
            format!("guest body {body_len} bytes exceeds the {body_cap_bytes}-byte cap"),
        )
        .with_remediation("return a smaller body, or raise the instance memory ceiling"));
    }
    Ok(Response {
        status: response.status,
        headers,
        body: response.body,
    })
}

/// The response for a failed guest call.
///
/// The message is the guest's own where there is one, because an operator
/// debugging an app wants the app's reason rather than QQQ's.
pub(crate) fn failure_response(e: &Error) -> Response {
    let mut r = Response::text(502, format!("the application failed: {}", e.message));
    r.set_header("X-QQQ-Error", &format!("{:?}", e.code));
    r
}

/// The error for a request shed by the buffer budget (`F-03`).
///
/// `HostResourceExhausted` with the pool's `Retry-After` estimate, so the
/// existing overload mapping renders 503. Built separately from the response
/// because the shed path feeds this error into `settle` for the `Failed`
/// row while the client gets the 503 response.
fn buffer_overload_error(pool: &Pool, completion_rate: f64) -> Error {
    Error::new(
        ErrorCode::HostResourceExhausted,
        "host buffer budget exhausted: too many large bodies in flight",
    )
    .with_context(
        "retry-after",
        pool.retry_after_seconds(completion_rate).to_string(),
    )
    .with_remediation("retry the request; reduce concurrent large uploads")
}

/// The response for a request shed by the buffer budget (`F-03`).
///
/// A 503 with `Retry-After`, built through the same error-to-response
/// mapping as every other overload (`error_response` + `from_error`) rather
/// than hand-rolled, so the status, retry header, and generic body match the
/// pool-exhausted shape exactly. Returned as `Ok` (a served shedding
/// response), not `Err`: the request was valid, the host is full, and the
/// failure path renders 502, which would misreport capacity as a guest bug.
fn buffer_overload(pool: &Pool, completion_rate: f64) -> Response {
    let error = buffer_overload_error(pool, completion_rate);
    qqq_serve::response::from_error(&qqq_serve::response::error_response(&error, false))
}

/// The error for a request refused because its evidence could not persist
/// (`F-09`, `FailClosed`).
///
/// `HostResourceExhausted` like the shed path: the guest did nothing wrong,
/// the host cannot keep its evidence promise, and the client must retry
/// rather than receive an answer that was never recorded.
fn audit_persist_error(pool: &Pool, completion_rate: f64, detail: &str) -> Error {
    Error::new(
        ErrorCode::HostResourceExhausted,
        format!("audit evidence could not be persisted: {detail}"),
    )
    .with_context(
        "retry-after",
        pool.retry_after_seconds(completion_rate).to_string(),
    )
    .with_remediation(
        "retry the request; page the operator if 503s persist — the audit sink is down",
    )
}

/// The 503 for a `FailClosed` audit refusal, shaped exactly like the shed
/// 503: same error-to-response mapping, same `Retry-After`, returned as
/// `Ok` for the same reason (the request was valid; reporting capacity
/// as a guest bug would be the 502 misreport).
fn audit_unavailable(pool: &Pool, completion_rate: f64, detail: &str) -> Response {
    let error = audit_persist_error(pool, completion_rate, detail);
    qqq_serve::response::from_error(&qqq_serve::response::error_response(&error, false))
}

// Release capacity during unwinding too; successful responses and traps share this guard.
struct RequestPermit<'a> {
    pool: &'a Pool,
    /// Set when the request failed: a store that trapped, panicked, or
    /// errored is dropped, never returned to the idle list (`F-01`, `F-11`).
    /// V1 builds a fresh instance per request, so only clean completions
    /// hand their slot back; anything else goes through `discard()`.
    tainted: std::sync::atomic::AtomicBool,
}

impl<'a> RequestPermit<'a> {
    fn clean(pool: &'a Pool) -> Self {
        Self {
            pool,
            tainted: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Mark the guarded request as failed before the guard drops.
    fn taint(&self) {
        self.tainted
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Drop for RequestPermit<'_> {
    fn drop(&mut self) {
        // Panic-free by construction (`F-21`): both paths saturate rather
        // than assert, and the diagnostic write swallows its own errors.
        if self.tainted.load(std::sync::atomic::Ordering::Relaxed) {
            self.pool.discard();
        } else {
            self.pool.release();
        }
    }
}

fn timed_options(limits: LimitSet, deterministic: bool) -> qqq_host::InstanceOptions {
    qqq_host::InstanceOptions {
        epoch_ticks: Some(limits.epoch_deadline_ms.max(1)),
        deterministic,
        ..Default::default()
    }
}

/// One timer per engine lineage, retained until all generations drain. Fuel
/// remains a second bound; an epoch cannot interrupt a blocking host import.
struct EpochTicker {
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl EpochTicker {
    fn start(engine: wasmtime::Engine) -> Result<Self> {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let driver = engine;
        let thread = std::thread::Builder::new()
            .name("qqq-epochs".into())
            .spawn(move || {
                // Fail-stop first (`F-01`): a dead ticker silently disables
                // wall-clock deadlines, leaving only fuel to bound CPU. A
                // panic here aborts the process rather than parking the
                // safety mechanism. Request threads must NOT use this guard —
                // their panics are contained into traps by `guard`.
                let _fail_stop = qqq_host::guard::AbortOnPanic::new("qqq-epochs");
                let started = std::time::Instant::now();
                let mut emitted = 0;
                while !stopped.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    // Account for scheduler/timer granularity (notably Windows):
                    // one sleep is not necessarily one millisecond of elapsed time.
                    let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    for _ in emitted..elapsed {
                        driver.increment_epoch();
                    }
                    emitted = elapsed;
                }
            })
            .map_err(|e| Error::new(ErrorCode::InternalInvariantViolated, e.to_string()))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
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
        test_app_with_capacity(1, qqq_cap::resolve::GrantSet::empty())
    }

    /// A test app granted `HttpServer`, for tests that assert on the granted
    /// outcome arms (`Granted`/`Failed`) rather than the ungranted one. The
    /// manifest is the sole layer permitted to grant, so the test declares
    /// the capability the same way production does.
    fn granted_test_app() -> Option<GuestApp> {
        let manifest = qqq_cap::Manifest::parse(
            "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n\
             [capabilities.http]\nserver = true\n",
        )
        .expect("a minimal manifest parses");
        test_app_with_capacity(1, qqq_cap::resolve::GrantSet::from_manifest(&manifest))
    }

    /// A test app with room for concurrent requests. The default builder
    /// sizes the pool to one slot, so a concurrency test through it would
    /// measure pool refusals rather than audit persistence.
    fn test_app_with_capacity(
        workers: u32,
        grants: qqq_cap::resolve::GrantSet,
    ) -> Option<GuestApp> {
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
        GuestApp::with_capacity(engine, &bytes, grants, limits, "127.0.0.1:8080", workers).ok()
    }

    /// **F-09: a dead sink refuses with 503 and never runs the guest.**
    ///
    /// `/dev/full` fails every write with `ENOSPC`, deterministically —
    /// the disk-died-mid-run case without staging a dying disk. The first
    /// request's persist fails after the guest ran (`FailClosed` turns the
    /// response into 503); the worker is now failed, so the second
    /// request is refused by the pre-flight with the guest unexecuted,
    /// proven by the stream holding no new rows. Unix-only: there is no
    /// always-failing device on Windows.
    #[cfg(unix)]
    #[test]
    fn f09_fail_closed_returns_503_without_running_the_guest() {
        let Some(mut app) = test_app() else {
            return;
        };
        app.attach_audit_file(std::path::Path::new("/dev/full"))
            .expect("attach opens the device");
        let first = app
            .handle_request(
                &head(qqq_serve::Method::Get, "/orders"),
                None,
                "test-tenant",
            )
            .expect("well-formed");
        assert_eq!(
            first.status, 503,
            "an unpersistable request must 503, not serve over a hole"
        );
        let held = {
            app.audit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len()
        };
        let second = app
            .handle_request(
                &head(qqq_serve::Method::Get, "/orders"),
                None,
                "test-tenant",
            )
            .expect("well-formed");
        assert_eq!(second.status, 503, "the dead worker refuses up front");
        assert_eq!(
            app.audit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            held,
            "the refused request ran no guest and recorded no rows"
        );
    }

    /// **F-09: `FailOpenWithAlarm` serves and counts every drop.**
    ///
    /// Same dead device, but the operator chose availability: the
    /// request serves, each drop logs, and the counter audits the total.
    #[cfg(unix)]
    #[test]
    fn f09_fail_open_serves_and_counts_every_drop() {
        let Some(mut app) = test_app() else {
            return;
        };
        app.set_audit_failure_policy(qqq_host::audit_sink::AuditFailurePolicy::FailOpenWithAlarm);
        app.attach_audit_file(std::path::Path::new("/dev/full"))
            .expect("attach opens the device");
        let response = app
            .handle_request(
                &head(qqq_serve::Method::Get, "/orders"),
                None,
                "test-tenant",
            )
            .expect("well-formed");
        assert_ne!(
            response.status, 503,
            "FailOpen serves through a dead sink: {}",
            response.status
        );
        assert_eq!(app.audit_drops(), 1, "the drop is counted, not wished");
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

    /// **A live request holds its tenant's output entry, and no other tenant's.**
    ///
    /// The tenant string travels `serve` → handler → `serve_one` → registry,
    /// and the only observable point is mid-flight: the entry exists while the
    /// request runs and evicts after. A wrong tenant key would show up here as
    /// a missing entry for the requested tenant, or a present one for a tenant
    /// with no request.
    #[test]
    fn serve_one_accounts_the_request_to_its_tenant() {
        let Some(app) = test_app() else {
            return;
        };
        let app = Arc::new(app);
        let worker = Arc::clone(&app);
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = Arc::clone(&done);
        // Keep requesting until the observer has seen the entry: one pass is
        // usually enough, and the loop bounds the wait instead of assuming it.
        let t = std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let head = head(qqq_serve::Method::Get, "/orders");
                let _ = worker.handle_request(&head, None, "tenant-a");
            }
        });
        let start = std::time::Instant::now();
        let mut observed = false;
        while start.elapsed() < std::time::Duration::from_secs(10) {
            if app.tenant_outputs.live("tenant-a") >= 1 {
                assert_eq!(
                    app.tenant_outputs.live("tenant-b"),
                    0,
                    "a request for tenant-a must not open tenant-b's entry"
                );
                observed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        t.join().expect("the request thread must finish");
        assert!(
            observed,
            "a live request must hold its tenant's entry; increase the timeout before doubting the wiring"
        );
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
        let _ = app.handle_request(&head, None, "test-tenant");

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
        let _ = app.handle_request(&head, None, "test-tenant");
        let _ = app.handle_request(&head, None, "test-tenant");

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
        // **Verify each served row's chain from its own fields**, not by
        // re-appending: re-recording assigns a fresh timestamp, so a
        // re-recorded chain can never equal the served one (`F-09`
        // timestamps are part of the digest). The claim under test is that
        // the chain is a function of the row's contents — recomputing from
        // the observed fields must reproduce it exactly — plus the link
        // check, which an empty-stream verify would pass trivially
        // (`§O-293`).
        for (i, served) in records.iter().enumerate() {
            let recomputed = qqq_host::AuditRecord::compute_chain_v2(&served.fields(), None);
            assert_eq!(
                served.chain, recomputed,
                "record {i}: the chain the served path produced must be reproducible from the \
                 record's own fields -- otherwise the chain is not a function of its contents"
            );
        }
        let mut replay = qqq_host::AuditStream::with_default_capacity();
        for record in &records {
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
        assert!(
            replay.verify_chain().is_ok(),
            "the replayed chain must verify: {replay:?}",
            replay = replay.verify_chain().err()
        );
    }

    /// **Every record the file lacks is persisted -- not only the last one.** `CodeRabbit` finding #12.
    ///
    /// # Why this test could not have passed before the fix, and why the defect survived
    ///
    /// The code appended `stream.records().last()`. With **one** record appended per call the two
    /// behaviours are indistinguishable -- and every existing test appends one -- so a module with
    /// this much audit coverage had nothing to say about it. **Three** records make them differ by
    /// two, which is the whole test.
    ///
    /// The review called it `critical`, and the reason is in the code's own comment three lines above
    /// where the bug was: the write happens inside the block *"so the record written is the record
    /// appended"*. It was not. An evidence file that holds a subset of the stream it came from cannot
    /// answer the only question it exists to answer.
    /// **The worker persists every row it is handed, and a resend duplicates nothing.**
    ///
    /// The property the old `persist_pending` test pinned — three records in,
    /// three lines out, and a second identical handoff appending nothing —
    /// now belongs to the worker: sequence-keyed buffering makes a repeated
    /// row an overwrite of the identical entry rather than a second line.
    /// Three records make the single-row and whole-suffix behaviours differ,
    /// which is the whole test.
    #[test]
    fn worker_persists_every_handed_row_without_duplicating_resends() {
        use std::time::Duration;

        let dir = std::env::temp_dir().join(format!("qqq-cr12-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("audit.jsonl");

        let mut stream = qqq_host::audit::AuditStream::with_default_capacity();
        let component = qqq_host::tenant::ComponentDigest::new("0011223344556677").expect("digest");
        let grants = qqq_host::tenant::GrantDigest::new("aabbccdd").expect("digest");
        for outcome in [
            qqq_host::audit::Outcome::Granted,
            qqq_host::audit::Outcome::Denied,
            qqq_host::audit::Outcome::Granted,
        ] {
            let _ = stream.record(
                None,
                &component,
                &grants,
                qqq_cap::capability::Capability::HttpServer,
                "handle_request",
                outcome,
            );
        }
        assert_eq!(
            stream.records().len(),
            3,
            "three records, so the last is not the whole"
        );

        let file = qqq_host::audit_sink::AuditFile::open(&path, 0).expect("open");
        let appender = qqq_host::audit_sink::AuditAppender::spawn(
            file,
            qqq_host::audit_sink::AppenderConfig::default(),
        )
        .expect("spawn");
        let rows = stream.records().to_vec();
        let ack = appender
            .persist(&rows, Duration::from_secs(30))
            .expect("a live worker persists");
        assert_eq!(ack.persisted, 3, "the barrier must confirm all three");

        // A second identical handoff to the SAME worker must not duplicate:
        // every sequence is already past its frontier, so the rows land in
        // the reorder buffer and never reach the file again. (A fresh worker
        // would legitimately rewrite them — its frontier starts empty — which
        // is why sharing one appender per file is structural, not optional.)
        let ack = appender
            .persist(&rows, Duration::from_secs(30))
            .expect("resend reaches a live worker");
        assert_eq!(ack.persisted, 3, "nothing new may be written twice");
        assert_eq!(
            appender.stats().resent_skipped,
            3,
            "the resend must be counted as skipped, not buffered"
        );
        assert_eq!(
            appender.stats().late_after_skip,
            0,
            "a resend of written rows is a duplicate, not a late loss"
        );
        drop(appender);

        let text = std::fs::read_to_string(&path).expect("read");
        assert_eq!(
            text.lines().count(),
            3,
            "the file must hold all three exactly once: {text}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The attach derives the worker's tripwires from the epoch deadline.**
    ///
    /// Ambient rows are recorded during guest execution, which preemption
    /// bounds — so a stall longer than twice the epoch deadline plus a margin
    /// is a dead producer, while anything shorter may be a legitimate slow
    /// request the worker must wait out rather than skip. The test app runs a
    /// 10 s deadline, so the stall must be 20 s and the persist tripwire 50 s;
    /// a hardcoded pair would silently stop tracking the limits it claims to
    /// follow the moment the deadline changed.
    #[test]
    fn attach_derives_worker_timeouts_from_the_epoch_deadline() {
        let Some(mut app) = test_app() else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("qqq-audit-timeouts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("audit.jsonl");

        app.attach_audit_file(&path).expect("attach");
        let appender = app
            .audit_appender
            .as_ref()
            .expect("attach installs a worker");
        assert_eq!(
            appender.config().stall_timeout,
            std::time::Duration::from_secs(20),
            "the 10 s test-app deadline plus the margin"
        );
        assert_eq!(
            appender.config().persist_timeout,
            std::time::Duration::from_secs(50),
            "the persist tripwire stays ordered after the stall"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Concurrent requests persist without barrier deadlock or late loss.**
    ///
    /// The persist blocks on the worker's barrier, so whatever it holds while
    /// waiting is a lock-ordering decision: holding the stream guard across
    /// it would wedge against a worker waiting on a row whose producer waits
    /// on that same guard. The persist therefore receives cloned rows after
    /// an explicit `drop(stream)` — a structural fact (the signature takes a
    /// slice, not the guard), not a convention. This test exercises the fixed
    /// pattern under churn: four threads serving ten requests each through
    /// one app must all persist without a single timeout, with every stream
    /// row in the file and no late loss. The app carries eight pool slots so
    /// a capacity refusal can never stand in for a served request — errors
    /// are counted, and all forty requests must succeed, or the file/stream
    /// agreement below would pass on requests that never ran.
    #[test]
    fn concurrent_requests_persist_without_barrier_deadlock() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;
        let Some(app) = test_app_with_capacity(8, qqq_cap::resolve::GrantSet::empty()) else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("qqq-audit-conc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("audit.jsonl");
        let mut app = app;
        app.attach_audit_file(&path).expect("attach");
        let app = Arc::new(app);
        let served = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let app = Arc::clone(&app);
            let served = Arc::clone(&served);
            handles.push(std::thread::spawn(move || {
                for _ in 0..10 {
                    let head = head(qqq_serve::Method::Get, "/orders");
                    if app.handle_request(&head, None, "test-tenant").is_ok() {
                        served.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("worker thread must not panic");
        }
        assert_eq!(
            served.load(Ordering::Relaxed),
            40,
            "every request must be served, not refused by a full pool"
        );
        let stats = app.audit_appender.as_ref().expect("attached").stats();
        assert_eq!(
            stats.late_after_skip, 0,
            "no row may arrive after a skip on a healthy run: {stats:?}"
        );
        assert_eq!(
            stats.unpersisted_after_failure, 0,
            "no row may be lost: {stats:?}"
        );
        let (stream_rows, _) = app.audit_snapshot();
        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("read")
                .lines()
                .count(),
            stream_rows.len(),
            "every stream row must reach the file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The record is persisted, and a second process continues the chain — `OBS-002`.**
    ///
    /// This is Gate 1's *"a request through `qqqai serve` produces a chained record that survives a
    /// restart"*, at the level where the record is actually written. Before persistence the stream
    /// lived in `GuestApp`'s memory and died with the process, so the record could not outlive the
    /// server it was evidence about.
    #[test]
    fn the_audit_record_is_persisted_and_a_restart_continues_the_chain() {
        let Some(mut first) = test_app() else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("qqq-audit-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("audit.jsonl");

        first.attach_audit_file(&path).expect("attach");
        let head = head(qqq_serve::Method::Get, "/orders");
        let _ = first.handle_request(&head, None, "test-tenant");

        let written = std::fs::read_to_string(&path).expect("the file exists after one request");
        assert_eq!(
            written.lines().count(),
            1,
            "one served request must write exactly one line; got: {written:?}"
        );
        let (before, _) = first.audit_snapshot();
        assert_eq!(before.len(), 1);
        let head_before = before[0].chain.clone();

        // --- the "restart": a second app, attaching the same file -----------------
        let Some(mut second) = test_app() else {
            return;
        };
        second.attach_audit_file(&path).expect("resume");
        let (resumed, _) = second.audit_snapshot();
        assert_eq!(resumed.len(), 1, "the history was read back");
        assert_eq!(
            resumed[0].chain, head_before,
            "the resumed history must be the history that was written"
        );

        let _ = second.handle_request(&head, None, "test-tenant");
        let (after, _) = second.audit_snapshot();
        assert_eq!(
            after.len(),
            2,
            "the second request appended to the resumed history"
        );
        assert_eq!(
            after[1].previous, after[0].chain,
            "the new record must chain from the one written by the previous process"
        );
        assert_eq!(
            after[1].sequence, 2,
            "the sequence continues across the restart"
        );
        assert!(
            second.audit_snapshot().0.len() == 2
                && std::fs::read_to_string(&path).unwrap().lines().count() == 2,
            "and the file holds both, so the record outlived the process that made it"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A chain-broken audit file refuses to attach, rather than being extended.**
    ///
    /// A server that resumed a broken chain would append to it, and every later record would
    /// commit to a predecessor that was already wrong — so the corruption would be **extended
    /// rather than detected**, and the file would look healthy from the restart onward.
    #[test]
    fn a_tampered_audit_file_refuses_to_attach() {
        let Some(mut app) = test_app() else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("qqq-audit-tamper-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("audit.jsonl");

        app.attach_audit_file(&path).expect("attach");
        let head = head(qqq_serve::Method::Get, "/orders");
        let _ = app.handle_request(&head, None, "test-tenant");
        let (records, _) = app.audit_snapshot();
        let good = records[0].chain.clone();

        // Rewrite the chain digest in the file, leaving the line well-formed JSON.
        let text = std::fs::read_to_string(&path).expect("read");
        std::fs::write(&path, text.replace(&good, &"0".repeat(good.len()))).expect("tamper");

        let Some(mut victim) = test_app() else {
            return;
        };
        let refused = victim.attach_audit_file(&path);
        assert!(
            refused.is_err(),
            "attaching a tampered record must refuse, not resume -- got Ok"
        );
        let message = format!("{:?}", refused.err());
        assert!(
            message.contains("broken chain"),
            "the refusal must name the broken chain, got: {message}"
        );

        let _ = std::fs::remove_dir_all(&dir);
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
        let served =
            to_served(guest, MAX_GUEST_RESPONSE_BODY_BYTES).expect("valid guest response converts");
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
        let served =
            to_served(guest, MAX_GUEST_RESPONSE_BODY_BYTES).expect("other headers still convert");
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
        let served =
            to_served(guest, MAX_GUEST_RESPONSE_BODY_BYTES).expect("valid UTF-8 still converts");
        assert_eq!(served.headers.len(), 1);
        assert_eq!(served.headers[0].1, "café");
    }

    fn guest_response(status: u16, headers: Vec<(&str, &[u8])>) -> abi::Response {
        abi::Response {
            status,
            headers: headers
                .into_iter()
                .map(|(name, value)| abi::Header {
                    name: name.to_owned(),
                    value: value.to_vec(),
                })
                .collect(),
            body: Vec::new(),
        }
    }

    /// **Guest statuses outside 100–599 are refused, not serialized.**
    ///
    /// Audit `F-02`: a status the wire has no meaning for (99, 600, let alone
    /// 99999) must never reach the serializer — there is no reason phrase for
    /// it and no client behavior defined. Refusal here becomes the 502 the
    /// caller already renders for failed guests.
    #[test]
    fn f02_invalid_status_is_refused() {
        for status in [0, 99, 600, 999] {
            let err = to_served(
                guest_response(status, vec![]),
                MAX_GUEST_RESPONSE_BODY_BYTES,
            )
            .expect_err(&format!("status {status} must be refused"));
            assert!(
                matches!(err.code, qqq_core::ErrorCode::GuestResponseRefused),
                "wrong code: {err:?}"
            );
        }
        for status in [100, 200, 201, 404, 500, 599] {
            let served = to_served(
                guest_response(status, vec![]),
                MAX_GUEST_RESPONSE_BODY_BYTES,
            )
            .unwrap_or_else(|e| panic!("status {status} must convert: {e:?}"));
            assert_eq!(served.status, status);
        }
    }

    /// **Host-controlled framing headers from a guest are refused.**
    ///
    /// `Content-Length`, `Connection`, and `Transfer-Encoding` are the
    /// serializer's to write (it skips them when present); a guest setting
    /// them is either confused or attempting to desynchronize the stream.
    /// Refusing the whole response fails closed where silently dropping would
    /// hide the attempt.
    #[test]
    fn f02_host_controlled_headers_are_refused() {
        for name in ["Content-Length", "connection", "TRANSFER-ENCODING"] {
            let err = to_served(
                guest_response(200, vec![(name, b"0")]),
                MAX_GUEST_RESPONSE_BODY_BYTES,
            )
            .expect_err(&format!("{name} from a guest must be refused"));
            assert!(
                matches!(err.code, qqq_core::ErrorCode::GuestResponseRefused),
                "wrong code: {err:?}"
            );
        }
        // Ordinary headers are unaffected.
        let served = to_served(
            guest_response(200, vec![("Content-Type", b"text/plain")]),
            MAX_GUEST_RESPONSE_BODY_BYTES,
        )
        .expect("ordinary header converts");
        assert_eq!(served.headers[0].0, "Content-Type");
    }

    /// **A poisoned name is refused even when its value is undecodable.**
    ///
    /// Name validation runs before value decoding: a host-controlled name
    /// with a non-UTF-8 value refuses the response instead of dropping the
    /// header and hiding the attempt. Decoding first would `continue` past
    /// the framing header — the drop is for values, never for names.
    #[test]
    fn f02_host_controlled_name_with_bad_value_is_refused() {
        let err = to_served(
            guest_response(200, vec![("Content-Length", b"\xff\xfe")]),
            MAX_GUEST_RESPONSE_BODY_BYTES,
        )
        .expect_err("host-controlled name with bad value must be refused, not dropped");
        assert!(
            matches!(err.code, qqq_core::ErrorCode::GuestResponseRefused),
            "wrong code: {err:?}"
        );
    }

    /// **Oversized header sets are refused before serialization.**
    ///
    /// 129 headers where 128 are allowed, and a single value over 8 KiB:
    /// both must fail with the response refusal, because the serializer
    /// writes what it is given without further checks.
    #[test]
    fn f02_oversized_headers_are_refused() {
        let many: Vec<(String, Vec<u8>)> = (0..129)
            .map(|i| (format!("x-pad-{i}"), b"v".to_vec()))
            .collect();
        let guest = abi::Response {
            status: 200,
            headers: many
                .into_iter()
                .map(|(name, value)| abi::Header { name, value })
                .collect(),
            body: Vec::new(),
        };
        to_served(guest, MAX_GUEST_RESPONSE_BODY_BYTES).expect_err("129 headers must be refused");
        let big_value = vec![b'v'; 8193];
        let big = guest_response(200, vec![("x-big", &big_value)]);
        to_served(big, MAX_GUEST_RESPONSE_BODY_BYTES).expect_err("over-long value must be refused");
    }

    /// **CR and LF in values are escaped, never emitted raw.**
    ///
    /// A `value` containing `\r\nEvil: x` would split the response on the
    /// wire. Percent-encoding (with `%` itself encoded first, so `%0D` in
    /// input becomes `%250D` rather than a smuggled decode) keeps the
    /// response intact: no raw CR or LF may survive in any emitted header.
    #[test]
    fn f02_crlf_in_values_is_escaped_not_emitted() {
        let served = to_served(
            guest_response(200, vec![("x-note", b"a\r\nEvil: x")]),
            MAX_GUEST_RESPONSE_BODY_BYTES,
        )
        .expect("CRLF value converts with escaping");
        assert_eq!(served.headers[0].1, "a%0D%0AEvil: x");
        for (_, value) in &served.headers {
            assert!(
                !value.contains('\r') && !value.contains('\n'),
                "raw CR/LF must never survive: {value:?}"
            );
        }
        // `%0D` in input double-encodes: it must not decode back.
        let served = to_served(
            guest_response(200, vec![("x-note", b"%0D")]),
            MAX_GUEST_RESPONSE_BODY_BYTES,
        )
        .expect("percent converts");
        assert_eq!(served.headers[0].1, "%250D");
        // NUL and DEL take the same path: no ASCII control except tab survives.
        let served = to_served(
            guest_response(200, vec![("x-note", b"a\x00b\x7f")]),
            MAX_GUEST_RESPONSE_BODY_BYTES,
        )
        .expect("controls convert");
        assert_eq!(served.headers[0].1, "a%00b%7F");
        for (_, value) in &served.headers {
            assert!(
                !value.chars().any(|c| c.is_ascii_control() && c != '\t'),
                "no control byte except tab may survive: {value:?}"
            );
        }
    }

    /// **A poisoned guest response becomes a clean 502 carrying none of the poison.**
    ///
    /// End to end at the conversion boundary: `to_served` refuses, the
    /// failure path renders 502, and the wire bytes contain neither the evil
    /// header nor the illegal status. Zero guest bytes are written before
    /// validation because validation happens before serialization.
    #[test]
    fn f02_malicious_guest_becomes_a_clean_502() {
        use qqq_serve::http1::Version;
        use qqq_serve::response::write_response;
        let guest = abi::Response {
            status: 99,
            headers: vec![abi::Header {
                name: "x-evil".to_owned(),
                value: b"a\r\nInjected: yes".to_vec(),
            }],
            body: b"poison-body".to_vec(),
        };
        let err = to_served(guest, MAX_GUEST_RESPONSE_BODY_BYTES)
            .expect_err("poisoned response must fail");
        let failure = failure_response(&err);
        assert_eq!(failure.status, 502);
        let wire = String::from_utf8(write_response(&failure, Version::Http11, false, false))
            .expect("error responses are valid UTF-8");
        assert!(wire.starts_with("HTTP/1.1 502 "), "{wire}");
        assert!(
            !wire.contains("x-evil"),
            "guest header must not reach the wire"
        );
        assert!(
            !wire.contains("poison-body"),
            "guest body must not reach the wire"
        );
        assert!(
            !wire.contains("HTTP/1.1 99"),
            "guest status must not become the response status"
        );
    }

    /// **A boundary rejection audits as `Failed`, never `Granted`.**
    ///
    /// Independent review of the F-02 walk caught the ordering defect this
    /// pins: `handle_request` derived the audit outcome from the raw guest
    /// result and converted with `to_served` afterwards, so a response the
    /// boundary refuses (illegal status, host-controlled header, breached
    /// cap) was recorded as `Granted` while the caller rendered its 502.
    /// The conversion now precedes the audit row. This test drives a
    /// `to_served`-rejected answer through the real convert-then-classify
    /// seam (`settle`, the exact step `handle_request` runs before the row)
    /// on a granted app and asserts the row kind is `Failed` — alongside
    /// the three neighbouring cases, so the mapping cannot drift one arm
    /// at a time.
    #[test]
    fn f02_boundary_rejection_audits_as_failed() {
        let Some(granted) = granted_test_app() else {
            return;
        };
        let poisoned = abi::Response {
            status: 99,
            headers: vec![abi::Header {
                name: "Content-Length".to_owned(),
                value: b"0".to_vec(),
            }],
            body: b"poison-body".to_vec(),
        };
        let (converted, kind) = granted.settle(Ok(poisoned));
        assert!(
            converted.is_err(),
            "the poisoned answer must still fail conversion"
        );
        assert_eq!(
            kind,
            qqq_host::Outcome::Failed,
            "a refused answer on a granted app audits as a failed exercise"
        );

        let valid = || abi::Response {
            status: 200,
            headers: vec![],
            body: b"ok".to_vec(),
        };
        let (converted, kind) = granted.settle(Ok(valid()));
        assert!(converted.is_ok(), "the valid answer must convert");
        assert_eq!(
            kind,
            qqq_host::Outcome::Granted,
            "a served answer audits as the authority exercised to success"
        );

        let (converted, kind) = granted.settle(Err(Error::new(
            ErrorCode::GuestResponseRefused,
            "trap stand-in",
        )));
        assert!(converted.is_err(), "a failed call stays failed");
        assert_eq!(
            kind,
            qqq_host::Outcome::Failed,
            "a trapped call on a granted app audits as failed"
        );

        let Some(ungranted) = test_app() else {
            return;
        };
        let (converted, kind) = ungranted.settle(Ok(valid()));
        assert!(converted.is_ok(), "conversion does not depend on grants");
        assert_eq!(
            kind,
            qqq_host::Outcome::Attempted,
            "no grant means an attempt, however the call ended"
        );
    }

    /// A granted app serving a caller-supplied WAT guest, for request-path
    /// tests that need the guest to misbehave (hostile answers, traps).
    /// The fixture is compiled in (`include_str!` at the call site), so a
    /// build failure here is a real failure, never a missing artifact:
    /// `expect`, not an early return. (The orders-component builders return
    /// early because that artifact lives outside the repo and may be absent;
    /// these fixtures cannot be.)
    fn granted_app_for_wat(source: &str) -> GuestApp {
        let manifest = qqq_cap::Manifest::parse(
            "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n\
             [capabilities.http]\nserver = true\n",
        )
        .expect("a minimal manifest parses");
        let cfg = qqq_host::config::EngineConfig::default();
        let wasmtime_cfg = cfg.to_wasmtime_config().expect("engine config");
        let engine = wasmtime::Engine::new(&wasmtime_cfg).expect("engine");
        let limits = qqq_host::LimitSet {
            memory_bytes: 64 * 1024 * 1024,
            fuel: 1_000_000_000,
            epoch_deadline_ms: 10_000,
            max_open_handles: 64,
            max_subrequests: 16,
        };
        GuestApp::with_capacity(
            engine,
            source.as_bytes(),
            qqq_cap::resolve::GrantSet::from_manifest(&manifest),
            limits,
            "127.0.0.1:8080",
            1,
        )
        .expect("the WAT fixture must build")
    }

    /// A hostile guest answering outside the protocol gets a 502 and a
    /// `Failed` row — through the real request path, not the seam.
    ///
    /// The `settle` test above pins the convert-then-classify mapping, but
    /// the defect lived in `handle_request`'s ordering (the row read the raw
    /// answer), so only a request through `handle_request` with the audit
    /// block executing proves the row. The hostile fixture answers status
    /// 99: `to_served` refuses it, the caller renders 502, and the recorded
    /// row must read `Failed` — a guest that answers outside the protocol
    /// is exercising the authority and failing, never succeeding quietly.
    #[test]
    fn f02_hostile_answer_audits_as_failed_on_the_request_path() {
        let source = include_str!("../tests/fixtures/hostile-response.wat");
        let mut app = granted_app_for_wat(source);
        let dir = std::env::temp_dir().join(format!("qqq-audit-hostile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("audit.jsonl");
        app.attach_audit_file(&path).expect("attach");
        let outcome = app.handle_request(
            &head(qqq_serve::Method::Get, "/orders"),
            None,
            "test-tenant",
        );
        let err = outcome.expect_err("the hostile answer must fail the request");
        assert!(
            matches!(err.code, qqq_core::ErrorCode::GuestResponseRefused),
            "wrong code: {err:?}"
        );
        assert_eq!(
            failure_response(&err).status,
            502,
            "the hostile answer must render 502"
        );
        let (rows, _) = app.audit_snapshot();
        assert_eq!(rows.len(), 1, "one request writes exactly one row");
        assert_eq!(
            rows[0].outcome,
            qqq_host::Outcome::Failed,
            "a boundary-refused answer audits as a failed exercise"
        );
        // F-11: the settled rule routes boundary refusals through `discard()`
        // like traps — the instance produced protocol-violating output, so no
        // slot returns to idle.
        assert_eq!(
            app.pool.metrics().discarded(),
            1,
            "the boundary-refused slot is discarded, not released"
        );
        assert_eq!(app.pool.idle(), 0, "no slot returns to idle on failure");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **F-01: a trapped request discards its slot through the request path.**
    ///
    /// V1 builds a fresh instance per request, so only clean completions hand
    /// their pool slot back: any error from `serve_one` taints the permit and
    /// the slot goes through `Pool::discard()`, never to idle. The trapping
    /// guest (`trap.wat`: `unreachable` in the handler) fails the request;
    /// the test then proves the routing three ways — the discarded metric
    /// moves, idle stays zero (no slot returned), and the audit row reads
    /// `Failed`. A slot that returned to idle after a trap would let a later
    /// acquire report a reusable slot for a store that no longer exists.
    #[test]
    fn f01_trapped_request_discards_its_slot() {
        let source = include_str!("../tests/fixtures/trap.wat");
        let mut app = granted_app_for_wat(source);
        let dir = std::env::temp_dir().join(format!("qqq-audit-trap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("audit.jsonl");
        app.attach_audit_file(&path).expect("attach");
        let outcome = app.handle_request(
            &head(qqq_serve::Method::Get, "/orders"),
            None,
            "test-tenant",
        );
        assert!(outcome.is_err(), "the trapping guest must fail the request");
        assert_eq!(
            app.pool.metrics().discarded(),
            1,
            "exactly one discard: the trapped slot, routed through discard()"
        );
        assert_eq!(app.pool.idle(), 0, "no slot returns to idle after a trap");
        let (rows, _) = app.audit_snapshot();
        assert_eq!(
            rows[0].outcome,
            qqq_host::Outcome::Failed,
            "a trapped request audits as a failed exercise"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **F-11: a healthy request releases its slot through the request path.**
    ///
    /// The mirror of the trap test: `live-http.wat` answers inside the
    /// protocol, the request succeeds, and the slot goes through
    /// `Pool::release()` — released counts one, the slot returns to idle,
    /// and nothing is discarded. Together the three request-path tests pin
    /// the routing for every outcome class: trap, boundary refusal, success.
    #[test]
    fn f11_healthy_request_releases_its_slot() {
        let source = include_str!("../tests/fixtures/live-http.wat");
        let app = granted_app_for_wat(source);
        let outcome = app.handle_request(
            &head(qqq_serve::Method::Get, "/orders"),
            None,
            "test-tenant",
        );
        assert!(outcome.is_ok(), "the healthy guest must serve: {outcome:?}");
        assert_eq!(
            app.pool.metrics().released(),
            1,
            "exactly one release: the healthy slot, handed back"
        );
        assert_eq!(
            app.pool.metrics().discarded(),
            0,
            "nothing discarded on the success path"
        );
        assert_eq!(app.pool.idle(), 1, "the slot returns to idle on success");
    }

    /// **F-03/F-24: the echo guest returns every body byte-identical.**
    ///
    /// The safety net for the marshalling refactor, green BEFORE the typed
    /// switch and required green after: `echo-http.wat` copies the request
    /// body into the response through guest memory, so any asymmetry between
    /// the dynamic `Val::U8` path and the typed bulk-copy path — a dropped
    /// byte, a truncation, an off-by-one in the option lifting — fails here.
    /// Absent echoes as empty (the response shape carries a list, not an
    /// option, so there is no absent to preserve); everything present must
    /// round-trip exactly, up to the 2 MiB ingress cap.
    #[test]
    fn f03_echo_guest_returns_bodies_byte_identical() {
        let source = include_str!("../tests/fixtures/echo-http.wat");
        for body in [
            None,
            Some(Vec::new()),
            Some(vec![0xAB]),
            Some(vec![0x55; 64 * 1024]),
            Some(vec![0xA5; 2 * 1024 * 1024]),
        ] {
            let app = granted_app_for_wat(source);
            let expected = body.clone().unwrap_or_default();
            let outcome =
                app.handle_request(&head(qqq_serve::Method::Post, "/echo"), body, "test-tenant");
            let response = outcome.expect("echo must serve");
            assert_eq!(
                response.body,
                expected,
                "echo of {} bytes must be byte-identical",
                expected.len()
            );
        }
    }

    /// **F-03/F-24: marshalling benchmark, 1 KiB / 64 KiB / 2 MiB through the
    /// echo guest.**
    ///
    /// Ignored by default like the `qqq-bench` harnesses: tens of seconds and
    /// machine-sensitive. Run explicitly: `cargo test -p qqq-run --lib
    /// f03_marshal_benchmark -- --ignored --nocapture`. Reports median
    /// `handle_request` latency per size over 10 iterations on one reused app
    /// (engine build amortized, per-request cost isolated). It lives here
    /// rather than in `qqq-bench` because that crate cannot depend on
    /// `qqq-host` (PERF-005) and this measures the production path, not the
    /// raw mechanism. Pair with process-peak sampling for RSS (see the F-03
    /// commit message for the before/after numbers and method).
    #[test]
    #[ignore = "benchmark: seconds per size, machine-sensitive, run explicitly"]
    fn f03_marshal_benchmark() {
        let source = include_str!("../tests/fixtures/echo-http.wat");
        for (label, size) in [
            ("1KiB", 1024usize),
            ("64KiB", 64 * 1024),
            ("2MiB", 2 * 1024 * 1024),
        ] {
            let app = granted_app_for_wat(source);
            let body = vec![0xA5; size];
            // Warmup off the clock: pool slot, engine caches, allocator.
            for _ in 0..2 {
                let _ = app.handle_request(
                    &head(qqq_serve::Method::Post, "/echo"),
                    Some(body.clone()),
                    "test-tenant",
                );
            }
            let mut samples = Vec::with_capacity(10);
            for _ in 0..10 {
                let start = std::time::Instant::now();
                let outcome = app.handle_request(
                    &head(qqq_serve::Method::Post, "/echo"),
                    Some(body.clone()),
                    "test-tenant",
                );
                let response = outcome.expect("echo must serve");
                assert_eq!(response.body.len(), size);
                samples.push(start.elapsed().as_secs_f64() * 1000.0);
            }
            samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
            eprintln!("BENCH {label}: median {:.2} ms over 10", samples[5]);
        }
    }

    /// **F-03: a body over the cap is refused; exactly the cap serves.**
    ///
    /// Written first and failing first: `to_served` takes no cap today, so
    /// this does not compile — which is the red. The cap travels as a
    /// parameter (the effective bound is `min` of the response constant and
    /// the instance's memory ceiling, computed by the caller), so the
    /// boundary is unit-testable without a 9 MiB guest. The code is the
    /// response-side `GuestResponseRefused`, the same as the other shape
    /// refusals — one code for "the guest answered outside the contract".
    #[test]
    fn f03_response_body_over_cap_is_refused_at_cap_is_served() {
        let big = abi::Response {
            status: 200,
            headers: vec![],
            body: vec![0xA5; 101],
        };
        let err = to_served(big, 100).expect_err("101 bytes against a 100 cap must fail");
        assert_eq!(err.code, qqq_core::ErrorCode::GuestResponseRefused);
        let exact = abi::Response {
            status: 200,
            headers: vec![],
            body: vec![0xA5; 100],
        };
        let served = to_served(exact, 100).expect("exactly the cap must serve");
        assert_eq!(served.body.len(), 100);
    }

    /// **F-03: an exhausted buffer budget sheds with 503 + `Retry-After`.**
    ///
    /// Written first and failing first: no semaphore exists yet, so neither
    /// the field access nor the 503 compiles — which is the red. Holding the
    /// whole budget leaves no byte for the request; the shed response must
    /// carry 503 and a `Retry-After` header, never 502 (which would misreport
    /// capacity as a guest bug) and never a wait (queues turn heap pressure
    /// into OOM).
    #[test]
    fn f03_buffer_budget_exhaustion_sheds_with_503() {
        let source = include_str!("../tests/fixtures/echo-http.wat");
        let app = granted_app_for_wat(source);
        let full = u32::try_from(BUFFER_BUDGET_BYTES).expect("256 MiB fits");
        let _held = app
            .buffer_budget
            .try_acquire_many(full)
            .expect("a fresh budget acquires in full");
        let outcome = app.handle_request(
            &head(qqq_serve::Method::Post, "/echo"),
            Some(vec![0xA5; 1024]),
            "test-tenant",
        );
        let response = outcome.expect("shedding still serves a response");
        assert_eq!(
            response.status, 503,
            "exhaustion must shed, not fail: {response:?}"
        );
        assert!(
            response.header("Retry-After").is_some(),
            "the shed response must tell the client when to retry"
        );
        // The shed happens before any pool slot is taken (budget gate runs
        // first), so nothing leaks: `in_use` stays zero.
        assert_eq!(
            app.pool.in_use(),
            0,
            "a shed request must not consume a pool slot"
        );
    }

    /// **F-03: the budget returns when the request completes.**
    ///
    /// Both permits (request body at entry, response body after lifting) are
    /// held by guards dropped at every exit path: after one echo the full
    /// budget acquires again. A leak here would shrink the budget
    /// monotonically — a server that gets slower the more it serves.
    #[test]
    fn f03_buffer_budget_returns_after_request() {
        let source = include_str!("../tests/fixtures/echo-http.wat");
        let app = granted_app_for_wat(source);
        let outcome = app.handle_request(
            &head(qqq_serve::Method::Post, "/echo"),
            Some(vec![0xA5; 1024]),
            "test-tenant",
        );
        assert!(outcome.is_ok(), "echo must serve: {outcome:?}");
        let full = u32::try_from(BUFFER_BUDGET_BYTES).expect("256 MiB fits");
        assert!(
            app.buffer_budget.try_acquire_many(full).is_ok(),
            "the whole budget must come back when the request completes"
        );
    }

    /// **F-03: an over-cap body is refused through the request path.**
    ///
    /// The integration half of the cap: a 9 MiB echo against the 8 MiB
    /// response constant (under the 64 MiB instance ceiling, so the ceiling
    /// is not what fires) fails with the response-side refusal, while the
    /// unit test above pins the exact-cap boundary without a 9 MiB guest.
    /// The guest runs fine — it is the host that declines to serve what
    /// does not fit the bound.
    #[test]
    fn f03_over_cap_body_is_refused_on_the_request_path() {
        let source = include_str!("../tests/fixtures/echo-http.wat");
        let app = granted_app_for_wat(source);
        let outcome = app.handle_request(
            &head(qqq_serve::Method::Post, "/echo"),
            Some(vec![0xA5; 9 * 1024 * 1024]),
            "test-tenant",
        );
        let err = outcome.expect_err("9 MiB against an 8 MiB cap must fail");
        assert_eq!(
            err.code,
            qqq_core::ErrorCode::GuestResponseRefused,
            "the cap refusal must carry the response code: {err:?}"
        );
    }

    /// **F-03: a shed response is still audited, and its slot is released.**
    ///
    /// The response-budget twin of the entry test: room for the 1 KiB
    /// request but not its 1 KiB echo, so the guest runs and its answer is
    /// dropped. The shed flows through `settle` (a `Failed` row — the
    /// authority was exercised) while the client gets the 503, and the permit
    /// stays untainted (the instance did nothing wrong) so the slot is
    /// released, not discarded.
    #[test]
    fn f03_shed_response_audits_failed_and_releases() {
        let source = include_str!("../tests/fixtures/echo-http.wat");
        let app = granted_app_for_wat(source);
        let full = u32::try_from(BUFFER_BUDGET_BYTES).expect("256 MiB fits");
        // Leave 1536 bytes: the 1 KiB request fits, its 1 KiB echo does not.
        let _held = app
            .buffer_budget
            .try_acquire_many(full - 1536)
            .expect("partial hold must succeed");
        let outcome = app.handle_request(
            &head(qqq_serve::Method::Post, "/echo"),
            Some(vec![0xA5; 1024]),
            "test-tenant",
        );
        let response = outcome.expect("shedding still serves a response");
        assert_eq!(response.status, 503, "exhaustion must shed: {response:?}");
        assert_eq!(
            app.pool.metrics().released(),
            1,
            "the blameless slot comes back"
        );
        assert_eq!(
            app.pool.metrics().discarded(),
            0,
            "nothing trapped, nothing discarded"
        );
        let (rows, _) = app.audit_snapshot();
        assert_eq!(
            rows[0].outcome,
            qqq_host::Outcome::Failed,
            "a shed answer audits as a failed exercise"
        );
    }

    /// **F-11: a marked permit counts as a discard, never a release.**
    ///
    /// The unit half of the routing proof: `taint()` (the `mark_discard`
    /// outcome flag under its established name) routes `Drop` to
    /// `Pool::discard()`. The acquire first is load-bearing, not setup: a
    /// permit dropped with nothing checked out takes the saturating path,
    /// and a test that never acquires would pass while proving nothing about
    /// routing. The invariant holds throughout: `in_use + idle <= capacity`.
    #[test]
    fn f11_marked_permit_counts_as_discard() {
        let pool = qqq_host::Pool::new(4);
        pool.acquire(0.0).expect("capacity");
        let permit = RequestPermit::clean(&pool);
        permit.taint();
        drop(permit);
        assert_eq!(
            pool.metrics().discarded(),
            1,
            "one discard, routed by the mark"
        );
        assert_eq!(
            pool.metrics().released(),
            0,
            "no release on the marked path"
        );
        let (in_use, idle) = pool.snapshot();
        assert_eq!((in_use, idle), (0, 0), "a discard returns no slot to idle");
        assert!(
            in_use + idle <= 4,
            "the capacity invariant holds after discard"
        );
    }

    /// **F-11: an unmarked permit counts as a release.**
    ///
    /// The mirror image: a clean completion hands its slot back. Same
    /// acquire-first discipline, same invariant.
    #[test]
    fn f11_unmarked_permit_counts_as_release() {
        let pool = qqq_host::Pool::new(4);
        pool.acquire(0.0).expect("capacity");
        let permit = RequestPermit::clean(&pool);
        drop(permit);
        assert_eq!(
            pool.metrics().released(),
            1,
            "one release on the clean path"
        );
        assert_eq!(pool.metrics().discarded(), 0, "no discard without the mark");
        let (in_use, idle) = pool.snapshot();
        assert_eq!((in_use, idle), (0, 1), "a release returns the slot to idle");
        assert!(
            in_use + idle <= 4,
            "the capacity invariant holds after release"
        );
    }
}
