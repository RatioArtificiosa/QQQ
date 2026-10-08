// SPDX-License-Identifier: Apache-2.0

//! Sanitising sinks for guest stdout and stderr.
//!
//! # The defect this module exists to close
//!
//! `host_wasi::context` used to call `WasiCtxBuilder::inherit_stdout()` and
//! `inherit_stderr()`. The comment beside those calls said *"stdout and stderr go to
//! the host's, so an app's own output is visible"* — which is true, and which was the
//! whole problem: `qqq-serve`'s access log is written to the **same** stdout
//! (`qqq_serve::server::emit_record`, one `writeln!` to the locked stdout handle). A
//! guest that printed
//!
//! ```text
//! {"ts":"2026-01-01T00:00:00Z","method":"DELETE","path":"/admin","status":200,...}
//! ```
//!
//! produced a line **byte-identical** to a host access record. Any log collector, SIEM
//! rule, or incident review reading that stream would treat it as one. This is the
//! forged-record shape: the trusted channel and the untrusted one were the same
//! channel, and nothing marked the boundary.
//!
//! It is worth being precise about what the guest gains. It does not gain a capability
//! — it cannot read another tenant's data or reach an ungranted import. It gains
//! **plausible deniability about its own actions and the ability to fabricate
//! somebody else's**: a forged `status: 200` line beside a real `403` hides the
//! refusal, and a forged line naming another tenant's path manufactures evidence.
//! For a runtime whose entire premise is that a guest's authority is exactly what its
//! manifest names, a guest that can write into the host's audit stream has authority
//! its manifest did not name.
//!
//! # The rule
//!
//! **No byte a guest emits may begin a physical line on a host stream.** Two
//! mechanisms, both total:
//!
//! 1. Every physical line of guest output is prefixed with a fixed marker
//!    ([`STDOUT_PREFIX`] or [`STDERR_PREFIX`]), so a forged record can never be the
//!    first thing on a line.
//! 2. Every control byte except `\n` is escaped. `\n` becomes a **real** line break
//!    with the prefix re-armed, which is what makes the marker hold for *every* line
//!    rather than only the first — and it keeps the app's own line structure intact,
//!    so an operator reading the log sees what the guest actually printed.
//!
//! A third, softer rule keeps the sink bounded: an unterminated run is broken at
//! [`MAX_ESCAPED_RUN`] bytes with a real newline, and the continuation carries the
//! prefix again. Without it a guest could hold one line open indefinitely, which turns
//! a log file into one unreadable line and gives a collector nothing to parse.
//!
//! # The breach policy: fail the write, count the breach
//!
//! Each output (stdout, stderr) carries its own [`MAX_OUTPUT_BYTES`] lifetime quota
//! in escaped bytes, shared by every writer of that output so opening more
//! streams cannot multiply it. A write past the quota fails with a
//! quota-exhausted stream error to the guest and increments the breach count
//! the host reads through [`GuestOutput::breaches`]. Failing rather than
//! truncating silently is deliberate: silent truncation rewrites the guest's
//! observable behavior without telling either side, while an error is a fact
//! both the guest and the host's accounting can see.
//!
//! # The tenant bound, stated as a composition
//!
//! The quota is per instance: [`host_wasi::context`](crate::host_wasi::context) builds
//! fresh outputs for every store, and each request runs on its own store, so each
//! request gets two fresh [`MAX_OUTPUT_BYTES`] budgets. Where the request carries
//! a tenant, its budgets additionally share one [`TenantOutputBudgets`] ceiling of
//! [`TENANT_OUTPUT_BYTES`]: concurrent requests of one tenant draw on the same
//! tenant budget through their [`TenantOutputGuard`], so a tenant's concurrent
//! output is bounded by that ceiling rather than by budget times requests, and
//! concurrent requests per tenant are capped by
//! `qqq_serve::conn::ConnectionLedger` (`ServerConfig::connections_per_tenant`,
//! overridable per tenant with `max_connections`). The reset boundary is the last
//! guard drop: while at least one request holds the tenant the ceiling persists,
//! and when the last guard drops the entry is evicted, so the tenant's next
//! request starts at zero. What this does not bound is sequential requests over
//! time — each gets a fresh budget, exactly as each gets fresh fuel and memory —
//! so long-term log volume remains an operator retention decision.
//!
//! # Why the write leaves the executor thread
//!
//! `poll_write` runs on an executor worker, and the destination is a host stream:
//! a slow pipe or terminal can block a synchronous write indefinitely, stalling
//! every task queued behind that worker. So each physical sink owns one writer
//! thread — a [`crate::sink_lane::SinkLane`] — draining a FIFO queue shared by
//! every output on that sink, and no guest-output write ever touches Tokio's
//! blocking pool (which also runs guest handlers: sharing it once froze
//! requests behind a stalled log). Order is structural: one thread consumes
//! one queue, so a guest's output cannot reorder against itself the way
//! per-write spawned tasks could.
//!
//! The queue is bounded, and a full queue parks the *guest*, not the executor:
//! past [`crate::sink_lane::LANE_QUEUE_MSGS`] messages — or past the
//! per-output in-flight byte cap — the next `poll_write` stores the caller's
//! waker and returns `Pending`; the lane wakes it after its next completed
//! write. Three bounds share the work: the byte quota
//! ([`MAX_OUTPUT_BYTES`]) caps how much a guest may emit in total, the lane
//! queue caps how many messages may wait, and the in-flight caps bound
//! undrained bytes per output and per tenant.
//!
//! Outside a Tokio runtime (unit tests driving `poll_write` directly) there is
//! no executor to protect and no lane traffic to join, so the write runs
//! inline on the calling thread. The two paths never mix in production:
//! construction happens outside the runtime, and the first poll inside one
//! takes the lane.
//!
//! # What this does and does not defend
//!
//! It defends **whole-line** readers, which is what an access log is: one record per
//! line, parsed from the start of the line. A collector that parses each line as a JSON
//! document will fail to parse `qqq-guest stdout | {"ts":...}` and will not mistake it
//! for a record.
//!
//! It does not defend a reader that searches the raw stream for a substring. Under any
//! design the guest's text is present — escaping it into `\x7b\x22...` would only make
//! the log unreadable while a determined matcher decoded it anyway. The honest claim is
//! the one the marker makes: *this line is not a host record*.
//!
//! # Why a trait object and not a generic
//!
//! `StdoutStream::async_stream` returns `Box<dyn AsyncWrite + Send + Sync>`, so the
//! writer is boxed either way. Keeping the destination behind `Arc<dyn GuestSink>`
//! means one `GuestOutput` type serves both the process streams (production) and a
//! captured buffer (tests), which is what makes the escaping testable **on the type
//! production uses** rather than on a copy of it.

use std::future::Future as _;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use qqq_core::sync::LockRecover;

use tokio::io::AsyncWrite;
use tokio::sync::oneshot;
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};

/// The marker every line of a guest's standard output carries.
///
/// Fixed and greppable on purpose: an operator filtering a log for guest output uses
/// this, and an operator filtering for host records excludes it.
pub const STDOUT_PREFIX: &str = "qqq-guest stdout | ";

/// The marker every line of a guest's standard error carries.
///
/// Distinct from [`STDOUT_PREFIX`] so that the two remain separable when a deployment
/// merges the streams, which is the common case (`2>&1`, container runtimes,
/// `docker logs`).
pub const STDERR_PREFIX: &str = "qqq-guest stderr | ";

/// The longest escaped run emitted before a real line break is forced.
///
/// See the module docs: without a bound, a guest that never emits `\n` holds one line
/// open for as long as it likes, and a line-oriented collector has nothing to parse
/// until the guest exits.
pub const MAX_ESCAPED_RUN: usize = 4096;

/// Maximum guest-emitted bytes accepted by one stdout or stderr destination.
///
/// Escaped bytes, prefix included: the quota is charged on what reaches the
/// sink, so a newline flood or control-byte spray cannot multiply past it.
/// `MAX_ESCAPED_RUN` bounds one physical line, not the lifetime of a process.
/// Without a total budget a guest can still fill a host log indefinitely by
/// emitting many short lines. The budget is shared by all writers obtained from
/// one `GuestOutput`, so opening multiple WASI streams cannot multiply it.
pub const MAX_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;

/// Default lifetime output budget shared by one tenant's requests on one app.
///
/// Eight full-bleed instances at the 8 MiB per-stream quota: large enough that
/// ordinary tenants never notice it, small enough that a compromised or buggy
/// guest cannot fill a host log indefinitely. Per application, matching the
/// pool: tenants are not global identities here (audit records carry `None`
/// for the same reason), so each deployed component bounds its own tenants,
/// exactly as each bounds its own instance slots.
///
/// ```
/// use qqq_host::guest_output::TENANT_OUTPUT_BYTES;
///
/// assert_eq!(TENANT_OUTPUT_BYTES, 64 * 1024 * 1024);
/// ```
pub const TENANT_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

/// A byte budget: standalone per instance, or nested under a tenant ceiling.
///
/// Every output owns one; a tenant's requests additionally share one through
/// [`TenantOutputBudgets`]. Reservation checks the local budget first and the
/// linked parent second, refusing when either is exhausted, so one tenant's
/// requests share a ceiling no single request can exceed alone.
///
/// ```
/// use qqq_host::guest_output::OutputBudget;
///
/// let budget = OutputBudget::new(8);
/// assert_eq!(budget.used(), 0);
/// assert_eq!(budget.breaches(), 0);
/// ```
#[derive(Debug)]
pub struct OutputBudget {
    used: AtomicU64,
    /// Escaped bytes accepted but not yet drained to the sink.
    ///
    /// Distinct from `used`: the lifetime counter bounds what a request may
    /// ever emit, this bounds what is still queued. `InFlight` values add on
    /// construction and subtract on drop; direct (runtime-less) writes never
    /// touch it, because nothing they emit waits anywhere.
    in_flight: AtomicU64,
    limit: u64,
    /// Writes refused for exceeding the quota.
    ///
    /// A sampling counter in the `metrics.rs` sense: nothing decides on it, so
    /// `Relaxed` is the correct ordering. It is the host-visible half of the
    /// breach policy — the guest sees a stream error, and the host reads this.
    breaches: AtomicU64,
    /// The enclosing budget, if this one nests inside one.
    ///
    /// A per-instance budget with a tenant parent refuses when *either* is
    /// exhausted, so one tenant's requests share a ceiling no single request
    /// can exceed alone. Set once during instance construction; `None` is the
    /// standalone budget every existing caller means.
    parent: std::sync::Mutex<Option<Arc<OutputBudget>>>,
    /// The operator-visible refusal meter, on tenant ceilings only.
    ///
    /// Set once by the tenant registry for the budgets it creates; per-output
    /// budgets never carry one, so one tenant refusal notes exactly once —
    /// at the parent that refused it — never once per child that observed it.
    meter: std::sync::Mutex<Option<Arc<crate::metrics::Metrics>>>,
}

impl OutputBudget {
    /// A standalone byte budget.
    ///
    /// ```
    /// use qqq_host::guest_output::OutputBudget;
    ///
    /// let budget = OutputBudget::new(8);
    /// assert_eq!(budget.breaches(), 0);
    /// ```
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self {
            used: AtomicU64::new(0),
            in_flight: AtomicU64::new(0),
            limit,
            breaches: AtomicU64::new(0),
            parent: std::sync::Mutex::new(None),
            meter: std::sync::Mutex::new(None),
        }
    }

    /// Bytes accepted under this budget so far.
    ///
    /// ```
    /// use qqq_host::guest_output::OutputBudget;
    ///
    /// let budget = OutputBudget::new(8);
    /// assert_eq!(budget.used(), 0);
    /// ```
    #[must_use]
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    /// Writes refused for exceeding this budget.
    ///
    /// ```
    /// use qqq_host::guest_output::OutputBudget;
    ///
    /// let budget = OutputBudget::new(8);
    /// assert_eq!(budget.breaches(), 0);
    /// ```
    #[must_use]
    pub fn breaches(&self) -> u64 {
        self.breaches.load(Ordering::Relaxed)
    }

    /// Enclose this budget in a shared parent.
    ///
    /// First call wins: the linkage is made once during instance construction,
    /// and a second parent would mean two ceilings arguing over one budget.
    /// `pub(crate)` because only instance construction wires parents; every
    /// other crate meets budgets through [`TenantOutputGuard::budget`].
    pub(crate) fn set_parent(&self, parent: &Arc<OutputBudget>) {
        if let Ok(mut slot) = self.parent.lock() {
            if slot.is_none() {
                *slot = Some(Arc::clone(parent));
            }
        }
    }

    /// Reserve `bytes`, first here, then in the parent if one is linked.
    ///
    /// Returns the ceiling that refused and its breach count including this
    /// refusal, so the caller reports the limit that actually tripped rather
    /// than whichever one it checked first.
    fn reserve(&self, bytes: usize) -> Result<(), Refusal> {
        let amount = u64::try_from(bytes).unwrap_or(u64::MAX);
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let Some(next) = used.checked_add(amount) else {
                return Err(self.refused());
            };
            if next > self.limit {
                return Err(self.refused());
            }
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(actual) => used = actual,
            }
        }
        if let Some(parent) = self.parent.lock().ok().and_then(|p| p.clone()) {
            if let Err(refusal) = parent.reserve(bytes) {
                self.unreserve(bytes);
                // The host reads this output's own counter, and a tenant
                // refusal is still a refused write on this output: without
                // this, `breaches` would stay zero while `last_truncation`
                // reports a breach for the same write.
                self.breaches.fetch_add(1, Ordering::Relaxed);
                return Err(refusal);
            }
        }
        Ok(())
    }

    /// Count this refusal and name the ceiling that tripped.
    ///
    /// Notes the operator meter when one is attached: only tenant ceilings
    /// carry one, so each tenant refusal is metered exactly once however many
    /// children observe it.
    fn refused(&self) -> Refusal {
        if let Ok(meter) = self.meter.lock() {
            if let Some(meter) = meter.as_ref() {
                meter.note_output_refusal();
            }
        }
        Refusal {
            limit: self.limit,
            breaches: self.breaches.fetch_add(1, Ordering::Relaxed) + 1,
        }
    }

    /// Release a reservation `reserve` made, when the write it paid for never
    /// queued — the parent check runs after the local one, and a parent refusal
    /// must give the local bytes back rather than burn them on a write that
    /// never happened.
    ///
    /// Private, because the only caller that can owe a refund is `reserve`
    /// itself, in the same call.
    fn unreserve(&self, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.used.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Attach the operator-visible refusal meter, if this budget is a tenant ceiling.
    ///
    /// `pub(crate)`: only the tenant registry meters budgets, and only the
    /// budgets it creates — per-output budgets stay unmetered, so one tenant
    /// refusal notes exactly once (at the parent that refused it), never once
    /// per child that observed it.
    pub(crate) fn set_meter(&self, meter: &Arc<crate::metrics::Metrics>) {
        if let Ok(mut slot) = self.meter.lock() {
            if slot.is_none() {
                *slot = Some(Arc::clone(meter));
            }
        }
    }

    /// Hold `bytes` of in-flight space here and in the tenant parent, if any.
    ///
    /// The lane admission half of backpressure: the lifetime `reserve` bounds
    /// what a request may ever emit, this bounds what is still undrained.
    /// Each side admits when its own counter is empty (an empty queue takes
    /// one message of any size — parking it would wait for a drain that can
    /// never start) and refuses past its cap otherwise: the per-output
    /// fairness cap here, the tenant ceiling on the parent. A parent refusal
    /// releases this budget's hold, so a failed admission leaves no trace.
    /// Check-then-act like the queue bound, so concurrent writers may
    /// overshoot softly; a single writer is exact, which is what the fairness
    /// test proves.
    pub(crate) fn reserve_in_flight(&self, bytes: u64) -> bool {
        if !admit_in_flight(
            self.in_flight.load(Ordering::Relaxed),
            crate::sink_lane::OUTPUT_IN_FLIGHT_BYTES as u64,
            bytes,
        ) {
            return false;
        }
        self.in_flight.fetch_add(bytes, Ordering::Relaxed);
        let parent = self.parent.lock().ok().and_then(|p| p.clone());
        if let Some(parent) = parent {
            if !admit_in_flight(
                parent.in_flight.load(Ordering::Relaxed),
                parent.limit,
                bytes,
            ) {
                sub_saturating(&self.in_flight, bytes);
                return false;
            }
            parent.in_flight.fetch_add(bytes, Ordering::Relaxed);
        }
        true
    }

    /// Release in-flight bytes a drain (or an abandoned message) frees.
    ///
    /// Saturating: a release must never panic or wrap on an accounting
    /// surprise. Called with the same amount `reserve_in_flight` held — the
    /// `InFlight` guard carries it, so the pairing cannot drift apart.
    pub(crate) fn release_in_flight(&self, bytes: u64) {
        sub_saturating(&self.in_flight, bytes);
        if let Ok(parent) = self.parent.lock() {
            if let Some(parent) = parent.as_ref() {
                sub_saturating(&parent.in_flight, bytes);
            }
        }
    }
}

/// A per-output budget returns its consumed bytes when its request ends.
///
/// Dropping the last `Arc` runs this: the budget type itself is the shared
/// payload, so there is no separate inner to key on, and a cloneable handle
/// cannot exist to double-refund. What returns is exactly what this budget
/// successfully reserved from the parent — rollbacks already removed anything
/// refused, so the parent's counter holds precisely this amount for this
/// child. Saturating: a release must never be able to panic or wrap on an
/// accounting surprise. Budgets without a parent (standalone, or tenant
/// ceilings themselves) refund to nothing.
///
/// This is what makes the tenant ceiling a *concurrent* bound rather than a
/// cumulative one: while a request lives its bytes count; when it ends they
/// stop. Volume over time is deliberately NOT bounded here — a token bucket
/// at the sink belongs to a later, separate decision (see the module docs),
/// and conflating the two would turn a memory bound into a rate limit.
impl Drop for OutputBudget {
    /// Panic-free by construction (`F-21`): the lock recovers rather than
    /// panicking, and the saturating subtraction cannot wrap.
    fn drop(&mut self) {
        let used = self.used.load(Ordering::Relaxed);
        if used == 0 {
            return;
        }
        if let Ok(parent) = self.parent.lock() {
            if let Some(parent) = parent.as_ref() {
                sub_saturating(&parent.used, used);
            }
        }
    }
}

/// Which ceiling refused a reservation, and its breach count including it.
///
/// Private: the caller translates it into the I/O error the guest sees and the
/// [`TruncationEvent`] the host reads, and neither of those names this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refusal {
    limit: u64,
    breaches: u64,
}

/// One tenant's shared output budget, held by the registry below.
///
/// Cloned from the registry on every acquire; all live clones account into
/// the same counters, so concurrent requests of one tenant share one ceiling
/// no single request can exceed alone.
///
/// ```
/// use qqq_host::guest_output::TenantOutputBudgets;
///
/// let budgets = TenantOutputBudgets::new(10);
/// let first = budgets.acquire("tenant-a");
/// let second = budgets.acquire("tenant-a");
/// assert!(std::ptr::eq(
///     std::sync::Arc::as_ptr(first.budget()),
///     std::sync::Arc::as_ptr(second.budget())
/// ));
/// ```
#[derive(Debug, Clone)]
pub struct TenantOutputBudgets {
    inner: Arc<TenantBudgetsInner>,
}

#[derive(Debug)]
struct TenantBudgetsInner {
    limit: u64,
    /// # Lock rule (`F-21`): recover, never panic
    ///
    /// Every critical section on this mutex is panic-free map and integer
    /// work (`entry`/`or_insert_with` on fresh keys, `+= 1`,
    /// `saturating_sub`, `remove`): either the whole transition ran or none
    /// of it did, so a recovered guard holds a consistent registry. All
    /// acquisitions use `lock_recover()` (including the `live()` observer: a
    /// reading is an observation, never a decision that must fail closed). A
    /// recovered map may be missing an entry whose insert raced the panic — `acquire` re-establishes it via
    /// `or_insert_with`, and the guard's `Drop` tolerates a missing entry by
    /// doing nothing, which is exactly the evicted-at-zero state.
    state: std::sync::Mutex<std::collections::HashMap<String, TenantEntry>>,
    /// The operator-visible refusal meter, shared by every tenant budget here.
    ///
    /// Wired once per app at construction; entry budgets created after that
    /// inherit it, and the registry (hence the meter link) is cloned, never
    /// rebuilt, on replacement.
    meter: std::sync::Mutex<Option<Arc<crate::metrics::Metrics>>>,
}

/// One tenant's entry in the registry: the shared budget plus its live count.
#[derive(Debug)]
struct TenantEntry {
    budget: Arc<OutputBudget>,
    /// Requests currently holding this tenant's budget.
    live: u64,
}

impl TenantOutputBudgets {
    /// A registry issuing per-tenant shared budgets of `limit` bytes each.
    ///
    /// ```
    /// use qqq_host::guest_output::TenantOutputBudgets;
    ///
    /// let budgets = TenantOutputBudgets::new(1024);
    /// let _guard = budgets.acquire("tenant-a");
    /// ```
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self {
            inner: Arc::new(TenantBudgetsInner {
                limit,
                state: std::sync::Mutex::new(std::collections::HashMap::new()),
                meter: std::sync::Mutex::new(None),
            }),
        }
    }

    /// Meter this registry's tenant-ceiling refusals into shared metrics.
    ///
    /// Called once per app at construction, before any acquire: entry budgets
    /// created afterwards inherit the meter, so every tenant refusal notes
    /// exactly once into the recorder operators render. Cloned registries
    /// share the link through the inner `Arc`.
    pub fn set_meter(&self, meter: &Arc<crate::metrics::Metrics>) {
        if let Ok(mut slot) = self.inner.meter.lock() {
            if slot.is_none() {
                *slot = Some(Arc::clone(meter));
            }
        }
    }

    /// The budget for one tenant, creating it on first use.
    ///
    /// The guard keeps the budget alive and counted; dropping the last guard
    /// for a tenant evicts the entry, which is the reset boundary — a tenant
    /// with no live request starts its next request at zero, and a tenant
    /// that never returns cannot accumulate state here.
    ///
    /// ```
    /// use qqq_host::guest_output::TenantOutputBudgets;
    ///
    /// let budgets = TenantOutputBudgets::new(1024);
    /// let guard = budgets.acquire("tenant-a");
    /// assert_eq!(guard.tenant(), "tenant-a");
    /// ```
    ///
    /// A poisoned lock recovers rather than panics (see the lock rule on the
    /// registry). `or_insert_with` re-establishes an entry whose insert raced
    /// a panic, so recovery converges rather than accumulating damage.
    #[must_use]
    pub fn acquire(&self, tenant: &str) -> TenantOutputGuard {
        let mut state = self.inner.state.lock_recover();
        let entry = state
            .entry(tenant.to_owned())
            .or_insert_with(|| TenantEntry {
                budget: Arc::new(OutputBudget::new(self.inner.limit)),
                live: 0,
            });
        // A re-established entry (after eviction, or after a recovered panic
        // dropped the map) needs the meter as much as a fresh one: without
        // this, the first tenant after an eviction would meter nothing.
        if let Ok(meter) = self.inner.meter.lock() {
            if let Some(meter) = meter.as_ref() {
                entry.budget.set_meter(meter);
            }
        }
        entry.live += 1;
        TenantOutputGuard {
            inner: Arc::clone(&self.inner),
            tenant: tenant.to_owned(),
            budget: Arc::clone(&entry.budget),
        }
    }

    /// Requests currently holding one tenant's budget.
    ///
    /// Zero for an unknown or fully released tenant. An operator counter in
    /// the `LedgerReport` spirit — and the observation point the request-path
    /// tests poll to prove a live request holds its tenant's entry.
    ///
    /// ```
    /// use qqq_host::guest_output::TenantOutputBudgets;
    ///
    /// let budgets = TenantOutputBudgets::new(1024);
    /// assert_eq!(budgets.live("tenant-a"), 0);
    /// let _guard = budgets.acquire("tenant-a");
    /// assert_eq!(budgets.live("tenant-a"), 1);
    /// ```
    #[must_use]
    pub fn live(&self, tenant: &str) -> u64 {
        self.inner
            .state
            .lock_recover()
            .get(tenant)
            .map_or(0, |entry| entry.live)
    }
}

/// One request's hold on its tenant's shared output budget.
///
/// Dropping decrements the tenant's live count and evicts the entry at zero,
/// which is what makes the reset boundary real rather than documented: the map
/// cannot grow without bound on distinct tenant names, because an entry exists
/// only while at least one request holds it.
///
/// Cloning is manual rather than derived on purpose: a derived clone would
/// duplicate the guard without counting, and the uncounted clone's drop would
/// evict a budget a live request still holds — splitting one tenant's
/// accounting in two. Every live guard is counted, no exceptions.
#[derive(Debug)]
pub struct TenantOutputGuard {
    inner: Arc<TenantBudgetsInner>,
    tenant: String,
    budget: Arc<OutputBudget>,
}

impl Clone for TenantOutputGuard {
    fn clone(&self) -> Self {
        let mut state = self.inner.state.lock_recover();
        // Created by `acquire`, so the entry exists; a missing entry would
        // mean an eviction raced a counted guard, which the locking forbids.
        if let Some(entry) = state.get_mut(&self.tenant) {
            entry.live += 1;
        }
        Self {
            inner: Arc::clone(&self.inner),
            tenant: self.tenant.clone(),
            budget: Arc::clone(&self.budget),
        }
    }
}

impl Drop for TenantOutputGuard {
    /// Panic-free by construction (`F-21`): the lock recovers rather than
    /// panicking, the entry lookup tolerates a missing entry, and the counter
    /// saturates. A `Drop` that panics during unwinding aborts the process
    /// even after `F-01` — this one cannot.
    fn drop(&mut self) {
        let mut state = self.inner.state.lock_recover();
        if let Some(entry) = state.get_mut(&self.tenant) {
            entry.live = entry.live.saturating_sub(1);
            if entry.live == 0 {
                state.remove(&self.tenant);
            }
        }
    }
}

impl TenantOutputGuard {
    /// The tenant this guard accounts for.
    ///
    /// ```
    /// use qqq_host::guest_output::TenantOutputBudgets;
    ///
    /// let budgets = TenantOutputBudgets::new(1024);
    /// let guard = budgets.acquire("tenant-a");
    /// assert_eq!(guard.tenant(), "tenant-a");
    /// ```
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The shared budget, for wiring into instance outputs.
    ///
    /// ```
    /// use qqq_host::guest_output::TenantOutputBudgets;
    ///
    /// let budgets = TenantOutputBudgets::new(1024);
    /// let guard = budgets.acquire("tenant-a");
    /// assert_eq!(guard.budget().breaches(), 0);
    /// ```
    #[must_use]
    pub fn budget(&self) -> &Arc<OutputBudget> {
        &self.budget
    }
}

/// A destination for guest output, writable through a shared reference.
///
/// # Why `&self` rather than `&mut self`
///
/// A guest can acquire several output streams, and wasmtime-wasi calls
/// `async_stream` once per acquired stream. Those writers must all reach one
/// destination, so the destination is held behind an `Arc` — and an `Arc` hands out
/// shared references only. Requiring `&mut self` here would have forced a `Mutex`
/// around every sink including `std::io::Stdout`, which already supports writes
/// through `&Stdout` and needs no lock.
///
/// The three provided implementations cover the two production destinations and the
/// general case: `Stdout`, `Stderr`, and any `Mutex<W>` for a `W: Write` that needs a
/// lock (which is what a captured buffer in a test is).
pub trait GuestSink: Send + Sync + 'static {
    /// Write all of `bytes`, or report why not.
    ///
    /// # Errors
    ///
    /// Whatever the destination reports. The caller in
    /// [`SanitisingWriter::poll_write`] surfaces it to the guest as a stream error
    /// rather than panicking: a broken log sink must not abort a request, which is the
    /// same reasoning `qqq_serve::server::emit_record` records for its own sink.
    fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()>;

    /// Flush the destination.
    ///
    /// # Errors
    ///
    /// Whatever the destination reports.
    fn flush_shared(&self) -> io::Result<()>;
}

impl GuestSink for io::Stdout {
    fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()> {
        // `impl Write for &Stdout` is what makes this possible without a lock.
        let mut handle = self;
        handle.write_all(bytes)
    }

    fn flush_shared(&self) -> io::Result<()> {
        let mut handle = self;
        handle.flush()
    }
}

impl GuestSink for io::Stderr {
    fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()> {
        let mut handle = self;
        handle.write_all(bytes)
    }

    fn flush_shared(&self) -> io::Result<()> {
        let mut handle = self;
        handle.flush()
    }
}

impl<W: Write + Send + 'static> GuestSink for std::sync::Mutex<W> {
    fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()> {
        // A poisoned lock is reported as an error rather than unwrapped. A guest
        // whose sink panicked on another thread must not take down the host by
        // panicking here too -- `§4.8`'s rule that a guest never aborts the host.
        let mut guard = self
            .lock()
            .map_err(|_| io::Error::other("the guest-output sink's lock is poisoned"))?;
        guard.write_all(bytes)
    }

    fn flush_shared(&self) -> io::Result<()> {
        let mut guard = self
            .lock()
            .map_err(|_| io::Error::other("the guest-output sink's lock is poisoned"))?;
        guard.flush()
    }
}

impl<W: GuestSink + ?Sized> GuestSink for Arc<W> {
    fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()> {
        (**self).write_all_shared(bytes)
    }

    fn flush_shared(&self) -> io::Result<()> {
        (**self).flush_shared()
    }
}

/// A destination for the escaping rule: counting or collecting.
///
/// One implementation of the loop serves both the quota probe and the real
/// write, so the two can never disagree about a byte's escaped size. Private:
/// the only sink production needs is the byte buffer below.
trait EscapeSink {
    /// Accept escaped output bytes.
    fn push(&mut self, bytes: &[u8]);
}

/// A sink that counts escaped bytes without storing them.
///
/// The quota probe: measures what a write would cost before anything is
/// reserved or allocated. A throwaway `Vec` here would allocate up to 20x the
/// input before the quota check — the amplification this module exists to
/// remove — so the probe must never materialise the output.
struct CountSink(usize);

impl EscapeSink for CountSink {
    fn push(&mut self, bytes: &[u8]) {
        self.0 += bytes.len();
    }
}

impl EscapeSink for Vec<u8> {
    fn push(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// The escaping rule, as a pure state machine.
///
/// # Why this is separate from the writer
///
/// The writer is an `AsyncWrite` impl, which needs a `Pin`, a `Context`, and a
/// destination before it can be exercised. The rule needs none of those. Extracting it
/// means the escaping is tested directly on the bytes it produces, and the writer below
/// is a thin adapter that cannot contain a second, different rule.
#[derive(Debug, Clone)]
pub struct Escaper {
    prefix: &'static str,
    at_line_start: bool,
    since_break: usize,
}

impl Escaper {
    /// A new escaper whose every line begins with `prefix`.
    #[must_use]
    pub fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            at_line_start: true,
            since_break: 0,
        }
    }

    /// Append `bytes`, escaped, to `out`.
    ///
    /// Returns the number of input bytes consumed, which is always `bytes.len()`: the
    /// transformation is byte-for-byte, so an `AsyncWrite` caller can report a full
    /// write and the guest never sees a short write it would have to retry.
    pub fn push(&mut self, bytes: &[u8], out: &mut Vec<u8>) -> usize {
        self.run(bytes, out)
    }

    /// Append `bytes`, escaped, to any sink, returning input bytes consumed.
    ///
    /// The single implementation behind both [`Escaper::push`] and
    /// [`Escaper::escaped_len`]: the quota probe and the real write run the
    /// same loop over the same state, so a reservation computed from the probe
    /// always covers the write that follows it.
    fn run<S: EscapeSink>(&mut self, bytes: &[u8], sink: &mut S) -> usize {
        for &byte in bytes {
            if self.at_line_start {
                sink.push(self.prefix.as_bytes());
                self.at_line_start = false;
            }
            match byte {
                // A real line break, and the prefix is re-armed for the next line.
                //
                // # Why this is the one byte that is *not* escaped
                //
                // The property being defended is "no guest byte begins a physical
                // line", and re-arming the prefix achieves that on its own: the guest's
                // newline ends a line that already carries the marker, and the line
                // after it gets a fresh one. Escaping it as well would emit `\\n`
                // **and** a break, doubling the line count and mangling the app's
                // output for no security gain — the forged record still appears, just
                // as `qqq-guest stdout | {"ts":...}` instead of on a line by itself.
                b'\n' => self.break_line(sink),
                // Everything else in C0, plus DEL, is escaped. `\r` because it is a line
                // terminator to some readers; `\x1b` because an escape sequence can
                // rewrite what a terminal shows for the host's own records; the rest
                // because a total rule is auditable and a list of dangerous bytes is a
                // claim that goes stale.
                //
                // The run bound counts OUTPUT bytes (the arm's emission), so the
                // longest physical line the sink can see is bounded no matter how
                // expansively one input byte encodes. The fixed prefix is excluded:
                // it is host-chosen and constant, not guest-controlled.
                b'\r' => {
                    sink.push(b"\\r");
                    self.since_break += 2;
                }
                b'\t' => {
                    sink.push(b"\\t");
                    self.since_break += 2;
                }
                // So a guest cannot emit a literal `\n` and have a reader mistake it for
                // a break the host inserted.
                b'\\' => {
                    sink.push(b"\\\\");
                    self.since_break += 2;
                }
                0x00..=0x1f | 0x7f => {
                    // Stack-assembled, never formatted: `format!` here would
                    // heap-allocate per control byte in both the probe and the
                    // real write — bounded scratch, but gratuitous on the path
                    // whose whole point is allocation discipline. Lowercase hex
                    // matches the previous `{:02x}` output byte for byte.
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    let escaped = [
                        b'\\',
                        b'x',
                        HEX[usize::from(byte >> 4)],
                        HEX[usize::from(byte & 0x0f)],
                    ];
                    sink.push(&escaped);
                    self.since_break += 4;
                }
                _ => {
                    sink.push(&[byte]);
                    self.since_break += 1;
                }
            }
            if self.since_break >= MAX_ESCAPED_RUN {
                self.break_line(sink);
            }
        }
        bytes.len()
    }

    /// How many sink bytes `bytes` would produce from the current state.
    ///
    /// Pure: runs the escaping loop on a clone, so a refused write can be
    /// costed without advancing the real escaper (see `poll_write`). The clone
    /// is a three-word state struct, and the probe sink counts without
    /// allocating — never a throwaway output buffer.
    fn escaped_len(&self, bytes: &[u8]) -> usize {
        let mut probe = self.clone();
        let mut count = CountSink(0);
        probe.run(bytes, &mut count);
        count.0
    }

    /// End the current physical line and require the prefix on the next one.
    ///
    /// Also called when the run bound is reached, which is why the prefix is re-armed
    /// here rather than only on `\n`: the two are the same event to a line reader.
    fn break_line<S: EscapeSink>(&mut self, sink: &mut S) {
        sink.push(b"\n");
        self.at_line_start = true;
        self.since_break = 0;
    }
}

/// The most recent quota breach on one output, in full.
///
/// The guest observes a stream error; the counter from [`GuestOutput::breaches`]
/// observes a number; this observes the *fact* — which stream, how much was
/// asked, what the ceiling was, and which breach number it was. Tenant identity
/// is deliberately absent: below the connection layer the host has no tenant
/// name to put here (audit records carry `None` for the same reason), so the
/// stream marker is the finest identity this layer can state honestly.
///
/// ```
/// use qqq_host::guest_output::TruncationEvent;
///
/// let event = TruncationEvent {
///     stream: qqq_host::guest_output::STDOUT_PREFIX,
///     requested_bytes: 9,
///     limit: 5,
///     total_breaches: 1,
/// };
/// assert_eq!(event.total_breaches, 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruncationEvent {
    /// Which stream breached, as its marker — [`STDOUT_PREFIX`] or [`STDERR_PREFIX`].
    pub stream: &'static str,
    /// How many escaped bytes the refused write asked for.
    pub requested_bytes: u64,
    /// The quota that refused it.
    pub limit: u64,
    /// The breach count including this one.
    pub total_breaches: u64,
}

/// State shared by an output and all its writers.
struct Shared {
    /// Which stream this output is, for breach reports.
    stream: &'static str,
    /// The destination, also held by the lane for the actual writes.
    ///
    /// Kept here for the runtime-less inline path, which writes on the
    /// calling thread exactly as before lanes existed.
    sink: Arc<dyn GuestSink>,
    budget: Arc<OutputBudget>,
    /// The lane this output enqueues to.
    lane: Arc<crate::sink_lane::SinkLane>,
    /// The first asynchronous write failure, surfaced on later calls.
    ///
    /// A sink failure happens on the lane thread, after `poll_write` already
    /// reported success for those bytes. Swallowing it would make a dead log
    /// look healthy; recording the first one and failing subsequent calls keeps
    /// the failure visible without inventing a history the caller cannot use.
    ///
    /// Shared by `Arc` rather than held inline so the lane thread can report
    /// without holding the whole `Shared`: the thread must not own a sender or
    /// a `Shared`, or the inbox would never drain shut and the thread would
    /// never end.
    failure: Arc<std::sync::Mutex<Option<String>>>,
    /// The most recent quota breach, for [`GuestOutput::last_truncation`].
    last_truncation: std::sync::Mutex<Option<TruncationEvent>>,
}

/// A guest's standard output or standard error, sanitised.
///
/// Installed by `host_wasi::context` in place of `inherit_stdout`/`inherit_stderr`.
/// Implements [`StdoutStream`] — wasmtime-wasi's trait for *both* stdout and stderr —
/// so the same type serves both, distinguished only by the prefix.
#[derive(Clone)]
pub struct GuestOutput {
    prefix: &'static str,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for GuestOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestOutput")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl GuestOutput {
    /// Guest standard output, written to the host process's stdout.
    ///
    /// Shares the process-wide stdout lane: every stdout output of every
    /// request enqueues to one FIFO drained by one thread, which is what
    /// keeps a stalled sink from pinning per-request resources.
    #[must_use]
    pub fn stdout() -> Self {
        Self::to_lane(STDOUT_PREFIX, Self::stdout_lane())
    }

    /// Guest standard error, written to the host process's stderr.
    ///
    /// Shares the process-wide stderr lane, like [`GuestOutput::stdout`].
    #[must_use]
    pub fn stderr() -> Self {
        Self::to_lane(STDERR_PREFIX, Self::stderr_lane())
    }

    /// Guest output on an already-running lane.
    ///
    /// The two process lanes live here rather than at the call sites, so
    /// there is exactly one stdout lane and one stderr lane per process no
    /// matter how many stores are built. Each output mints its own failure
    /// slot: sharing one slot across outputs would poison every present and
    /// future output with one transient sink error, since nothing ever
    /// clears it.
    fn to_lane(prefix: &'static str, lane: Arc<crate::sink_lane::SinkLane>) -> Self {
        let sink = lane.sink();
        let failure: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
        Self::with_lane_and_sink(prefix, lane, sink, failure, MAX_OUTPUT_BYTES)
    }

    /// The process-wide stdout lane, started once.
    fn stdout_lane() -> Arc<crate::sink_lane::SinkLane> {
        use std::sync::OnceLock;
        static LANE: OnceLock<Arc<crate::sink_lane::SinkLane>> = OnceLock::new();
        Arc::clone(LANE.get_or_init(|| {
            crate::sink_lane::SinkLane::spawn(
                "qqq-stdout-lane",
                Arc::new(io::stdout()) as Arc<dyn GuestSink>,
            )
            .expect("the stdout lane thread spawns")
        }))
    }

    /// The process-wide stderr lane, started once.
    fn stderr_lane() -> Arc<crate::sink_lane::SinkLane> {
        use std::sync::OnceLock;
        static LANE: OnceLock<Arc<crate::sink_lane::SinkLane>> = OnceLock::new();
        Arc::clone(LANE.get_or_init(|| {
            crate::sink_lane::SinkLane::spawn(
                "qqq-stderr-lane",
                Arc::new(io::stderr()) as Arc<dyn GuestSink>,
            )
            .expect("the stderr lane thread spawns")
        }))
    }

    /// Guest output with an explicit prefix and destination.
    ///
    /// The destination is an `Arc` so that repeated calls to `async_stream` — which
    /// wasmtime-wasi makes freely, one per acquired stream — share one sink rather than
    /// racing on several.
    ///
    /// Spawns a private lane for the sink: the shared process lanes belong to
    /// [`GuestOutput::stdout`] and [`GuestOutput::stderr`], and any other sink
    /// gets its own FIFO and thread rather than borrowing one.
    #[must_use]
    pub fn to(prefix: &'static str, sink: impl GuestSink) -> Self {
        Self::to_with_limit(prefix, sink, MAX_OUTPUT_BYTES)
    }

    /// Construct guest output with an explicit lifetime byte quota.
    ///
    /// # Panics
    ///
    /// When the OS refuses the lane thread. Thread spawn fails only on
    /// resource exhaustion, and a server that cannot spawn one thread is
    /// already fail-stopped — panicking moves that failure to construction
    /// rather than hanging the first write.
    #[must_use]
    pub fn to_with_limit(prefix: &'static str, sink: impl GuestSink, limit: u64) -> Self {
        let sink = Arc::new(sink);
        let shared_failure: Arc<std::sync::Mutex<Option<String>>> =
            Arc::new(std::sync::Mutex::new(None));
        // A private lane cannot fail to start in any situation the host
        // survives: thread spawn fails only on resource exhaustion, and a
        // server that cannot spawn one thread is already fail-stopped.
        let lane = crate::sink_lane::SinkLane::spawn(
            "qqq-output-lane",
            Arc::clone(&sink) as Arc<dyn GuestSink>,
        )
        .expect("a guest-output lane thread spawns");
        Self::with_lane_and_sink(prefix, lane, sink, shared_failure, limit)
    }

    /// Construct guest output on an existing lane.
    ///
    /// Test-only: production paths use the shared process lanes
    /// ([`GuestOutput::stdout`], [`GuestOutput::stderr`]) or spawn a private
    /// one ([`GuestOutput::to`]); only tests share a lane across outputs to
    /// prove ordering and fairness on one FIFO.
    #[cfg(test)]
    pub(crate) fn with_lane(
        prefix: &'static str,
        lane: &Arc<crate::sink_lane::SinkLane>,
        limit: u64,
    ) -> Self {
        Self {
            prefix,
            shared: Arc::new(Shared {
                stream: prefix,
                sink: lane.sink(),
                budget: Arc::new(OutputBudget::new(limit)),
                lane: Arc::clone(lane),
                failure: Arc::new(std::sync::Mutex::new(None)),
                last_truncation: std::sync::Mutex::new(None),
            }),
        }
    }

    /// Construct guest output on a lane with an explicit sink and failure slot.
    ///
    /// The `to_*` constructors funnel through here so there is one place that
    /// assembles a `Shared`, rather than three copies of the same struct
    /// literal drifting apart.
    fn with_lane_and_sink(
        prefix: &'static str,
        lane: Arc<crate::sink_lane::SinkLane>,
        sink: Arc<dyn GuestSink>,
        failure: Arc<std::sync::Mutex<Option<String>>>,
        limit: u64,
    ) -> Self {
        Self {
            prefix,
            shared: Arc::new(Shared {
                stream: prefix,
                sink,
                budget: Arc::new(OutputBudget::new(limit)),
                lane,
                failure,
                last_truncation: std::sync::Mutex::new(None),
            }),
        }
    }

    /// The most recent quota breach, if any.
    ///
    /// ```
    /// use std::sync::Mutex;
    /// let output = qqq_host::guest_output::GuestOutput::to(
    ///     qqq_host::guest_output::STDOUT_PREFIX,
    ///     Mutex::new(Vec::new()),
    /// );
    /// assert!(output.last_truncation().is_none());
    /// ```
    #[must_use]
    pub fn last_truncation(&self) -> Option<TruncationEvent> {
        self.shared.last_truncation.lock().ok()?.clone()
    }

    /// The marker this output's lines carry.
    #[must_use]
    pub fn prefix(&self) -> &'static str {
        self.prefix
    }

    /// Enclose this output's budget in a shared parent.
    ///
    /// `pub(crate)` because only instance construction wires parents: every
    /// other crate meets shared budgets through [`TenantOutputGuard::budget`].
    /// First call wins — the linkage is made once during construction, and a
    /// second parent would mean two ceilings arguing over one budget.
    pub(crate) fn share_parent(&self, parent: &std::sync::Arc<OutputBudget>) {
        self.shared.budget.set_parent(parent);
    }

    /// A fresh writer over this output's sink.
    #[must_use]
    pub fn writer(&self) -> SanitisingWriter {
        SanitisingWriter {
            escaper: Escaper::new(self.prefix),
            shared: Arc::clone(&self.shared),
            flush_rx: None,
            pending: None,
        }
    }

    /// Bytes accepted under the quota so far, across all writers of this output.
    ///
    /// ```
    /// use std::sync::Mutex;
    /// let output = qqq_host::guest_output::GuestOutput::to(
    ///     qqq_host::guest_output::STDOUT_PREFIX,
    ///     Mutex::new(Vec::new()),
    /// );
    /// assert_eq!(output.bytes_written(), 0);
    /// ```
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.shared.budget.used.load(Ordering::Relaxed)
    }

    /// Writes refused for exceeding the quota.
    ///
    /// The host-visible half of the breach policy: the guest observes a stream
    /// error, and this count is what the host reports and meters. A writer that
    /// never breached reads zero, so the count distinguishes clean runs.
    ///
    /// ```
    /// use std::sync::Mutex;
    /// let output = qqq_host::guest_output::GuestOutput::to(
    ///     qqq_host::guest_output::STDOUT_PREFIX,
    ///     Mutex::new(Vec::new()),
    /// );
    /// assert_eq!(output.breaches(), 0);
    /// ```
    #[must_use]
    pub fn breaches(&self) -> u64 {
        self.shared.budget.breaches.load(Ordering::Relaxed)
    }
}

impl IsTerminal for GuestOutput {
    /// Always `false`, and deliberately not the host's answer.
    ///
    /// Reporting the host's terminal state would leak one bit of the host's
    /// environment to the guest — the same class of ambient authority the clock
    /// denials in `host_wasi` exist to remove — and a guest that colours its output
    /// for a TTY would be colouring a log file.
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for GuestOutput {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(self.writer())
    }
}

/// The `AsyncWrite` wasmtime-wasi writes a guest's output through.
pub struct SanitisingWriter {
    escaper: Escaper,
    shared: Arc<Shared>,
    /// A flush marker already sent to the lane and not yet answered.
    flush_rx: Option<oneshot::Receiver<io::Result<()>>>,
    /// An escaped write accepted against the quota but not yet queued,
    /// with its in-flight guard once admitted.
    ///
    /// A lane-full park holds bytes and guard for the retry; an
    /// in-flight-cap park holds nothing (payment is refunded) and the retry
    /// re-runs payment from scratch. Either way the escaper never re-runs on
    /// retry: re-running the stateful escaper on the same input would advance
    /// it twice for one write, dropping the line marker and drifting the run
    /// bound.
    pending: Option<(usize, Vec<u8>, Option<crate::sink_lane::InFlight>)>,
}

impl std::fmt::Debug for SanitisingWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SanitisingWriter").finish_non_exhaustive()
    }
}

impl AsyncWrite for SanitisingWriter {
    /// Escape, then queue, then report the **input** length.
    ///
    /// # Why the whole buffer is reported as written
    ///
    /// The escape is byte-for-byte: one input byte produces one or more output bytes,
    /// never fewer. So a caller that retried the unwritten tail would resend input
    /// bytes whose output is already in the sink. Reporting `bytes.len()` is therefore
    /// the correct answer, not an optimistic one — and it is what keeps the guest from
    /// observing a short write, which WASI surfaces as a stream error.
    ///
    /// `Pending` means exactly one thing: the pump queue is full and the write is
    /// held, escaped and quota-paid, for the retry. The writer task wakes the
    /// caller after its next receive.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // The recorded failure first: a broken output refuses without
        // consuming quota, so failed writes cannot burn the budget retrying.
        if let Some(failure) = stored_failure(&this.shared) {
            return Poll::Ready(Err(io::Error::other(failure)));
        }
        // Escape once per logical write and hold the buffer across parks: the
        // escaper is stateful, and re-running it on retry would advance the
        // line marker and the run bound twice for one write.
        //
        // Outside a runtime there is no executor to protect and no lane
        // traffic to join: write inline on the calling thread, exactly as
        // before lanes existed. All unit tests driving writes directly take
        // this path, and nothing they emit waits anywhere, so no in-flight
        // accounting applies.
        if tokio::runtime::Handle::try_current().is_err() {
            if this.pending.is_none() {
                let need = this.escaper.escaped_len(buf);
                if let Err(refusal) = this.shared.budget.reserve(need) {
                    record_truncation(&this.shared, need, refusal);
                    return Poll::Ready(Err(io::Error::other("guest output quota exhausted")));
                }
                let mut escaped = Vec::with_capacity(need);
                let consumed = this.escaper.push(buf, &mut escaped);
                debug_assert_eq!(
                    escaped.len(),
                    need,
                    "the probe and the write run the same loop over the same state"
                );
                this.pending = Some((consumed, escaped, None));
            }
            let (consumed, escaped, _) = this.pending.take().expect("just stored");
            let result = direct_write(&this.shared, &escaped).map(|()| consumed);
            return Poll::Ready(result);
        }
        // On a lane the write moves through three stages, each settled once:
        // escape (stateful, never repeated), payment (lifetime quota plus
        // in-flight admission), and the lane send. A parked write retries from
        // its held state at whichever stage it reached.
        if this.pending.is_none() {
            // Probe, then pay, then escape: a refused write must leave the
            // escaper exactly as it found it, so the reservation (lifetime
            // quota) and the admission (in-flight caps) both settle before a
            // single byte is escaped. Escaping first and refunding on refusal
            // would advance the line marker and run bound for a write that
            // never happened.
            let need = this.escaper.escaped_len(buf);
            if let Err(refusal) = this.shared.budget.reserve(need) {
                record_truncation(&this.shared, need, refusal);
                return Poll::Ready(Err(io::Error::other("guest output quota exhausted")));
            }
            let need_u64 = u64::try_from(need).unwrap_or(u64::MAX);
            let Some(flight) = crate::sink_lane::InFlight::reserve(&this.shared.budget, need_u64)
            else {
                // Over the in-flight caps: the lifetime bytes go back (the
                // write never queued) and the write parks until the lane
                // drains. Nothing is held, so the retry re-runs payment from
                // scratch — and the escaper, never advanced, re-probes
                // identically.
                this.shared.budget.unreserve(need);
                this.shared.lane.park(cx.waker());
                return Poll::Pending;
            };
            let mut escaped = Vec::with_capacity(need);
            let consumed = this.escaper.push(buf, &mut escaped);
            debug_assert_eq!(
                escaped.len(),
                need,
                "the probe and the write run the same loop over the same state"
            );
            this.pending = Some((consumed, escaped, Some(flight)));
        }
        let (consumed, escaped, flight) = this.pending.take().expect("paid above");
        match this.shared.lane.send(crate::sink_lane::LaneMsg::Data {
            bytes: escaped,
            flight: flight.expect("paid writes always carry their guard"),
            failure: Arc::clone(&this.shared.failure),
        }) {
            crate::sink_lane::LaneSend::Sent => Poll::Ready(Ok(consumed)),
            crate::sink_lane::LaneSend::Full(crate::sink_lane::LaneMsg::Data {
                bytes,
                flight,
                ..
            }) => {
                // The lane owns nothing yet; hold bytes and guard for the
                // retry (the failure slot is re-read from the output on the
                // next send — it never changes). Quota, escaper state, and
                // in-flight counts were settled above, exactly once.
                this.shared.lane.park(cx.waker());
                this.pending = Some((consumed, bytes, Some(flight)));
                Poll::Pending
            }
            crate::sink_lane::LaneSend::Full(_) => Poll::Ready(Err(io::Error::other(
                "guest-output lane returned a flush marker",
            ))),
            crate::sink_lane::LaneSend::Closed => Poll::Ready(Err(pump_gone())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // A flush must not report success over a recorded write failure: the
        // bytes the marker stands behind may never have reached the sink, and
        // the drain proof would then hide lost output behind an `Ok`.
        if let Some(failure) = stored_failure(&this.shared) {
            this.flush_rx = None;
            return Poll::Ready(Err(io::Error::other(failure)));
        }
        // A marker already in flight: poll it rather than queueing a second one
        // behind it, so flushes complete in the order they were requested.
        if let Some(rx) = this.flush_rx.as_mut() {
            return match Pin::new(rx).poll(cx) {
                Poll::Ready(Ok(result)) => {
                    this.flush_rx = None;
                    Poll::Ready(result)
                }
                Poll::Ready(Err(_)) => {
                    this.flush_rx = None;
                    Poll::Ready(Err(pump_gone()))
                }
                Poll::Pending => Poll::Pending,
            };
        }
        // Outside a runtime there is no lane traffic to join: flush inline.
        if tokio::runtime::Handle::try_current().is_err() {
            return Poll::Ready(direct_flush(&this.shared));
        }
        let lane = Arc::clone(&this.shared.lane);
        {
            let (done, rx) = oneshot::channel();
            // Register interest in the answer in the same step that sends
            // the marker, so no wake-up between the send and the first poll
            // can be lost.
            let mut rx = rx;
            match lane.send(crate::sink_lane::LaneMsg::Flush(done)) {
                crate::sink_lane::LaneSend::Closed => Poll::Ready(Err(pump_gone())),
                // The marker was not queued; the next poll sends a fresh
                // one, and the dropped sender answers nothing. Park so the
                // retry waits for drain rather than spinning.
                crate::sink_lane::LaneSend::Full(_) => {
                    lane.park(cx.waker());
                    Poll::Pending
                }
                crate::sink_lane::LaneSend::Sent => match Pin::new(&mut rx).poll(cx) {
                    // The marker only proves the flush ran; a write the
                    // pump already failed still has to surface here.
                    Poll::Ready(Ok(Err(error))) => Poll::Ready(Err(error)),
                    Poll::Ready(Ok(Ok(()))) => match stored_failure(&this.shared) {
                        Some(failure) => {
                            this.flush_rx = None;
                            Poll::Ready(Err(io::Error::other(failure)))
                        }
                        None => Poll::Ready(Ok(())),
                    },
                    Poll::Ready(Err(_)) => Poll::Ready(Err(pump_gone())),
                    Poll::Pending => {
                        this.flush_rx = Some(rx);
                        Poll::Pending
                    }
                },
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Shutdown is a flush: every byte accepted before it must reach the sink
        // before the stream is closed. The marker stands behind them in the FIFO,
        // so its answer proves the drain.
        self.poll_flush(cx)
    }
}

/// Whether `bytes` more fits under an in-flight cap from `current`.
///
/// An empty counter admits anything: parking a message with nothing queued
/// waits for a drain that can never start, so the bound is always the cap
/// plus one message. Saturating addition, so a corrupted-large counter
/// refuses rather than wrapping into admission.
fn admit_in_flight(current: u64, cap: u64, bytes: u64) -> bool {
    current == 0 || current.saturating_add(bytes) <= cap
}

/// Subtract without wrapping: releases must never panic the holder.
fn sub_saturating(counter: &AtomicU64, bytes: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(bytes))
    });
}

/// Remember the first asynchronous failure; later calls surface it.
///
/// Shared with the lane thread, which reports sink failures here rather than
/// carrying its own slot: one output, one failure record, however many
/// threads touch it.
pub(crate) fn record_failure(failure: &Arc<std::sync::Mutex<Option<String>>>, message: String) {
    if let Ok(mut slot) = failure.lock() {
        if slot.is_none() {
            *slot = Some(message);
        }
    }
}

/// The recorded failure, if any.
fn stored_failure(shared: &Shared) -> Option<String> {
    shared.failure.lock().ok()?.clone()
}

/// Remember a quota breach as a structured event.
///
/// Called with the reservation already refused; the refusal carries the breach
/// count including this refusal, so `total_breaches` names it exactly. The
/// ceiling is whichever tripped — the instance's own, or the shared tenant
/// ceiling when the parent refused.
fn record_truncation(shared: &Shared, requested: usize, refusal: Refusal) {
    let event = TruncationEvent {
        stream: shared.stream,
        requested_bytes: u64::try_from(requested).unwrap_or(u64::MAX),
        limit: refusal.limit,
        total_breaches: refusal.breaches,
    };
    if let Ok(mut slot) = shared.last_truncation.lock() {
        *slot = Some(event);
    }
}

/// A write outside any runtime: straight to the sink on the calling thread.
fn direct_write(shared: &Shared, bytes: &[u8]) -> io::Result<()> {
    shared.sink.write_all_shared(bytes)
}

/// A flush outside any runtime.
fn direct_flush(shared: &Shared) -> io::Result<()> {
    shared.sink.flush_shared()
}

/// The pump is gone, so queued work will never complete.
fn pump_gone() -> io::Error {
    io::Error::other("the guest-output writer task is gone")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    use std::time::Duration;

    /// A captured sink.
    ///
    /// An alias rather than a newtype on purpose: `Arc<Mutex<Vec<u8>>>` is **already**
    /// a `GuestSink` through the two provided implementations, so the test drives the
    /// production escaping path with no bespoke type in between.
    type Captured = Arc<Mutex<Vec<u8>>>;

    fn captured() -> Captured {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn text(captured: &Captured) -> String {
        String::from_utf8(captured.lock().expect("not poisoned").clone()).expect("utf-8")
    }

    fn escape(prefix: &'static str, input: &[u8]) -> String {
        let mut out = Vec::new();
        let mut escaper = Escaper::new(prefix);
        escaper.push(input, &mut out);
        String::from_utf8(out).expect("the escape output is utf-8")
    }

    /// A line that would be a host access record, byte for byte.
    const FORGED_RECORD: &str = r#"{"ts":"2026-01-01T00:00:00Z","method":"DELETE","path":"/admin","status":200,"tenant":"other"}"#;

    /// **F-21: dropping a guard after poison must not panic.**
    ///
    /// Written first and failing first: on the old `.lock().expect("tenant
    /// output budgets are not poisoned")` code the `drop` below panics — and
    /// a `Drop` that panics during unwinding aborts the process even after
    /// F-01, which is the double-panic hazard. The `is_poisoned` assertion is
    /// the anti-vacuity pin: without it the test could pass with no poison.
    #[test]
    fn f21_tenant_guard_drop_does_not_panic_after_poison() {
        use std::sync::Arc;
        let budgets = Arc::new(TenantOutputBudgets::new(64));
        let guard = budgets.acquire("tenant-a");
        let poisoner = Arc::clone(&budgets);
        let _ = std::thread::spawn(move || {
            // Test-only: hold the registry lock across a panic to poison it
            // on purpose (the tests module sees the private field, so no
            // accessor widens the API for fault injection).
            let _held = poisoner.inner.state.lock().expect("test setup: unpoisoned");
            panic!("poison the tenant budgets lock on purpose");
        })
        .join();
        assert!(
            budgets.inner.state.is_poisoned(),
            "the fixture must really poison the lock, or this test proves nothing"
        );
        drop(guard);
        // The registry keeps working: a fresh acquire re-establishes the entry
        // (the recovered map is empty after the drop evicted it).
        let _again = budgets.acquire("tenant-a");
        assert_eq!(budgets.live("tenant-a"), 1);
    }

    #[test]
    fn a_guest_line_cannot_impersonate_an_access_record() {
        // The defect, stated as the property that actually holds: the forged line must
        // not be a line of its own on the host's stream.
        let rendered = escape(STDOUT_PREFIX, FORGED_RECORD.as_bytes());
        assert!(
            rendered.starts_with(STDOUT_PREFIX),
            "a guest line must begin with the marker: {rendered}"
        );
        assert_ne!(
            rendered.trim_end_matches('\n'),
            FORGED_RECORD,
            "the forged record became a line of its own"
        );
        assert!(
            !rendered.lines().any(|l| l == FORGED_RECORD),
            "some line of the output is exactly the forged record: {rendered}"
        );
        // And it is still readable, so an operator can see what the guest said.
        assert!(
            rendered.contains(FORGED_RECORD),
            "the guest's own bytes must remain legible after the marker: {rendered}"
        );
    }

    #[test]
    fn a_guest_cannot_open_an_unprefixed_line() {
        // The case that makes the marker mean "every line": a guest that emits its own
        // newline, including a record on the second line.
        let rendered = escape(
            STDOUT_PREFIX,
            format!("innocent\n{FORGED_RECORD}\nmore").as_bytes(),
        );
        for line in rendered.lines() {
            assert!(
                line.starts_with(STDOUT_PREFIX),
                "every physical line must carry the marker; found {line:?} in {rendered:?}"
            );
        }
        assert_eq!(
            rendered.matches('\n').count(),
            2,
            "the guest's two line breaks must survive as two line breaks: {rendered:?}"
        );
    }

    #[test]
    fn every_control_byte_is_escaped() {
        // The total rule, over the whole range rather than a list of "dangerous" bytes.
        // `\n` is excluded because it is the one byte that legitimately ends a line; the
        // next line carries the marker, which `a_guest_cannot_open_an_unprefixed_line`
        // asserts.
        let controls: Vec<u8> = (0x00u8..=0x1f)
            .chain(std::iter::once(0x7f))
            .filter(|b| *b != b'\n')
            .collect();
        let rendered = escape(STDOUT_PREFIX, &controls);
        assert!(
            !rendered
                .bytes()
                .any(|b| (b < 0x20 && b != b'\n') || b == 0x7f),
            "a raw control byte reached the sink: {rendered:?}"
        );
        assert_eq!(
            rendered.matches('\\').count(),
            controls.len(),
            "every escaped control byte must produce exactly one escape sequence: {rendered:?}"
        );
    }

    #[test]
    fn an_unterminated_run_is_broken_at_the_bound() {
        // A guest that never emits a newline must not be able to hold one line open
        // forever: a line-oriented collector would have nothing to parse.
        let input = vec![b'x'; MAX_ESCAPED_RUN * 2 + 7];
        let rendered = escape(STDOUT_PREFIX, &input);
        assert_eq!(
            rendered.matches('\n').count(),
            2,
            "two full runs must produce two forced breaks"
        );
        for line in rendered.lines() {
            assert!(
                line.starts_with(STDOUT_PREFIX),
                "the continuation line must carry the marker too"
            );
        }
    }

    #[test]
    fn the_bound_does_not_fire_early() {
        // The control for the test above. Without it, a bound of zero would satisfy
        // "runs are broken" while breaking every line the guest writes.
        let input = vec![b'x'; MAX_ESCAPED_RUN - 1];
        let rendered = escape(STDOUT_PREFIX, &input);
        assert_eq!(
            rendered.matches('\n').count(),
            0,
            "a run below the bound must not be broken"
        );
    }

    #[test]
    fn a_guest_cannot_forge_the_escape_sequence() {
        // `\` is escaped too, so a guest cannot emit a literal `\n` and have a reader
        // mistake it for a real break that the host inserted.
        let rendered = escape(STDOUT_PREFIX, b"a\\nb");
        assert_eq!(rendered, format!("{STDOUT_PREFIX}a\\\\nb"));
    }

    #[test]
    fn stdout_and_stderr_are_distinguishable_when_merged() {
        // `2>&1` and every container runtime merge the streams, so the markers must
        // differ or the merge destroys the distinction.
        assert_ne!(STDOUT_PREFIX, STDERR_PREFIX);
        assert!(!STDERR_PREFIX.contains(STDOUT_PREFIX));
        assert!(!STDOUT_PREFIX.contains(STDERR_PREFIX));
    }

    #[test]
    fn the_stream_interface_sanitises_through_the_real_trait_method() {
        // Drives `StdoutStream::async_stream` -- the exact method wasmtime-wasi calls
        // (`p2::stdio` -> `ctx.stdout.p2_stream()` -> the default adapter over
        // `async_stream`) -- against a captured sink. This is what proves the
        // `AsyncWrite` impl delegates to `Escaper` rather than carrying a second rule.
        let captured = captured();
        let output = GuestOutput::to(STDOUT_PREFIX, captured.clone());

        let written = futures_write(output.async_stream(), FORGED_RECORD.as_bytes());
        assert_eq!(
            written,
            FORGED_RECORD.len(),
            "the writer must report every input byte consumed, or WASI surfaces a short write"
        );

        let text = text(&captured);
        assert!(
            text.starts_with(STDOUT_PREFIX),
            "bytes reached the sink without the marker: {text:?}"
        );
        assert!(
            !text.lines().any(|l| l == FORGED_RECORD),
            "the forged record became a line of its own through the real trait path: {text:?}"
        );
    }

    #[test]
    fn guest_output_enforces_one_shared_total_quota_across_writers() {
        let captured = captured();
        // Escaped bytes: "123" costs the 19-byte prefix plus 3 (22 total).
        let output = GuestOutput::to_with_limit(STDOUT_PREFIX, captured, 25);
        let mut first = output.writer();
        let mut second = output.writer();
        let mut cx = Context::from_waker(std::task::Waker::noop());

        assert!(matches!(
            Pin::new(&mut first).poll_write(&mut cx, b"123"),
            Poll::Ready(Ok(3))
        ));
        assert!(matches!(
            Pin::new(&mut second).poll_write(&mut cx, b"456"),
            Poll::Ready(Err(_))
        ));
    }

    /// One framed write through the real `AsyncWrite` path, for spawned tasks.
    ///
    /// `futures_write` below drives with a no-op waker outside a runtime, which a
    /// `tokio::spawn`ed task cannot use. This is the same trait method on the same
    /// type, awaited instead.
    async fn framed_write(writer: &mut SanitisingWriter) {
        use tokio::io::AsyncWriteExt as _;
        writer
            .write_all(b"stuck-payload")
            .await
            .expect("the released sink writes");
    }

    /// Drive an `AsyncWrite` to completion with a no-op waker.
    ///
    /// `Waker::noop` is the standard library's own no-op waker, so this needs no
    /// hand-built vtable and therefore no `unsafe` — which the crate-level
    /// `forbid(unsafe_code)` would reject outright, since `forbid` cannot be relaxed by
    /// an inner `allow`. Building a `RawWaker` by hand was the first attempt and the
    /// compiler refused it, correctly.
    ///
    /// A `Pending` here panics rather than looping forever. `poll_write` only
    /// pends on a full pump queue, which needs a runtime and dozens of queued
    /// writes; these direct-driven unit tests never approach it, so a pend is
    /// a bug in the writer rather than backpressure.
    fn futures_write(stream: Box<dyn AsyncWrite + Send + Sync>, buf: &[u8]) -> usize {
        // `Pin<Box<dyn AsyncWrite>>` is itself `AsyncWrite` (tokio implements the trait
        // for `Pin<P>` where `P: DerefMut + Unpin`), and `Pin<Box<_>>` is `Unpin`, so
        // `Pin::new` is available here without any `unsafe`.
        let mut stream = Box::into_pin(stream);
        let mut cx = Context::from_waker(std::task::Waker::noop());

        match Pin::new(&mut stream).poll_write(&mut cx, buf) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => panic!("the guest write failed: {e}"),
            Poll::Pending => panic!("the writer must not return Pending"),
        }
    }

    #[test]
    fn a_quota_breach_fails_the_write_and_counts_it_for_the_host() {
        // The two halves of the breach policy: the guest observes a stream
        // error, and the host observes a number. A breach the host cannot read
        // is a policy nobody can meter.
        let captured = captured();
        let output = GuestOutput::to_with_limit(STDOUT_PREFIX, captured, 25);
        assert_eq!(output.breaches(), 0, "a fresh output has no breaches");
        let mut writer = output.writer();
        let mut cx = Context::from_waker(std::task::Waker::noop());

        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"123"),
            Poll::Ready(Ok(3))
        ));
        assert_eq!(output.bytes_written(), 22);
        // A fresh writer: each writer starts at a line start, so the second
        // write carries the prefix too (22 escaped bytes, 44 total > 25).
        let mut second = output.writer();
        assert!(matches!(
            Pin::new(&mut second).poll_write(&mut cx, b"456"),
            Poll::Ready(Err(_))
        ));
        assert_eq!(output.breaches(), 1, "the refused write must be counted");
        assert_eq!(
            output.bytes_written(),
            22,
            "refused bytes must not consume the quota"
        );
        assert_eq!(
            output.last_truncation(),
            Some(TruncationEvent {
                stream: STDOUT_PREFIX,
                requested_bytes: 22,
                limit: 25,
                total_breaches: 1,
            }),
            "the breach must be recorded as a structured event"
        );
    }

    /// A sink that refuses its first write, then behaves.
    ///
    /// The split is the instrument: the failed bytes were already acknowledged
    /// to the guest, while the later flush succeeds on its own. A flush that
    /// reports `Ok` here proves the recorded failure was dropped on the floor.
    struct FailOnceSink {
        remaining_failures: AtomicUsize,
        buf: std::sync::Mutex<Vec<u8>>,
    }

    impl GuestSink for FailOnceSink {
        fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()> {
            if self
                .remaining_failures
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(io::Error::other("sink exploded"));
            }
            self.buf
                .lock()
                .expect("not poisoned")
                .extend_from_slice(bytes);
            Ok(())
        }

        fn flush_shared(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// **A flush reports a write the pump already failed.**
    ///
    /// Acceptance precedes failure by design — `poll_write` cannot know the
    /// future — so the flush marker is where the recorded failure has to
    /// surface. FIFO order makes this deterministic: the marker stands behind
    /// the failed bytes, so an answered flush proves they were processed.
    #[tokio::test]
    async fn a_flush_reports_a_write_the_pump_already_failed() {
        use tokio::io::AsyncWriteExt as _;

        let sink = Arc::new(FailOnceSink {
            remaining_failures: AtomicUsize::new(1),
            buf: std::sync::Mutex::new(Vec::new()),
        });
        let output = GuestOutput::to(STDOUT_PREFIX, Arc::clone(&sink));
        let mut writer = output.writer();
        writer
            .write_all(b"lost")
            .await
            .expect("acceptance precedes the failure");
        let error = writer
            .flush()
            .await
            .expect_err("the flush must surface the recorded write failure");
        assert!(
            error.to_string().contains("sink exploded"),
            "the flush must name the recorded failure: {error}"
        );
    }

    /// **Dropping the output ends the lane thread.**
    ///
    /// The thread must hold no sender and no `Shared`: either one keeps the
    /// inbox open, `recv` never returns `None`, and every request leaks a
    /// thread plus its sink and budget on a long-running server. The `Weak`
    /// observes the thread's own sink clone, so its death proves the thread
    /// ended rather than merely going quiet.
    #[tokio::test]
    async fn dropping_the_output_ends_the_lane_thread() {
        use tokio::io::AsyncWriteExt as _;

        let sink = Arc::new(Mutex::new(Vec::new()));
        let weak = Arc::downgrade(&sink);
        let output = GuestOutput::to(STDOUT_PREFIX, Arc::clone(&sink));
        // Start the lane: without a poll inside the runtime no message is
        // sent, and the assertion below would pass on an output that never
        // queued.
        output.writer().write_all(b"hello").await.expect("write");
        drop(sink);
        drop(output);
        tokio::time::timeout(Duration::from_secs(5), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the lane thread must end after the output is dropped");
    }

    /// **A full lane queue parks the writer until space frees.**
    ///
    /// The gate holds the lane inside its first sink write, so after an
    /// initial burst of takes (bounded: the thread blocks in its first
    /// write) the queue refills and the next write must come back `Pending`
    /// rather than blocking the worker or dropping the bytes; opening the
    /// gate must let the parked write finish. The exact send count at the
    /// park is schedule-dependent (it depends on how many takes the first
    /// burst got), so the test asserts the park happens, not where: what is
    /// deterministic is that a full queue parks and a drained one proceeds.
    /// Quota and in-flight caps sit far above the few hundred queued bytes,
    /// so only the queue bound is under test — a tripped quota would fail
    /// the write for a different, already-tested reason.
    #[tokio::test]
    async fn a_full_lane_queue_parks_the_writer_until_space_frees() {
        let blocked_sink = Arc::new(BlockingSink::new());
        let _open = OpenOnDrop {
            sink: &blocked_sink,
        };
        let output = GuestOutput::to(STDOUT_PREFIX, Arc::clone(&blocked_sink));
        let mut writer = output.writer();
        let mut cx = Context::from_waker(std::task::Waker::noop());

        let mut parked = false;
        for _ in 0..100_000 {
            match Pin::new(&mut writer).poll_write(&mut cx, b"x") {
                Poll::Ready(Ok(_)) => {}
                Poll::Pending => {
                    parked = true;
                    break;
                }
                Poll::Ready(Err(error)) => panic!("the write must park, not fail: {error}"),
            }
        }
        assert!(
            parked,
            "a full queue must park the writer rather than block or drop"
        );

        blocked_sink.release();
        for _ in 0..100 {
            match Pin::new(&mut writer).poll_write(&mut cx, b"x") {
                Poll::Ready(Ok(_)) => break,
                Poll::Pending => {
                    tokio::task::yield_now().await;
                }
                Poll::Ready(Err(error)) => panic!("the write must succeed after release: {error}"),
            }
        }
    }

    /// **F-12 red-first: queued small writes are coalesced.**
    ///
    /// 64 numbered 5-byte payloads from one writer must reach the sink as a
    /// handful of `write_all` calls (at least 8x fewer than messages), with
    /// bytes in exact arrival order. 64 fills but does not exceed the queue,
    /// so every write is accepted and the test cannot hang on backpressure.
    /// Today every message is its own blocking write: 64 calls, so this fails
    /// on the count, not the order.
    #[tokio::test]
    async fn f12_queued_small_writes_are_coalesced() {
        use tokio::io::AsyncWriteExt as _;

        let sink = Arc::new(CountingSink::new());
        let _open = OpenOnDrop { sink: &sink.inner };
        let output = GuestOutput::to(STDOUT_PREFIX, Arc::clone(&sink));
        let mut writer = output.writer();
        let mut expected = String::from(STDOUT_PREFIX);
        for i in 0..64u32 {
            let payload = format!("{i:04}:");
            expected.push_str(&payload);
            writer
                .write_all(payload.as_bytes())
                .await
                .expect("the queue accepts small writes");
        }
        sink.release();
        output.writer().flush().await.expect("drain proves order");
        let calls = sink.calls.load(Ordering::Relaxed);
        assert!(
            calls <= 8,
            "64 messages must coalesce to at most 8 sink writes (8x), took {calls}"
        );
        let bytes = sink.inner.buf.lock().expect("not poisoned").clone();
        assert_eq!(
            String::from_utf8(bytes).expect("ascii"),
            expected,
            "coalescing must preserve exact arrival order"
        );
    }

    /// A sink that counts `write_all_shared` calls behind a gate.
    ///
    /// The call count is the coalescing observable: batching turns N queued
    /// messages into fewer, larger writes. Bytes still land in order — the
    /// count proves batching happened, the buffer proves nothing reordered.
    struct CountingSink {
        inner: BlockingSink,
        calls: AtomicUsize,
    }

    impl CountingSink {
        fn new() -> Self {
            Self {
                inner: BlockingSink::new(),
                calls: AtomicUsize::new(0),
            }
        }

        fn release(&self) {
            self.inner.release();
        }
    }

    impl GuestSink for CountingSink {
        fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.inner.write_all_shared(bytes)
        }

        fn flush_shared(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Opens the gate when dropped, so a failed assertion cannot leave the
    /// pump task parked on the gate while the test runtime shuts down — and
    /// runtime shutdown waits for the blocking pool, which waits for the gate:
    /// a hung test binary rather than a red test.
    struct OpenOnDrop<'a> {
        sink: &'a BlockingSink,
    }
    impl Drop for OpenOnDrop<'_> {
        fn drop(&mut self) {
            self.sink.release();
        }
    }

    /// **Tenants that never return leave nothing behind.**
    ///
    /// The registry is keyed by names the operator does not control, so an
    /// entry must exist only while at least one request holds it. Each acquire
    /// counts, each drop uncounts, and the last drop evicts — which is the
    /// reset boundary: a tenant with no live request starts its next request
    /// at zero, and a tenant that never returns cannot accumulate state here.
    #[test]
    fn tenant_entries_evict_when_the_last_guard_drops() {
        let budgets = TenantOutputBudgets::new(1024);
        let first = budgets.acquire("tenant-a");
        let second = budgets.acquire("tenant-a");
        assert!(
            Arc::ptr_eq(first.budget(), second.budget()),
            "concurrent requests of one tenant must share one budget object"
        );
        let retired = Arc::downgrade(second.budget());
        first
            .budget()
            .reserve(512)
            .expect("half the tenant budget must be reservable");
        assert_eq!(first.budget().used(), 512);
        drop(first);
        drop(second);
        assert!(
            retired.upgrade().is_none(),
            "dropping the last guard must free the retired tenant budget"
        );
        assert_eq!(budgets.live("tenant-a"), 0);
        let third = budgets.acquire("tenant-a");
        assert_eq!(
            third.budget().used(),
            0,
            "after eviction the next request must start a fresh budget at zero"
        );
    }

    /// **Two tenants never share a budget.**
    ///
    /// The control for the test above: shared accounting that keyed on the
    /// wrong thing — every tenant, or no tenant — would pass a same-tenant
    /// test while charging one tenant for another's output.
    #[test]
    fn different_tenants_get_different_budgets() {
        let budgets = TenantOutputBudgets::new(1024);
        let a = budgets.acquire("tenant-a");
        let b = budgets.acquire("tenant-b");
        assert!(
            !Arc::ptr_eq(a.budget(), b.budget()),
            "tenant budgets must be distinct objects"
        );
    }

    /// **Two independent outputs trip one shared tenant ceiling.**
    ///
    /// The cross-request property: each output's own quota is generous, but
    /// their combined bytes exceed the tenant budget, so the second output's
    /// write is refused, the tenant breach count rises, and the output records
    /// a structured event naming the tenant ceiling rather than its own.
    #[test]
    fn two_outputs_share_one_tenant_ceiling() {
        // Escaped bytes: each 6-byte write costs the 19-byte prefix plus 6 (25).
        let budgets = TenantOutputBudgets::new(30);
        let guard_a = budgets.acquire("tenant-a");
        let guard_b = budgets.acquire("tenant-a");
        let out_a = GuestOutput::to_with_limit(STDOUT_PREFIX, captured(), u64::MAX);
        out_a.share_parent(guard_a.budget());
        let out_b = GuestOutput::to_with_limit(STDOUT_PREFIX, captured(), u64::MAX);
        out_b.share_parent(guard_b.budget());
        let mut cx = Context::from_waker(std::task::Waker::noop());

        let mut w1 = out_a.writer();
        assert!(matches!(
            Pin::new(&mut w1).poll_write(&mut cx, b"123456"),
            Poll::Ready(Ok(6))
        ));
        let mut w2 = out_b.writer();
        assert!(
            matches!(
                Pin::new(&mut w2).poll_write(&mut cx, b"789012"),
                Poll::Ready(Err(_))
            ),
            "fifty escaped bytes against a thirty-byte tenant ceiling must refuse"
        );
        assert_eq!(
            guard_a.budget().breaches(),
            1,
            "the tenant budget must count the refusal"
        );
        assert_eq!(
            out_b.breaches(),
            1,
            "the refused output must count the tenant refusal the host reads"
        );
        assert_eq!(
            out_b.last_truncation(),
            Some(TruncationEvent {
                stream: STDOUT_PREFIX,
                requested_bytes: 25,
                limit: 30,
                total_breaches: 1,
            }),
            "the event must name the tenant ceiling that tripped"
        );
    }

    /// **F-07 red-first: escaped-size charging.**
    ///
    /// Each `b"\n"` input byte costs the
    /// 19-byte prefix plus the newline itself (20 escaped bytes), so a limit of
    /// 100 escaped bytes admits exactly 5 of 10 newline writes. On the old
    /// input-byte charging all 10 pass.
    #[test]
    fn f07_newline_flood_is_charged_at_escaped_size() {
        let captured = captured();
        let output = GuestOutput::to_with_limit(STDOUT_PREFIX, captured, 100);
        let mut writer = output.writer();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut accepted = 0;
        for _ in 0..10 {
            if matches!(
                Pin::new(&mut writer).poll_write(&mut cx, b"\n"),
                Poll::Ready(Ok(_))
            ) {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 5, "100 / 20 = 5 newline writes may succeed");
    }

    /// **F-07 red-first: control bytes cost 4 escaped bytes each.** 19-byte prefix
    /// plus 30 control bytes at 4 each is 139 escaped bytes against a limit of
    /// 100, so the write must fail. On input-byte charging (30 bytes) it passes.
    #[test]
    fn f07_control_bytes_are_charged_at_four_bytes_each() {
        let captured = captured();
        let output = GuestOutput::to_with_limit(STDOUT_PREFIX, captured, 100);
        let mut writer = output.writer();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            matches!(
                Pin::new(&mut writer).poll_write(&mut cx, &[0x01u8; 30]),
                Poll::Ready(Err(_))
            ),
            "19 + 30*4 = 139 escaped bytes must exceed the 100-byte limit"
        );
    }

    /// **F-07 red-first: a refused write must not advance the escaper.** After one
    /// short line and a refused flood, continuing the same line must not emit
    /// a second prefix — the state is exactly as the refusal found it.
    #[test]
    fn f07_refused_write_does_not_advance_escaper_state() {
        let captured = captured();
        // "qqq-guest stdout | ab" is 21 escaped bytes; the flood below is refused.
        let output = GuestOutput::to_with_limit(STDOUT_PREFIX, captured.clone(), 25);
        let mut writer = output.writer();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"ab"),
            Poll::Ready(Ok(_))
        ));
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"\n\n\n\n\n"),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"cd"),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(
            text(&captured).matches(STDOUT_PREFIX).count(),
            1,
            "the refused write must not have armed a second prefix"
        );
    }

    /// **F-07: the probe predicts the write, byte for byte.**
    ///
    /// Two thousand deterministic pseudo-random inputs (full byte range, so
    /// newlines, prefixes-in-waiting, and control runs all occur) across two
    /// starting states: `escaped_len` must equal the length the real `run`
    /// produces from the same state. Any disagreement is a quota bypass in
    /// one direction or a false refusal in the other. No external RNG crate:
    /// a 64-bit LCG is deterministic per seed and sufficient for coverage.
    #[test]
    fn f07_escaped_len_equals_actual_output_length() {
        fn pseudo_random_bytes(seed: u64, max_len: usize) -> Vec<u8> {
            const MULTIPLIER: u64 = 6_364_136_223_846_793_005;
            const INCREMENT: u64 = 1_442_695_040_888_963_407;
            let mut state = seed.wrapping_mul(MULTIPLIER).wrapping_add(INCREMENT);
            let len = 1 + usize::try_from(seed % 300).expect("a remainder under 300 fits");
            let len = len.min(max_len).max(1);
            (0..len)
                .map(|_| {
                    state = state.wrapping_mul(MULTIPLIER).wrapping_add(INCREMENT);
                    u8::try_from((state >> 33) & 0xff).expect("masked to one byte")
                })
                .collect()
        }
        for seed in 0..2000u64 {
            let input = pseudo_random_bytes(seed, 300);
            let mut escaper = Escaper::new(STDOUT_PREFIX);
            if seed % 2 == 1 {
                // Mid-line state with a partial run, so the probe is tested
                // somewhere other than a fresh line.
                let mut discard = Vec::new();
                escaper.push(b"pre", &mut discard);
            }
            let predicted = escaper.escaped_len(&input);
            let mut out = Vec::new();
            escaper.run(&input, &mut out);
            assert_eq!(predicted, out.len(), "seed {seed}");
        }
    }

    /// **F-07: control escapes are lowercase hex, stack-built.**
    ///
    /// Pins the exact bytes of the `\xNN` arm after the `format!` removal:
    /// any case or width change breaks this rather than drifting silently
    /// into the log stream.
    #[test]
    fn f07_control_escapes_are_lowercase_hex() {
        assert_eq!(
            escape(STDOUT_PREFIX, &[0x01, 0x7f]),
            format!("{STDOUT_PREFIX}\\x01\\x7f")
        );
    }

    /// **F-07: an empty queue admits one oversized message.**
    ///
    /// A single write larger than the lane queue with nothing queued must
    /// still queue: parking it waits for a drain that can never start, because
    /// the lane only receives what writers send. The bound is therefore the
    /// limit plus one message, never a hang.
    #[tokio::test]
    async fn f07_empty_queue_admits_one_oversized_message() {
        let captured = captured();
        let output = GuestOutput::to(STDOUT_PREFIX, captured);
        let mut writer = output.writer();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let big = vec![b'z'; 2 * 1024 * 1024];
        assert!(
            matches!(
                Pin::new(&mut writer).poll_write(&mut cx, &big),
                Poll::Ready(Ok(_))
            ),
            "an empty queue must admit one oversized message rather than park it forever"
        );
    }

    /// **F-07/F-12: a parked writer wakes after bytes free, not after takes.**
    ///
    /// The lane must release in-flight bytes (by completing writes) BEFORE
    /// waking parked writers: a wake against a stale count re-parks, and
    /// after the final write no further wake will ever come — stranded with
    /// space available. The spawned writer below completes with no test-side
    /// re-polling if and only if the wake fires on the updated count.
    #[tokio::test]
    async fn f07_parked_writer_wakes_after_bytes_free() {
        use tokio::io::AsyncWriteExt as _;
        use tokio::sync::oneshot;

        let blocked_sink = Arc::new(BlockingSink::new());
        let _open = OpenOnDrop {
            sink: &blocked_sink,
        };
        let output = GuestOutput::to(STDOUT_PREFIX, Arc::clone(&blocked_sink));
        // Seven 32 KiB writes (229,395 in-flight bytes): an eighth would pass
        // the 256 KiB per-output cap, so the fill below stops at seven and
        // the spawned writer is the one that parks.
        let mut first = output.writer();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let chunk = vec![b'y'; 32 * 1024];
        for _ in 0..7 {
            assert!(matches!(
                Pin::new(&mut first).poll_write(&mut cx, &chunk),
                Poll::Ready(Ok(_))
            ));
        }
        // A further 32 KiB write fits only once the lane is fully drained, so
        // it parks through every write and proves the final wake by completing.
        let parked = output.clone();
        let (done, wait) = oneshot::channel();
        let parked_task = tokio::spawn(async move {
            let mut writer = parked.writer();
            writer
                .write_all(&vec![b'w'; 32 * 1024])
                .await
                .expect("the parked write must complete after the drain");
            let _ = done.send(());
        });
        // Let the spawned writer poll and park while the counts are still
        // high: the test must prove the FINAL wake, which needs the writer
        // parked across the last write rather than arriving after the drain.
        tokio::time::sleep(Duration::from_millis(100)).await;
        blocked_sink.release();
        output
            .writer()
            .flush()
            .await
            .expect("a released sink drains");
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .expect("the parked writer must wake after the bytes free, with no re-poll")
            .expect("the spawned task must not be dropped");
        parked_task.await.expect("writer tasks must not panic");
    }

    /// **F-06 red-first: a busy tenant is never permanently throttled.**
    ///
    /// Anchor guard keeps `live >= 1` for the whole run (steady traffic with
    /// no moment of complete idleness): 10,000 sequential request budgets each
    /// reserving 16 bytes against a 1024-byte tenant ceiling must all succeed,
    /// because every request's end refunds its bytes. On the cumulative
    /// counter the ceiling trips after 64 iterations and never recovers.
    #[test]
    fn f06_busy_tenant_is_not_permanently_throttled() {
        let budgets = TenantOutputBudgets::new(1024);
        let _anchor = budgets.acquire("tenant-a");
        for i in 0..10_000u32 {
            let guard = budgets.acquire("tenant-a");
            let child = Arc::new(OutputBudget::new(256));
            child.set_parent(guard.budget());
            assert!(
                child.reserve(16).is_ok(),
                "iteration {i}: refused although at most 16 bytes are live"
            );
        }
    }

    /// **F-06 red-first: the ceiling still bounds concurrent output, and a
    /// finished request's bytes return.**
    #[test]
    fn f06_ceiling_still_bounds_concurrent_output() {
        let budgets = TenantOutputBudgets::new(64);
        let first = budgets.acquire("tenant-a");
        let second = budgets.acquire("tenant-a");
        let one = Arc::new(OutputBudget::new(64));
        one.set_parent(first.budget());
        let two = Arc::new(OutputBudget::new(64));
        two.set_parent(second.budget());
        assert!(one.reserve(40).is_ok());
        assert!(
            two.reserve(40).is_err(),
            "concurrent total 80 must exceed the 64-byte tenant ceiling"
        );
        drop(one);
        assert!(
            two.reserve(40).is_ok(),
            "after the first request ends its bytes are refunded"
        );
    }

    /// **F-06 guard: a refund can never underflow the parent.**
    ///
    /// Passes before the fix too (nothing is subtracted yet) — its job is to
    /// pin the saturating semantics across the change, not to prove the
    /// defect. The defect is proven by the two tests above.
    #[test]
    fn f06_refund_never_underflows() {
        let budgets = TenantOutputBudgets::new(64);
        let guard = budgets.acquire("tenant-a");
        let child = Arc::new(OutputBudget::new(64));
        child.set_parent(guard.budget());
        assert!(child.reserve(1000).is_err(), "over-limit reserves nothing");
        drop(child);
        let fresh = Arc::new(OutputBudget::new(64));
        fresh.set_parent(guard.budget());
        assert!(
            fresh.reserve(64).is_ok(),
            "the full ceiling must still be available"
        );
    }

    /// **F-06: tenant refusals are metered exactly once each.**
    ///
    /// A registry wired to shared metrics counts one per tenant-ceiling
    /// refusal — never per observing child, and never for a child-limit
    /// refusal that never reached the tenant. Added with the meter; the
    /// busy/concurrent tests above are the red proofs for the refund itself.
    #[test]
    fn f06_tenant_refusals_are_metered() {
        let meter = Arc::new(crate::metrics::Metrics::new());
        let budgets = TenantOutputBudgets::new(40);
        budgets.set_meter(&meter);
        let guard = budgets.acquire("tenant-a");
        let child = Arc::new(OutputBudget::new(64));
        child.set_parent(guard.budget());
        assert!(child.reserve(40).is_ok());
        assert_eq!(meter.output_refusals(), 0, "successes meter nothing");
        assert!(
            child.reserve(1).is_err(),
            "41 bytes must exceed the tenant 40"
        );
        assert_eq!(meter.output_refusals(), 1, "one tenant refusal notes once");
        assert!(child.reserve(1).is_err());
        assert_eq!(
            meter.output_refusals(),
            2,
            "each refusal notes, none double"
        );
    }

    /// **F-12 red-first: a stalled sink must not starve the blocking pool.**
    ///
    /// Eight outputs share one gated sink on a runtime with four blocking
    /// threads. Today every pump holds a blocking thread inside its sink
    /// write, so a `spawn_blocking` probe cannot run within 500 ms. After the
    /// lane change no guest-output write touches the blocking pool and the
    /// probe passes immediately. The gate opens on drop so a failure cannot
    /// hang runtime shutdown on parked blocking threads.
    #[test]
    fn f12_stalled_sink_does_not_starve_the_blocking_pool() {
        use tokio::io::AsyncWriteExt as _;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(4)
            .enable_all()
            .build()
            .expect("test runtime builds");
        rt.block_on(async {
            let sink = Arc::new(BlockingSink::new());
            let _open = OpenOnDrop { sink: &sink };
            let mut outputs = Vec::new();
            for _ in 0..8 {
                let output = GuestOutput::to(STDOUT_PREFIX, Arc::clone(&sink));
                output
                    .writer()
                    .write_all(b"stuck-payload")
                    .await
                    .expect("enqueue accepts");
                outputs.push(output);
            }
            // Let the pumps reach the gate: acceptance only enqueues, so the
            // writes above prove nothing until the sink side is engaged.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let probe = tokio::time::timeout(
                Duration::from_millis(500),
                tokio::task::spawn_blocking(|| 1 + 1),
            )
            .await;
            assert!(
                probe.is_ok(),
                "spawn_blocking starved by a stalled log sink"
            );
        });
    }

    /// **F-12: per-output order survives a shared lane.**
    ///
    /// Two outputs on one lane write interleaved numbered chunks; each
    /// output's subsequence must appear in order in the sink. Arrival order
    /// is deterministic (sequential awaits), so the full byte string is
    /// asserted exactly — any reorder breaks it.
    #[tokio::test]
    async fn f12_order_is_preserved_per_output_across_lane() {
        use tokio::io::AsyncWriteExt as _;

        let sink = captured();
        let lane =
            crate::sink_lane::SinkLane::spawn("test-order", sink.clone() as Arc<dyn GuestSink>)
                .expect("a lane thread spawns");
        let first = GuestOutput::with_lane(STDOUT_PREFIX, &lane, u64::MAX);
        let second = GuestOutput::with_lane(STDOUT_PREFIX, &lane, u64::MAX);
        let mut a = first.writer();
        let mut b = second.writer();
        let mut expected = String::new();
        let mut first_a = true;
        let mut first_b = true;
        for i in 0..20u32 {
            let payload = format!("a{i:04}:");
            if first_a {
                expected.push_str(STDOUT_PREFIX);
                first_a = false;
            }
            expected.push_str(&payload);
            a.write_all(payload.as_bytes()).await.expect("lane accepts");
            let payload = format!("b{i:04}:");
            if first_b {
                expected.push_str(STDOUT_PREFIX);
                first_b = false;
            }
            expected.push_str(&payload);
            b.write_all(payload.as_bytes()).await.expect("lane accepts");
        }
        first.writer().flush().await.expect("drain proves order");
        assert_eq!(
            text(&sink),
            expected,
            "each output's chunks must appear in order across the shared lane"
        );
    }

    /// **F-12: the per-output in-flight cap parks instead of dropping.**
    ///
    /// 32 KiB chunks against the 256 KiB per-output cap: exactly 7 queue
    /// (19 + 7×32768 under the cap) while the sink is stalled, the 8th parks;
    /// after release every queued payload byte drains. Takes do not release —
    /// only completed writes do — so the count is exact, not racing the lane.
    #[tokio::test]
    async fn f12_per_output_in_flight_cap_parks_not_drops() {
        use tokio::io::AsyncWriteExt as _;

        let blocked_sink = Arc::new(BlockingSink::new());
        let _open = OpenOnDrop {
            sink: &blocked_sink,
        };
        let lane = crate::sink_lane::SinkLane::spawn(
            "test-fair",
            Arc::clone(&blocked_sink) as Arc<dyn GuestSink>,
        )
        .expect("a lane thread spawns");
        let output = GuestOutput::with_lane(STDOUT_PREFIX, &lane, u64::MAX);
        let mut writer = output.writer();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let chunk = vec![b'y'; 32 * 1024];
        let mut queued = 0;
        for _ in 0..64 {
            match Pin::new(&mut writer).poll_write(&mut cx, &chunk) {
                Poll::Ready(Ok(_)) => queued += 1,
                Poll::Pending => break,
                Poll::Ready(Err(error)) => panic!("the cap must park, not refuse: {error}"),
            }
        }
        assert_eq!(queued, 7, "seven 32 KiB chunks fit under the 256 KiB cap");
        blocked_sink.release();
        output.writer().flush().await.expect("drain the lane");
        let bytes = blocked_sink.buf.lock().expect("not poisoned").clone();
        let mut payload = 0usize;
        for byte in &bytes {
            if *byte == b'y' {
                payload += 1;
            }
        }
        assert_eq!(payload, 7 * 32 * 1024, "every queued payload byte drains");
    }

    /// **F-12: a sink failure taints only the outputs it dropped bytes for.**
    ///
    /// On a shared lane, output A writes through a fail-once sink (first
    /// write dies, then the sink behaves); output B, created after, must
    /// still write cleanly. A lane-wide failure slot would poison B — and
    /// every future output — with A's stale failure permanently. The flush
    /// after A's write proves the failure landed before B writes.
    #[tokio::test]
    async fn f12_sink_failure_does_not_taint_later_outputs_on_the_lane() {
        use tokio::io::AsyncWriteExt as _;

        let sink = Arc::new(FailOnceSink {
            remaining_failures: AtomicUsize::new(1),
            buf: std::sync::Mutex::new(Vec::new()),
        });
        let lane = crate::sink_lane::SinkLane::spawn(
            "test-failure-scope",
            Arc::clone(&sink) as Arc<dyn GuestSink>,
        )
        .expect("a lane thread spawns");
        let first = GuestOutput::with_lane(STDOUT_PREFIX, &lane, u64::MAX);
        first
            .writer()
            .write_all(b"lost")
            .await
            .expect("acceptance precedes the failure");
        // Let the lane process (and fail) the data before flushing: the flush
        // must observe the recorded failure rather than carry the failed bytes
        // inside its own batch, which would report through the marker alone
        // and leave the slot — the thing under test — empty.
        tokio::time::sleep(Duration::from_millis(200)).await;
        first
            .writer()
            .flush()
            .await
            .expect_err("the flush must surface the recorded write failure");
        let second = GuestOutput::with_lane(STDOUT_PREFIX, &lane, u64::MAX);
        second
            .writer()
            .write_all(b"clean")
            .await
            .expect("a later output must not inherit the earlier failure");
        second.writer().flush().await.expect("drain");
        let bytes = sink.buf.lock().expect("not poisoned").clone();
        assert!(
            String::from_utf8(bytes).expect("ascii").contains("clean"),
            "the healthy output's bytes must reach the recovered sink"
        );
    }

    /// A sink that blocks until released and fails its first two writes.
    ///
    /// The gate pins the lane thread inside one write while the test queues
    /// the next messages behind it; the two failures then land on two
    /// different drain paths (the post-loop batch write, then the `Flush`
    /// branch). `flush_shared` always succeeds so a later flush can only
    /// fail via the recorded slot — the instrument this test reads.
    struct GatedFailTwiceSink {
        gate: std::sync::Mutex<bool>,
        wake: std::sync::Condvar,
        writes: AtomicUsize,
        entered: AtomicBool,
    }

    impl GatedFailTwiceSink {
        fn new() -> Self {
            Self {
                gate: std::sync::Mutex::new(false),
                wake: std::sync::Condvar::new(),
                writes: AtomicUsize::new(0),
                entered: AtomicBool::new(false),
            }
        }

        fn release(&self) {
            *self.gate.lock().expect("not poisoned") = true;
            self.wake.notify_all();
        }
    }

    impl GuestSink for GatedFailTwiceSink {
        fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()> {
            // Signal before waiting: the test queues the next messages only
            // after this fires, so the first write provably holds the first
            // message alone and the second write provably runs in the `Flush`
            // arm — no settle-timing anywhere in this test.
            self.entered.store(true, Ordering::Relaxed);
            let mut open = self.gate.lock().expect("not poisoned");
            while !*open {
                open = self.wake.wait(open).expect("not poisoned");
            }
            drop(open);
            let _ = bytes;
            if self.writes.fetch_add(1, Ordering::Relaxed) < 2 {
                return Err(io::Error::other("flush-branch write failed"));
            }
            Ok(())
        }

        fn flush_shared(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// **F-12 committed-review: a `Flush`-branch write failure still blames
    /// its data owner.**
    ///
    /// The lane's `Flush` arm used to clear the pending failure slots without
    /// recording when its batch write failed, so the owning output's slot
    /// stayed clean and a later flush wrongly reported `Ok` over lost bytes.
    /// The gate pins the lane thread inside the first write while B's data
    /// and flush queue behind it, forcing the second (failing) write through
    /// the `Flush` arm deterministically — no settle-timing involved.
    #[tokio::test]
    async fn f12_flush_branch_write_failure_is_attributed_to_the_data_owner() {
        use tokio::io::AsyncWriteExt as _;

        let sink = Arc::new(GatedFailTwiceSink::new());
        let lane = crate::sink_lane::SinkLane::spawn(
            "test-flush-branch-attribution",
            Arc::clone(&sink) as Arc<dyn GuestSink>,
        )
        .expect("a lane thread spawns");
        let _open = GatedOpenOnDrop { sink: &sink };
        let first = GuestOutput::with_lane(STDOUT_PREFIX, &lane, u64::MAX);
        first
            .writer()
            .write_all(b"pinned")
            .await
            .expect("acceptance precedes the drain");
        // The lane thread dequeues the only queued message and parks inside
        // its gated write; everything queued after this point waits behind it.
        // An entry signal, not a settle sleep: the wait ends exactly when the
        // thread holds the first message inside its write.
        tokio::time::timeout(Duration::from_secs(5), async {
            while !sink.entered.load(Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the lane thread enters the gated write");
        let second = GuestOutput::with_lane(STDOUT_PREFIX, &lane, u64::MAX);
        second
            .writer()
            .write_all(b"doomed")
            .await
            .expect("acceptance precedes the drain");
        let (flush_result, ()) = tokio::join!(
            async {
                second
                    .writer()
                    .flush()
                    .await
                    .expect_err("the flush must surface the failed batch write")
            },
            async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                sink.release();
            },
        );
        let _ = flush_result;
        // Both failure paths ran: the gated post-loop write and the `Flush`
        // arm write. Without this pin the test could pass without ever
        // exercising the arm under test.
        assert_eq!(
            sink.writes.load(Ordering::Relaxed),
            2,
            "the first flush must follow exactly two failed writes"
        );
        second
            .writer()
            .flush()
            .await
            .expect_err("the data owner's slot must remember the Flush-arm failure");
    }

    /// Opens the gated fail-twice sink on drop, so a failed assertion cannot
    /// leave the lane thread parked on the gate — a hung test binary rather
    /// than a red test.
    struct GatedOpenOnDrop<'a> {
        sink: &'a GatedFailTwiceSink,
    }
    impl Drop for GatedOpenOnDrop<'_> {
        fn drop(&mut self) {
            self.sink.release();
        }
    }

    /// **F-07 on the lane path: a refused write leaves state untouched.**
    ///
    /// The same property as `f07_refused_write_does_not_advance_escaper_state`,
    /// but through the lane path inside a runtime: one short line, a refused
    /// flood, then the same line continued. A reserve-after-escape
    /// implementation advances the escaper before refusing, and the
    /// continuation wrongly carries a second prefix.
    #[tokio::test]
    async fn f07_refused_write_leaves_state_untouched_on_lane() {
        use tokio::io::AsyncWriteExt as _;

        let captured = captured();
        // "qqq-guest stdout | ab" is 21 escaped bytes; the flood below is refused.
        let output = GuestOutput::to_with_limit(STDOUT_PREFIX, captured.clone(), 25);
        let mut writer = output.writer();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"ab"),
            Poll::Ready(Ok(_))
        ));
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"\n\n\n\n\n"),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"cd"),
            Poll::Ready(Ok(_))
        ));
        output.writer().flush().await.expect("drain");
        assert_eq!(
            text(&captured).matches(STDOUT_PREFIX).count(),
            1,
            "the refused write must not have armed a second prefix, on the lane path too"
        );
    }

    /// A sink that blocks until the test releases it.
    ///
    /// `std` primitives rather than `tokio` ones on purpose: the writer task
    /// calls a **synchronous** trait method from a blocking-pool thread, so the
    /// gate must be waitable without an executor — awaiting a `tokio` mutex
    /// there would need the very runtime the test is trying to prove stays
    /// usable.
    struct BlockingSink {
        gate: std::sync::Mutex<bool>,
        wake: std::sync::Condvar,
        buf: std::sync::Mutex<Vec<u8>>,
    }

    impl BlockingSink {
        fn new() -> Self {
            Self {
                gate: std::sync::Mutex::new(false),
                wake: std::sync::Condvar::new(),
                buf: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn release(&self) {
            *self.gate.lock().expect("not poisoned") = true;
            self.wake.notify_all();
        }
    }

    impl GuestSink for BlockingSink {
        fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()> {
            let mut open = self.gate.lock().expect("not poisoned");
            while !*open {
                open = self.wake.wait(open).expect("not poisoned");
            }
            self.buf
                .lock()
                .expect("not poisoned")
                .extend_from_slice(bytes);
            Ok(())
        }

        fn flush_shared(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// **A blocked guest-output write does not stall an unrelated request.**
    ///
    /// The blocked bytes wait on a blocking-pool thread, never on an executor
    /// worker, so the runtime schedules the other task on its one worker. A
    /// writer that blocked the worker itself would freeze the second write
    /// until the gate opened; the 200 ms bound below is generous to scheduling
    /// jitter and tight against a freeze, which would wait the full gate
    /// instead. Both writes run as spawned tasks: the test body itself runs on
    /// the harness thread, which is not an executor worker at all, so driving
    /// the unrelated write inline would prove nothing about the workers.
    ///
    /// The gate opens on every exit path through the guard below. Without it,
    /// a failed assertion would leave the pump task parked on the gate while
    /// the test runtime shuts down — and runtime shutdown waits for the
    /// blocking pool, which waits for the gate: a hung test binary rather
    /// than a red test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_blocked_sink_does_not_stall_an_unrelated_request() {
        use tokio::io::AsyncWriteExt as _;

        let blocked_sink = Arc::new(BlockingSink::new());
        let _open = OpenOnDrop {
            sink: &blocked_sink,
        };
        let blocked = GuestOutput::to(STDOUT_PREFIX, Arc::clone(&blocked_sink));
        let free = GuestOutput::to(STDOUT_PREFIX, captured());
        let drain = blocked.clone();

        let stuck_task = tokio::spawn(async move {
            let mut stuck = blocked.writer();
            framed_write(&mut stuck).await;
        });
        let free_task = tokio::spawn(async move {
            let mut unblocked = free.writer();
            unblocked
                .write_all(b"unrelated")
                .await
                .expect("an unblocked sink writes");
        });

        // Let the stuck write reach the gate. Acceptance only enqueues, so the
        // task itself is done quickly; what must still be parked is the pump's
        // blocking call — proven by the sink staying empty, not by the task.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            blocked_sink.buf.lock().expect("not poisoned").is_empty(),
            "gated bytes must wait in the queue, not reach the sink before release"
        );

        // The unrelated request proceeds while the first is still gated: the
        // timeout runs with the gate closed, so only a genuinely unblocked
        // worker can beat it.
        tokio::time::timeout(Duration::from_millis(200), free_task)
            .await
            .expect("an unrelated request must complete while another output is blocked")
            .expect("the writer task must not panic");

        blocked_sink.release();
        tokio::time::timeout(Duration::from_secs(5), stuck_task)
            .await
            .expect("the released write must finish")
            .expect("the writer task must not panic");
        // Drain before reading: the join proves the bytes were accepted, and
        // only the flush marker proves they reached the sink.
        drain
            .writer()
            .flush()
            .await
            .expect("a released sink flushes");
        assert!(
            blocked_sink
                .buf
                .lock()
                .expect("not poisoned")
                .starts_with(STDOUT_PREFIX.as_bytes()),
            "the released write must still carry the marker"
        );
    }

    /// A sink that locks per byte, like the process streams do.
    ///
    /// `impl Write for &Stdout` locks the global handle per `write` syscall, not
    /// per `write_all` call — so one logical write is many critical sections.
    /// `Mutex<Vec<u8>>` locks once per `write_all_shared` and would serialize
    /// whole buffers by itself, which would let this test pass with the output
    /// lock removed. This sink reproduces the process-stream shape: without the
    /// output-level serialization lock, concurrent writers interleave mid-buffer.
    struct BytewiseSink {
        buf: std::sync::Mutex<Vec<u8>>,
    }

    impl GuestSink for BytewiseSink {
        fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()> {
            for byte in bytes {
                self.buf.lock().expect("not poisoned").push(*byte);
            }
            Ok(())
        }

        fn flush_shared(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Concurrent writers of one output keep each write's bytes contiguous.
    ///
    /// The serialization lock exists so two streams' escaped bytes cannot
    /// interleave mid-line and detach a marker from its line. Eight tasks each
    /// write one 64-byte payload of a distinct printable byte — printable so the
    /// escaper passes it through unchanged and the assertion reads the sink
    /// literally rather than through the escaping rule, which has its own tests.
    /// Every payload must survive as one run.
    ///
    /// The barrier is what makes this a concurrency test rather than eight
    /// sequential writes that happen to share a runtime: all tasks start their
    /// write loops together, and each writes twenty times, so without the lock
    /// the bytewise sink interleaves them with near certainty.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_writers_keep_each_write_contiguous() {
        use tokio::io::AsyncWriteExt as _;

        let sink = Arc::new(BytewiseSink {
            buf: std::sync::Mutex::new(Vec::new()),
        });
        let output = GuestOutput::to(STDOUT_PREFIX, Arc::clone(&sink));
        let start = Arc::new(tokio::sync::Barrier::new(8));
        let mut tasks = Vec::new();
        for id in 0u8..8 {
            let output = output.clone();
            let start = Arc::clone(&start);
            tasks.push(tokio::spawn(async move {
                start.wait().await;
                let mut writer = output.writer();
                for _ in 0..20 {
                    writer
                        .write_all(&[b'a' + id; 64])
                        .await
                        .expect("a memory sink writes");
                }
            }));
        }
        for task in tasks {
            task.await.expect("writer tasks must not panic");
        }
        // Drain the pump before reading the sink: sends only enqueue, so the
        // bytes may still be queued when the writers are done. The flush
        // marker stands behind them in the FIFO, and its answer proves the
        // drain rather than racing it.
        output
            .writer()
            .flush()
            .await
            .expect("a memory sink flushes");
        let bytes = sink.buf.lock().expect("not poisoned").clone();
        let text = String::from_utf8(bytes).expect("the sink is all marker and payload ascii");
        // Strip the eight markers: each writer emits exactly one, on its first
        // write, because no payload contains a newline and no writer reaches
        // the run bound. What remains is pure payload, so the run arithmetic
        // below reads writes rather than markers.
        let stripped: String = text.split(STDOUT_PREFIX).collect();
        let payload = stripped.as_bytes();
        // Eight writers, eight first writes, eight markers: a retried first
        // write must keep its marker rather than re-escaping without one.
        assert_eq!(
            text.matches(STDOUT_PREFIX).count(),
            8,
            "every writer's first write must carry the marker, including after queue parks",
        );
        assert_eq!(
            payload.len(),
            8 * 20 * 64,
            "every payload byte must reach the sink: {}",
            payload.len(),
        );
        for id in 0u8..8 {
            // Counted with an explicit loop rather than `filter().count()`: the
            // naive-bytecount lint is right that a crate does this faster, and a
            // new dependency for one test assertion is the worse trade.
            let mut found = 0usize;
            for byte in payload {
                if *byte == b'a' + id {
                    found += 1;
                }
            }
            assert!(
                found == 20 * 64,
                "payload {} must arrive whole, found {found}",
                b'a' + id,
            );
        }
        // Every maximal run is a whole number of writes: a mid-write
        // interleave would split a 64-byte write into fragments whose lengths
        // cannot all be multiples of 64.
        let mut run = 1usize;
        for pair in payload.windows(2) {
            if pair[0] == pair[1] {
                run += 1;
            } else {
                assert_eq!(run % 64, 0, "a fragmented write left a run of {run}");
                run = 1;
            }
        }
        assert_eq!(run % 64, 0, "a fragmented write left a tail run of {run}");
    }

    #[test]
    fn the_production_constructors_name_the_process_streams() {
        // Wiring: `host_wasi::context` installs `GuestOutput::stdout()` and
        // `GuestOutput::stderr()`. This asserts the two constructors are the sanitising
        // type with the expected markers, so the call site cannot be swapped for
        // `inherit_stdout` without this failing.
        assert_eq!(GuestOutput::stdout().prefix(), STDOUT_PREFIX);
        assert_eq!(GuestOutput::stderr().prefix(), STDERR_PREFIX);
        assert!(!GuestOutput::stdout().is_terminal());
        assert!(!GuestOutput::stderr().is_terminal());
    }

    #[test]
    fn a_writer_started_mid_line_still_prefixes() {
        // Each `async_stream` call returns a fresh writer. The second one must not
        // assume it begins mid-line: its first byte could be a whole forged record.
        let captured = captured();
        let output = GuestOutput::to(STDOUT_PREFIX, captured.clone());
        let _ = output.writer();
        let mut second = output.writer();
        let mut out = Vec::new();
        second.escaper.push(b"{\"status\":200}", &mut out);
        assert!(
            String::from_utf8(out)
                .expect("utf-8")
                .starts_with(STDOUT_PREFIX),
            "a fresh writer must prefix its first line"
        );
    }
}
