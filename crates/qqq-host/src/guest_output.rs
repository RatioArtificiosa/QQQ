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
//! Each output (stdout, stderr) carries its own [`MAX_OUTPUT_BYTES`] lifetime quota,
//! shared by every writer of that output so opening more streams cannot multiply it.
//! A write past the quota fails with a quota-exhausted stream error to the guest and
//! increments the breach count the host reads through [`GuestOutput::breaches`].
//! Failing rather than truncating silently is deliberate: silent truncation rewrites
//! the guest's observable behavior without telling either side, while an error is a
//! fact both the guest and the host's accounting can see.
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
//! every task queued behind that worker. So each output owns one writer task that
//! drains a FIFO queue, and every blocking sink call runs on Tokio's blocking
//! pool via `spawn_blocking` — which works on multi-thread runtimes and on the
//! current-thread runtime the serve path builds, where `block_in_place` would
//! panic. Order is structural: one task consumes one queue, so a guest's output
//! cannot reorder against itself the way per-write spawned tasks could.
//!
//! The queue is bounded, and a full queue parks the *guest*, not the executor:
//! once [`PUMP_QUEUE_MSGS`] messages wait, the next `poll_write` stores the
//! caller's waker and returns `Pending`; the writer task wakes it after its
//! next receive. Two bounds share the work: the byte quota
//! ([`MAX_OUTPUT_BYTES`]) caps how much a guest may emit in total, and the
//! message bound caps how far ahead of a slow sink the executor may run.
//!
//! Outside a Tokio runtime (unit tests driving `poll_write` directly) there is
//! no executor to protect and no task to spawn, so the write runs inline on the
//! calling thread. The two paths never mix in production: construction happens
//! outside the runtime, and the first poll inside one starts the pump.
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
use std::task::{Context, Poll, Waker};

use tokio::io::AsyncWrite;
use tokio::sync::{mpsc, oneshot};
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

/// Maximum guest-written bytes accepted by one stdout or stderr destination.
///
/// `MAX_ESCAPED_RUN` bounds one physical line, not the lifetime of a process.
/// Without a total budget a guest can still fill a host log indefinitely by
/// emitting many short lines. The budget is shared by all writers obtained from
/// one `GuestOutput`, so opening multiple WASI streams cannot multiply it.
pub const MAX_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;

/// How many messages wait in one output's pump queue before writers park.
///
/// Sixty-four small writes, or fewer large ones once the byte quota bites
/// first: the quota bounds *how much* may wait, this bounds *how many turns*
/// the executor may run ahead of a slow sink. A full queue returns `Pending`
/// with the caller's waker stored, and the writer task wakes it after its next
/// receive — backpressure with no lost wake-up, because a recheck after storing
/// closes the race where space frees first.
///
/// ```
/// use qqq_host::guest_output::PUMP_QUEUE_MSGS;
///
/// assert_eq!(PUMP_QUEUE_MSGS, 64);
/// ```
pub const PUMP_QUEUE_MSGS: usize = 64;

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
            limit,
            breaches: AtomicU64::new(0),
            parent: std::sync::Mutex::new(None),
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
    fn refused(&self) -> Refusal {
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
    state: std::sync::Mutex<std::collections::HashMap<String, TenantEntry>>,
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
            }),
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
    /// # Panics
    ///
    /// When the registry lock is poisoned — which means another thread panicked
    /// while acquiring, and proceeding with a possibly half-inserted entry
    /// would account one tenant's bytes to another.
    #[must_use]
    pub fn acquire(&self, tenant: &str) -> TenantOutputGuard {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("tenant output budgets are not poisoned");
        let entry = state
            .entry(tenant.to_owned())
            .or_insert_with(|| TenantEntry {
                budget: Arc::new(OutputBudget::new(self.inner.limit)),
                live: 0,
            });
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
            .lock()
            .ok()
            .and_then(|state| state.get(tenant).map(|entry| entry.live))
            .unwrap_or(0)
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
        let mut state = self
            .inner
            .state
            .lock()
            .expect("tenant output budgets are not poisoned");
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
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("tenant output budgets are not poisoned");
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
        for &byte in bytes {
            if self.at_line_start {
                out.extend_from_slice(self.prefix.as_bytes());
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
                b'\n' => self.break_line(out),
                // Everything else in C0, plus DEL, is escaped. `\r` because it is a line
                // terminator to some readers; `\x1b` because an escape sequence can
                // rewrite what a terminal shows for the host's own records; the rest
                // because a total rule is auditable and a list of dangerous bytes is a
                // claim that goes stale.
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                // So a guest cannot emit a literal `\n` and have a reader mistake it for
                // a break the host inserted.
                b'\\' => out.extend_from_slice(b"\\\\"),
                0x00..=0x1f | 0x7f => {
                    out.extend_from_slice(format!("\\x{byte:02x}").as_bytes());
                }
                _ => out.push(byte),
            }
            self.since_break += 1;
            if self.since_break >= MAX_ESCAPED_RUN {
                self.break_line(out);
            }
        }
        bytes.len()
    }

    /// End the current physical line and require the prefix on the next one.
    ///
    /// Also called when the run bound is reached, which is why the prefix is re-armed
    /// here rather than only on `\n`: the two are the same event to a line reader.
    fn break_line(&mut self, out: &mut Vec<u8>) {
        out.push(b'\n');
        self.at_line_start = true;
        self.since_break = 0;
    }
}

/// Work for one output's writer task, in guest order.
enum PumpMsg {
    /// Escaped bytes to append to the sink.
    Bytes(Vec<u8>),
    /// Flush the sink, then report completion through the channel.
    Flush(oneshot::Sender<io::Result<()>>),
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
    /// How many bytes the refused write asked for.
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
    sink: Arc<dyn GuestSink>,
    budget: Arc<OutputBudget>,
    /// The writer task's inbox, once one exists.
    ///
    /// `None` until the first poll inside a runtime spawns the pump; unit tests
    /// driving `poll_write` outside any runtime never create one and write
    /// inline instead.
    pump: std::sync::Mutex<Option<mpsc::Sender<PumpMsg>>>,
    /// The first asynchronous write failure, surfaced on later calls.
    ///
    /// A sink failure happens on the writer task, after `poll_write` already
    /// reported success for those bytes. Swallowing it would make a dead log
    /// look healthy; recording the first one and failing subsequent calls keeps
    /// the failure visible without inventing a history the caller cannot use.
    ///
    /// Shared by `Arc` rather than held inline so the writer task can report
    /// without holding the whole `Shared`: the task must not own a sender or
    /// a `Shared`, or the inbox would never drain shut and the task would
    /// never end.
    failure: Arc<std::sync::Mutex<Option<String>>>,
    /// Writers parked on a full queue, woken after the next receive.
    ///
    /// Every parked writer leaves its waker — plural on purpose. Storing only
    /// the latest would drop the others on the floor: with several writers
    /// parked, one receive would wake one writer and strand the rest with no
    /// further receive guaranteed to wake them. Spurious wakes are harmless;
    /// every woken writer rechecks the queue before proceeding.
    queue_wakers: Arc<std::sync::Mutex<Vec<Waker>>>,
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
    #[must_use]
    pub fn stdout() -> Self {
        Self::to(STDOUT_PREFIX, io::stdout())
    }

    /// Guest standard error, written to the host process's stderr.
    #[must_use]
    pub fn stderr() -> Self {
        Self::to(STDERR_PREFIX, io::stderr())
    }

    /// Guest output with an explicit prefix and destination.
    ///
    /// The destination is an `Arc` so that repeated calls to `async_stream` — which
    /// wasmtime-wasi makes freely, one per acquired stream — share one sink rather than
    /// racing on several.
    #[must_use]
    pub fn to(prefix: &'static str, sink: impl GuestSink) -> Self {
        Self::to_with_limit(prefix, sink, MAX_OUTPUT_BYTES)
    }

    /// Construct guest output with an explicit lifetime byte quota.
    #[must_use]
    pub fn to_with_limit(prefix: &'static str, sink: impl GuestSink, limit: u64) -> Self {
        Self {
            prefix,
            shared: Arc::new(Shared {
                stream: prefix,
                sink: Arc::new(sink),
                budget: Arc::new(OutputBudget::new(limit)),
                pump: std::sync::Mutex::new(None),
                failure: Arc::new(std::sync::Mutex::new(None)),
                queue_wakers: Arc::new(std::sync::Mutex::new(Vec::new())),
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
    /// A flush marker already sent to the pump and not yet answered.
    flush_rx: Option<oneshot::Receiver<io::Result<()>>>,
    /// An escaped write accepted against the quota but not yet queued.
    ///
    /// A full queue parks the writer with the bytes held here rather than
    /// re-escaping on retry: re-running the stateful escaper on the same input
    /// would advance it twice for one write, dropping the line marker and
    /// drifting the run bound. The quota stays reserved while parked, so no
    /// refund path exists to go wrong.
    pending: Option<(usize, Vec<u8>)>,
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
        if this.pending.is_none() {
            if let Err(refusal) = this.shared.budget.reserve(buf.len()) {
                record_truncation(&this.shared, buf.len(), refusal);
                return Poll::Ready(Err(io::Error::other("guest output quota exhausted")));
            }
            let mut escaped = Vec::with_capacity(buf.len() + 16);
            let consumed = this.escaper.push(buf, &mut escaped);
            this.pending = Some((consumed, escaped));
        }
        let (consumed, escaped) = this.pending.take().expect("just stored");
        match ensure_pump(&this.shared) {
            // Outside a runtime: write inline, exactly as before.
            None => {
                let result = direct_write(&this.shared, &escaped).map(|()| consumed);
                Poll::Ready(result)
            }
            Some(tx) => match try_send_or_park(&tx, &this.shared, cx, PumpMsg::Bytes(escaped)) {
                Ok(None) => Poll::Ready(Ok(consumed)),
                Ok(Some(held)) => {
                    // The pump owns nothing yet; hold the bytes for the retry.
                    // Quota and escaper state were settled above, exactly once.
                    let PumpMsg::Bytes(back) = held else {
                        // Only `Bytes` is ever sent from here; anything else
                        // would be a second message type smuggled past review.
                        return Poll::Ready(Err(io::Error::other(
                            "guest-output queue returned a flush marker",
                        )));
                    };
                    this.pending = Some((consumed, back));
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(error)),
            },
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
        match ensure_pump(&this.shared) {
            None => Poll::Ready(direct_flush(&this.shared)),
            Some(tx) => {
                let (done, rx) = oneshot::channel();
                // Register interest in the answer in the same step that sends
                // the marker, so no wake-up between the send and the first poll
                // can be lost.
                let mut rx = rx;
                match try_send_or_park(&tx, &this.shared, cx, PumpMsg::Flush(done)) {
                    Err(error) => Poll::Ready(Err(error)),
                    // The marker was not queued; the next poll sends a fresh
                    // one, and the dropped sender answers nothing.
                    Ok(Some(_)) => Poll::Pending,
                    Ok(None) => match Pin::new(&mut rx).poll(cx) {
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
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Shutdown is a flush: every byte accepted before it must reach the sink
        // before the stream is closed. The marker stands behind them in the FIFO,
        // so its answer proves the drain.
        self.poll_flush(cx)
    }
}

/// Try one send; hand the message back when the queue is full.
///
/// A full queue stores the caller's waker alongside the other parked writers;
/// the writer task wakes them all after its next receive, when a slot has
/// definitely freed. The recheck after storing closes the race where space
/// frees first. The message comes back so the caller holds it for the retry
/// instead of rebuilding stateful work. A poisoned waker slot fails rather
/// than parking forever unwoken.
fn try_send_or_park(
    tx: &mpsc::Sender<PumpMsg>,
    shared: &Shared,
    cx: &mut Context<'_>,
    msg: PumpMsg,
) -> Result<Option<PumpMsg>, io::Error> {
    use mpsc::error::TrySendError;
    match tx.try_send(msg) {
        Ok(()) => Ok(None),
        Err(TrySendError::Closed(_)) => Err(pump_gone()),
        Err(TrySendError::Full(msg)) => {
            {
                let mut parked = shared
                    .queue_wakers
                    .lock()
                    .map_err(|_| io::Error::other("the guest-output queue wakers are poisoned"))?;
                parked.push(cx.waker().clone());
            }
            match tx.try_send(msg) {
                Ok(()) => Ok(None),
                Err(TrySendError::Closed(_)) => Err(pump_gone()),
                // Every parked waker is woken after the task's next receive,
                // so parking here always resolves.
                Err(TrySendError::Full(msg)) => Ok(Some(msg)),
            }
        }
    }
}

/// The pump's inbox if one exists, spawning the writer task on first use.
///
/// Returns `None` outside a Tokio runtime, where there is no executor to spawn
/// onto and no executor thread to protect — the caller writes inline instead.
fn ensure_pump(shared: &Arc<Shared>) -> Option<mpsc::Sender<PumpMsg>> {
    let mut guard = shared.pump.lock().ok()?;
    if let Some(tx) = guard.as_ref() {
        return Some(tx.clone());
    }
    if tokio::runtime::Handle::try_current().is_err() {
        return None;
    }
    let (tx, rx) = mpsc::channel(PUMP_QUEUE_MSGS);
    // Only what the task needs travels with it: the sink, the failure slot,
    // and the parked-writer waker. Handing it the whole `Shared` would also
    // hand it the inbox sender held inside `Shared`, and a sender that never
    // drops keeps the task — and everything it holds — alive forever.
    tokio::spawn(pump_loop(
        rx,
        Arc::clone(&shared.sink),
        Arc::clone(&shared.failure),
        Arc::clone(&shared.queue_wakers),
    ));
    *guard = Some(tx.clone());
    Some(tx)
}

/// The one task that touches an output's sink.
///
/// FIFO consumption is the ordering guarantee: bytes reach the sink in the order
/// `poll_write` accepted them, which per-write spawned tasks could not promise.
/// Every blocking call runs on the blocking pool, so neither the multi-thread
/// nor the current-thread executor ever stalls on a slow sink. The task ends
/// when the last sender is dropped — the output and its writers — after
/// draining whatever is still queued.
async fn pump_loop(
    mut rx: mpsc::Receiver<PumpMsg>,
    sink: Arc<dyn GuestSink>,
    failure: Arc<std::sync::Mutex<Option<String>>>,
    queue_wakers: Arc<std::sync::Mutex<Vec<Waker>>>,
) {
    while let Some(msg) = rx.recv().await {
        // A slot just freed: wake every parked writer. Each rechecks the
        // queue on waking, so wakes that arrive too late are harmless and no
        // writer waits on a waker overwritten by another.
        if let Ok(mut parked) = queue_wakers.lock() {
            for waker in parked.drain(..) {
                waker.wake();
            }
        }
        match msg {
            PumpMsg::Bytes(bytes) => {
                let sink = Arc::clone(&sink);
                let outcome =
                    tokio::task::spawn_blocking(move || sink.write_all_shared(&bytes)).await;
                match outcome {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => record_failure(&failure, error.to_string()),
                    Err(error) => {
                        let message = format!("guest-output writer task failed: {error}");
                        record_failure(&failure, message);
                    }
                }
            }
            PumpMsg::Flush(done) => {
                let sink = Arc::clone(&sink);
                let outcome = tokio::task::spawn_blocking(move || sink.flush_shared()).await;
                let result = match outcome {
                    Ok(result) => result,
                    Err(error) => Err(io::Error::other(format!(
                        "guest-output writer task failed: {error}"
                    ))),
                };
                let _ = done.send(result);
            }
        }
    }
}

/// Remember the first asynchronous failure; later calls surface it.
fn record_failure(failure: &Arc<std::sync::Mutex<Option<String>>>, message: String) {
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
        let output = GuestOutput::to_with_limit(STDOUT_PREFIX, captured, 5);
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
        let output = GuestOutput::to_with_limit(STDOUT_PREFIX, captured, 5);
        assert_eq!(output.breaches(), 0, "a fresh output has no breaches");
        let mut writer = output.writer();
        let mut cx = Context::from_waker(std::task::Waker::noop());

        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"123"),
            Poll::Ready(Ok(3))
        ));
        assert_eq!(output.bytes_written(), 3);
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"456"),
            Poll::Ready(Err(_))
        ));
        assert_eq!(output.breaches(), 1, "the refused write must be counted");
        assert_eq!(
            output.bytes_written(),
            3,
            "refused bytes must not consume the quota"
        );
        assert_eq!(
            output.last_truncation(),
            Some(TruncationEvent {
                stream: STDOUT_PREFIX,
                requested_bytes: 3,
                limit: 5,
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

    /// **Dropping the output ends the pump task.**
    ///
    /// The task must hold no sender and no `Shared`: either one keeps the
    /// inbox open, `recv` never returns `None`, and every request leaks a
    /// task plus its sink and budget on a long-running server. The `Weak`
    /// observes the task's own sink clone, so its death proves the task ended
    /// rather than merely going quiet.
    #[tokio::test]
    async fn dropping_the_output_ends_the_pump_task() {
        use tokio::io::AsyncWriteExt as _;

        let sink = Arc::new(Mutex::new(Vec::new()));
        let weak = Arc::downgrade(&sink);
        let output = GuestOutput::to(STDOUT_PREFIX, Arc::clone(&sink));
        // Start the pump: without a poll inside the runtime no task exists,
        // and the assertion below would pass on an output that never pumps.
        output.writer().write_all(b"hello").await.expect("write");
        drop(sink);
        drop(output);
        tokio::time::timeout(Duration::from_secs(5), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the pump task must end after the output is dropped");
    }

    /// **A full pump queue parks the writer until space frees.**
    ///
    /// The gate holds the pump on its first message, so nothing drains while
    /// the test fills all [`PUMP_QUEUE_MSGS`] slots with one-byte writes. The
    /// next write must come back `Pending` rather than blocking the worker or
    /// dropping the bytes; opening the gate must let the parked write finish.
    /// The quota (8 MiB here) is deliberately far above the few hundred queued
    /// bytes, so only the queue bound is under test — a tripped quota would
    /// fail the write for a different, already-tested reason.
    #[tokio::test]
    async fn a_full_pump_queue_parks_the_writer_until_space_frees() {
        let blocked_sink = Arc::new(BlockingSink::new());
        let _open = OpenOnDrop {
            sink: &blocked_sink,
        };
        let output = GuestOutput::to(STDOUT_PREFIX, Arc::clone(&blocked_sink));
        let mut writer = output.writer();
        let mut cx = Context::from_waker(std::task::Waker::noop());

        for _ in 0..PUMP_QUEUE_MSGS {
            assert!(matches!(
                Pin::new(&mut writer).poll_write(&mut cx, b"x"),
                Poll::Ready(Ok(1))
            ));
        }
        assert!(
            matches!(
                Pin::new(&mut writer).poll_write(&mut cx, b"x"),
                Poll::Pending
            ),
            "a full queue must park the writer rather than block or drop"
        );

        blocked_sink.release();
        let mut parked = false;
        for _ in 0..100 {
            match Pin::new(&mut writer).poll_write(&mut cx, b"x") {
                Poll::Ready(Ok(_)) => break,
                Poll::Pending => {
                    parked = true;
                    tokio::task::yield_now().await;
                }
                Poll::Ready(Err(error)) => panic!("the write must succeed after release: {error}"),
            }
        }
        assert!(
            parked,
            "the writer must have parked at least once before the drain"
        );
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
        let budgets = TenantOutputBudgets::new(10);
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
            "twelve bytes against a ten-byte tenant ceiling must refuse"
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
                requested_bytes: 6,
                limit: 10,
                total_breaches: 1,
            }),
            "the event must name the tenant ceiling that tripped"
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
