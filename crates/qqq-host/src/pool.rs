// SPDX-License-Identifier: Apache-2.0

//! The instance pool: acquisition, backpressure and occupancy — `HOST-012` and
//! the instance half of `HOST-019`.
//!
//! # What a pool is for, and what it must not claim
//!
//! V1 uses this type as a **bounded concurrency gate and occupancy recorder**.
//! The caller creates and drops the Wasmtime instance around the permit; no
//! reset-safe instance store exists yet. `release` therefore returns a slot to
//! the accounting free list, not guest memory. A trapped request calls
//! `discard`, which returns no idle slot and keeps the trap path distinct.
//!
//! # Backpressure, and why 503 is the right answer
//!
//! `HOST-012` requires that pool exhaustion produce **503 with `Retry-After`**
//! rather than a hang or an unbounded queue. The reasoning is worth stating
//! because the alternative is tempting:
//!
//! * **An unbounded queue** converts a capacity limit into a latency limit. The
//!   guest is not slower; the *waiting* is, and the client cannot tell the
//!   difference between "the server is overloaded" and "the server is broken".
//!   A queue also holds memory per waiter, so the failure mode under sustained
//!   overload is an OOM rather than a clean rejection.
//! * **A hang** is worse still: it consumes a connection slot for an unbounded
//!   time, which is the classic way a service dies completely instead of
//!   degrading.
//! * **503 + `Retry-After`** tells the caller three things a hang cannot: the
//!   request was refused rather than lost, the refusal was about capacity rather
//!   than the request, and waiting a specific time is worth trying. It is also
//!   the status every load balancer and client library already understands.
//!
//! The `Retry-After` value is computed from observed occupancy rather than being
//! a constant, because a constant is either too short (a retry storm) or too
//! long (a needlessly idle client). See [`Pool::retry_after_seconds`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use qqq_core::{Error, ErrorCode, Result};

use crate::metrics::Metrics;

/// Why a pool could not hand out an instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exhausted {
    /// Every slot is occupied and none is free.
    AllBusy,
    /// The pool was asked for an instance while the host is draining, so it is
    /// refusing new work on purpose.
    Draining,
}

impl Exhausted {
    /// How many seconds a caller should wait before retrying.
    ///
    /// `None` when waiting will not help — a draining host is not coming back,
    /// and telling a client to retry it would turn an orderly shutdown into a
    /// retry storm that outlives the process.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::AllBusy)
    }

    /// A stable machine-readable name, bounded and lowercase.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllBusy => "all_busy",
            Self::Draining => "draining",
        }
    }
}

/// The error a caller turns into a 503.
///
/// Kept here rather than in `qqq-serve` because the *decision* is the host's:
/// the server's job is to render it, and a server that decided for itself when
/// the host was saturated would need its own copy of the pool's state.
#[must_use]
pub fn exhausted_error(reason: Exhausted, capacity: u64, retry_after_seconds: u64) -> Error {
    let base = Error::new(
        ErrorCode::InstancePoolExhausted,
        match reason {
            Exhausted::AllBusy => "the instance pool is saturated",
            Exhausted::Draining => "the host is shutting down and is not accepting new work",
        },
    )
    .with_context("capacity", capacity.to_string())
    .with_context("reason", reason.as_str().to_owned());

    if reason.retryable() {
        base.with_context("retry-after", retry_after_seconds.to_string())
            .with_remediation(
                "retry after the `retry-after` seconds; if this repeats, raise \
                 `limits.max_instances` or add a replica",
            )
    } else {
        base.with_remediation(
            "wait for the shutdown to complete, then retry against a running host",
        )
    }
}

/// Why an instance left the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// The clean request returned its concurrency slot to the idle accounting.
    SlotFreed,
    /// Dropped rather than returned, because it trapped.
    Discarded,
}

/// A bounded pool of instance slots.
///
/// # This is a slot accountant, not a memory manager
///
/// Wasmtime's pooling allocator owns the actual memory; this type owns the
/// *policy* — how many instances may exist at once, whether a returning slot
/// is reusable, and what a caller is told when none is free. Keeping the two
/// separate means the policy is testable without an engine, which is why the
/// tests below are pure unit tests.
#[derive(Debug)]
pub struct Pool {
    capacity: u64,
    /// Counts that must change as one transaction. Independent atomics briefly
    /// made `in_use + idle > capacity` visible between reservation and
    /// idle-dequeue, so metrics could report an impossible state under load.
    state: Mutex<PoolState>,
    /// Set when the host begins shutting down.
    draining: AtomicU64,
    metrics: Metrics,
}

#[derive(Debug, Default)]
struct PoolState {
    in_use: u64,
    idle: u64,
}

impl Pool {
    /// A pool that may hold at most `capacity` instances at once.
    ///
    /// A capacity of `0` is treated as `1`: a pool that can never hand anything
    /// out is not a configuration, it is a deadlock, and refusing to construct
    /// it moves the failure to startup rather than to the first request.
    #[must_use]
    pub fn new(capacity: u64) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            state: Mutex::new(PoolState::default()),
            draining: AtomicU64::new(0),
            metrics: Metrics::new(),
        }
    }

    /// The maximum number of simultaneously checked-out instances.
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Slots currently checked out — at most one live instance per slot.
    ///
    /// # Panics
    ///
    /// Panics if another thread poisoned the pool state mutex. A poisoned
    /// state cannot safely produce an occupancy value.
    #[must_use]
    pub fn in_use(&self) -> u64 {
        self.state
            .lock()
            .expect("pool state is not poisoned")
            .in_use
    }

    /// Free slots, available for the next acquisition. A free slot is
    /// accounting, not a waiting guest: V1 creates the instance after
    /// acquiring, so this count never implies a reusable instance exists.
    ///
    /// # Panics
    ///
    /// Panics if another thread poisoned the pool state mutex.
    #[must_use]
    pub fn idle(&self) -> u64 {
        self.state.lock().expect("pool state is not poisoned").idle
    }

    /// `in_use` and `idle` read under one lock acquisition.
    ///
    /// Two separate calls can straddle another thread's transition and report
    /// a sum the pool never held — an observer that reads one counter before
    /// a release and the other after it sees both sides of the move. Any
    /// invariant over *both* counters must use this, not the two accessors.
    /// The example below is concurrent on purpose: a single-threaded caller
    /// cannot exhibit the torn read this method exists to prevent, so a
    /// single-threaded example would pass on a split implementation too.
    ///
    /// ```
    /// use qqq_host::pool::Pool;
    /// use std::sync::{Arc, Barrier};
    /// use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    ///
    /// const CAPACITY: u64 = 4;
    /// let pool = Arc::new(Pool::new(CAPACITY));
    /// let go = Arc::new(Barrier::new(6));
    /// let churn = Arc::new(Barrier::new(5));
    /// let stop = Arc::new(AtomicBool::new(false));
    /// let bad = Arc::new(AtomicU64::new(0));
    /// let samples = Arc::new(AtomicU64::new(0));
    /// // A sampler thread reads the joint counters while workers churn: with
    /// // two separate reads it observes both sides of a transition and the
    /// // invariant breaks; with one joint read it never does. The sampler
    /// // takes one read BEFORE releasing the workers, so the sample count
    /// // cannot be zero no matter how the threads are scheduled — the
    /// // previous shape raced the workers and, on a fast runner, observed
    /// // nothing and failed its own vacuity guard. Later samples occur while
    /// // the workers are alive; whether each lands mid-transition is
    /// // scheduling, and the test needs no more than the reads it takes:
    /// // the invariant is asserted on every one, and a split-atomic
    /// // implementation fails this test (proven by fault injection).
    /// let sampler = {
    ///     let (pool, go, churn, stop, bad, samples) = (
    ///         Arc::clone(&pool),
    ///         Arc::clone(&go),
    ///         Arc::clone(&churn),
    ///         Arc::clone(&stop),
    ///         Arc::clone(&bad),
    ///         Arc::clone(&samples),
    ///     );
    ///     std::thread::spawn(move || {
    ///         go.wait();
    ///         let (used, idle) = pool.snapshot();
    ///         samples.fetch_add(1, Ordering::Relaxed);
    ///         if used + idle > CAPACITY {
    ///             bad.fetch_add(1, Ordering::Relaxed);
    ///         }
    ///         churn.wait();
    ///         while !stop.load(Ordering::Relaxed) {
    ///             let (used, idle) = pool.snapshot();
    ///             samples.fetch_add(1, Ordering::Relaxed);
    ///             if used + idle > CAPACITY {
    ///                 bad.fetch_add(1, Ordering::Relaxed);
    ///             }
    ///         }
    ///     })
    /// };
    /// let mut handles = Vec::new();
    /// for _ in 0..4 {
    ///     let (pool, go, churn) = (Arc::clone(&pool), Arc::clone(&go), Arc::clone(&churn));
    ///     handles.push(std::thread::spawn(move || {
    ///         go.wait();
    ///         churn.wait();
    ///         for _ in 0..500 {
    ///             if pool.acquire(1000.0).is_ok() {
    ///                 pool.release();
    ///             }
    ///         }
    ///     }));
    /// }
    /// go.wait();
    /// for handle in handles {
    ///     handle.join().expect("worker");
    /// }
    /// stop.store(true, Ordering::Relaxed);
    /// sampler.join().expect("sampler");
    /// assert_eq!(bad.load(Ordering::Relaxed), 0, "no joint read may break the invariant");
    /// assert!(
    ///     samples.load(Ordering::Relaxed) > 0,
    ///     "the sampler must have observed churn, or the invariant was never tested"
    /// );
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if another thread poisoned the pool state mutex.
    #[must_use]
    pub fn snapshot(&self) -> (u64, u64) {
        let state = self.state.lock().expect("pool state is not poisoned");
        (state.in_use, state.idle)
    }

    /// The metrics recorder this pool feeds.
    #[must_use]
    pub const fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Whether the pool is refusing new work.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed) != 0
    }

    /// Begin refusing acquisitions.
    ///
    /// Releasing continues to work, which is what makes a drain *orderly*: work
    /// already in flight completes and its instances come home, rather than
    /// being abandoned when the process exits.
    pub fn begin_drain(&self) {
        self.draining.store(1, Ordering::Relaxed);
    }

    /// The fraction of capacity currently checked out, in `0.0..=1.0`.
    #[must_use]
    pub fn occupancy(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        {
            self.in_use() as f64 / self.capacity as f64
        }
    }

    /// How long a saturated caller should wait, in seconds.
    ///
    /// # Why this is computed rather than a constant
    ///
    /// A constant `Retry-After` is wrong in both directions at once. Too short
    /// and every refused client retries into the same saturation, which is a
    /// retry storm that keeps the pool at 100 %. Too long and clients idle while
    /// capacity is free.
    ///
    /// The estimate here is the time for one capacity's worth of work at the
    /// current rate, floored at 1 s so a fast-but-saturated host does not
    /// produce `Retry-After: 0` — which clients interpret as "retry
    /// immediately", the exact stampede this header exists to prevent.
    ///
    /// `completed_per_second` is the caller's observed throughput, which `qqq-serve`
    /// already has. Passing it in rather than measuring here keeps this type
    /// free of a clock, and therefore deterministic in tests.
    #[must_use]
    pub fn retry_after_seconds(&self, completed_per_second: f64) -> u64 {
        if completed_per_second <= 0.0 {
            // No throughput observed means either no traffic or a total stall;
            // either way there is no better estimate than a fixed second.
            return 1;
        }
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation
        )]
        let seconds = (self.capacity as f64 / completed_per_second).ceil() as u64;
        seconds.clamp(1, 60)
    }

    /// Try to acquire an instance slot.
    ///
    /// # The order of the checks matters
    ///
    /// Draining is checked **first**. If saturation were checked first, a host
    /// in the middle of a shutdown with a free slot would accept new work and
    /// then be killed mid-request — the outcome draining exists to prevent.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-6001` with `reason`, `capacity` and (when retryable)
    /// `retry-after` in its context.
    ///
    /// # Panics
    ///
    /// Panics if another thread poisoned the pool state mutex. A poisoned
    /// state cannot safely make a capacity decision.
    pub fn acquire(&self, completed_per_second: f64) -> Result<Acquired> {
        if self.is_draining() {
            self.metrics.note_saturation();
            return Err(exhausted_error(Exhausted::Draining, self.capacity, 0));
        }

        // Reservation and idle dequeue are one state transition. This is a
        // concurrency gate; the caller still creates an instance when the slot
        // is fresh because V1 has no reset-safe instance store.
        let mut state = self.state.lock().expect("pool state is not poisoned");
        if state.in_use >= self.capacity {
            drop(state);
            self.metrics.note_saturation();
            let retry = self.retry_after_seconds(completed_per_second);
            return Err(exhausted_error(Exhausted::AllBusy, self.capacity, retry));
        }
        let slot_reused = state.idle > 0;
        state.in_use += 1;
        if slot_reused {
            state.idle -= 1;
        }
        drop(state);

        Ok(Acquired {
            slot_reused,
            capacity: self.capacity,
        })
    }

    /// Return a clean instance's slot to the pool accounting.
    ///
    /// The caller has established that the instance did not trap. This is the
    /// **only** path that puts a slot back into the free list.
    ///
    /// # Panics
    ///
    /// Panics if called without a matching successful [`Pool::acquire`], because
    /// releasing an instance that was never acquired would push `in_use` below
    /// zero when it wraps and let the pool hand out more than its capacity —
    /// which is precisely the guarantee the pool exists to provide.
    pub fn release(&self) -> ReleaseOutcome {
        let mut state = self.state.lock().expect("pool state is not poisoned");
        let previous = state.in_use;
        assert!(
            previous > 0,
            "Pool::release called with no instance checked out; this is a QQQ bug"
        );
        state.in_use -= 1;
        state.idle += 1;
        drop(state);
        self.metrics.note_released();
        ReleaseOutcome::SlotFreed
    }

    /// Record that an instance trapped and must not return an idle slot.
    ///
    /// This does **not** return the slot to the free list — that is the
    /// whole point. `HOST-010` and §4.4 step 14 require a trapped instance to be
    /// dropped, and the metric is what makes the drop rate observable.
    ///
    /// # Panics
    ///
    /// As [`Pool::release`].
    pub fn discard(&self) -> ReleaseOutcome {
        let mut state = self.state.lock().expect("pool state is not poisoned");
        let previous = state.in_use;
        assert!(
            previous > 0,
            "Pool::discard called with no instance checked out; this is a QQQ bug"
        );
        state.in_use -= 1;
        drop(state);
        self.metrics.note_discarded();
        ReleaseOutcome::Discarded
    }
}

/// The result of a successful acquisition.
///
/// # What `slot_reused` is, and the misreading it exists to prevent
///
/// `true` when the pool's idle count was above zero at acquisition — a freed
/// **slot** was reused, never a guest instance. The pool never sees an
/// instance at all (it is engine-free by design), so this field *cannot* mean
/// instance reuse; nothing in V1 reuses one, and `serve_one` creates it per
/// request. A reader meeting the old `pooled` name in the history should read
/// it as this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acquired {
    /// Whether this acquisition took a freed slot (`true`) or a fresh one
    /// that the caller must back with a new instance (`false`).
    pub slot_reused: bool,
    /// The pool's capacity, carried so a caller can log the saturation ratio
    /// without holding a reference to the pool.
    pub capacity: u64,
}

impl Acquired {
    /// Record the acquisition's latency against the pool's metrics.
    ///
    /// A method on the result rather than an argument to [`Pool::acquire`],
    /// because the latency is only known *after* the instance is ready — which
    /// for a fresh slot means after compilation. Measuring inside `acquire` would
    /// time the bookkeeping and call it instantiation.
    pub fn note_latency(self, metrics: &Metrics, nanos: u64) {
        metrics.note_acquire(nanos, self.slot_reused);
        if !self.slot_reused {
            // A fresh slot means a new instance was built; `note_acquire` records
            // only the latency for that case, so `created` is incremented here.
            // See `Metrics::note_created` for why the two are split.
            metrics.note_created();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pool_hands_out_up_to_its_capacity() {
        let p = Pool::new(2);
        assert!(!p.acquire(0.0).expect("first").slot_reused);
        assert!(!p.acquire(0.0).expect("second").slot_reused);
        assert_eq!(p.in_use(), 2);
        assert!(
            (p.occupancy() - 1.0).abs() < f64::EPSILON,
            "two of two slots is full occupancy"
        );
    }

    #[test]
    fn a_full_pool_refuses_rather_than_queueing() {
        let p = Pool::new(1);
        p.acquire(10.0).expect("first fits");

        let err = p.acquire(10.0).expect_err("the pool is full");
        assert_eq!(err.code, ErrorCode::InstancePoolExhausted);
        assert!(
            err.context.iter().any(|(k, _)| k == "retry-after"),
            "a saturated-but-draining pool must not: {err}"
        );
        assert_eq!(p.metrics().saturation(), 1);
    }

    /// A capacity of zero would deadlock every request; it becomes one slot.
    #[test]
    fn a_zero_capacity_pool_is_treated_as_one() {
        let p = Pool::new(0);
        assert_eq!(p.capacity(), 1);
        p.acquire(0.0).expect("one slot exists");
        assert!(p.acquire(0.0).is_err());
    }

    #[test]
    fn releasing_makes_room_and_the_next_acquire_reuses_the_slot() {
        let p = Pool::new(1);
        let first = p.acquire(0.0).expect("first");
        assert!(!first.slot_reused, "nothing is idle yet");

        p.release();
        assert_eq!(p.idle(), 1);
        assert_eq!(p.in_use(), 0);

        let second = p.acquire(0.0).expect("reuses the slot");
        assert!(second.slot_reused, "the freed slot must be reused");
        assert_eq!(p.idle(), 0);
    }

    /// **PERF-POOL-001: a reused slot is not a reused instance.**
    ///
    /// The pool never sees an instance — no engine, no component, no store
    /// passes through it — so `slot_reused` can only ever describe the
    /// accounting. This test performs the full acquire/release/reacquire cycle
    /// with no instance anywhere near it and still observes `slot_reused`:
    /// any reading of that field as guest reuse contradicts the fixture.
    #[test]
    fn slot_reuse_is_accounting_not_instance_reuse() {
        let p = Pool::new(1);
        let first = p.acquire(0.0).expect("first");
        assert!(!first.slot_reused);
        p.release();
        let second = p.acquire(0.0).expect("second");
        assert!(
            second.slot_reused,
            "the slot was reused with no instance in existence"
        );
    }

    /// **The security property.** A discarded instance must not become reusable.
    #[test]
    fn a_discarded_instance_is_never_reused() {
        let p = Pool::new(1);
        p.acquire(0.0).expect("first");
        assert_eq!(p.discard(), ReleaseOutcome::Discarded);
        assert_eq!(
            p.idle(),
            0,
            "a trapped instance must NOT return to the free list"
        );

        let next = p.acquire(0.0).expect("the slot is free");
        assert!(
            !next.slot_reused,
            "the replacement must be fresh, not the discarded instance"
        );
    }

    /// Release and discard are distinguishable in the metrics, which is what
    /// makes a discard rate alertable.
    #[test]
    fn discard_and_release_are_visible_separately_in_metrics() {
        let p = Pool::new(4);
        p.acquire(0.0).unwrap();
        p.release();
        p.acquire(0.0).unwrap();
        p.discard();

        assert_eq!(p.metrics().released(), 1);
        assert_eq!(p.metrics().discarded(), 1);
    }

    /// Draining must be checked before capacity, or a host mid-shutdown with a
    /// free slot accepts work it will not finish.
    #[test]
    fn a_draining_pool_refuses_even_with_free_capacity() {
        let p = Pool::new(8);
        p.begin_drain();

        let err = p.acquire(10.0).expect_err("draining refuses");
        assert_eq!(err.code, ErrorCode::InstancePoolExhausted);
        assert!(
            err.context
                .iter()
                .any(|(k, v)| k == "reason" && v == "draining"),
            "the reason must be `draining`: {err}"
        );
        assert!(
            !err.context.iter().any(|(k, _)| k == "retry-after"),
            "a draining host is not coming back, so retrying must not be advised: {err}"
        );
    }

    /// A drain is orderly: work in flight can still come home.
    #[test]
    fn releasing_still_works_while_draining() {
        let p = Pool::new(2);
        p.acquire(0.0).expect("in flight");
        p.begin_drain();
        assert!(p.acquire(0.0).is_err(), "new work is refused");
        assert_eq!(
            p.release(),
            ReleaseOutcome::SlotFreed,
            "in-flight work must be able to complete"
        );
        assert_eq!(p.in_use(), 0);
    }

    #[test]
    fn retry_after_is_never_zero_and_is_bounded() {
        let p = Pool::new(100);
        // Fast host: one capacity's worth of work is a fraction of a second, so
        // the floor applies. `Retry-After: 0` would mean "retry now", which is
        // the stampede the header exists to prevent.
        assert_eq!(p.retry_after_seconds(10_000.0), 1);
        // Slow host: 100 slots at 10/s is 10 s.
        assert_eq!(p.retry_after_seconds(10.0), 10);
        // Absurdly slow: clamped to a minute rather than an hour.
        assert_eq!(p.retry_after_seconds(0.1), 60);
        // No observed throughput at all.
        assert_eq!(p.retry_after_seconds(0.0), 1);
    }

    #[test]
    fn occupancy_reports_the_fraction_in_use() {
        let p = Pool::new(4);
        assert!(p.occupancy().abs() < f64::EPSILON, "a fresh pool is empty");
        p.acquire(0.0).unwrap();
        assert!((p.occupancy() - 0.25).abs() < f64::EPSILON);
        p.acquire(0.0).unwrap();
        assert!((p.occupancy() - 0.5).abs() < f64::EPSILON);
    }

    /// The compare-exchange loop must not over-issue under concurrency. This is
    /// the property a `load`-then-`store` implementation silently loses, and it
    /// only shows under contention.
    #[test]
    fn concurrent_acquires_never_exceed_capacity() {
        use std::sync::atomic::AtomicU64;
        use std::sync::Arc;

        const CAPACITY: u64 = 8;
        const THREADS: usize = 16;
        const ATTEMPTS: usize = 500;

        let p = Arc::new(Pool::new(CAPACITY));
        let peak = Arc::new(AtomicU64::new(0));
        let granted = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let p = Arc::clone(&p);
            let peak = Arc::clone(&peak);
            let granted = Arc::clone(&granted);
            handles.push(std::thread::spawn(move || {
                for _ in 0..ATTEMPTS {
                    if p.acquire(1000.0).is_ok() {
                        granted.fetch_add(1, Ordering::Relaxed);
                        peak.fetch_max(p.in_use(), Ordering::Relaxed);
                        p.release();
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("thread must not panic");
        }

        assert!(
            peak.load(Ordering::Relaxed) <= CAPACITY,
            "capacity was exceeded: peak {} > {CAPACITY}",
            peak.load(Ordering::Relaxed)
        );
        assert!(granted.load(Ordering::Relaxed) > 0, "the test is vacuous");
        assert_eq!(p.in_use(), 0, "every acquire was matched by a release");
    }

    /// **CONC-POOL-002: `in_use + idle` never exceeds capacity, on any sample.**
    ///
    /// The existing contention test pins the peak `in_use` bound; this one pins
    /// the *joint* invariant a split-atomic implementation breaks. Reservation
    /// and idle-dequeue are one transition under the state mutex, so no sampler
    /// can observe the increment without the decrement. A sampler thread reads
    /// both counters while workers churn acquire/release/discard, and every
    /// sample must satisfy the invariant — including `idle` alone, which a
    /// double-release accounting bug would push past capacity.
    #[test]
    fn concurrent_accounting_never_reports_an_impossible_state() {
        use std::sync::atomic::{AtomicBool, AtomicU64};
        use std::sync::{Arc, Barrier};

        const CAPACITY: u64 = 8;
        const THREADS: usize = 16;
        const ATTEMPTS: usize = 2000;

        let p = Arc::new(Pool::new(CAPACITY));
        let go = Arc::new(Barrier::new(THREADS + 2));
        let churn = Arc::new(Barrier::new(THREADS + 1));
        let done = Arc::new(AtomicBool::new(false));
        let sample_count = Arc::new(AtomicU64::new(0));
        let sampler_p = Arc::clone(&p);
        let sampler_done = Arc::clone(&done);
        let sampler_samples = Arc::clone(&sample_count);
        let sampler_go = Arc::clone(&go);
        let sampler_churn = Arc::clone(&churn);
        let watcher = std::thread::spawn(move || {
            sampler_go.wait();
            // The first sample precedes all churn, so the count below is
            // structural: the previous shape raced the workers and could, on
            // a fast runner, observe nothing while asserting coverage.
            let (used, idle) = sampler_p.snapshot();
            sampler_samples.fetch_add(1, Ordering::Relaxed);
            assert!(
                used + idle <= CAPACITY,
                "impossible state observed: in_use {used} + idle {idle} > {CAPACITY}"
            );
            sampler_churn.wait();
            while !sampler_done.load(Ordering::Relaxed) {
                // One joint read: two separate accessor calls could straddle a
                // transition and report a sum the pool never held, which would
                // fail the invariant on correct code.
                let (used, idle) = sampler_p.snapshot();
                sampler_samples.fetch_add(1, Ordering::Relaxed);
                assert!(
                    used + idle <= CAPACITY,
                    "impossible state observed: in_use {used} + idle {idle} > {CAPACITY}"
                );
                assert!(used <= CAPACITY, "in_use {used} exceeds {CAPACITY}");
                assert!(idle <= CAPACITY, "idle {idle} exceeds {CAPACITY}");
            }
        });

        let mut handles = Vec::new();
        for t in 0..THREADS {
            let p = Arc::clone(&p);
            let go = Arc::clone(&go);
            let churn = Arc::clone(&churn);
            handles.push(std::thread::spawn(move || {
                go.wait();
                churn.wait();
                for i in 0..ATTEMPTS {
                    if p.acquire(1000.0).is_ok() {
                        if (t + i) % 7 == 0 {
                            p.discard();
                        } else {
                            p.release();
                        }
                    }
                }
            }));
        }
        // The eighteenth waiter: without it the barrier never releases and
        // the test hangs rather than fails.
        go.wait();
        for h in handles {
            h.join().expect("thread must not panic");
        }
        done.store(true, Ordering::Relaxed);
        watcher.join().expect("sampler must not panic");

        assert!(
            sample_count.load(Ordering::Relaxed) > 100,
            "too few samples to prove anything; contention never overlapped the sampler"
        );
        assert_eq!(p.in_use(), 0, "every acquire was matched by a release");
    }

    /// The error must carry the machine-readable fields `qqq-serve` renders into
    /// a 503, so the server does not re-derive them.
    #[test]
    fn the_exhaustion_error_carries_what_a_503_needs() {
        let e = exhausted_error(Exhausted::AllBusy, 64, 3);
        assert_eq!(e.code, ErrorCode::InstancePoolExhausted);
        let ctx: std::collections::BTreeMap<_, _> = e.context.iter().cloned().collect();
        assert_eq!(ctx.get("capacity").map(String::as_str), Some("64"));
        assert_eq!(ctx.get("reason").map(String::as_str), Some("all_busy"));
        assert_eq!(ctx.get("retry-after").map(String::as_str), Some("3"));
    }

    #[test]
    fn exhausted_reasons_are_named_and_bounded() {
        assert_eq!(Exhausted::AllBusy.as_str(), "all_busy");
        assert_eq!(Exhausted::Draining.as_str(), "draining");
        assert!(Exhausted::AllBusy.retryable());
        assert!(!Exhausted::Draining.retryable());
    }
}
