// SPDX-License-Identifier: Apache-2.0

//! Instance and execution metrics — `HOST-019`, and the Instance/Execution/
//! Memory rows of Proposal §10.2.
//!
//! # What this module is, and what it deliberately is not
//!
//! It is the **recording** side of §10.2: named counters, gauges and one
//! histogram, incremented at the points in the instance lifecycle where the
//! proposal says they must be. It is not an exporter — there is no Prometheus
//! text format, no OpenTelemetry SDK, no listener here. That separation is
//! deliberate and matches the crate topology in §4.3: `qqq-host` owns the
//! engine, `qqq-io` and the layers above own I/O, and a metrics recorder that
//! opened a socket would invert the dependency graph the topology check
//! enforces.
//!
//! # The cardinality rule, enforced by the type system
//!
//! §10.2 states the discipline plainly:
//!
//! > **Cardinality discipline:** no metric label may take an unbounded value (no
//! > raw paths, no user IDs, no full URLs). Enforced by a lint on metric
//! > definitions.
//!
//! A lint over metric definitions is hard to write and easy to bypass — a label
//! is just a `&str` at the call site. This module enforces the rule *before* that
//! point by giving labels types that **cannot hold an unbounded value**:
//!
//! * [`TrapLabel`] is a closed enum whose variants map to fixed [`ErrorCode`]s.
//!   It cannot be constructed from a string, and a formatted error message can
//!   never become a label.
//!
//! There is no `label(name, value: &str)` API on [`Metrics`] at all, which is
//! the structural half of the guarantee: a caller who wants a new dimension must
//! add a typed label, and that is a visible change rather than a quiet one.
//!
//! # Why the histogram is fixed-bucket
//!
//! A prometheus-style histogram needs a bounded set of buckets to be
//! cardinality-safe, and an HDR histogram's quantile error is a documented
//! tradeoff. This one uses explicit nanosecond-ish bounds chosen for the range
//! §9 quotes: instantiation is hundreds of nanoseconds, a routed request's p99
//! budget is 2 ms, and a cold compile is tens of milliseconds. Values above the
//! top bucket land in `+Inf`, which is what makes the p99.9 claim measurable
//! rather than silently truncated.
//!
//! # Concurrency
//!
//! Every counter is a [`std::sync::atomic::AtomicU64`] with `Relaxed` ordering.
//! `Relaxed` is correct here and the reason is worth stating: metrics are a
//! *sampling* surface, not a synchronisation primitive. Nothing in this crate
//! makes a decision based on a metric value, so there is no happens-before
//! relationship to preserve. Using `SeqCst` would add fences to the request path
//! to buy an ordering guarantee no reader can observe.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use qqq_core::ErrorCode;

/// How many buckets the acquire-latency histogram has.
///
/// The upper bound is inclusive and the histogram has one extra `+Inf` bucket
/// beyond it, so `BUCKETS.len() + 1` counts are always recorded.
const BUCKETS: [u64; 16] = [
    100,         // 100 ns — pooled acquire, the target
    250,         // 250 ns
    500,         // 500 ns — measured p50 for a fresh instantiation
    1_000,       // 1 µs
    2_500,       // 2.5 µs
    5_000,       // 5 µs — cold-from-cache budget is 5 ms, so this is warm
    10_000,      // 10 µs
    25_000,      // 25 µs
    50_000,      // 50 µs
    100_000,     // 100 µs — the warm-pool budget in §2.3
    250_000,     // 250 µs
    500_000,     // 500 µs
    1_000_000,   // 1 ms
    2_500_000,   // 2.5 ms — above the routed p99 budget in §2.3
    10_000_000,  // 10 ms
    100_000_000, // 100 ms — a cold compile of a large component
];

/// A closed set of trap categories, for the "traps by code" metric.
///
/// # Why this is an enum and not a `&str`
///
/// This is §10.2's cardinality discipline made structural. A trap label built
/// from a formatted error message would be unbounded — a guest controls much of
/// that text — and would let a hostile component create a new time series per
/// request, which is a denial-of-service vector against whatever scrapes these
/// numbers. Every variant below maps to a fixed set of [`ErrorCode`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrapLabel {
    /// Fuel exhausted — `QQQ-3002`.
    Fuel,
    /// Epoch deadline exceeded — `QQQ-3003`.
    Epoch,
    /// Memory limit exceeded — `QQQ-3001`.
    Memory,
    /// The guest reached a resource handle that is not valid — `QQQ-3005`.
    Handles,
    /// The guest trapped inside wasm, for any reason other than the limits
    /// above — `QQQ-3004` and `QQQ-3007` (out-of-bounds).
    Wasm,
    /// The guest panicked explicitly — `QQQ-3006`. Distinguished from a plain
    /// wasm trap because it names a guest-side abort rather than a host-imposed
    /// limit.
    GuestPanic,
    /// A **host** function panicked and the host contained it — `QQQ-6007`
    /// (`HOST-011`).
    ///
    /// Always a QQQ defect rather than the guest's fault: no host function
    /// should panic on any input, and its inputs are attacker-controlled. A
    /// separate label exists so a dashboard can alert on it — a contained panic
    /// reported as a guest trap sends an operator to inspect the wrong artifact.
    HostPanic,
    /// The guest called a host function that is not granted. This is a
    /// *security* event and is counted separately so it can be alerted on.
    Ungranted,
    /// Anything the taxonomy could not classify. Deliberately a single bucket:
    /// an "unknown" label that varied would defeat the purpose.
    Other,
}

impl TrapLabel {
    /// Classify an error code into its trap label.
    ///
    /// Returns `None` for codes that are not traps at all — a malformed manifest
    /// is a build error, not a guest trapping — so the caller does not
    /// accidentally inflate trap counts with unrelated failures.
    #[must_use]
    pub const fn from_code(code: ErrorCode) -> Option<Self> {
        match code {
            ErrorCode::FuelExhausted => Some(Self::Fuel),
            ErrorCode::EpochDeadlineExceeded => Some(Self::Epoch),
            ErrorCode::MemoryLimitExceeded => Some(Self::Memory),
            ErrorCode::InvalidResourceHandle => Some(Self::Handles),
            ErrorCode::GuestTrap | ErrorCode::GuestOutOfBounds => Some(Self::Wasm),
            ErrorCode::GuestPanic => Some(Self::GuestPanic),
            ErrorCode::HostPanicContained => Some(Self::HostPanic),
            // A denied capability is not the same as an ungranted *import*: the
            // first is a grant that exists but does not cover this call, the
            // second is an import the linker never bound. Both are security
            // events and both belong in the alertable bucket.
            ErrorCode::CapabilityDenied | ErrorCode::CapabilityOutOfScope => Some(Self::Ungranted),
            _ => None,
        }
    }

    /// The bounded label string used as the metric dimension.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fuel => "fuel",
            Self::Epoch => "epoch",
            Self::Memory => "memory",
            Self::Handles => "handles",
            Self::Wasm => "wasm",
            Self::GuestPanic => "guest_panic",
            Self::HostPanic => "host_panic",
            Self::Ungranted => "ungranted",
            Self::Other => "other",
        }
    }

    /// Every variant, in a fixed order, for iteration and exporters.
    ///
    /// A fixed array rather than a derived iterator so that adding a variant is
    /// a compile error here until it is listed — the same exhaustiveness
    /// discipline the error catalogue uses.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Fuel,
            Self::Epoch,
            Self::Memory,
            Self::Handles,
            Self::Wasm,
            Self::GuestPanic,
            Self::HostPanic,
            Self::Ungranted,
            Self::Other,
        ]
    }

    /// The index into the per-label counter array.
    const fn index(self) -> usize {
        match self {
            Self::Fuel => 0,
            Self::Epoch => 1,
            Self::Memory => 2,
            Self::Handles => 3,
            Self::Wasm => 4,
            Self::GuestPanic => 5,
            Self::HostPanic => 6,
            Self::Ungranted => 7,
            Self::Other => 8,
        }
    }
}

/// A fixed-bucket latency histogram.
///
/// Buckets are **inclusive upper bounds** in nanoseconds; a value exactly equal
/// to a bound lands in that bucket. One additional count records everything
/// above the largest bound, so the total always equals the number of
/// observations and no value is silently dropped.
#[derive(Debug)]
pub struct Histogram {
    /// `BUCKETS.len()` finite buckets plus one overflow bucket.
    counts: [AtomicU64; BUCKETS.len() + 1],
    /// The sum, for a mean that does not need a second pass.
    sum: AtomicU64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Histogram {
    /// A histogram with no observations.
    #[must_use]
    pub const fn new() -> Self {
        // `AtomicU64` is not `Copy`, so the array cannot be built by a repeated
        // expression. `const` blocks with `from_fn` would need a non-const
        // closure; this explicit form is the one that compiles in const context
        // and is written out rather than macro-generated so it stays readable.
        #[allow(clippy::declare_interior_mutable_const)]
        const Z: AtomicU64 = AtomicU64::new(0);
        Self {
            counts: [Z; BUCKETS.len() + 1],
            sum: AtomicU64::new(0),
        }
    }

    /// Record one observation, in nanoseconds.
    ///
    /// Saturating: an observation is clamped to `u64::MAX` rather than wrapping.
    /// A wrapped latency would report a very slow call as a very fast one, which
    /// is the direction that hides a problem.
    pub fn observe(&self, nanos: u64) {
        let idx = BUCKETS
            .iter()
            .position(|&bound| nanos <= bound)
            .unwrap_or(BUCKETS.len());
        self.counts[idx].fetch_add(1, Ordering::Relaxed);
        // `fetch_add` wraps on overflow; a histogram sum that wrapped would
        // understate total time. Practically unreachable (2^64 ns is 584 years)
        // but the guard is one comparison and the failure mode is silent.
        let _ = self
            .sum
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(nanos)
            });
        debug_assert!(
            idx <= BUCKETS.len(),
            "the bucket search must always land inside the array"
        );
    }

    /// Total observations recorded.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.counts.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    /// The sum of all observations, in nanoseconds.
    #[must_use]
    pub fn sum(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }

    /// A snapshot: one `(upper_bound_ns, cumulative_count)` pair per bucket.
    ///
    /// The upper bound of the final pair is `None`, meaning `+Inf` — the
    /// convention every Prometheus histogram uses and the reason a quantile can
    /// be computed by interpolation rather than guessed.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(Option<u64>, u64)> {
        let mut out = Vec::with_capacity(BUCKETS.len() + 1);
        let mut cumulative = 0_u64;
        for (i, &bound) in BUCKETS.iter().enumerate() {
            cumulative = cumulative.saturating_add(self.counts[i].load(Ordering::Relaxed));
            out.push((Some(bound), cumulative));
        }
        cumulative = cumulative.saturating_add(self.counts[BUCKETS.len()].load(Ordering::Relaxed));
        out.push((None, cumulative));
        out
    }

    /// The estimated quantile, in nanoseconds, by linear interpolation within
    /// the bucket that contains it.
    ///
    /// # Why interpolation rather than the bucket's upper bound
    ///
    /// Returning the upper bound overstates every quantile by up to the width of
    /// a bucket, which for the lowest buckets is 100 % or more. Linear
    /// interpolation assumes observations are uniform within a bucket — an
    /// approximation, and one that is stated here rather than hidden — and is
    /// what Prometheus' own `histogram_quantile` does.
    ///
    /// Returns `None` when nothing has been observed, which is distinguishable
    /// from `Some(0)`: "we have no data" and "the measurement was instant" are
    /// different facts, and a monitoring system that conflates them reports a
    /// healthy p99 for a service receiving no traffic.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation
    )]
    pub fn quantile(&self, q: f64) -> Option<u64> {
        let total = self.count();
        if total == 0 {
            return None;
        }
        // The `f64` round-trip is inherent to interpolating a quantile: the
        // fraction `target / count` is a ratio, and `count` is a bucket tally
        // rather than a count of anything that could approach 2^53. The casts
        // are allowed at the function level with that reasoning stated, rather
        // than scattered as four separate attributes.
        let target = (q.clamp(0.0, 1.0) * total as f64).ceil() as u64;
        let target = target.max(1);

        let mut cumulative = 0_u64;
        let mut lower = 0_u64;
        for (i, &bound) in BUCKETS.iter().enumerate() {
            let count_in_bucket = self.counts[i].load(Ordering::Relaxed);
            if cumulative + count_in_bucket >= target {
                if count_in_bucket == 0 {
                    // Degenerate but reachable if a concurrent observer added to
                    // a later bucket between the two loads; falling back to the
                    // bound is exact and never panics.
                    return Some(bound);
                }
                let fraction = (target - cumulative) as f64 / count_in_bucket as f64;
                let width = bound.saturating_sub(lower);
                let estimated = lower as f64 + fraction * width as f64;
                return Some(estimated.round() as u64);
            }
            cumulative += count_in_bucket;
            lower = bound;
        }
        // The overflow bucket. Its upper bound is unknown by construction, so
        // the last finite bound is the honest answer.
        Some(*BUCKETS.last().unwrap_or(&0))
    }
}

/// The instance, execution and memory metrics of Proposal §10.2.
///
/// One `Metrics` instance is intended to live for the lifetime of a host
/// process. It is `Send + Sync` and every method takes `&self`, so it can be
/// shared behind an `Arc` without a lock on any hot path.
#[derive(Debug, Default)]
pub struct Metrics {
    // -- Instance ---------------------------------------------------------
    /// Instances created from scratch (as opposed to acquired from a pool).
    created: AtomicU64,
    /// Instances taken from a pool.
    acquired: AtomicU64,
    /// Instances returned to a pool.
    released: AtomicU64,
    /// Instances discarded because they trapped, and therefore never released.
    discarded: AtomicU64,
    /// Instances currently live.
    live: AtomicU64,
    /// Times a pool was found empty and a caller had to wait or create.
    saturation: AtomicU64,
    /// How long acquisition took.
    acquire_latency: Histogram,

    // -- Execution --------------------------------------------------------
    /// Total fuel consumed across every execution.
    fuel: AtomicU64,
    /// Executions that completed successfully.
    executions_ok: AtomicU64,
    /// Traps, by bounded label.
    traps: [AtomicU64; TrapLabel::all().len()],

    // -- Memory -----------------------------------------------------------
    /// The highest per-instance memory peak observed, in bytes.
    peak_memory: AtomicU64,
    /// Bytes currently reserved by live instances.
    live_memory: AtomicU64,
}

impl Metrics {
    /// A fresh, all-zero recorder.
    #[must_use]
    pub const fn new() -> Self {
        #[allow(clippy::declare_interior_mutable_const)]
        const Z: AtomicU64 = AtomicU64::new(0);
        Self {
            created: Z,
            acquired: Z,
            released: Z,
            discarded: Z,
            live: Z,
            saturation: Z,
            acquire_latency: Histogram::new(),
            fuel: Z,
            executions_ok: Z,
            traps: [Z; TrapLabel::all().len()],
            peak_memory: Z,
            live_memory: Z,
        }
    }

    /// Record that an instance was created rather than pooled.
    ///
    /// # This is the *only* place `created` is incremented
    ///
    /// [`Metrics::note_acquire`] deliberately does **not** touch `created`. The
    /// two are separate events: an instance is created once (compiled and
    /// instantiated), and acquired once per use (possibly from a pool, many
    /// times). An earlier version incremented `created` from both, so a fresh
    /// acquisition counted twice and the "created" series over-reported by
    /// exactly the number of cold starts — the metric a capacity planner would
    /// use to size a pool.
    pub fn note_created(&self) {
        self.created.fetch_add(1, Ordering::Relaxed);
        self.live.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an instance acquisition, with how long it took.
    ///
    /// `pooled` distinguishes a pool hit from a fresh instantiation, because
    /// §2.3's two budgets — 100 µs warm-pool and 5 ms cold-from-cache — are
    /// different SLOs and averaging them together hides both.
    ///
    /// A **pooled** acquisition is the only thing this records besides the
    /// latency: a non-pooled one has already been counted by
    /// [`Metrics::note_created`], which the caller performs when it builds the
    /// instance. See that method for why the split matters.
    pub fn note_acquire(&self, nanos: u64, pooled: bool) {
        self.acquire_latency.observe(nanos);
        if pooled {
            self.acquired.fetch_add(1, Ordering::Relaxed);
            self.live.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record that an instance was returned to a pool intact.
    pub fn note_released(&self) {
        self.released.fetch_add(1, Ordering::Relaxed);
        self.live.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record that an instance was discarded after a trap.
    ///
    /// This is the metric that makes §4.4 step 14 observable: a discard rate
    /// that climbs steeply is the first sign of a hostile or broken guest, and
    /// it is invisible in a "requests succeeded" count because a trap is a
    /// failed request either way.
    pub fn note_discarded(&self) {
        self.discarded.fetch_add(1, Ordering::Relaxed);
        self.live.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record that a pool had no free instance available.
    pub fn note_saturation(&self) {
        self.saturation.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a completed execution.
    ///
    /// `fuel` is `None` when metering was disabled, which is a different fact
    /// from "zero fuel consumed" and must not be summed as zero.
    pub fn note_execution(&self, fuel: Option<u64>) {
        self.executions_ok.fetch_add(1, Ordering::Relaxed);
        if let Some(f) = fuel {
            let _ = self
                .fuel
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| c.checked_add(f));
        }
    }

    /// Record a trap by its bounded label.
    pub fn note_trap(&self, label: TrapLabel) {
        self.traps[label.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a trap by error code, when the code is one the taxonomy knows.
    ///
    /// Unrecognised codes are counted as [`TrapLabel::Other`] rather than
    /// dropped: a trap that produced no metric is the one nobody investigates.
    pub fn note_trap_code(&self, code: ErrorCode) {
        self.note_trap(TrapLabel::from_code(code).unwrap_or(TrapLabel::Other));
    }

    /// Record an instance's peak linear-memory use, in bytes.
    pub fn note_peak_memory(&self, bytes: u64) {
        self.peak_memory.fetch_max(bytes, Ordering::Relaxed);
    }

    /// Adjust the reserved-memory gauge by `delta` bytes.
    ///
    /// `fetch_update` rather than `fetch_add` so the gauge saturates at zero
    /// instead of wrapping: a negative occupancy is not meaningful and a wrapped
    /// one would report an enormous value.
    pub fn note_memory_delta(&self, delta: i64) {
        let _ = self.memory_delta_target(delta).fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_add_signed(delta)),
        );
    }

    const fn memory_delta_target(&self, _delta: i64) -> &AtomicU64 {
        &self.live_memory
    }

    /// Instances created from scratch.
    #[must_use]
    pub fn created(&self) -> u64 {
        self.created.load(Ordering::Relaxed)
    }

    /// Instances taken from a pool.
    #[must_use]
    pub fn acquired(&self) -> u64 {
        self.acquired.load(Ordering::Relaxed)
    }

    /// Instances returned to a pool.
    #[must_use]
    pub fn released(&self) -> u64 {
        self.released.load(Ordering::Relaxed)
    }

    /// Instances discarded after a trap.
    #[must_use]
    pub fn discarded(&self) -> u64 {
        self.discarded.load(Ordering::Relaxed)
    }

    /// Instances currently live.
    #[must_use]
    pub fn live(&self) -> u64 {
        self.live.load(Ordering::Relaxed)
    }

    /// Times a pool was found empty.
    #[must_use]
    pub fn saturation(&self) -> u64 {
        self.saturation.load(Ordering::Relaxed)
    }

    /// The acquisition-latency histogram.
    #[must_use]
    pub const fn acquire_latency(&self) -> &Histogram {
        &self.acquire_latency
    }

    /// Total fuel consumed.
    #[must_use]
    pub fn fuel(&self) -> u64 {
        self.fuel.load(Ordering::Relaxed)
    }

    /// Successful executions.
    #[must_use]
    pub fn executions_ok(&self) -> u64 {
        self.executions_ok.load(Ordering::Relaxed)
    }

    /// The count recorded against one trap label.
    #[must_use]
    pub fn trap_count(&self, label: TrapLabel) -> u64 {
        self.traps[label.index()].load(Ordering::Relaxed)
    }

    /// Every trap count, as `(label, count)` in a fixed order.
    #[must_use]
    pub fn traps(&self) -> Vec<(TrapLabel, u64)> {
        TrapLabel::all()
            .iter()
            .map(|&l| (l, self.trap_count(l)))
            .collect()
    }

    /// The highest per-instance memory peak seen, in bytes.
    #[must_use]
    pub fn peak_memory(&self) -> u64 {
        self.peak_memory.load(Ordering::Relaxed)
    }

    /// Bytes currently reserved by live instances.
    #[must_use]
    pub fn live_memory(&self) -> u64 {
        self.live_memory.load(Ordering::Relaxed)
    }

    /// Render every metric in the Prometheus text exposition format.
    ///
    /// # Why this lives in `qqq-host` despite the module doc saying it is only
    /// the recording side
    ///
    /// Formatting a `String` is not I/O, so this does not invert the crate
    /// topology (`tools/check_topology.py` checks dependencies, not behaviour).
    /// Keeping the format here means the metric *names* are defined once, next
    /// to the counters they describe — an exporter that spelled them itself
    /// would be a second source of truth, and the two would drift.
    ///
    /// Every series is emitted even at zero. A counter that disappears when it
    /// is zero makes `rate()` return nothing instead of zero, which reads as
    /// "no data" rather than "no traps", and that ambiguity is exactly what a
    /// security dashboard must not have.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);
        self.write_counters(&mut out);
        self.write_gauges(&mut out);
        self.write_traps(&mut out);
        self.write_acquire_latency(&mut out);
        out
    }

    /// Write every counter, including the ones still at zero.
    fn write_counters(&self, out: &mut String) {
        let counters: [(&str, &str, u64); 7] = [
            (
                "qqq_instance_created_total",
                "Instances instantiated from scratch.",
                self.created(),
            ),
            (
                "qqq_instance_acquired_total",
                "Instances taken from a pool.",
                self.acquired(),
            ),
            (
                "qqq_instance_released_total",
                "Instances returned to a pool intact.",
                self.released(),
            ),
            (
                "qqq_instance_discarded_total",
                "Instances discarded after a trap and never reused.",
                self.discarded(),
            ),
            (
                "qqq_instance_pool_saturation_total",
                "Acquisitions that found the pool empty.",
                self.saturation(),
            ),
            (
                "qqq_execution_ok_total",
                "Executions that completed without trapping.",
                self.executions_ok(),
            ),
            (
                "qqq_execution_fuel_total",
                "Fuel consumed by guest execution.",
                self.fuel(),
            ),
        ];
        for (name, help, value) in counters {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name} {value}");
        }
    }

    /// Write every gauge, including the ones still at zero.
    fn write_gauges(&self, out: &mut String) {
        for (name, help, value) in [
            (
                "qqq_instance_live",
                "Instances currently live.",
                self.live(),
            ),
            (
                "qqq_memory_live_bytes",
                "Bytes reserved by live instances.",
                self.live_memory(),
            ),
            (
                "qqq_instance_peak_memory_bytes",
                "Highest per-instance memory peak observed.",
                self.peak_memory(),
            ),
        ] {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} gauge");
            let _ = writeln!(out, "{name} {value}");
        }
    }

    /// Write the trap counter, one series per bounded label.
    ///
    /// Every label is emitted even at zero, because a `kind` series that
    /// vanishes when there are no traps makes `rate()` return no data instead of
    /// zero — and "no data" on an ungranted-import counter is the ambiguity a
    /// security dashboard cannot afford.
    fn write_traps(&self, out: &mut String) {
        let _ = writeln!(
            out,
            "# HELP qqq_trap_total Guest traps, by bounded category."
        );
        let _ = writeln!(out, "# TYPE qqq_trap_total counter");
        for (label, count) in self.traps() {
            let _ = writeln!(out, "qqq_trap_total{{kind=\"{}\"}} {count}", label.as_str());
        }
    }

    /// Write the acquisition-latency histogram in the standard cumulative form.
    #[allow(clippy::cast_precision_loss)]
    fn write_acquire_latency(&self, out: &mut String) {
        const NAME: &str = "qqq_instance_acquire_latency_seconds";
        let _ = writeln!(
            out,
            "# HELP {NAME} Instance acquisition latency, warm-pool and cold alike."
        );
        let _ = writeln!(out, "# TYPE {NAME} histogram");
        for (bound, cumulative) in self.acquire_latency.snapshot() {
            match bound {
                Some(ns) => {
                    let seconds = ns as f64 / 1e9;
                    let _ = writeln!(out, "{NAME}_bucket{{le=\"{seconds}\"}} {cumulative}");
                }
                None => {
                    let _ = writeln!(out, "{NAME}_bucket{{le=\"+Inf\"}} {cumulative}");
                }
            }
        }
        // The sum is in seconds to match the bucket unit; a sum in nanoseconds
        // beside second-denominated buckets is a silent factor-of-1e9 error in
        // any `rate(sum)/rate(count)` average.
        let sum_seconds = self.acquire_latency.sum() as f64 / 1e9;
        let _ = writeln!(out, "{NAME}_sum {sum_seconds}");
        let _ = writeln!(out, "{NAME}_count {}", self.acquire_latency.count());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_recorder_is_all_zero() {
        let m = Metrics::new();
        assert_eq!(m.created(), 0);
        assert_eq!(m.live(), 0);
        assert_eq!(m.fuel(), 0);
        assert_eq!(m.acquire_latency().count(), 0);
        assert_eq!(m.acquire_latency().quantile(0.5), None);
    }

    #[test]
    fn the_live_gauge_tracks_create_and_release() {
        let m = Metrics::new();
        m.note_created();
        m.note_created();
        assert_eq!(m.live(), 2);

        m.note_released();
        assert_eq!(m.live(), 1, "a released instance is no longer live");

        m.note_discarded();
        assert_eq!(m.live(), 0, "a discarded instance is no longer live");

        // The counters are cumulative even as the gauge returns to zero — this
        // is what makes a discard *rate* computable.
        assert_eq!(m.created(), 2);
        assert_eq!(m.released(), 1);
        assert_eq!(m.discarded(), 1);
    }

    /// A discard is not a release, and conflating them hides the security signal.
    #[test]
    fn discards_and_releases_are_counted_separately() {
        let m = Metrics::new();
        m.note_created();
        m.note_discarded();
        assert_eq!(m.released(), 0);
        assert_eq!(m.discarded(), 1);
    }

    #[test]
    fn pooled_and_fresh_acquisitions_are_distinguishable() {
        let m = Metrics::new();
        // A fresh acquisition is: create the instance, then record the acquire
        // latency. `created` counts the instantiation; `note_acquire` counts
        // only a pool hit.
        m.note_created();
        m.note_acquire(700, false);
        assert_eq!(m.created(), 1, "a fresh acquisition must count once");
        assert_eq!(m.acquired(), 0, "a fresh acquisition is not a pool hit");
        assert_eq!(m.live(), 1);

        m.note_acquire(80, true);
        assert_eq!(m.acquired(), 1);
        assert_eq!(m.created(), 1, "a pool hit must not re-count creation");
        assert_eq!(m.live(), 2);
        assert_eq!(m.acquire_latency().count(), 2);
    }

    /// Every trap label is reachable, and each maps to its own counter.
    ///
    /// Without this, two variants could share an index and the counts would be
    /// silently merged — the kind of defect a "traps are recorded" test passes
    /// straight through.
    #[test]
    fn every_trap_label_has_its_own_counter() {
        let m = Metrics::new();
        for label in TrapLabel::all() {
            m.note_trap(*label);
        }
        for (label, count) in m.traps() {
            assert_eq!(count, 1, "{label:?} must have its own counter");
        }
    }

    #[test]
    fn trap_codes_classify_and_unknowns_are_other() {
        assert_eq!(
            TrapLabel::from_code(ErrorCode::FuelExhausted),
            Some(TrapLabel::Fuel)
        );
        assert_eq!(
            TrapLabel::from_code(ErrorCode::EpochDeadlineExceeded),
            Some(TrapLabel::Epoch)
        );
        assert_eq!(
            TrapLabel::from_code(ErrorCode::GuestPanic),
            Some(TrapLabel::GuestPanic)
        );
        // A manifest error is not a trap at all, so it must not be counted as one.
        assert_eq!(TrapLabel::from_code(ErrorCode::ManifestSyntaxInvalid), None);

        // And a code that is not a trap, routed through `note_trap_code`, lands
        // in `Other` rather than vanishing.
        let m = Metrics::new();
        m.note_trap_code(ErrorCode::ManifestSyntaxInvalid);
        assert_eq!(m.trap_count(TrapLabel::Other), 1);
    }

    #[test]
    fn every_trap_label_string_is_distinct_and_bounded() {
        let mut seen = std::collections::BTreeSet::new();
        for label in TrapLabel::all() {
            let s = label.as_str();
            assert!(!s.is_empty());
            assert!(
                s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{s} must be a bounded, lowercase label"
            );
            assert!(seen.insert(s), "duplicate label string: {s}");
        }
    }

    #[test]
    fn histogram_observations_land_in_the_right_bucket() {
        let h = Histogram::new();
        h.observe(50); // <= 100
        h.observe(100); // exactly the first bound, inclusive
        h.observe(200); // <= 250
        h.observe(u64::MAX); // overflow

        let snap = h.snapshot();
        assert_eq!(snap[0], (Some(100), 2), "50 and 100 both land in <=100");
        assert_eq!(snap[1], (Some(250), 3));
        assert_eq!(snap.last().unwrap().1, 4, "every observation is counted");
        assert_eq!(snap.last().unwrap().0, None, "the last bucket is +Inf");
        assert_eq!(h.count(), 4);
    }

    /// The categories must be exhaustive: no observation may be dropped.
    #[test]
    fn the_histogram_never_loses_an_observation() {
        let h = Histogram::new();
        for v in [0_u64, 1, 99, 100, 101, 1_000_000, u64::MAX] {
            h.observe(v);
        }
        assert_eq!(h.count(), 7);
    }

    #[test]
    fn quantiles_are_interpolated_and_none_when_empty() {
        let h = Histogram::new();
        assert_eq!(h.quantile(0.5), None, "no data is not the same as zero");

        // 100 observations evenly placed below 100 ns.
        for v in 1..=100 {
            h.observe(v);
        }
        let p50 = h.quantile(0.5).expect("data exists");
        assert!(
            (1..=100).contains(&p50),
            "p50 {p50} must be inside the bucket"
        );

        // The median of 1..=100 is ~50, so interpolation must land near it
        // rather than at the bucket's upper bound of 100.
        assert!(p50 < 100, "interpolation must not return the upper bound");

        let p100 = h.quantile(1.0).expect("data exists");
        assert!(p100 <= 100);
    }

    #[test]
    fn quantile_clamps_out_of_range_inputs() {
        let h = Histogram::new();
        h.observe(10);
        assert!(h.quantile(-1.0).is_some(), "a negative q clamps to 0");
        assert!(h.quantile(2.0).is_some(), "a q above 1 clamps to 1");
    }

    #[test]
    fn the_sum_accumulates_without_wrapping() {
        let h = Histogram::new();
        h.observe(100);
        h.observe(250);
        assert_eq!(h.sum(), 350);
    }

    #[test]
    fn execution_fuel_is_not_summed_when_unmetered() {
        let m = Metrics::new();
        m.note_execution(None);
        assert_eq!(m.executions_ok(), 1);
        assert_eq!(m.fuel(), 0, "an unmetered execution contributes no fuel");

        m.note_execution(Some(1_000));
        assert_eq!(m.fuel(), 1_000);
        assert_eq!(m.executions_ok(), 2);
    }

    #[test]
    fn peak_memory_keeps_the_maximum_not_the_last() {
        let m = Metrics::new();
        m.note_peak_memory(4096);
        m.note_peak_memory(1024);
        assert_eq!(m.peak_memory(), 4096, "a peak must not be lowered");
        m.note_peak_memory(8192);
        assert_eq!(m.peak_memory(), 8192);
    }

    /// The live-memory gauge must saturate at zero rather than wrap.
    ///
    /// A wrapped gauge reports an enormous positive number, which on a capacity
    /// dashboard reads as a full host — the most alarming possible way to render
    /// a bookkeeping slip.
    #[test]
    fn the_live_memory_gauge_saturates_at_zero() {
        let m = Metrics::new();
        m.note_memory_delta(1024);
        assert_eq!(m.live_memory(), 1024);
        m.note_memory_delta(-2048);
        assert_eq!(m.live_memory(), 0, "must clamp, not wrap");
    }

    /// The exposition format must contain every series, including zero-valued
    /// ones, and must be parseable shape-wise.
    #[test]
    fn prometheus_output_is_complete_and_well_formed() {
        let m = Metrics::new();
        m.note_created();
        m.note_trap(TrapLabel::Fuel);
        m.note_acquire(150, false);

        let text = m.render_prometheus();

        for expected in [
            "qqq_instance_created_total 1",
            "qqq_instance_acquired_total 0",
            "qqq_instance_discarded_total 0",
            "qqq_trap_total{kind=\"fuel\"} 1",
            "qqq_trap_total{kind=\"epoch\"} 0",
            "qqq_instance_acquire_latency_seconds_count 1",
            "le=\"+Inf\"",
        ] {
            assert!(text.contains(expected), "missing `{expected}` in:\n{text}");
        }

        // Every non-comment line must be `name value` with exactly one space,
        // which is what makes the output machine-parseable.
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            assert!(!line.is_empty());
            assert_eq!(
                line.matches(' ').count(),
                1,
                "a sample line must be `name value`: `{line}`"
            );
        }

        // HELP and TYPE must both precede every metric family.
        let families: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("# TYPE "))
            .map(|l| l.trim_start_matches("# TYPE ").split(' ').next().unwrap())
            .collect();
        for family in families {
            assert!(
                text.contains(&format!("# HELP {family} ")),
                "family {family} has a TYPE but no HELP"
            );
        }
    }

    /// A second `render_prometheus` call must be identical — the render must not
    /// mutate counters. Cheap to assert, and a renderer that observed its own
    /// output would corrupt every metric it reported.
    #[test]
    fn rendering_is_read_only() {
        let m = Metrics::new();
        m.note_created();
        let a = m.render_prometheus();
        let b = m.render_prometheus();
        assert_eq!(a, b);
        assert_eq!(m.created(), 1);
    }

    /// The recorder is shared across threads without a lock; a concurrent
    /// increment must not lose a count.
    #[test]
    fn concurrent_updates_do_not_lose_counts() {
        use std::sync::Arc;
        let m = Arc::new(Metrics::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = Arc::clone(&m);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1_000 {
                    m.note_created();
                    m.note_trap(TrapLabel::Wasm);
                    m.acquire_latency().observe(120);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread must not panic");
        }
        assert_eq!(m.created(), 8_000);
        assert_eq!(m.trap_count(TrapLabel::Wasm), 8_000);
        assert_eq!(m.acquire_latency().count(), 8_000);
    }
}
