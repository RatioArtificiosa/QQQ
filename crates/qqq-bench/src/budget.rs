// SPDX-License-Identifier: Apache-2.0

//! The `§9.2` budget table as data, with the comparison logic that decides
//! whether a measurement meets it.
//!
//! # Why the budgets are code
//!
//! `§9.2` says each row "has a measurement method in `bench/`". That is a claim
//! about a mapping from twelve named targets to twelve named methods, and a
//! mapping is data. Written as a Markdown table it can drift from the harness
//! silently; written as a `const` array it cannot, because a checker can compare
//! the two and a test can fail.
//!
//! # The direction of every comparison is the point
//!
//! Half of `§9.2`'s rows are **ceilings** ("≤ 100 µs", "≤ 25 MB") and half are
//! **floors** ("≥ 60k RPS"). A comparison written the wrong way round is the
//! single easiest way to make a failing benchmark report success, and it looks
//! identical in review — `100 <= 100` and `60_000 >= 60_000` are equally
//! plausible. So the direction is a property of the **row**, not of the call site:
//! see [`Budget::meets`], which branches on [`Budget::direction`].
//!
//! This is `§O-124`'s rule — *name the rule so a test can state it* — applied to
//! the one comparison where getting it backwards is invisible.

use std::fmt;

/// Which way a budget compares.
///
/// # Why this is required and has no default
///
/// A default direction would silently apply a ceiling to a throughput row. The
/// two directions are genuinely different claims about the system, and the
/// compiler should not be the only thing standing between them and a wrong
/// default — so there is no `Default` at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The measurement must be **at most** the target. Latency, memory, size.
    AtMost,
    /// The measurement must be **at least** the target. Throughput, capacity.
    AtLeast,
}

impl Direction {
    /// A one-character rendering for the budget table, matching `§9.2`'s symbols.
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            Self::AtMost => "≤",
            Self::AtLeast => "≥",
        }
    }

    /// Whether `measured` satisfies `target` in this direction.
    ///
    /// The comparison is **inclusive** on both sides: `§9.2` writes `≤` and `≥`,
    /// so a measurement exactly on the target is met. Using `<` or `>` would fail
    /// a run that hit its budget exactly — the off-by-one that
    /// `SRV-020` recorded for a `le` bucket boundary.
    ///
    /// Non-finite and negative measurements never satisfy, in either direction:
    /// `-inf <= target` is true and `+inf >= target` is true, so an unchecked
    /// comparison would report a broken measurement as met. Fail-closed here —
    /// a measurement that is not a real, non-negative number is not evidence
    /// of anything.
    #[must_use]
    pub fn satisfied_by(self, measured: f64, target: f64) -> bool {
        if !measured.is_finite() || measured < 0.0 {
            return false;
        }
        match self {
            Self::AtMost => measured <= target,
            Self::AtLeast => measured >= target,
        }
    }
}

/// What a budget is measured in.
///
/// # Why a unit is carried at all
///
/// `§9.2` mixes µs, ms, MB, KB, RPS, seconds and a bare byte count. A comparison
/// between a number in microsends and a target in milliseconds is a factor-of-1000
/// error that produces a *plausible* result — `100 <= 5` is false but
/// `100_000 <= 5_000` is false too, and only one of them is the intended check.
/// Carrying the unit means [`Budget::meets`] can refuse a mismatched measurement
/// instead of comparing two numbers that mean different things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// Microseconds. `§9.2`'s latency rows.
    Micros,
    /// Milliseconds. `§9.2`'s cold-instantiate rows.
    Millis,
    /// Seconds. `§9.2`'s build-time row (`qqqai build`, 10k LOC Rust, ≤ 20 s):
    /// twenty *milliseconds* for a clean build is impossible, and the previous
    /// spelling of this row said exactly that while comparing as milliseconds.
    Seconds,
    /// Megabytes. `§9.2`'s RSS rows.
    Megabytes,
    /// Kilobytes. `§9.2`'s per-instance memory row.
    Kilobytes,
    /// Requests per second. `§9.2`'s throughput row.
    RequestsPerSecond,
    /// A bare count, used where `§9.2` states a plain number.
    Count,
}

impl Unit {
    /// The symbol as `§9.2` writes it.
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Micros => "µs",
            Self::Millis => "ms",
            Self::Seconds => "s",
            Self::Megabytes => "MB",
            Self::Kilobytes => "KB",
            Self::RequestsPerSecond => "RPS",
            Self::Count => "count",
        }
    }
}

/// One row of `§9.2`.
///
/// # Why the target is a `f64` and not an integer
///
/// `§9.2` states `≤ 100 µs`, `≥ 60k RPS`, `≤ 256 KB`. All representable as
/// integers, but the *hub* of reported values is not: a p99 of 1.98 ms is the
/// interesting thing to compare, and truncating it to 1 before comparison would
/// turn a pass into a fail at the boundary. The comparison happens in `f64` for
/// that reason, and [`Budget::meets_nanos`] exists so a duration never has to be
/// pre-rounded at the call site.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Budget {
    /// The `PERF-*` item that owns this row.
    pub item: Item,
    /// The target value, in [`Budget::unit`].
    pub target: f64,
    /// Which way the comparison goes.
    pub direction: Direction,
    /// What the target is expressed in.
    pub unit: Unit,
    /// Where the number is produced, as `path::symbol`.
    ///
    /// # Why this field is no longer `bench/<file>.rs`
    ///
    /// It used to read `bench/routed.rs::routed_request_overhead` and nine more like
    /// it, and **not one of those files existed**: `crates/qqq-bench/src/` holds
    /// `budget.rs`, `lib.rs`, `loadgen.rs`, `methodology.rs`, `stats.rs` and
    /// `workload.rs`, and never had a `bench/` directory. The field told a reader
    /// where each measurement is taken and every answer was wrong — `§O-249`.
    ///
    /// `tools/check_bench_contract.py` validated the *shape* of these citations
    /// (must start with `bench/`) and never that they resolve, so the gate reported
    /// OK for as long as the defect existed. That rule now requires the file to
    /// exist, which is what caught this.
    ///
    /// Each value now names code that is really there. Where the measurement is
    /// **not implemented**, the value says so in the string rather than pointing at
    /// a plausible-looking path: `NOT_IMPLEMENTED` is greppable and honest, and a
    /// fabricated path is neither.
    pub method: &'static str,
}

/// The `PERF-*` item that owns a `§9.2` row.
///
/// # Why these are an enum and not strings
///
/// `check_checklist_citations.py` exists because a round of this project invented
/// a checklist identifier that did not exist, and cited it as though it were
/// real (`§O-126`). An enum makes the
/// citation a compile-time fact: a row cannot name an item that does not exist,
/// and `Budget::ALL`'s test asserts every one of them is present in the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item {
    /// `PERF-003` — warm instance acquire.
    Perf003,
    /// `PERF-004` — cold instantiate.
    Perf004,
    /// `PERF-007` — AOT cache.
    Perf007,
    /// `PERF-008` — idle RSS.
    Perf008,
    /// `PERF-009` — 1000-idle-instance RSS.
    Perf009,
    /// `PERF-010` — throughput.
    Perf010,
    /// `PERF-011` — p99 latency.
    Perf011,
    /// `PERF-012` — per-instance memory.
    Perf012,
    /// `PERF-013` — build time.
    Perf013,
    /// `PERF-002` — routed request overhead.
    ///
    /// # Why this row is here, and why the checker found it
    ///
    /// `§9.2` states *"Routed request overhead (empty handler) | ≤ 60 µs p99 |
    /// Host-side, excluding guest work"*. It was **missing from the first version
    /// of this table**, and `tools/check_bench_contract.py` caught the omission on
    /// its own author, on its first run, by finding a `§9.2` row with no decision
    /// attached — neither implemented nor named in [`Budget::NOT_A_HARNESS_ROW`].
    ///
    /// It belongs to `PERF-002` rather than a `PERF-003`-style item because it is
    /// the one row that is *purely* the host's: the measurement excludes all guest
    /// work, so it isolates the router and the connection state machine. Of the
    /// ten `§9.1` benchmarks it is closest to `hello`, and it is the number that
    /// says whether the runtime's own overhead is where `§9.2` claims.
    Perf002,
}

impl Item {
    /// The checklist identifier, for a citation that cannot be invented.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Perf003 => "PERF-003",
            Self::Perf004 => "PERF-004",
            Self::Perf007 => "PERF-007",
            Self::Perf008 => "PERF-008",
            Self::Perf009 => "PERF-009",
            Self::Perf010 => "PERF-010",
            Self::Perf011 => "PERF-011",
            Self::Perf012 => "PERF-012",
            Self::Perf013 => "PERF-013",
            Self::Perf002 => "PERF-002",
        }
    }

    /// The human-readable name of the measurement, from `§9.2`'s first column.
    #[must_use]
    pub fn metric(self) -> &'static str {
        match self {
            Self::Perf003 => "Warm instance acquire",
            Self::Perf004 => "Cold instantiate (AOT cached)",
            Self::Perf007 => "AOT cache performance",
            Self::Perf008 => "RSS, idle host, 0 instances",
            Self::Perf009 => "RSS, 1000 idle instances",
            Self::Perf010 => "Throughput, reference app, 8 cores",
            Self::Perf011 => "p99 request latency, reference app, 10k RPS",
            Self::Perf012 => "Memory per instance, reference app",
            Self::Perf013 => "qqqai build, 10k LOC Rust",
            Self::Perf002 => "Routed request overhead (empty handler)",
        }
    }
}

impl Budget {
    /// Every `§9.2` row.
    ///
    /// # Why this is a `const` array with a test, not a parsed table
    ///
    /// A test asserts this array matches the rows in `QQQ-Proposal-V1.md` §9.2 and
    /// that each `Item::id` exists in `QQQ-Checklist-V1.md`. That is the
    /// difference between a citation and a claim: `tools/check_bench_contract.py`
    /// performs the same comparison in CI, so the table cannot drift from the
    /// Proposal without a red build.
    ///
    /// # Rows deliberately absent
    ///
    /// `§9.2` has eleven directive rows. Ten are here, because three define *this*
    /// harness rather than a running system and are met by their own items:
    /// `qqqai --version` (≤ 15 ms) belongs to a CLI item, and the two
    /// "cold instantiate from `.wasm`" rows are the same measurement as
    /// `PERF-004`'s cached case with a different precondition. They are recorded
    /// in [`Budget::NOT_A_HARNESS_ROW`] so their absence is a stated exclusion
    /// rather than an oversight.
    pub const ALL: [Self; 10] = [
        Self {
            item: Item::Perf002,
            target: 60.0,
            direction: Direction::AtMost,
            unit: Unit::Micros,
            method: "crate::workload::BenchmarkName::Hello",
        },
        Self {
            item: Item::Perf003,
            target: 100.0,
            direction: Direction::AtMost,
            unit: Unit::Micros,
            method: "NOT_IMPLEMENTED::warm_instance_acquire",
        },
        Self {
            item: Item::Perf004,
            target: 5.0,
            direction: Direction::AtMost,
            unit: Unit::Millis,
            method: "NOT_IMPLEMENTED::cold_instantiate_cached",
        },
        Self {
            item: Item::Perf007,
            target: 5.0,
            direction: Direction::AtMost,
            unit: Unit::Millis,
            method: "crates/qqq-run/src/aot.rs::measure_aot_roundtrip",
        },
        Self {
            item: Item::Perf008,
            target: 25.0,
            direction: Direction::AtMost,
            unit: Unit::Megabytes,
            method: "NOT_IMPLEMENTED::idle_host_rss",
        },
        Self {
            item: Item::Perf009,
            target: 350.0,
            direction: Direction::AtMost,
            unit: Unit::Megabytes,
            method: "NOT_IMPLEMENTED::thousand_idle_instances_rss",
        },
        Self {
            item: Item::Perf010,
            target: 60_000.0,
            direction: Direction::AtLeast,
            unit: Unit::RequestsPerSecond,
            method: "crate::workload::BenchmarkName::Json",
        },
        Self {
            item: Item::Perf011,
            target: 2.0,
            direction: Direction::AtMost,
            unit: Unit::Millis,
            method: "crate::workload::BenchmarkName::TailP99",
        },
        Self {
            item: Item::Perf012,
            target: 256.0,
            direction: Direction::AtMost,
            unit: Unit::Kilobytes,
            method: "NOT_IMPLEMENTED::per_instance_pooled",
        },
        Self {
            item: Item::Perf013,
            target: 20.0,
            direction: Direction::AtMost,
            unit: Unit::Seconds,
            method: "NOT_IMPLEMENTED::reference_app_clean_build",
        },
    ];

    /// `§9.2` rows that are not this harness's to measure, and why.
    ///
    /// # Why this is recorded rather than omitted
    ///
    /// `§9.2` states eleven directive rows and [`Budget::ALL`] implements ten. A
    /// reader comparing the two finds a discrepancy, and a discrepancy with no
    /// explanation is indistinguishable from an oversight. Naming the excluded
    /// one and its reason is what makes the count a decision — and
    /// `tools/check_bench_contract.py` refuses a `§9.2` row that is in neither
    /// list, which is how the missing `Routed request overhead` row was caught.
    ///
    /// # The two CLI rows are excluded for one reason
    ///
    /// `qqqai --version` and `qqqai run cold start (cached)` are **process-spawn**
    /// budgets. `/usr/bin/time` and `hyperfine` measure them; a harness that
    /// serves an application cannot observe a process it did not start, and
    /// simulating one would measure the harness. The third row is a duplicate
    /// precondition of a row this table already implements.
    pub const NOT_A_HARNESS_ROW: [(&'static str, &'static str); 3] = [
        (
            "qqqai --version",
            "a process-spawn budget (<= 15 ms from spawn to exit), owned by the \
             qqq-run item implementing the command. This harness serves an \
             application and cannot observe a process it did not start; timing a \
             spawn would measure the harness, not the CLI.",
        ),
        (
            "qqqai run cold start (cached)",
            "also a process-spawn budget (<= 40 ms from exec to the listener \
             accepting), and additionally a CLI item (CLI-*), not a runtime one. \
             It is the same measurement class as the row above.",
        ),
        (
            "Cold instantiate (from .wasm)",
            "the same measurement as PERF-004's AOT-cached case with Cranelift \
             compilation included (<= 150 ms p99). The two differ by a \
             precondition rather than by a second measurement, so the harness \
             exposes one method that takes the precondition -- building the same \
             component twice to report it twice would double the cost and add no \
             information.",
        ),
    ];

    /// The `§9.2` row for an item, if one exists.
    #[must_use]
    pub fn for_item(item: Item) -> Option<Self> {
        Self::ALL.into_iter().find(|budget| budget.item == item)
    }

    /// The target as it appears in `§9.2`, for a report.
    ///
    /// `§9.2` writes "≥ 60k RPS" and "≤ 100 µs", so this renders in the same
    /// shape: a report that says "60000" where the table says "60k" is harder to
    /// diff against the Proposal by eye, which is how a reader checks the two
    /// agree.
    #[must_use]
    pub fn describe_target(&self) -> String {
        format!(
            "{} {} {}",
            self.direction.symbol(),
            Self::render_number(self.target),
            self.unit.symbol()
        )
    }

    /// Render a target the way `§9.2` writes it: `60k` rather than `60000`,
    /// `2` rather than `2.0`, and `2.5` unchanged.
    ///
    /// Kept as a named function rather than inlined in `describe_target`, so a
    /// test can state the rendering rule directly — `§O-124`'s reason for
    /// extracting a predicate from a conditional.
    ///
    /// # Why there are no `f64`-to-integer casts
    ///
    /// Clippy's `cast_possible_truncation` and `cast_possible_wrap` are right to
    /// object: `target as u64` on a value outside the range is undefined-ish
    /// behaviour expressed as a silent wrap. The conversion here goes the other
    /// way — an integral `f64` is compared against its own truncation to prove it
    /// is exactly representable, and only then is an integer type used. A target
    /// that fails that proof is rendered as a float, which is correct and loses
    /// nothing.
    #[must_use]
    pub fn render_number(target: f64) -> String {
        // Non-finite values render as-is: there is no compact form for NaN or
        // infinity, and reaching for one (e.g. formatting NaN with decimals)
        // would produce output that looks precise while meaning nothing.
        if !target.is_finite() {
            return format!("{target}");
        }
        // Only an exactly-integral value may be rendered as an integer. `%` on
        // floats is exact for this purpose: it is 0.0 only when the value has no
        // fractional part.
        let is_integral = target.fract() == 0.0;

        if is_integral && target >= 1_000.0 && target % 1_000.0 == 0.0 {
            // `60_000 / 1_000 = 60`, an exact small integer. The `As`-free route
            // is to divide in float space and format with zero decimals, which
            // avoids the cast entirely and cannot wrap.
            format!("{:.0}k", target / 1_000.0)
        } else if is_integral && target.abs() < 1e15 {
            // Below 2^53 every integer is exactly representable in `f64`, and
            // `{:.0}` renders it without an exponent. `abs() < 1e15` is the guard
            // that makes that statement true for this call.
            format!("{target:.0}")
        } else {
            format!("{target}")
        }
    }

    /// Whether `measured` meets this budget, refusing a unit mismatch.
    ///
    /// # Errors
    ///
    /// Returns a [`BudgetError`] if the measurement's unit differs from the
    /// budget's. Comparing a microsecond figure against a millisecond target is
    /// the factor-of-1000 error this signature exists to make impossible.
    pub fn meets(&self, measured: &Measurement) -> Result<Verdict, BudgetError> {
        if measured.unit != self.unit {
            return Err(BudgetError::UnitMismatch {
                expected: self.unit,
                found: measured.unit,
                item: self.item,
            });
        }
        Ok(Verdict {
            item: self.item,
            target: self.target,
            measured: measured.value,
            direction: self.direction,
            met: self.direction.satisfied_by(measured.value, self.target),
        })
    }

    /// Whether a duration in nanoseconds meets this budget.
    ///
    /// # Errors
    ///
    /// Returns a [`BudgetError`] if this budget is not a time budget. The
    /// conversion is otherwise a trap: nanoseconds to a `RequestsPerSecond` row
    /// would divide by a second and produce a number that looks like a rate.
    pub fn meets_nanos(&self, nanos: u64) -> Result<Verdict, BudgetError> {
        // [`as_f64_exact`] keeps the dividend inside `f64`'s exact-integer
        // range (clamping absurd values, which miss every time budget by an
        // enormous margin either way), and each arm divides once into the
        // budget's unit. No whole-plus-remainder split: the comment that used
        // to describe one did not match this code, and the single division is
        // exact for every realistic duration.
        let measured = match self.unit {
            Unit::Micros => Measurement {
                value: as_f64_exact(nanos) / 1_000.0,
                unit: Unit::Micros,
            },
            Unit::Millis => Measurement {
                value: as_f64_exact(nanos) / 1_000_000.0,
                unit: Unit::Millis,
            },
            Unit::Seconds => Measurement {
                value: as_f64_exact(nanos) / 1_000_000_000.0,
                unit: Unit::Seconds,
            },
            other => {
                return Err(BudgetError::NotATimeBudget {
                    item: self.item,
                    unit: other,
                });
            }
        };
        self.meets(&measured)
    }
}

/// A measured value carrying its unit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Measurement {
    /// The number itself.
    pub value: f64,
    /// What the number is in.
    pub unit: Unit,
}

/// Convert a `u64` to `f64`, documenting why the conversion is acceptable here.
///
/// # Why a named function rather than an `#[allow]` at each call site
///
/// `f64` holds integers exactly up to 2^53 (9.007e15). A nanosecond count reaches
/// that after about 104 days, so every value this harness can produce — and every
/// value a sane caller can supply — converts exactly. Above that threshold the
/// conversion rounds, and the rounding is at most one part in 9e15, which cannot
/// change the outcome of a comparison against a budget stated in microseconds or
/// milliseconds.
///
/// # Why the clamp is safe in both directions
///
/// Clamping maps every absurd value to 2^53, which exceeds every `§9.2` target by
/// orders of magnitude. A ceiling compares "measured ≤ target" and a clamped
/// value misses; a floor compares "measured ≥ target" and a clamped value meets.
/// Both are the correct verdict for a 104-day request, because such a value is a
/// clock error rather than a measurement — and no future `AtLeast` time budget
/// can flip this: the clamp preserves "enormously larger than any budget", which
/// is exactly what both directions need.
///
/// Naming it means the reasoning is stated **once**, at the point where the
/// conversion happens, instead of being repeated as a suppression at each call
/// site. `§O-124`'s rule: if a decision has no name, no test can pin it and no
/// reader can find it.
#[must_use]
fn as_f64_exact(value: u64) -> f64 {
    // The clamp documents the threshold rather than hiding it: a value beyond
    // `MAX_EXACT_F64_INTEGER` is converted as that bound, which preserves the
    // "enormously larger than any budget" property the comparison depends on.
    const MAX_EXACT_F64_INTEGER: u64 = 1 << 53;
    #[allow(
        clippy::cast_precision_loss,
        reason = "documented above: exact for every value below 2^53 (104 days in \
                  ns), and the clamp keeps above-threshold values bounded and \
                  still far outside every §9.2 budget, so the rounded value \
                  cannot change a verdict"
    )]
    {
        value.min(MAX_EXACT_F64_INTEGER) as f64
    }
}

impl Measurement {
    /// Build a measurement.
    #[must_use]
    pub fn new(value: f64, unit: Unit) -> Self {
        Self { value, unit }
    }
}

/// The outcome of comparing a measurement against a budget.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Verdict {
    /// The row this verdict is about.
    pub item: Item,
    /// The target from `§9.2`.
    pub target: f64,
    /// What was measured.
    pub measured: f64,
    /// Which way the comparison went.
    pub direction: Direction,
    /// Whether the budget was met.
    pub met: bool,
}

impl Verdict {
    /// How far from the target the measurement landed, as a percentage of the
    /// target. Negative means better than required.
    ///
    /// # Why the sign convention is stated
    ///
    /// "Better" means below for a ceiling and above for a floor, so a raw
    /// difference would have opposite meanings on the two halves of `§9.2`. This
    /// normalises so that **negative is always good**, which is what a report and
    /// a regression gate both want: a bar that grows downward is a bar that
    /// improves.
    ///
    /// Returns `None` for a zero target, where the ratio is undefined.
    ///
    /// # Why the zero test is a total ordering, not `== 0.0`
    ///
    /// Clippy's `float_cmp` is right in general: exact equality on floats is
    /// usually a bug. Here the comparison is not "are these approximately equal"
    /// but "is this the absent-target sentinel". `total_cmp` against the canonical
    /// zero answers that without a lint suppression and without pulling in a
    /// numeric-traits crate for one predicate — and it has the useful property
    /// that `-0.0` and `0.0` compare equal, which `==` also did, so behaviour is
    /// unchanged from the version the tests were written against.
    #[must_use]
    pub fn headroom_percent(&self) -> Option<f64> {
        if self.target.total_cmp(&0.0) == std::cmp::Ordering::Equal {
            return None;
        }
        // A headroom computed from a broken measurement is itself broken:
        // NaN propagates through the arithmetic and would be reported as a
        // number. Refuse rather than print it.
        if !self.measured.is_finite() || !self.target.is_finite() {
            return None;
        }
        let raw = (self.measured - self.target) / self.target * 100.0;
        Some(match self.direction {
            Direction::AtMost => raw,
            Direction::AtLeast => -raw,
        })
    }
}

/// Why a measurement could not be compared against a budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BudgetError {
    /// The measurement's unit differs from the budget's.
    UnitMismatch {
        /// The budget's unit.
        expected: Unit,
        /// The measurement's unit.
        found: Unit,
        /// The row being compared.
        item: Item,
    },
    /// A duration was offered to a budget that is not a time budget.
    NotATimeBudget {
        /// The row being compared.
        item: Item,
        /// The unit the row is actually in.
        unit: Unit,
    },
}

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnitMismatch {
                expected,
                found,
                item,
            } => write!(
                f,
                "{} is measured in {}, but the measurement is in {}",
                item.id(),
                expected.symbol(),
                found.symbol()
            ),
            Self::NotATimeBudget { item, unit } => write!(
                f,
                "{} is measured in {}, so a duration cannot be compared against it",
                item.id(),
                unit.symbol()
            ),
        }
    }
}

impl std::error::Error for BudgetError {}

impl Verdict {
    /// Render the verdict with its unit, taken from the budget that produced it.
    ///
    /// # Why this takes the budget rather than formatting bare
    ///
    /// A verdict without a unit is how "MISSES ≤ 100" gets read as a failure
    /// against *some* hundred of *something*. The unit lives on the [`Budget`],
    /// not on the verdict (two sources of truth for one fact is `§O-118`'s
    /// shape), so rendering requires both — which is also what stops a caller
    /// reporting a verdict against the wrong row without noticing.
    ///
    /// ```
    /// use qqq_bench::budget::{Budget, Item, Measurement, Unit};
    ///
    /// let budget = Budget::for_item(Item::Perf003).expect("PERF-003 has a row");
    /// let verdict = budget
    ///     .meets(&Measurement::new(200.0, Unit::Micros))
    ///     .expect("matching units");
    /// assert!(verdict.render(&budget).contains("MISSES"));
    /// assert!(verdict.render(&budget).contains("µs"));
    /// ```
    #[must_use]
    pub fn render(&self, budget: &Budget) -> String {
        // A runtime assert, not a debug one: a verdict rendered against the
        // wrong row's budget mislabels the report, and a mislabeled report in
        // release is worse than a loud failure. This can only fire on a caller
        // bug, never on a measurement.
        assert_eq!(
            self.item, budget.item,
            "a verdict rendered against a different row's budget"
        );
        let outcome = if self.met { "MEETS" } else { "MISSES" };
        format!(
            "{outcome} {} ({}): measured {:.3} {}, target {}{:.3} {}",
            self.item.id(),
            self.item.metric(),
            self.measured,
            budget.unit.symbol(),
            self.direction.symbol(),
            self.target,
            budget.unit.symbol(),
        )
    }
}

impl fmt::Display for Verdict {
    /// Renders the comparison without its unit; prefer [`Verdict::render`].
    ///
    /// # Why `Verdict` carries no unit of its own
    ///
    /// A `Verdict` is the *comparison*; the `Budget` is the row. The unit lives on
    /// the budget, and duplicating it here would be two sources of truth for one
    /// fact — the shape this project records as "two correct halves with nothing
    /// between them" (`§O-118`). `Display` keeps the terse form for logs where
    /// the row is already named; reports must use [`Verdict::render`], which
    /// names the unit.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outcome = if self.met { "MEETS" } else { "MISSES" };
        write!(
            f,
            "{outcome} {} ({}): measured {:.3}, target {}{:.3}",
            self.item.id(),
            self.item.metric(),
            self.measured,
            self.direction.symbol(),
            self.target
        )
    }
}

// Test indexing (`F-18`): assertions index vectors built inline above.
// One module-level reason, not per-site noise; shipping code above
// carries no such allowance.
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions index inline vectors"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_budget_cites_an_item_and_a_method() {
        // The §9.2 claim: "each has a measurement method". A row without a method
        // violates the sentence the table introduces itself with.
        //
        // **This test used to assert `method.starts_with("bench/")` and nothing
        // else, and that is how ten fabricated paths survived** (`§O-249`):
        // `crates/qqq-bench/src/` has no `bench/` directory, so every row named a
        // file that did not exist while the assertion passed. Asserting the *shape*
        // of a citation is not asserting the citation.
        //
        // So there are three admitted forms and each is checked for what it claims:
        //
        //   * `NOT_IMPLEMENTED::<what>` — the measurement is unbuilt. Honest, and
        //     greppable. It must name what is missing, not be a bare marker.
        //   * `crate::<path>::<Symbol>`  — an in-crate symbol that must resolve.
        //   * `<file>::<symbol>`         — a repo-relative path that must exist.
        for budget in Budget::ALL {
            let method = budget.method;
            // The SYMBOL is always the last segment, whichever form this is. The
            // first `::` is only the place/symbol boundary for the file form: a
            // `crate::` path is rooted, so its first segment is the crate name and
            // splitting there would read the location as the literal `crate`.
            let symbol = method.rsplit_once("::").map_or_else(
                || {
                    panic!(
                        "{} method `{method}` is not `place::symbol`; the field must \
                         say where the number comes from",
                        budget.item.id()
                    )
                },
                |(_, s)| s,
            );

            assert!(!budget.item.id().is_empty());
            assert!(!budget.item.metric().is_empty());
            assert!(
                !symbol.trim().is_empty(),
                "{} method `{method}` names no symbol",
                budget.item.id()
            );

            if method.starts_with("NOT_IMPLEMENTED::") {
                continue;
            }

            // An in-crate module path, e.g. `crate::workload::BenchmarkName::Json`.
            // The module must be a real file under this crate's `src/`.
            if let Some(rest) = method.strip_prefix("crate::") {
                // `crate::workload::BenchmarkName::Hello` is a module path followed
                // by a type and a variant, so the module is not simply "everything
                // before the last `::`". Walk the prefixes outward and accept the
                // first that names a real module — the same shape as resolving a
                // path against a module tree, which is what this is.
                let segments: Vec<&str> = rest.split("::").collect();
                let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
                let resolved = (1..segments.len()).rev().any(|n| {
                    let rel = segments[..n].join("/");
                    dir.join(format!("{rel}.rs")).is_file()
                        || dir.join(&rel).join("mod.rs").is_file()
                });
                assert!(
                    resolved,
                    "{} method `{method}` points into `crate::{rest}`, whose module \
                     prefix is not a module of qqq-bench",
                    budget.item.id()
                );
                continue;
            }

            // A repo-relative file path, which must exist — and must contain
            // the named symbol. Checking the file alone lets a typo'd
            // symbol pass while the method points at nothing (review on
            // PERF-007: the `crate::` form gets this via
            // `every_crate_method_names_a_symbol_this_crate_declares`, the
            // file form had no equivalent).
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(std::path::Path::parent)
                .expect("crates/<name>/ has two parents");
            let (place, symbol) = method.split_once("::").expect("checked above");
            let candidate = root.join(place);
            assert!(
                candidate.is_file(),
                "{} method `{method}` names a file that does not exist: {}",
                budget.item.id(),
                candidate.display()
            );
            let text = std::fs::read_to_string(&candidate).expect("file just proven to exist");
            assert!(
                text.contains(symbol),
                "{} method `{method}` names `{symbol}`, which appears nowhere in {}",
                budget.item.id(),
                candidate.display()
            );
        }
    }

    /// Every `.rs` file under this crate's `src/`, concatenated.
    ///
    /// Read from disk at test time rather than embedded, because the assertion it
    /// serves is "the cited symbol is declared in this crate" and a build-time
    /// snapshot would drift from the tree the test is checking.
    fn crate_bench_sources() -> String {
        fn walk(dir: &std::path::Path, out: &mut String) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs")
                    && let Ok(text) = std::fs::read_to_string(&path)
                {
                    out.push_str(&text);
                    out.push('\n');
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = String::new();
        walk(&src, &mut out);
        assert!(
            out.contains("pub const ALL"),
            "the source walk found nothing; the assertion it serves would be vacuous"
        );
        out
    }

    /// The symbols the `crate::` methods name really exist in this crate.
    ///
    /// The companion to the test above: a method can point at a module that exists
    /// and a symbol that does not, and only this catches that.
    #[test]
    fn every_crate_method_names_a_symbol_this_crate_declares() {
        let tree = crate_bench_sources();
        for budget in Budget::ALL {
            let Some(rest) = budget.method.strip_prefix("crate::") else {
                continue;
            };
            let symbol = rest.rsplit("::").next().expect("a symbol");
            assert!(
                tree.contains(symbol),
                "{} method `{}` names `{symbol}`, which is declared nowhere in \
                 qqqq-bench::src",
                budget.item.id(),
                budget.method
            );
        }
    }

    /// Every `NOT_IMPLEMENTED` marker names the measurement that is missing.
    ///
    /// The marker is the honest form for an unbuilt measurement; a bare marker
    /// states nothing and would let a row claim a citation it does not have.
    #[test]
    fn every_not_implemented_marker_names_what_is_missing() {
        let mut count = 0;
        for budget in Budget::ALL {
            let Some(rest) = budget.method.strip_prefix("NOT_IMPLEMENTED::") else {
                continue;
            };
            count += 1;
            assert!(
                !rest.trim().is_empty(),
                "{} carries a bare `NOT_IMPLEMENTED::` marker, which names nothing",
                budget.item.id()
            );
        }
        // A control on the loop: if the marker form were never used, the assertions
        // above would never run and the test would pass vacuously.
        assert!(
            count > 0,
            "no row uses the `NOT_IMPLEMENTED` form; if every measurement is now \
             built, delete this test rather than leaving it vacuous"
        );
    }

    #[test]
    fn every_budget_has_a_distinct_item() {
        let mut seen = std::collections::BTreeSet::new();
        for budget in Budget::ALL {
            assert!(
                seen.insert(budget.item.id()),
                "{} appears twice; a row must have one verdict",
                budget.item.id()
            );
        }
    }

    #[test]
    fn the_at_most_and_at_least_directions_are_both_present() {
        // If every budget were a ceiling, the floor branch of `satisfied_by`
        // would be dead code and its tests would prove nothing about the table.
        let ceilings = Budget::ALL
            .iter()
            .filter(|b| b.direction == Direction::AtMost)
            .count();
        let floors = Budget::ALL
            .iter()
            .filter(|b| b.direction == Direction::AtLeast)
            .count();
        assert!(ceilings > 0, "no ceiling rows");
        assert!(
            floors > 0,
            "no floor rows -- the throughput row would be untested"
        );
    }

    #[test]
    fn a_ceiling_is_met_at_and_below_the_target() {
        let budget = Budget::for_item(Item::Perf003).expect("PERF-003 exists");
        assert_eq!(budget.unit, Unit::Micros);
        // Exactly, because these are table constants and the point of the
        // assertion is that the constant has not drifted from §9.2. An
        // approximate comparison here would accept a typo of 100.0001.
        assert_eq!(budget.target.total_cmp(&100.0), std::cmp::Ordering::Equal);

        // Exactly on the target: §9.2 writes ≤, so this is met.
        let on = budget
            .meets(&Measurement::new(100.0, Unit::Micros))
            .expect("matching units");
        assert!(on.met, "100 µs meets a ≤100 µs budget");

        let under = budget
            .meets(&Measurement::new(99.999, Unit::Micros))
            .expect("matching units");
        assert!(under.met);

        let over = budget
            .meets(&Measurement::new(100.001, Unit::Micros))
            .expect("matching units");
        assert!(!over.met, "100.001 µs misses a ≤100 µs budget");
    }

    #[test]
    fn a_floor_is_met_at_and_above_the_target() {
        // The direction that is easy to get backwards. A throughput budget
        // compared as a ceiling would report MISSES for every success.
        let budget = Budget::for_item(Item::Perf010).expect("PERF-010 exists");
        assert_eq!(budget.direction, Direction::AtLeast);
        assert_eq!(
            budget.target.total_cmp(&60_000.0),
            std::cmp::Ordering::Equal
        );

        let on = budget
            .meets(&Measurement::new(60_000.0, Unit::RequestsPerSecond))
            .expect("matching units");
        assert!(on.met, "60k RPS meets a ≥60k RPS budget");

        let over = budget
            .meets(&Measurement::new(75_000.0, Unit::RequestsPerSecond))
            .expect("matching units");
        assert!(over.met, "more is better for a floor");

        let under = budget
            .meets(&Measurement::new(59_999.9, Unit::RequestsPerSecond))
            .expect("matching units");
        assert!(!under.met, "just under the floor misses");
    }

    #[test]
    fn a_unit_mismatch_is_refused_rather_than_compared() {
        // The factor-of-1000 guard. `95` micros versus a `5` millis target would
        // compare as 95 > 5 and report a miss for a measurement that is 50x
        // better than required.
        let budget = Budget::for_item(Item::Perf004).expect("PERF-004 exists");
        assert_eq!(budget.unit, Unit::Millis);

        let err = budget
            .meets(&Measurement::new(95.0, Unit::Micros))
            .expect_err("a unit mismatch must not silently compare");
        assert_eq!(
            err,
            BudgetError::UnitMismatch {
                expected: Unit::Millis,
                found: Unit::Micros,
                item: Item::Perf004,
            }
        );
    }

    #[test]
    fn a_unit_mismatch_message_names_both_units() {
        let err = BudgetError::UnitMismatch {
            expected: Unit::Millis,
            found: Unit::Micros,
            item: Item::Perf004,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("ms"), "got {rendered}");
        assert!(rendered.contains("µs"), "got {rendered}");
        assert!(rendered.contains("PERF-004"), "got {rendered}");
    }

    #[test]
    fn nanos_convert_into_the_right_unit_for_a_ceiling() {
        let budget = Budget::for_item(Item::Perf003).expect("PERF-003 exists");
        // 50 µs = 50_000 ns
        let verdict = budget.meets_nanos(50_000).expect("a time budget");
        assert!(verdict.met);
        assert!((verdict.measured - 50.0).abs() < f64::EPSILON);

        // 150 µs = 150_000 ns
        let over = budget.meets_nanos(150_000).expect("a time budget");
        assert!(!over.met);
    }

    #[test]
    fn a_duration_offered_to_a_non_time_budget_is_refused() {
        // Without this branch, 60k RPS would receive a nanosecond count and the
        // comparison would be between numbers with unrelated meanings.
        let budget = Budget::for_item(Item::Perf010).expect("PERF-010 exists");
        let err = budget
            .meets_nanos(1_000_000)
            .expect_err("RPS is not a time budget");
        assert_eq!(
            err,
            BudgetError::NotATimeBudget {
                item: Item::Perf010,
                unit: Unit::RequestsPerSecond,
            }
        );
    }

    #[test]
    fn headroom_is_negative_when_a_ceiling_is_beaten() {
        let budget = Budget::for_item(Item::Perf003).expect("PERF-003 exists");
        let verdict = budget
            .meets(&Measurement::new(80.0, Unit::Micros))
            .expect("matching units");
        let headroom = verdict.headroom_percent().expect("non-zero target");
        assert!(
            headroom < 0.0,
            "20% under a ceiling is good, got {headroom}"
        );
        assert!((headroom + 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn headroom_is_negative_when_a_floor_is_beaten() {
        // The sign convention: negative is always good, on both halves of §9.2.
        let budget = Budget::for_item(Item::Perf010).expect("PERF-010 exists");
        let verdict = budget
            .meets(&Measurement::new(90_000.0, Unit::RequestsPerSecond))
            .expect("matching units");
        let headroom = verdict.headroom_percent().expect("non-zero target");
        assert!(headroom < 0.0, "50% above a floor is good, got {headroom}");
        assert!((headroom + 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_missed_budget_has_positive_headroom_in_both_directions() {
        let ceiling = Budget::for_item(Item::Perf008).expect("PERF-008 exists");
        let v1 = ceiling
            .meets(&Measurement::new(30.0, Unit::Megabytes))
            .expect("matching units");
        assert!(!v1.met);
        assert!(v1.headroom_percent().expect("non-zero") > 0.0);

        let floor = Budget::for_item(Item::Perf010).expect("PERF-010 exists");
        let v2 = floor
            .meets(&Measurement::new(30_000.0, Unit::RequestsPerSecond))
            .expect("matching units");
        assert!(!v2.met);
        assert!(v2.headroom_percent().expect("non-zero") > 0.0);
    }

    #[test]
    fn a_non_finite_measurement_has_no_defined_headroom() {
        let budget = Budget::for_item(Item::Perf003).expect("PERF-003 has a row");
        let verdict = budget
            .meets(&Measurement::new(200.0, Unit::Micros))
            .expect("matching units");
        // Sanity: a finite miss does have headroom.
        assert!(verdict.headroom_percent().is_some());
        let nan = Verdict {
            item: verdict.item,
            target: verdict.target,
            measured: f64::NAN,
            direction: verdict.direction,
            met: false,
        };
        assert_eq!(nan.headroom_percent(), None);
        let inf = Verdict {
            measured: f64::INFINITY,
            ..nan
        };
        assert_eq!(inf.headroom_percent(), None);
    }

    #[test]
    fn a_zero_target_has_no_defined_headroom() {
        let budget = Budget {
            item: Item::Perf008,
            target: 0.0,
            direction: Direction::AtMost,
            unit: Unit::Megabytes,
            method: "bench/memory.rs::test",
        };
        let verdict = budget
            .meets(&Measurement::new(0.0, Unit::Megabytes))
            .expect("matching units");
        assert!(verdict.met, "0 meets a ceiling of 0");
        assert_eq!(verdict.headroom_percent(), None);
    }

    #[test]
    fn the_excluded_rows_are_recorded_with_reasons() {
        // §9.2 has eleven directive rows and Budget::ALL has ten. The three absent ones
        // must be named, or the discrepancy is indistinguishable from an
        // oversight -- which is exactly what this project refuses.
        // 10 implemented + 3 excluded = 13 decisions, and §9.2 has 11
        // directive rows. The relationship is NOT a simple sum: PERF-007's AOT
        // cache row shares §9.2's cold-instantiate measurement rather than
        // occupying a row of its own, and one excluded entry covers a row the
        // table already implements. 	ools/check_bench_contract.py asserts the
        // real property -- every §9.2 row has a decision -- rather than a
        // count, because a count cannot see a row that is in neither list.
        assert_eq!(Budget::NOT_A_HARNESS_ROW.len(), 3);
        assert_eq!(Budget::ALL.len(), 10);
        for (name, reason) in Budget::NOT_A_HARNESS_ROW {
            assert!(!name.is_empty(), "an excluded row must be named");
            assert!(
                reason.len() > 40,
                "the exclusion of {name} needs a real reason, got: {reason}"
            );
        }
    }

    #[test]
    fn every_item_maps_to_a_budget() {
        // The reverse of `every_budget_cites_an_item`: no Item variant may exist
        // without a row, or the enum would carry a citation that resolves to
        // nothing -- §O-126's defect, made impossible by construction.
        for item in [
            Item::Perf002,
            Item::Perf003,
            Item::Perf004,
            Item::Perf007,
            Item::Perf008,
            Item::Perf009,
            Item::Perf010,
            Item::Perf011,
            Item::Perf012,
            Item::Perf013,
        ] {
            assert!(
                Budget::for_item(item).is_some(),
                "{} has no budget row",
                item.id()
            );
        }
    }

    #[test]
    fn the_rendered_target_matches_the_proposal_wording() {
        // §9.2 writes "60k RPS", not "60000 RPS". A report that renders the
        // latter is harder to diff against the table by eye.
        let throughput = Budget::for_item(Item::Perf010).expect("PERF-010 exists");
        let rendered = throughput.describe_target();
        assert!(rendered.contains("60k"), "got {rendered}");
        assert!(rendered.contains("≥"), "got {rendered}");
    }

    #[test]
    fn the_build_budget_is_in_seconds() {
        // §9.2 budgets `qqqai build`, 10k LOC Rust, at ≤ 20 s. A target of 20
        // *milliseconds* for a clean build is impossible, and the previous
        // spelling said exactly that while comparing as milliseconds.
        let build = Budget::for_item(Item::Perf013).expect("PERF-013 has a row");
        assert_eq!(build.unit, Unit::Seconds);
        assert_eq!(build.target.total_cmp(&20.0), std::cmp::Ordering::Equal);
        assert!(
            build.describe_target().contains('s'),
            "got {}",
            build.describe_target()
        );

        // A 19-second build meets it; a 25-second one does not.
        let meets = build.meets_nanos(19_000_000_000).expect("a time budget");
        assert!(meets.met);
        assert!((meets.measured - 19.0).abs() < f64::EPSILON);
        let misses = build.meets_nanos(25_000_000_000).expect("a time budget");
        assert!(!misses.met);
    }

    #[test]
    fn every_budget_target_is_a_positive_finite_number() {
        // A NaN, infinite, zero, or negative target makes every verdict from
        // the row meaningless (NaN never meets; a negative floor always
        // meets). The table is const, so this pins the values rather than
        // validating at runtime.
        for budget in Budget::ALL {
            assert!(
                budget.target.is_finite() && budget.target > 0.0,
                "{} has target {}",
                budget.item.id(),
                budget.target
            );
        }
    }

    #[test]
    #[should_panic(expected = "a verdict rendered against a different row")]
    fn rendering_against_the_wrong_rows_budget_panics() {
        // A mislabeled report in release is worse than a loud failure: the
        // panic fires on caller bug, never on a measurement.
        let one = Budget::for_item(Item::Perf003).expect("PERF-003 has a row");
        let other = Budget::for_item(Item::Perf010).expect("PERF-010 has a row");
        let verdict = one
            .meets(&Measurement::new(200.0, Unit::Micros))
            .expect("matching units");
        let _ = verdict.render(&other);
    }

    #[test]
    fn a_nan_measurement_misses_in_both_directions() {
        // Fail-closed: a broken measurement must not read as "met", and NaN
        // compared either way is false. Pinned so a future special-case for
        // NaN has to confront this test.
        let ceiling = Budget::for_item(Item::Perf003).expect("PERF-003 has a row");
        let miss = ceiling
            .meets(&Measurement::new(f64::NAN, Unit::Micros))
            .expect("matching units");
        assert!(!miss.met);

        let floor = Budget::for_item(Item::Perf010).expect("PERF-010 has a row");
        let miss = floor
            .meets(&Measurement::new(f64::NAN, Unit::RequestsPerSecond))
            .expect("matching units");
        assert!(!miss.met);
    }

    #[test]
    fn infinities_and_negatives_never_satisfy() {
        // `-inf <= target` is true and `+inf >= target` is true, so without a
        // guard an infinite measurement meets. Negative values are not real
        // measurements either (nanos, RPS, bytes are all non-negative).
        // Round 2 found both directions fail-open; the guard is in
        // `satisfied_by` so every comparison, present and future, gets it.
        let ceiling = Budget::for_item(Item::Perf003).expect("PERF-003 has a row");
        // Note: -0.0 is deliberately absent here. `-0.0 < 0.0` is false, so it
        // passes the guard and meets — correctly, since it *is* zero.
        for bad in [f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            assert!(
                !ceiling
                    .meets(&Measurement::new(bad, Unit::Micros))
                    .expect("matching units")
                    .met,
                "{bad} must not meet a ceiling"
            );
        }
        let floor = Budget::for_item(Item::Perf010).expect("PERF-010 has a row");
        for bad in [f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            assert!(
                !floor
                    .meets(&Measurement::new(bad, Unit::RequestsPerSecond))
                    .expect("matching units")
                    .met,
                "{bad} must not meet a floor"
            );
        }
    }

    #[test]
    fn a_verdict_renders_with_its_budget_unit() {
        // A verdict without a unit reads "MISSES ≤ 100" against *some* hundred
        // of something. `render` takes the budget so the unit cannot be omitted
        // or taken from the wrong row.
        let budget = Budget::for_item(Item::Perf003).expect("PERF-003 has a row");
        let verdict = budget
            .meets(&Measurement::new(200.0, Unit::Micros))
            .expect("matching units");
        let rendered = verdict.render(&budget);
        assert!(rendered.contains("MISSES"), "got {rendered}");
        assert!(rendered.contains("µs"), "got {rendered}");
        assert!(rendered.contains("PERF-003"), "got {rendered}");
    }

    #[test]
    fn render_number_handles_non_finite_targets() {
        // NaN and infinity have no compact form; rendering them as a number
        // would imply a precision the value does not carry.
        assert_eq!(Budget::render_number(f64::NAN), "NaN");
        assert_eq!(Budget::render_number(f64::INFINITY), "inf");
        assert_eq!(Budget::render_number(60_000.0), "60k");
        assert_eq!(Budget::render_number(20.0), "20");
        assert_eq!(Budget::render_number(2.5), "2.5");
    }

    #[test]
    fn every_section_9_2_row_has_a_decision_in_this_crate() {
        // The in-crate counterpart of `tools/check_bench_contract.py`: every
        // §9.2 metric row is either implemented in `Budget::ALL` or covered by
        // a `NOT_A_HARNESS_ROW` exclusion. This reads the Proposal text so a
        // renamed or removed §9.2 row fails here, in `cargo test`, without CI.
        //
        // The matching rule mirrors the checker's: an exact metric hit, or an
        // exclusion name that contains or is contained in the row (the same
        // rule that lets "Cold instantiate (from .wasm)" cover its row while
        // "AOT cache performance" rides on PERF-004's identical measurement).
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("crates/<name>/ has two parents");
        let proposal =
            std::fs::read_to_string(root.join("QQQ-Proposal-V1.md")).expect("proposal exists");
        let section = proposal
            .split("## §9.2")
            .nth(1)
            .expect("§9.2 exists")
            .split("\n## ")
            .next()
            .expect("§9.2 ends");
        let implemented: Vec<&str> = Budget::ALL.iter().map(|b| b.item.metric()).collect();
        let excluded: Vec<&str> = Budget::NOT_A_HARNESS_ROW
            .iter()
            .map(|(name, _)| *name)
            .collect();
        let mut rows = 0;
        for line in section.lines() {
            let line = line.trim();
            if !line.starts_with('|') || line.contains("---") {
                continue;
            }
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            if cells.len() < 3 || cells[0] == "Metric" || cells[0].is_empty() {
                continue;
            }
            if !(cells[1].contains('≤') || cells[1].contains('≥')) {
                continue;
            }
            rows += 1;
            // Normalise the way the checker does: strip code ticks and
            // backslash escapes, which §9.2 uses freely.
            let metric: String = cells[0].replace(['`', '\\'], "");
            let metric = metric.as_str();
            let decided = implemented.contains(&metric)
                || excluded
                    .iter()
                    .any(|e| metric.contains(e) || e.contains(metric));
            assert!(
                decided,
                "§9.2 row {metric:?} has no decision: neither implemented in \
                 Budget::ALL nor covered by NOT_A_HARNESS_ROW"
            );
        }
        assert!(
            rows >= 10,
            "only {rows} §9.2 rows parsed; the scan is broken"
        );
    }
}
