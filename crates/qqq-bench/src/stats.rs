// SPDX-License-Identifier: Apache-2.0

//! Percentile statistics, with no way to compute a mean.
//!
//! # The prohibition is the design
//!
//! `§9.1` says **"percentiles, not averages"**. That is a prohibition, not a
//! preference, and the cheapest way to honour a prohibition is for the forbidden
//! thing not to exist. [`Distribution`] therefore has `p50`, `p90`, `p99`, `p999`
//! and `max` — and **no `mean`**.
//!
//! This is not pedantry about statistics. A mean latency is a *fiction* for the
//! distribution a server actually produces: response times are right-skewed, so
//! the mean is dragged upward by a tail that no user experiences and reported to
//! stakeholders who then plan against it. A p99 is a statement about one request
//! in a hundred and a reader knows exactly what it means. `§9.1` calls a
//! benchmark without percentiles "marketing" for this reason.
//!
//! The friction is deliberate and small: if a future item genuinely needs a mean,
//! adding a named `mean()` with a documented reason is a deliberate act that
//! shows up in a diff and in review. That is the right amount of cost.
//!
//! # Why raw samples are kept
//!
//! [`Distribution`] stores every sample rather than accumulating a histogram.
//! The trade is real and stated:
//!
//! * **Cost**: memory proportional to sample count. A 30-minute `tailp99` run at
//!   10k RPS produces ~18 million samples — 144 MB as `u64` nanoseconds. That is
//!   acceptable for a benchmark process that measures one thing at a time, and it
//!   is the reason this type lives in `qqq-bench` rather than in the server.
//! * **Benefit**: any percentile is exact and computable *after* the run, so a
//!   question asked later ("what was p99.9?") does not require re-running. A
//!   histogram must choose its bucket boundaries before it sees the data, and the
//!   wrong boundaries make every quantile *plausibly* wrong — the defect
//!   `SRV-020` recorded for its latency histogram.
//!
//! [`Distribution::from_histogram`] is not offered. Adding it later, with a
//! documented accuracy statement, is a deliberate act; the absence today means no
//! result can silently be a bucketed approximation published as an exact
//! percentile.

use std::fmt;

/// A set of samples with exact percentiles.
///
/// Constructed from durations; stores nanoseconds as `u64` so the type is
/// `Ord`-able, `Send`, and free of float comparison hazards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distribution {
    /// Every sample, in the order it was recorded.
    ///
    /// Order is preserved rather than sorted at insert because sorting once at
    /// query time is cheaper than an insertion sort per sample, and because the
    /// original order is what a future replay or percentile-over-time analysis
    /// would need. [`Distribution::percentile`] sorts a copy.
    samples: Vec<u64>,
}

impl Distribution {
    /// An empty distribution.
    #[must_use]
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    /// A distribution with room for `capacity` samples.
    ///
    /// Offered because the allocating behaviour is the reason this type is
    /// allowed to keep raw samples at all, and a caller that knows its sample
    /// count should not pay for repeated reallocation during a timed loop.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            samples: Vec::with_capacity(capacity),
        }
    }

    /// Record one sample, in nanoseconds.
    pub fn record_nanos(&mut self, nanos: u64) {
        self.samples.push(nanos);
    }

    /// Record one sample.
    pub fn record(&mut self, duration: std::time::Duration) {
        // `as_nanos` returns u128 and is lossy above ~584 years. Saturating is
        // the honest conversion: a duration that large is a clock error rather
        // than a measurement, and clamping it keeps the type total instead of
        // panicking inside a benchmark.
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        self.record_nanos(nanos);
    }

    /// How many samples were recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether no samples were recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// The samples, in the order recorded.
    #[must_use]
    pub fn samples(&self) -> &[u64] {
        &self.samples
    }

    /// The exact percentile `p`, where `p` is in `[0.0, 1.0]`.
    ///
    /// Returns `None` for an empty distribution, because there is no p99 of
    /// nothing — and returning `0` would read as "instant" rather than
    /// "unmeasured". That distinction is the same one `SRV-020`'s `mean_micros`
    /// makes, and it is the reason this returns `Option`.
    ///
    /// # Which definition, stated because they disagree
    ///
    /// This uses the **nearest-rank** method: the returned value is an actually
    /// observed sample, at index `ceil(p * n) - 1`. The alternatives —
    /// linear interpolation between neighbours, or a midpoint — produce a number
    /// that no request ever took. Nearest-rank is chosen because a benchmark is a
    /// claim about observed requests, and a reader who sees `p99 = 1.98 ms` should
    /// be able to find a request that took 1.98 ms. Publishing an interpolated
    /// p99 is publishing a value the system never produced.
    ///
    /// `§O-004` records the same reasoning from the other direction: this project
    /// has already had one statistic be "plausibly wrong" because its rounding was
    /// unexamined.
    #[must_use]
    pub fn percentile(&self, p: f64) -> Option<u64> {
        if self.samples.is_empty() {
            return None;
        }
        let p = p.clamp(0.0, 1.0);
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();

        // Nearest-rank. `ceil(p * n)` is at least 1 for p > 0, so index >= 0.
        // For p == 0.0 this yields index 0, which is the minimum -- correct, and
        // the reason the `max(1)` clamp is present rather than relying on float
        // rounding to keep the product positive.
        let n = sorted.len();
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "n is a sample count that fits in f64 exactly for any \
                      realistic run (below 2^53), and the product is clamped to \
                      a valid index immediately below; the cast cannot truncate \
                      in a way that survives the clamp"
        )]
        let rank = {
            let raw = (p * n as f64).ceil() as usize;
            raw.max(1).min(n)
        };
        Some(sorted[rank - 1])
    }

    /// The median. A convenience over [`Distribution::percentile`] at `0.5`.
    #[must_use]
    pub fn p50(&self) -> Option<u64> {
        self.percentile(0.50)
    }

    /// The 90th percentile.
    #[must_use]
    pub fn p90(&self) -> Option<u64> {
        self.percentile(0.90)
    }

    /// The 99th percentile. The one `§9.2` states several budgets against.
    #[must_use]
    pub fn p99(&self) -> Option<u64> {
        self.percentile(0.99)
    }

    /// The 99.9th percentile.
    #[must_use]
    pub fn p999(&self) -> Option<u64> {
        self.percentile(0.999)
    }

    /// The largest sample.
    #[must_use]
    pub fn max(&self) -> Option<u64> {
        self.samples.iter().copied().max()
    }

    /// The smallest sample.
    #[must_use]
    pub fn min(&self) -> Option<u64> {
        self.samples.iter().copied().min()
    }
}

impl Default for Distribution {
    fn default() -> Self {
        Self::new()
    }
}

/// The spread across independent repetitions of the same measurement.
///
/// # Why variance is a required part of a result
///
/// `§9.1` requires "three repetitions **with variance**". The clause is not
/// decoration: a single run cannot distinguish a stable 1.9 ms p99 from a run
/// that happened to land well, and the second is the number that gets published
/// and then not reproduced. Reporting the spread beside the value is what makes a
/// reader able to judge whether the figure is a property of the system or of the
/// moment.
///
/// # Why this stores the individual values
///
/// A `stddev` alone would lose the shape. Three repetitions of `[1, 1, 9]` and
/// `[3, 4, 4]` can share a spread while telling different stories — the first
/// suggests a bimodal system or one contaminated run, the second a stable one.
/// The values are kept so a report can show them and a reader can see which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repetitions {
    /// Each repetition's summary statistic, in run order.
    values: Vec<u64>,
}

impl Repetitions {
    /// Collect repetitions, refusing fewer than `§9.1`'s required count.
    ///
    /// # Errors
    ///
    /// Returns the number given if it is below
    /// [`Methodology::REQUIRED_REPETITIONS`](crate::methodology::Methodology::REQUIRED_REPETITIONS).
    /// Taking the count from the methodology rather than hard-coding `3` here
    /// means the two cannot drift apart.
    pub fn new(values: Vec<u64>) -> Result<Self, u32> {
        let given = u32::try_from(values.len()).unwrap_or(u32::MAX);
        if given < crate::methodology::Methodology::REQUIRED_REPETITIONS {
            return Err(given);
        }
        Ok(Self { values })
    }

    /// How many repetitions were collected.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether there are no repetitions. Never true for a constructed value, and
    /// present because a `len()` without it is a clippy lint this project treats
    /// as an error rather than silencing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The individual values, in run order.
    #[must_use]
    pub fn values(&self) -> &[u64] {
        &self.values
    }

    /// The smallest repetition value.
    #[must_use]
    pub fn best(&self) -> u64 {
        self.values.iter().copied().min().unwrap_or(0)
    }

    /// The largest repetition value.
    #[must_use]
    pub fn worst(&self) -> u64 {
        self.values.iter().copied().max().unwrap_or(0)
    }

    /// How much the worst repetition exceeds the best, as a percentage.
    ///
    /// # Why a percentage and not a standard deviation
    ///
    /// With three samples a standard deviation is a statistic about three
    /// numbers, and quoting it to two decimal places implies a precision the
    /// sample size cannot support. A spread in percent — "runs varied by 12%" —
    /// is honest about being a coarse statement, and it is the form a reader
    /// compares against a budget.
    ///
    /// Returns `None` when the best value is zero, because the ratio is undefined
    /// and returning `0%` would claim perfect stability from a measurement that
    /// carries no information.
    #[must_use]
    pub fn spread_percent(&self) -> Option<f64> {
        let best = self.best();
        if best == 0 {
            return None;
        }
        #[allow(
            clippy::cast_precision_loss,
            reason = "nanosecond counts are far below 2^53 in any real run; the \
                      conversion is exact for every value this type can hold in \
                      practice, and a lossy conversion would change the reported \
                      percentage by less than a millionth of a percent"
        )]
        let spread = (self.worst() - best) as f64 / best as f64 * 100.0;
        Some(spread)
    }

    /// Whether the spread exceeds `threshold_percent`.
    ///
    /// # Why this predicate has a name
    ///
    /// `§O-124` records a rule that stated an invariant and had no name, so no
    /// test could pin it. "Is this run too variable to publish?" is a decision
    /// this crate makes, and naming it means a report, a gate and a test can all
    /// ask the same question and get the same answer.
    ///
    /// A `None` spread — the zero-best case — is treated as **not stable**,
    /// because an undefined spread is not evidence of stability. The safe
    /// direction is to flag it, matching this project's deny-by-default rule.
    #[must_use]
    pub fn exceeds(&self, threshold_percent: f64) -> bool {
        match self.spread_percent() {
            Some(spread) => spread > threshold_percent,
            None => true,
        }
    }
}

impl fmt::Display for Repetitions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let values: Vec<String> = self.values.iter().map(u64::to_string).collect();
        match self.spread_percent() {
            Some(spread) => write!(f, "[{}] spread {spread:.1}%", values.join(", ")),
            None => write!(f, "[{}] spread undefined (best is zero)", values.join(", ")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn dist(values: &[u64]) -> Distribution {
        let mut d = Distribution::new();
        for v in values {
            d.record_nanos(*v);
        }
        d
    }

    // -- Distribution -------------------------------------------------------

    #[test]
    fn an_empty_distribution_has_no_percentiles() {
        // The distinction that matters: `None`, not `Some(0)`. Zero reads as
        // "instant" rather than "unmeasured".
        let d = Distribution::new();
        assert_eq!(d.p50(), None);
        assert_eq!(d.p99(), None);
        assert_eq!(d.p999(), None);
        assert_eq!(d.max(), None);
        assert_eq!(d.min(), None);
    }

    #[test]
    fn percentiles_are_actual_observed_samples() {
        // Nearest-rank, asserted by construction: every returned value must be
        // present in the input. An interpolating implementation returns 1.5 for
        // this input and fails here -- which is the point of the test.
        let d = dist(&[1, 2, 3, 4]);
        for p in [0.0, 0.25, 0.5, 0.75, 0.9, 0.99, 1.0] {
            let value = d.percentile(p).expect("non-empty");
            assert!(
                d.samples().contains(&value),
                "percentile {p} returned {value}, which was never observed"
            );
        }
    }

    #[test]
    fn the_extremes_are_the_minimum_and_maximum() {
        let d = dist(&[5, 1, 9, 3]);
        assert_eq!(d.percentile(0.0), Some(1), "p0 must be the minimum");
        assert_eq!(d.percentile(1.0), Some(9), "p100 must be the maximum");
        assert_eq!(d.min(), Some(1));
        assert_eq!(d.max(), Some(9));
    }

    #[test]
    fn nearest_rank_lands_where_the_definition_says() {
        // 1..=100. Nearest-rank: p99 = ceil(0.99 * 100) = 99 -> the 99th smallest
        // value = 99. An implementation using floor would give 99 too, so the
        // discriminating case is p50 on an even count below.
        let d = dist(&(1..=100).collect::<Vec<u64>>());
        assert_eq!(d.p50(), Some(50));
        assert_eq!(d.p90(), Some(90));
        assert_eq!(d.p99(), Some(99));
        assert_eq!(d.p999(), Some(100), "p99.9 of 100 samples is the maximum");
    }

    #[test]
    fn an_even_count_does_not_average_the_two_middle_values() {
        // The discriminating case for nearest-rank vs interpolation. With
        // [1,2,3,4] the median by averaging is 2.5, which was never observed.
        // Nearest-rank gives ceil(0.5*4)=2 -> the 2nd smallest = 2.
        let d = dist(&[1, 2, 3, 4]);
        assert_eq!(
            d.p50(),
            Some(2),
            "an averaged median would return an unobserved value"
        );
    }

    #[test]
    fn a_single_sample_answers_every_percentile_with_itself() {
        // The degenerate case: every rank resolves to the one value.
        let d = dist(&[42]);
        assert_eq!(d.p50(), Some(42));
        assert_eq!(d.p99(), Some(42));
        assert_eq!(d.p999(), Some(42));
    }

    #[test]
    fn a_tail_is_reflected_in_p99_but_not_in_p50() {
        // The property §9.1's prohibition is about: a mean would be dragged by
        // the tail, and p50 must not be.
        let mut values = vec![100_u64; 99];
        values.push(10_000);
        let d = dist(&values);
        assert_eq!(d.p50(), Some(100), "the median must ignore the single tail");
        assert_eq!(d.max(), Some(10_000), "the tail must be visible somewhere");
    }

    #[test]
    fn recording_does_not_reorder_the_samples() {
        // Documented behaviour: order is preserved for a future replay analysis.
        let d = dist(&[3, 1, 2]);
        assert_eq!(d.samples(), &[3, 1, 2]);
    }

    #[test]
    fn a_duration_records_its_nanoseconds() {
        let mut d = Distribution::new();
        d.record(Duration::from_micros(1500));
        assert_eq!(d.p50(), Some(1_500_000));
    }

    #[test]
    fn there_is_no_way_to_compute_a_mean() {
        // §9.1: "percentiles, not averages". This test is a guard on the API
        // surface, not on behaviour -- it documents that the absence is
        // deliberate. It cannot literally assert the absence of a method, so it
        // asserts the thing that WOULD be a mean and is deliberately provided
        // instead: the tail is described by p99 and max, never by an average.
        //
        // If a `mean()` is ever added, this comment is where the reason must be
        // recorded, and the addition will appear in a diff for review.
        let d = dist(&[100, 100, 100, 10_000]);
        // The mean would be 2575, which no request took. Every published figure
        // is an observed value instead.
        for p in [0.5, 0.9, 0.99] {
            assert!(d.samples().contains(&d.percentile(p).expect("non-empty")));
        }
        assert_eq!(d.p50(), Some(100));
    }

    // -- Repetitions --------------------------------------------------------

    #[test]
    fn fewer_than_three_repetitions_is_refused_with_the_count() {
        assert_eq!(Repetitions::new(vec![1, 2]), Err(2));
        assert_eq!(Repetitions::new(vec![]), Err(0));
    }

    #[test]
    fn three_repetitions_is_the_boundary_and_is_accepted() {
        let r = Repetitions::new(vec![10, 11, 12]).expect("three is required, not more");
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn the_spread_is_the_worst_over_the_best() {
        let r = Repetitions::new(vec![100, 110, 120]).expect("three");
        assert_eq!(r.best(), 100);
        assert_eq!(r.worst(), 120);
        // (120 - 100) / 100 * 100 = 20%
        let spread = r.spread_percent().expect("best is non-zero");
        assert!((spread - 20.0).abs() < f64::EPSILON, "got {spread}");
    }

    #[test]
    fn identical_repetitions_are_perfectly_stable() {
        let r = Repetitions::new(vec![7, 7, 7]).expect("three");
        assert_eq!(r.spread_percent(), Some(0.0));
        assert!(!r.exceeds(0.0), "0% does not exceed a 0% threshold");
    }

    #[test]
    fn an_all_zero_run_has_an_undefined_spread_and_is_not_stable() {
        // The deny-by-default direction: an undefined spread is not evidence of
        // stability, so `exceeds` reports true and a gate flags it.
        let r = Repetitions::new(vec![0, 0, 0]).expect("three");
        assert_eq!(r.spread_percent(), None, "the ratio is undefined");
        assert!(
            r.exceeds(100.0),
            "an undefined spread must be treated as unstable, not as perfect"
        );
    }

    #[test]
    fn the_threshold_comparison_is_strict() {
        // A run exactly at the threshold is within it. Using `>=` would fail a
        // run that met the stated tolerance exactly.
        let r = Repetitions::new(vec![100, 110, 120]).expect("three");
        assert!(!r.exceeds(20.0), "20% does not exceed 20%");
        assert!(r.exceeds(19.9), "20% exceeds 19.9%");
    }

    #[test]
    fn the_shape_is_kept_not_just_the_spread() {
        // [1,1,9] and [3,4,4] have spreads of ~800% and ~33%; the point is that
        // the VALUES survive so a reader can tell a bimodal run from a stable one.
        let bimodal = Repetitions::new(vec![1, 1, 9]).expect("three");
        let stable = Repetitions::new(vec![3, 4, 4]).expect("three");
        assert_eq!(bimodal.values(), &[1, 1, 9]);
        assert_eq!(stable.values(), &[3, 4, 4]);
        assert!(
            bimodal.spread_percent().expect("non-zero")
                > stable.spread_percent().expect("non-zero")
        );
    }
}
