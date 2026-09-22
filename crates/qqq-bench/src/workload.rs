// SPDX-License-Identifier: Apache-2.0

//! The ten `§9.1` benchmarks, as data.
//!
//! # Why the workloads are a table and not ten functions
//!
//! `§9.1` states ten rows; each names *what it measures* and *our expected
//! position*. The tempting implementation is ten functions that each do the
//! right thing, and it has two defects this repository has already paid for:
//!
//! 1. **Completeness becomes unprovable.** "Did we implement all ten?" is then a
//!    question answered by reading the file, and a missing one looks exactly like
//!    a workload that happens not to be called.
//! 2. **The mapping to `§9.2` disappears.** Four `§9.2` budgets name a specific
//!    `§9.1` workload as their measurement method (`json`, `tailp99`, and the
//!    reference app generally). A table lets `tools/check_bench_contract.py`
//!    verify that mapping; ten loose functions do not.
//!
//! So [`Workload::ALL`] is the table, [`Workload::SPECIFICATION_COUNT`] is the
//! checkable claim that it holds ten, and `crates/qqq-bench/src/workload.rs`'s
//! tests compare it against [`BenchmarkName::all_specified`] — two independent
//! statements of the same fact, which is what makes the comparison worth making
//! (`§O-149`: a list verified against itself verifies nothing).
//!
//! # Where the paths come from
//!
//! **Not from this file.** The reference application declares, on each of its own
//! routes, which `§9.1` benchmark that route implements
//! (`examples/orders-api/src/router.rs`, the `benchmark` field). The harness says
//! *which benchmark to run*; the app says *what reaches it*. A harness that
//! hard-coded `/orders/42` would be a second copy of a fact the app owns, and the
//! two would drift — the defect shape recorded twice in the previous round
//! (`§O-161`, `§O-162`).

use crate::methodology::{BenchmarkName, Concurrency, Warmup};

/// How a workload is driven.
///
/// # Why this is a type and not a duration
///
/// `§9.1`'s rows are not the same *kind* of measurement, and an earlier design
/// that treated them as "run for N seconds" got `cold` wrong: "instantiate and
/// serve once" is a single request, and driving it under load measures something
/// else entirely. The variant makes the distinction structural, so a workload
/// cannot accidentally be given the wrong shape by a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// One request, measured. `cold`.
    SingleShot,
    /// A fixed number of requests, measured individually. Latency rows.
    Fixed {
        /// How many requests to send.
        requests: u32,
    },
    /// Sustained load for a fixed duration. Throughput and tail-latency rows.
    Sustained {
        /// How long to drive, in seconds.
        seconds: u32,
    },
}

impl Shape {
    /// Whether this shape warms the connection before measuring.
    ///
    /// [`Shape::SingleShot`] does not, and that is the point of the variant.
    #[must_use]
    pub fn warms(self) -> bool {
        !matches!(self, Self::SingleShot)
    }
}

/// One `§9.1` benchmark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workload {
    /// The `§9.1` name, reusing the harness's closed enum so a workload cannot be
    /// named something `§9.1` does not contain.
    pub name: BenchmarkName,
    /// What `§9.1` says this row measures, verbatim from the Proposal's table.
    ///
    /// Carried rather than re-derived: a report that states what was measured is
    /// `§9.1`'s methodology requirement applied one level down, and quoting the
    /// Proposal is the only way to be sure the row still means what it says.
    pub measures: &'static str,
    /// What `§9.1` predicts QQQ's position to be, verbatim.
    ///
    /// Included because `§9.1` publishes losses as well as wins: `hello` is
    /// expected to be **behind Bun**. A report that omitted the expectation could
    /// not be checked against the outcome, and the two rows where QQQ expects to
    /// lose are the ones that make the other eight credible.
    pub expected: &'static str,
    /// The request shape.
    pub shape: Shape,
    /// How many requests are in flight at once.
    ///
    /// Per-workload, because the rows demand different answers: `multi` is
    /// literally "saturate 8 cores" while `cold` is meaningless under load.
    pub concurrency: Concurrency,
    /// How the run is warmed.
    pub warmup: Warmup,
    /// The HTTP method.
    pub method: &'static str,
    /// The request body, if any.
    pub body: Option<&'static str>,
}

/// The number of rows `§9.1` states.
///
/// Named so the claim is checkable in one place. A test compares it against
/// [`Workload::ALL`]'s length *and* against
/// [`BenchmarkName::all_specified`]'s, so the three agree.
pub const SPECIFICATION_COUNT: usize = 10;

/// The same specification, promoted to a `static` so it can be borrowed for
/// `'static`.
///
/// # Why both a `const` and a `static` exist
///
/// They serve different callers and neither can replace the other:
///
/// * [`Workload::ALL`] is a `const`, which makes `SPECIFICATION_COUNT` a
///   compile-time fact and lets a caller take the values by move.
/// * this is a `static`, which is what lets [`Workload::find`] return
///   `&'static Self`. A `const`'s value is a *temporary* at each use site, so
///   returning a reference into it is rejected — *"cannot return value referencing
///   temporary value"*, which is the error the first version of `find` produced.
///
/// It is at module scope rather than an associated static because Rust does not
/// allow associated `static` items in an `impl` block — the second error this
/// change produced, and a cheap one to accept.
///
/// Two names for one array is a duplication risk, so a test asserts they are equal
/// element-wise. Same reasoning as keeping `BenchmarkName::all_specified` and this
/// table as independent statements compared by test rather than deriving one from
/// the other (`§O-149`).
pub static TABLE: [Workload; SPECIFICATION_COUNT] = Workload::ALL;

impl Workload {
    /// Every `§9.1` workload, in the Proposal's order.
    ///
    /// # Why `warmup` is spelled out per row rather than defaulted
    ///
    /// `§9.1` requires the warmup procedure be **stated**, and `cold` is the row
    /// where the stated answer is "none" — `Warmup::None` with a justification,
    /// which `PERF-001` modelled as an explicit variant for exactly this case. A
    /// default would make "deliberately not warmed" and "not recorded" the same
    /// value.
    ///
    /// # Why the concurrency differs so sharply
    ///
    /// `hello`, `json`, `route` and `db` are latency measurements: one request at
    /// a time, so the percentile describes a single request's experience.
    /// `multi` is the opposite — `§9.1` says "saturate 8 cores", so its
    /// concurrency is [`Concurrency::Saturating`] and the number reported is a
    /// rate rather than a latency. `tailp99` is a *tail* measurement, which only
    /// exists under load, so it is sustained at a fixed level. Treating them all
    /// as "8 connections" would make three of the ten rows measure the wrong
    /// thing while looking correct.
    pub const ALL: [Self; SPECIFICATION_COUNT] = [
        Self {
            name: BenchmarkName::Hello,
            measures: "Raw framework + runtime overhead",
            expected: "Behind Bun, near/above Node",
            shape: Shape::Fixed { requests: 2_000 },
            concurrency: Concurrency::Sequential,
            warmup: Warmup::Discard { iterations: 200 },
            method: "GET",
            body: None,
        },
        Self {
            name: BenchmarkName::Json,
            measures: "Serialization + ABI",
            expected: "Ahead",
            shape: Shape::Fixed { requests: 2_000 },
            concurrency: Concurrency::Sequential,
            warmup: Warmup::Discard { iterations: 200 },
            method: "GET",
            body: None,
        },
        Self {
            name: BenchmarkName::Route,
            measures: "Routing",
            expected: "Ahead",
            shape: Shape::Fixed { requests: 2_000 },
            concurrency: Concurrency::Sequential,
            warmup: Warmup::Discard { iterations: 200 },
            method: "GET",
            body: None,
        },
        Self {
            name: BenchmarkName::Db,
            measures: "Real I/O + pooling",
            expected: "Ahead (pool reuse, no GC)",
            shape: Shape::Fixed { requests: 2_000 },
            concurrency: Concurrency::Sequential,
            warmup: Warmup::Discard { iterations: 200 },
            method: "GET",
            body: None,
        },
        Self {
            name: BenchmarkName::Crypto,
            measures: "Compiled compute",
            expected: "Far ahead",
            shape: Shape::Fixed { requests: 500 },
            concurrency: Concurrency::Sequential,
            warmup: Warmup::Discard { iterations: 50 },
            method: "POST",
            body: Some("seed=1KB-of-input-for-the-hash-workload-0123456789"),
        },
        Self {
            name: BenchmarkName::Template,
            measures: "String building",
            expected: "Ahead",
            shape: Shape::Fixed { requests: 1_000 },
            concurrency: Concurrency::Sequential,
            warmup: Warmup::Discard { iterations: 100 },
            method: "GET",
            body: None,
        },
        Self {
            name: BenchmarkName::Cpu,
            measures: "Pure compute",
            expected: "Far ahead",
            shape: Shape::Fixed { requests: 200 },
            concurrency: Concurrency::Sequential,
            warmup: Warmup::Discard { iterations: 20 },
            method: "GET",
            body: None,
        },
        Self {
            name: BenchmarkName::Multi,
            measures: "Concurrency model",
            expected: "Ahead (no single-threaded event loop)",
            shape: Shape::Sustained { seconds: 10 },
            concurrency: Concurrency::Saturating { cores: 8 },
            warmup: Warmup::Duration { millis: 1_000 },
            method: "GET",
            body: None,
        },
        Self {
            name: BenchmarkName::TailP99,
            measures: "Tail latency",
            // `§9.1` states a 30-minute run. Ten seconds is the default so the
            // command is usable interactively; `PERF-023` owns the 30-minute soak
            // and `--seconds` raises this deliberately rather than by accident.
            expected: "Far ahead (no GC)",
            shape: Shape::Sustained { seconds: 10 },
            concurrency: Concurrency::Fixed { connections: 64 },
            warmup: Warmup::Duration { millis: 2_000 },
            method: "GET",
            body: None,
        },
        Self {
            name: BenchmarkName::Cold,
            measures: "Cold start",
            expected: "Far ahead vs containers; comparable vs Bun",
            shape: Shape::SingleShot,
            concurrency: Concurrency::Sequential,
            // The row is "instantiate and serve once". Warming would measure the
            // opposite of what it claims, so the absence is deliberate and the
            // reason is required by `Warmup::None`'s shape.
            //
            // `Cow::Borrowed` rather than a bare literal because the field is a
            // `Cow<'static, str>`: borrowed here, owned when deserialized. See the
            // field's own docs for why neither `String` nor `&'static str` works.
            warmup: Warmup::None {
                justification: std::borrow::Cow::Borrowed(
                    "cold start: warming would measure the opposite of what this row claims",
                ),
            },
            method: "GET",
            body: None,
        },
    ];

    /// The path template for this workload, or `None` if the application does not
    /// declare one.
    ///
    /// # Why the harness asks the app rather than deciding
    ///
    /// The mapping from a `§9.1` name to a URL is a fact about the *application*,
    /// not about the harness. `examples/orders-api` declares it on its own routes.
    /// This function is a thin lookup so the caller does not have to know that;
    /// the authority remains the app.
    ///
    /// # Why this reads a `static` and not the `const`
    ///
    /// `Workload::ALL` is a `const`, so every mention of it produces a *temporary*.
    /// Returning a reference into a temporary is rejected — *"cannot return value
    /// referencing temporary value"* — and the first version of this function had
    /// exactly that error. [`Workload::TABLE`] is the same data promoted to a
    /// `static`, so a reference to it is `'static` and the lookup is sound. The
    /// `const` remains for callers that want the values (and for the length, which
    /// must be a compile-time constant), and a test asserts the two agree so the
    /// promotion cannot become a second, drifting copy.
    #[must_use]
    pub fn find(name: &BenchmarkName) -> Option<&'static Self> {
        TABLE.iter().find(|w| &w.name == name)
    }

    /// The `§9.1` name as a string.
    #[must_use]
    pub fn name_str(&self) -> String {
        self.name.as_str().into_owned()
    }

    /// A one-line rendering of the request this workload sends.
    #[must_use]
    pub fn describe_request(&self) -> String {
        match self.body {
            Some(body) => format!("{} {} ({} byte body)", self.method, self.name, body.len()),
            None => format!("{} {}", self.method, self.name),
        }
    }
}

/// The `§9.1` workloads in the order the Proposal lists them, as bare names.
///
/// A convenience for a report's completeness check. Derived from
/// [`Workload::ALL`] rather than written out, because a second hand-written list
/// of the same ten names is the drift this round has already recorded twice.
#[must_use]
pub fn specification_names() -> Vec<BenchmarkName> {
    Workload::ALL.iter().map(|w| w.name.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn there_are_exactly_ten_workloads() {
        // §9.1's table has ten rows. The constant and the array are compared so a
        // row added to one and not the other fails here rather than in a report.
        assert_eq!(Workload::ALL.len(), SPECIFICATION_COUNT);
    }

    #[test]
    fn the_static_matches_the_const_element_for_element() {
        // Two names for one array. `ALL` is what `SPECIFICATION_COUNT` is checked
        // against and what a caller takes by move; `TABLE` is what `find` borrows
        // for `'static`. They are the same data today, and this is the assertion
        // that keeps them the same data tomorrow -- the alternative to a test here
        // is discovering the drift as a benchmark that measures a row the harness
        // and the report disagree about.
        assert_eq!(TABLE.len(), Workload::ALL.len());
        for (from_static, from_const) in TABLE.iter().zip(Workload::ALL.iter()) {
            assert_eq!(
                from_static.name, from_const.name,
                "TABLE and ALL disagree about a row's name"
            );
            assert_eq!(
                from_static.shape, from_const.shape,
                "{}: TABLE and ALL disagree about the shape",
                from_static.name
            );
            assert_eq!(
                from_static.concurrency, from_const.concurrency,
                "{}: TABLE and ALL disagree about concurrency",
                from_static.name
            );
            assert_eq!(
                from_static.warmup, from_const.warmup,
                "{}: TABLE and ALL disagree about warmup",
                from_static.name
            );
            assert_eq!(
                from_static.method, from_const.method,
                "{}: TABLE and ALL disagree about the method",
                from_static.name
            );
            assert_eq!(
                from_static.body, from_const.body,
                "{}: TABLE and ALL disagree about the body",
                from_static.name
            );
        }
    }

    #[test]
    fn the_workloads_are_exactly_the_ten_specification_benchmarks() {
        // Two independent statements of one fact: this table, and the closed enum
        // `PERF-001` built from the Proposal. Comparing them is the check; a list
        // derived from itself would verify nothing (§O-149).
        let from_table = specification_names();
        let from_enum: Vec<BenchmarkName> = BenchmarkName::all_specified().into_iter().collect();
        assert_eq!(
            from_table, from_enum,
            "the workload table and BenchmarkName::all_specified disagree"
        );
    }

    #[test]
    fn the_names_match_the_proposals_spelling_and_order() {
        // Pinned literally, because §9.1's order is deliberate: a report that
        // lists the ten in Proposal order is diffable against the table by eye,
        // which is how a reader checks that all ten ran.
        let names: Vec<String> = Workload::ALL.iter().map(Workload::name_str).collect();
        assert_eq!(
            names,
            vec![
                "hello", "json", "route", "db", "crypto", "template", "cpu", "multi", "tailp99",
                "cold"
            ]
        );
    }

    #[test]
    fn every_workload_carries_its_measures_and_expected_text() {
        // §9.1 states both columns for every row. Empty strings would satisfy the
        // struct and state nothing, which is the vacuity failure this project
        // refuses everywhere else.
        for workload in Workload::ALL {
            assert!(
                !workload.measures.trim().is_empty(),
                "{} has no `measures` text",
                workload.name
            );
            assert!(
                !workload.expected.trim().is_empty(),
                "{} has no `expected` text",
                workload.name
            );
            assert!(
                workload.method.chars().all(|c| c.is_ascii_uppercase()),
                "{} has a non-uppercase method '{}'",
                workload.name,
                workload.method
            );
        }
    }

    #[test]
    fn cold_is_the_only_single_shot_and_it_does_not_warm_up() {
        // The row is "instantiate and serve once". Warming it, or driving it under
        // load, would measure something else while reporting the `cold` number.
        let single: Vec<&Workload> = Workload::ALL
            .iter()
            .filter(|w| w.shape == Shape::SingleShot)
            .collect();
        assert_eq!(single.len(), 1, "exactly one row is a single shot");
        assert_eq!(single[0].name, BenchmarkName::Cold);
        assert!(
            single[0].warmup.is_none(),
            "cold must state that it deliberately does not warm up"
        );
        assert!(!single[0].shape.warms(), "SingleShot must not warm");
    }

    #[test]
    fn cold_states_why_it_does_not_warm_up() {
        // `Warmup::None` carries a justification because "deliberately not warmed"
        // and "not recorded" must not be the same value.
        let cold = Workload::find(&BenchmarkName::Cold).expect("cold exists");
        match &cold.warmup {
            Warmup::None { justification } => {
                assert!(
                    justification.len() > 20,
                    "the justification must explain itself, got: {justification}"
                );
            }
            other => panic!("cold must use Warmup::None, found {other:?}"),
        }
    }

    #[test]
    fn every_other_workload_warms_up() {
        // The control for the test above: if every row were `Warmup::None` that
        // test would still pass while proving nothing about `cold` specifically.
        for workload in Workload::ALL {
            if workload.name == BenchmarkName::Cold {
                continue;
            }
            assert!(
                !workload.warmup.is_none(),
                "{} is not a cold-start row and must warm up",
                workload.name
            );
        }
    }

    #[test]
    fn multi_saturates_and_the_latency_rows_do_not() {
        // §9.1's `multi` row is literally "saturate 8 cores". Its concurrency is
        // the one that cannot name a number.
        let multi = Workload::find(&BenchmarkName::Multi).expect("multi exists");
        assert_eq!(multi.concurrency, Concurrency::Saturating { cores: 8 });
        assert_eq!(
            multi.concurrency.level(),
            None,
            "a saturating run has no chosen number"
        );

        // The control: a latency row states exactly one connection, so the two
        // shapes are distinguishable rather than all being the same value.
        let hello = Workload::find(&BenchmarkName::Hello).expect("hello exists");
        assert_eq!(hello.concurrency, Concurrency::Sequential);
        assert_eq!(hello.concurrency.level(), Some(1));
    }

    #[test]
    fn the_sustained_rows_are_the_ones_that_need_load() {
        // `tailp99` is a tail measurement: a tail does not exist at concurrency 1,
        // so a single-connection reading would report a p99 that is really a p50
        // of one request at a time.
        let tail = Workload::find(&BenchmarkName::TailP99).expect("tailp99 exists");
        assert!(matches!(tail.shape, Shape::Sustained { .. }));
        assert!(
            tail.concurrency.level().unwrap_or(0) > 1,
            "a tail-latency row needs more than one connection in flight"
        );

        // And `cold` must not be sustained.
        let cold = Workload::find(&BenchmarkName::Cold).expect("cold exists");
        assert!(!matches!(cold.shape, Shape::Sustained { .. }));
    }

    #[test]
    fn crypto_sends_a_body_and_the_get_rows_do_not() {
        // `crypto` is POST-only in the reference app, and `§9.1` says it hashes
        // 1 KB. A POST with no body would measure an empty hash.
        let crypto = Workload::find(&BenchmarkName::Crypto).expect("crypto exists");
        assert_eq!(crypto.method, "POST");
        assert!(crypto.body.is_some(), "the crypto row must carry a payload");

        for workload in Workload::ALL {
            if workload.method == "GET" {
                assert!(
                    workload.body.is_none(),
                    "{} is a GET and must not carry a body",
                    workload.name
                );
            }
        }
    }

    #[test]
    fn find_returns_the_right_workload_and_refuses_an_extension() {
        for name in BenchmarkName::all_specified() {
            let found = Workload::find(&name).expect("every specification name has a workload");
            assert_eq!(found.name, name);
        }
        // An extension is not a §9.1 row, so it has no workload.
        assert!(Workload::find(&BenchmarkName::Other("invented".to_owned())).is_none());
    }

    #[test]
    fn describe_request_names_the_method_and_mentions_a_body_only_when_there_is_one() {
        let hello = Workload::find(&BenchmarkName::Hello).expect("hello exists");
        assert_eq!(hello.describe_request(), "GET hello");

        let crypto = Workload::find(&BenchmarkName::Crypto).expect("crypto exists");
        let described = crypto.describe_request();
        assert!(described.starts_with("POST "), "got {described}");
        assert!(described.contains("byte body"), "got {described}");
    }
}
