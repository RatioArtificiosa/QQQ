// SPDX-License-Identifier: Apache-2.0

//! The QQQ benchmark harness — `§9.1`'s methodology as a type, `§9.2`'s budgets
//! as data.
//!
//! # What this crate is, and what it deliberately is not
//!
//! `PERF-001` asks for "the benchmark harness with the full published
//! methodology". That is the whole scope: the types that describe a measurement,
//! the statistics that summarise one, and the contract that decides whether a
//! number meets a budget.
//!
//! It is **not** the ten workloads — that is `PERF-002` — and it is **not** any
//! `§9.2` budget, which are `PERF-003` through `PERF-013`. The distinction is
//! load-bearing rather than bureaucratic: a budget item is met by a harness that
//! produces the number and a recorded comparison against the target, never by
//! asserting the target is achievable. Writing a number into the checklist before
//! something produced it would be the first fabricated measurement in a document
//! whose entire value is that its numbers came from commands.
//!
//! # The design in one sentence
//!
//! `§9.1` says a benchmark missing its methodology "is marketing, and we should
//! not publish it" — so the methodology is a **type**, and a result that lacks it
//! does not compile.
//!
//! ```
//! use qqq_bench::methodology::{Concurrency, Methodology, NonClaims, Warmup};
//! use qqq_bench::Environment;
//! use std::collections::BTreeMap;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let environment = Environment::new(
//!     "AMD Ryzen 9 7950X",
//!     16,
//!     64 * 1024 * 1024 * 1024,
//!     "Ubuntu 24.04.1 LTS",
//!     "6.8.0-45-generic",
//!     BTreeMap::from([("rustc".to_owned(), "1.98.0".to_owned())]),
//! )?;
//!
//! // Two repetitions is refused: §9.1 requires "three repetitions with variance".
//! let too_few = Methodology::new(
//!     environment.clone(),
//!     Warmup::Discard { iterations: 100 },
//!     Concurrency::Sequential,
//!     2,
//!     NonClaims::qualified(["nothing yet"])?,
//!     "https://github.com/RatioArtificiosa/QQQ",
//! );
//! assert!(too_few.is_err());
//!
//! // Three is the boundary and is accepted.
//! let methodology = Methodology::new(
//!     environment,
//!     Warmup::Discard { iterations: 100 },
//!     Concurrency::Sequential,
//!     Methodology::REQUIRED_REPETITIONS,
//!     NonClaims::qualified(["this example measures nothing"])?,
//!     "https://github.com/RatioArtificiosa/QQQ",
//! )?;
//! assert_eq!(methodology.repetitions, 3);
//! # Ok(())
//! # }
//! ```
//!
//! # The three prohibitions, and why each is enforced by absence
//!
//! | `§9.1` says | Enforced by |
//! |---|---|
//! | percentiles, **not averages** | [`stats::Distribution`] has no `mean` |
//! | published with **every** result | the elements are fields, not a document |
//! | a "what this does not measure" section | [`methodology::NonClaims`] is required |
//!
//! # Why the `db` caveat lives here
//!
//! `§O-155` and the `SRV-018` checklist entry both record that the `db` workload
//! measures a validated write and an in-guest map lookup — **not** a Postgres
//! round trip — because the host has no `qqq:sql` implementation and `§4.2`
//! creates one store per request. That fact was recorded in prose.
//!
//! `§9.1`'s ninth requirement *is* "what this does not measure", so the honest
//! place for it is a **required field**, where it cannot be lost: a `db` result
//! that omits the disclaimer does not compile. Turning a caveat into a compile
//! error is the most durable form this project has.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod budget;
pub mod loadgen;
pub mod methodology;
pub mod stats;
pub mod workload;

pub use budget::{Budget, BudgetError, Direction, Item, Measurement, Unit, Verdict};
pub use loadgen::{Plan, RunResult, Sample};
pub use methodology::{
    BenchmarkName, Concurrency, Environment, Methodology, MethodologyError, NonClaims, Pinning,
    Warmup,
};
pub use stats::{Distribution, Repetitions};
pub use workload::{Shape, Workload};

/// The URL `§9.1` requires be published with every result, so a reader can audit
/// the harness rather than trust it.
///
/// A single constant rather than a literal at each call site: `§9.1` requires the
/// harness be open source, and a result that pointed somewhere else would be a
/// claim about a different artifact. Named so a test can assert every result
/// carries it.
pub const HARNESS_SOURCE: &str = "https://github.com/RatioArtificiosa/QQQ";

/// The `§9.2` budget table, as the Proposal states it.
///
/// A re-export rather than a second copy: [`Budget::ALL`] is the one table, and a
/// reader wanting it should not have to know which module owns it.
///
/// The length is written as `Budget::ALL.len()` so it cannot drift — an earlier
/// version hard-coded `9` and stopped compiling the moment a row was added, which
/// is the compiler doing its job but is friction with no benefit: there is exactly
/// one table and this is an alias for it.
pub const BUDGETS: [Budget; Budget::ALL.len()] = Budget::ALL;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_harness_source_is_the_repository_that_contains_this_crate() {
        // §9.1: "the benchmark harness itself open source". A URL that pointed
        // elsewhere would make the claim about a different artifact than the one
        // that produced the number.
        assert_eq!(HARNESS_SOURCE, "https://github.com/RatioArtificiosa/QQQ");
    }

    #[test]
    fn the_reexported_budget_table_is_the_same_table() {
        // A re-export that had drifted into a copy would give two sources of
        // truth for one fact.
        assert_eq!(BUDGETS.len(), Budget::ALL.len());
        assert_eq!(BUDGETS[0].item.id(), Budget::ALL[0].item.id());
    }

    #[test]
    fn the_whole_methodology_pipeline_composes() {
        // An end-to-end exercise of the crate's contract, in the shape a real
        // measurement will take: environment, methodology with three
        // repetitions, three distributions, a Repetitions summary, and a budget
        // verdict.
        let environment = Environment::new(
            "AMD Ryzen 9 7950X",
            16,
            64 * 1024 * 1024 * 1024,
            "Ubuntu 24.04.1 LTS",
            "6.8.0-45-generic",
            std::collections::BTreeMap::from([("rustc".to_owned(), "1.98.0".to_owned())]),
        )
        .expect("a complete environment");

        let methodology = Methodology::new(
            environment,
            Warmup::Discard { iterations: 1_000 },
            Concurrency::Fixed { connections: 8 },
            Methodology::REQUIRED_REPETITIONS,
            NonClaims::qualified([
                "does not measure a network round trip",
                "was run on a development machine",
            ])
            .expect("non-blank"),
            HARNESS_SOURCE,
        )
        .expect("a complete methodology");

        // Three runs, each summarising its own samples.
        let mut summaries = Vec::new();
        for run in 0..methodology.repetitions {
            let mut distribution = Distribution::with_capacity(100);
            // `u64::from(run)` rather than `run as u64`: the conversion is
            // infallible and clippy is right that `From` says so.
            let offset = u64::from(run) * 1_000;
            for sample in 0..100_u64 {
                // A stable around 80-90 µs.
                distribution.record_nanos(80_000 + offset + sample);
            }
            summaries.push(distribution.p99().expect("100 samples"));
        }

        let repetitions = Repetitions::new(summaries).expect("three repetitions");

        // The verdict against §9.2's warm-acquire row.
        let budget = Budget::for_item(Item::Perf003).expect("PERF-003 has a row");
        let verdict = budget
            .meets_nanos(repetitions.worst())
            .expect("PERF-003 is a time budget");

        assert!(
            verdict.met,
            "a worst-case p99 of {} ns should meet ≤100 µs",
            repetitions.worst()
        );
        assert!(
            repetitions.spread_percent().expect("non-zero best") < 5.0,
            "the synthesised runs are stable: {repetitions}"
        );
        assert_eq!(methodology.non_claims.len(), 2);
    }
}
