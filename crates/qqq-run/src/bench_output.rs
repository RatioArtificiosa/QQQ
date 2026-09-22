// SPDX-License-Identifier: Apache-2.0

//! The `CommandOutput` implementation for `qqqai bench`.
//!
//! # Why this lives in its own file
//!
//! `bench.rs` holds the command's *logic* — options, the environment read, the
//! verdict mapping, the run loop. This file holds only the *rendering contract*
//! every command in this CLI implements, and the two have no business sharing a
//! file: the trait is boilerplate that must match `output.rs` exactly, while the
//! logic is where the design decisions are.
//!
//! It is also the half that was missing when `dispatch_bench` was first wired.
//! `Output::emit` requires `T: CommandOutput`, and without this impl the binary
//! failed to compile with *"the trait bound `BenchOutput: CommandOutput` is not
//! satisfied"* — a reminder that the two halves of a command are the *compute* and
//! the *render*, and shipping one without the other produces a command that either
//! does not build or (worse) builds and prints nothing.

use serde_json::json;

use crate::bench::BenchOutput;
use crate::output::{CommandName, CommandOutput};

impl CommandOutput for BenchOutput {
    fn command(&self) -> CommandName {
        CommandName::Bench
    }

    fn summary(&self) -> String {
        self.summarise()
    }

    fn to_json(&self) -> serde_json::Value {
        // `serde_json::to_value` cannot fail for this type — it holds only
        // strings, numbers, and `Option`s — but a panic here would lose the whole
        // run's output after minutes of load. The fallback states that rather than
        // asserting it, so a future field that *could* fail degrades to a
        // diagnosable object instead of taking the process down.
        serde_json::to_value(self).unwrap_or_else(|e| {
            json!({
                "error": "the bench output could not be serialized",
                "cause": e.to_string(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::{
        BenchOptions, BenchResult, BenchResultOutput, BudgetVerdict, HARNESS_SOURCE,
    };
    use qqq_bench::methodology::BenchmarkName;

    fn verdict(met: bool) -> BudgetVerdict {
        BudgetVerdict {
            item: "PERF-010",
            metric: "Throughput, reference app, 8 cores",
            target: 60_000.0,
            unit: "RPS",
            direction: "≥",
            measured: if met { 75_000.0 } else { 30_000.0 },
            met,
        }
    }

    fn result(name: BenchmarkName, budget: Option<BudgetVerdict>, failed: u64) -> BenchResult {
        BenchResult {
            name,
            measures: "test".to_owned(),
            expected: "test".to_owned(),
            attempted: 100,
            failed,
            p50_nanos: Some(1_000),
            p99_nanos: Some(2_000),
            rps: Some(50_000.0),
            verdict: budget,
        }
    }

    /// Build an output document with the given rows, using a real methodology so
    /// the environment section is populated as it will be in a live run.
    fn output(rows: Vec<BenchResult>) -> BenchOutput {
        let opts = BenchOptions::default();
        let workload = qqq_bench::workload::Workload::find(&BenchmarkName::Hello)
            .expect("hello is in the table");
        let methodology = crate::bench::methodology_for(workload, &opts)
            .expect("the hello methodology is constructible");
        BenchOutput::new(&rows, &methodology)
    }

    #[test]
    fn the_command_name_is_bench() {
        assert_eq!(output(vec![]).command(), CommandName::Bench);
    }

    #[test]
    fn the_summary_counts_met_budgets_and_names_the_denominator() {
        let doc = output(vec![
            result(BenchmarkName::Hello, Some(verdict(true)), 0),
            result(BenchmarkName::Json, Some(verdict(false)), 0),
        ]);
        let summary = doc.summary();
        assert!(summary.contains("1/2"), "got {summary}");
        assert!(summary.contains("budget"), "got {summary}");
    }

    #[test]
    fn a_run_with_no_budgets_says_so_rather_than_reporting_zero_of_zero() {
        // Nine of the ten rows have no §9.2 budget. `0/0 budgets met` would read
        // as total failure; the honest statement is that no row carried a target.
        let doc = output(vec![result(BenchmarkName::Cpu, None, 0)]);
        let summary = doc.summary();
        assert!(summary.contains("none with a"), "got {summary}");
        assert!(!summary.contains("0/0"), "got {summary}");
    }

    #[test]
    fn failed_requests_are_visible_in_the_summary() {
        // A run where every request was refused must not read as a clean pass.
        let doc = output(vec![result(BenchmarkName::Hello, Some(verdict(true)), 42)]);
        let summary = doc.summary();
        assert!(summary.contains("42"), "got {summary}");
        assert!(summary.contains("no response"), "got {summary}");
    }

    #[test]
    fn a_clean_run_does_not_mention_failures() {
        // The control for the test above: the failure note must be absent when
        // there is nothing to report, or every summary would carry it.
        let doc = output(vec![result(BenchmarkName::Hello, Some(verdict(true)), 0)]);
        assert!(!doc.summary().contains("no response"), "got {}", doc.summary());
    }

    #[test]
    fn the_json_carries_every_result_and_the_methodology() {
        let doc = output(vec![
            result(BenchmarkName::Hello, Some(verdict(true)), 0),
            result(BenchmarkName::Cpu, None, 0),
        ]);
        let value = doc.to_json();

        let results = value["results"].as_array().expect("results is an array");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["benchmark"], "hello");
        assert_eq!(results[1]["benchmark"], "cpu");

        // §9.1 requires the machine be published with every result.
        assert!(value["environment"]["cpu_model"].is_string());
        assert!(value["environment"]["os"].is_string());
        assert!(value["environment"]["kernel"].is_string());

        // §9.1's ninth requirement, as a required field.
        let caveats = value["does_not_measure"]
            .as_array()
            .expect("does_not_measure is an array");
        assert!(
            !caveats.is_empty(),
            "a result with no 'what this does not measure' section violates §9.1"
        );

        // §9.1 requires the harness be open source and locatable.
        assert_eq!(value["harness_source"], HARNESS_SOURCE);
    }

    #[test]
    fn the_json_omits_a_budget_for_a_row_that_has_none() {
        // `null` rather than an invented target: a row with no §9.2 budget is not
        // a row that failed one.
        let doc = output(vec![result(BenchmarkName::Cpu, None, 0)]);
        let value = doc.to_json();
        assert!(
            value["results"][0]["budget"].is_null(),
            "got {}",
            value["results"][0]["budget"]
        );
    }

    #[test]
    fn a_budget_verdict_survives_serialization_with_its_direction() {
        // The direction is what makes a verdict readable: `≥ 60k RPS met at 75k`
        // and `≤ 60k met at 75k` are opposite claims, and only the symbol tells
        // them apart.
        let doc = output(vec![result(
            BenchmarkName::Json,
            Some(verdict(true)),
            0,
        )]);
        let value = doc.to_json();
        let budget = &value["results"][0]["budget"];
        assert_eq!(budget["item"], "PERF-010");
        assert_eq!(budget["direction"], "≥");
        assert_eq!(budget["unit"], "RPS");
        assert_eq!(budget["met"], true);
    }

    #[test]
    fn the_latency_percentiles_are_carried_not_just_the_rate() {
        // §9.1 forbids averages and requires percentiles. A JSON shape that
        // carried only `requests_per_second` would make the percentiles
        // unrenderable for an agent even though the human path showed them.
        let doc = output(vec![result(BenchmarkName::TailP99, None, 0)]);
        let value = doc.to_json();
        let row = &value["results"][0];
        assert_eq!(row["p50_nanos"], 1_000);
        assert_eq!(row["p99_nanos"], 2_000);
        assert!(
            row.get("mean").is_none() && row.get("average").is_none(),
            "no mean may appear in the machine output either"
        );
    }

    #[test]
    fn the_result_text_comes_from_the_proposal_not_the_caller() {
        // `measures` and `expected` are §9.1's own columns, so an agent reading
        // --json can check a claim against the row it came from.
        let doc = output(vec![result(BenchmarkName::Hello, None, 0)]);
        let value = doc.to_json();
        assert_eq!(value["results"][0]["measures"], "Raw framework + runtime overhead");
        assert_eq!(
            value["results"][0]["expected"],
            "Behind Bun, near/above Node"
        );
    }

    #[test]
    fn the_serialized_row_type_matches_the_in_memory_one() {
        // A guard on the two structs staying in step: `BenchResult` is what the
        // command computes and `BenchResultOutput` is what it publishes, and a
        // field added to one and not the other would silently stop being reported.
        let rows = vec![result(BenchmarkName::Cold, Some(verdict(true)), 3)];
        let doc = output(rows);
        let serialized: Vec<BenchResultOutput> = doc.results.clone();
        assert_eq!(serialized.len(), 1);
        assert_eq!(serialized[0].benchmark, "cold");
        assert_eq!(serialized[0].attempted, 100);
        assert_eq!(serialized[0].failed, 3);
    }
}
