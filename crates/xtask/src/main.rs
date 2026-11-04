// SPDX-License-Identifier: Apache-2.0

// Belt and braces with `src/lib.rs` (which the architecture test reads):
// the forbid is enforced workspace-wide regardless, but the crate root a
// reader opens should state it. See `ARCH-008`.
#![forbid(unsafe_code)]

//! Developer workflows: one gate, fast hygiene, worktree fault injection.
//!
//! Phase 1 of `I-08`: this crate **invokes** the existing checks, it does
//! not reimplement them. The step table below is the union of the CI Rust
//! job and the bridge `checks` command; `ci.yml` and `docker/entrypoint.sh`
//! both call `cargo xtask ci`, and `tools/check_gate_parity.py` stays as
//! the backstop that proves the unification dropped nothing (it expands
//! `cargo xtask list` for the comparison).
//!
//! # Execution lanes, and why python checks are split across two of them
//!
//! Cargo steps serialise on the target directory themselves; `xtask` runs
//! them sequentially and accepts that. The cheap checks run in parallel in
//! a `thread::scope` — every bare, `--check`, `--matrix`, `--list` and
//! `--report` form, which only read, except the two checkers whose live
//! paths shell `cargo xtask list` (which compiles into that same target
//! dir and races there). Everything that can write goes sequentially in
//! listed order: every `--self-test` (temporary fixtures, fault
//! injections, builds), every cargo invocation, the orders-api workspace,
//! the release probe, and the two ported shell checks. A parallelised
//! fault-injection self-test could interleave with another check's restore
//! and flake; the sequential lane keeps today's exact behaviour for
//! exactly those steps.
//!
//! # What is deliberately NOT here (phase 2)
//!
//! Porting checkers to Rust, semver/structure tooling (`cargo-semver-checks`,
//! `cargo-modules`), and subsuming the specialised CI jobs (PERF measurement,
//! language matrix, SBOM build, MSRV, image). Those stay where they are;
//! this phase unifies the check list, not the whole pipeline.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Instant;

/// Which lane a step runs in (see the module docs for why the split exists).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    /// Read-only checks, run concurrently in a `thread::scope`.
    Par,
    /// Everything that can write, build, or serve, in listed order.
    Seq,
}

/// One gate step: a name for the summary, a lane, and how to run it.
#[derive(Clone, Copy)]
struct Step {
    name: &'static str,
    lane: Lane,
    kind: StepKind,
}

#[derive(Clone, Copy)]
enum StepKind {
    /// An external command. `dir`, when set, is the working directory
    /// relative to the workspace root (the orders-api workspace).
    Cmd {
        program: &'static str,
        args: &'static [&'static str],
        dir: Option<&'static str>,
    },
    /// A python checker: the interpreter is discovered at startup
    /// (`python3`, then `python`, then `py -3` for Windows).
    Py { args: &'static [&'static str] },
    /// Ported from the CI step of the same name (no portable shell).
    UnsafeScan,
    /// Ported from the CI step of the same name (needs the built binary).
    HelpBrevity,
}

impl Step {
    const fn py(lane: Lane, name: &'static str, args: &'static [&'static str]) -> Self {
        Self {
            name,
            lane,
            kind: StepKind::Py { args },
        }
    }
    const fn cmd(
        lane: Lane,
        name: &'static str,
        program: &'static str,
        args: &'static [&'static str],
        dir: Option<&'static str>,
    ) -> Self {
        Self {
            name,
            lane,
            kind: StepKind::Cmd { program, args, dir },
        }
    }
}

// ---------------------------------------------------------------------------
// The step table: the union of the CI Rust job and the bridge `checks`
// command, mechanically derived (see the I-08 commit) and reviewed here.
// `cargo xtask list` prints the python rows for `check_gate_parity.py`.
// ---------------------------------------------------------------------------

/// Cargo steps first in the sequential lane: format, lints, build, test.
const CARGO_STEPS: &[Step] = &[
    Step::cmd(
        Lane::Par,
        "fmt",
        "cargo",
        &["fmt", "--all", "--", "--check"],
        None,
    ),
    Step::cmd(
        Lane::Seq,
        "clippy",
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        None,
    ),
    Step::cmd(
        Lane::Seq,
        "build",
        "cargo",
        &["build", "--workspace", "--all-features"],
        None,
    ),
    Step::cmd(
        Lane::Seq,
        "test",
        "cargo",
        &["test", "--workspace", "--all-features"],
        None,
    ),
    Step::cmd(Lane::Par, "deny", "cargo", &["deny", "check"], None),
    Step::cmd(Lane::Par, "machete", "cargo", &["machete"], None),
];

/// The ignored integration tests the Rust job runs explicitly.
const IGNORED_TESTS: &[Step] = &[
    Step::cmd(
        Lane::Seq,
        "lang001",
        "cargo",
        &[
            "test",
            "-p",
            "qqq-run",
            "--all-features",
            "--test",
            "lang001_rust_guest",
            "--",
            "--ignored",
        ],
        None,
    ),
    Step::cmd(
        Lane::Seq,
        "lang002",
        "cargo",
        &[
            "test",
            "-p",
            "qqq-run",
            "--all-features",
            "--test",
            "lang002_bindings",
            "--",
            "--ignored",
        ],
        None,
    ),
    Step::cmd(
        Lane::Seq,
        "lang003",
        "cargo",
        &[
            "test",
            "-p",
            "qqq-run",
            "--all-features",
            "--test",
            "lang003_template",
            "--",
            "--ignored",
        ],
        None,
    ),
    Step::cmd(
        Lane::Seq,
        "conformance_exec",
        "cargo",
        &[
            "test",
            "-p",
            "qqq-run",
            "--all-features",
            "--test",
            "conformance_exec",
            "--",
            "--ignored",
        ],
        None,
    ),
    Step::cmd(
        Lane::Seq,
        "lang005",
        "cargo",
        &[
            "test",
            "-p",
            "qqq-run",
            "--all-features",
            "--test",
            "lang005_reference_app",
            "--",
            "--ignored",
        ],
        None,
    ),
    Step::cmd(
        Lane::Seq,
        "audit_load",
        "cargo",
        &[
            "test",
            "-p",
            "qqq-run",
            "--all-features",
            "--test",
            "audit_load",
            "--",
            "--ignored",
        ],
        None,
    ),
];

/// The reference application, a separate workspace with a locked test run.
const ORDERS_API_STEPS: &[Step] = &[
    Step::cmd(
        Lane::Par,
        "orders-fmt",
        "cargo",
        &["fmt", "--", "--check"],
        Some("examples/orders-api"),
    ),
    Step::cmd(
        Lane::Seq,
        "orders-clippy",
        "cargo",
        &[
            "clippy",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        Some("examples/orders-api"),
    ),
    Step::cmd(
        Lane::Seq,
        "orders-test",
        "cargo",
        &["test", "--all-features", "--locked"],
        Some("examples/orders-api"),
    ),
];

/// The python checks: the union of both gates, mechanically derived.
/// Parallel lane holds the read-only forms; every `--self-test` and
/// the few bare forms that can write or serve run sequentially.
const PY_STEPS: &[Step] = &[
    Step::py(Lane::Par, "check_admission", &["tools/check_admission.py"]),
    Step::py(
        Lane::Par,
        "check_advisories",
        &["tools/check_advisories.py"],
    ),
    Step::py(
        Lane::Par,
        "check_agent_bench",
        &["tools/check_agent_bench.py"],
    ),
    Step::py(
        Lane::Par,
        "check_agent_cookbook",
        &["tools/check_agent_cookbook.py"],
    ),
    Step::py(
        Lane::Par,
        "check_batch_first",
        &["tools/check_batch_first.py"],
    ),
    Step::py(
        Lane::Par,
        "check_bench_contract",
        &["tools/check_bench_contract.py"],
    ),
    Step::py(
        Lane::Par,
        "check_checklist_citations",
        &["tools/check_checklist_citations.py"],
    ),
    Step::py(
        Lane::Par,
        "check_checklist_counts",
        &["tools/check_checklist_counts.py"],
    ),
    Step::py(
        Lane::Par,
        "check_ci_examples",
        &["tools/check_ci_examples.py"],
    ),
    Step::py(
        Lane::Par,
        "check_coderabbit_config",
        &["tools/check_coderabbit_config.py"],
    ),
    Step::py(
        // Sequential, not parallel: the live path shells `cargo xtask list`,
        // which compiles the xtask binary into the shared target dir. Two
        // such checkers in the parallel wave race -- one deletes
        // `target/debug/xtask` mid-rebuild while the other is about to exec
        // it -- and CI failed `check_gate_parity` on macOS with exactly
        // that `could not execute process (never executed)`. The sequential
        // lane runs steps one at a time, so no two cargo processes share
        // the target dir.
        Lane::Seq,
        "check_conformance",
        &["tools/check_conformance.py"],
    ),
    Step::py(
        // Same cargo-shelling live path as the bare form above.
        Lane::Seq,
        "check_conformance",
        &["tools/check_conformance.py", "--matrix"],
    ),
    Step::py(
        Lane::Par,
        "check_doc_claims",
        &["tools/check_doc_claims.py"],
    ),
    Step::py(
        Lane::Par,
        "check_done_lines",
        &["tools/check_done_lines.py"],
    ),
    Step::py(Lane::Par, "check_error_all", &["tools/check_error_all.py"]),
    Step::py(
        Lane::Par,
        "check_error_catalogue",
        &["tools/check_error_catalogue.py"],
    ),
    Step::py(
        // Sequential, not parallel: this checker shells the prebuilt
        // `target/debug/qqqai`, and the parallel wave runs ahead of `build`
        // -- on a cold runner that is "no built qqqai binary" on all three
        // platforms. The sequential lane runs after `build` by table order.
        Lane::Seq,
        "check_error_standard",
        &["tools/check_error_standard.py"],
    ),
    Step::py(
        // Sequential, not parallel: same cargo-shelling live path as
        // `check_conformance` above (`cargo xtask list` compiles into the
        // shared target dir). See that step's comment for the macOS race.
        Lane::Seq,
        "check_gate_parity",
        &["tools/check_gate_parity.py"],
    ),
    Step::py(Lane::Par, "check_glossary", &["tools/check_glossary.py"]),
    Step::py(
        Lane::Par,
        "check_glossary_usage",
        &["tools/check_glossary_usage.py"],
    ),
    Step::py(
        Lane::Par,
        "check_include_str",
        &["tools/check_include_str.py"],
    ),
    Step::py(
        Lane::Par,
        "check_language_parity",
        &["tools/check_language_parity.py"],
    ),
    Step::py(
        Lane::Par,
        "check_license_boundary",
        &["tools/check_license_boundary.py"],
    ),
    Step::py(
        Lane::Par,
        "check_lifecycle_counts",
        &["tools/check_lifecycle_counts.py"],
    ),
    Step::py(
        Lane::Par,
        "check_metric_cardinality",
        &["tools/check_metric_cardinality.py"],
    ),
    Step::py(
        Lane::Par,
        "check_milestones",
        &["tools/check_milestones.py", "--report"],
    ),
    Step::py(
        Lane::Par,
        "check_no_ambient",
        &["tools/check_no_ambient.py"],
    ),
    Step::py(
        Lane::Par,
        "check_no_panic_in_host_impls",
        &["tools/check_no_panic_in_host_impls.py"],
    ),
    Step::py(
        Lane::Par,
        "check_no_poison_expect",
        &["tools/check_no_poison_expect.py"],
    ),
    Step::py(
        Lane::Par,
        "check_ordered_maps",
        &["tools/check_ordered_maps.py"],
    ),
    Step::py(
        Lane::Par,
        "check_panic_strategy",
        &["tools/check_panic_strategy.py"],
    ),
    Step::py(
        Lane::Par,
        "check_public_reachability",
        &["tools/check_public_reachability.py"],
    ),
    Step::py(
        Lane::Par,
        "check_reconciliation",
        &["tools/check_reconciliation.py"],
    ),
    Step::py(
        Lane::Par,
        "check_schema_conformance",
        &["tools/check_schema_conformance.py"],
    ),
    Step::py(
        Lane::Par,
        "check_scope_table",
        &["tools/check_scope_table.py"],
    ),
    Step::py(
        Lane::Par,
        "check_security_scope",
        &["tools/check_security_scope.py"],
    ),
    Step::py(
        Lane::Par,
        "check_source_claims",
        &["tools/check_source_claims.py", "--check"],
    ),
    Step::py(Lane::Par, "check_spdx", &["tools/check_spdx.py"]),
    Step::py(
        Lane::Par,
        "check_subprocess_encoding",
        &["tools/check_subprocess_encoding.py"],
    ),
    Step::py(
        Lane::Par,
        "check_threat_model",
        &["tools/check_threat_model.py"],
    ),
    Step::py(Lane::Par, "check_tiers", &["tools/check_tiers.py"]),
    Step::py(
        Lane::Par,
        "check_tombstones",
        &["tools/check_tombstones.py"],
    ),
    Step::py(Lane::Par, "check_toolchain", &["tools/check_toolchain.py"]),
    Step::py(Lane::Par, "check_topology", &["tools/check_topology.py"]),
    Step::py(
        Lane::Par,
        "check_unicode_escapes",
        &["tools/check_unicode_escapes.py"],
    ),
    Step::py(
        Lane::Par,
        "check_verified_facts",
        &["tools/check_verified_facts.py"],
    ),
    Step::py(Lane::Par, "check_wit", &["tools/check_wit.py"]),
    Step::py(
        Lane::Par,
        "check_wit_bindings",
        &["tools/check_wit_bindings.py"],
    ),
    Step::py(
        Lane::Par,
        "check_wit_deprecated",
        &["tools/check_wit_deprecated.py"],
    ),
    Step::py(
        Lane::Par,
        "check_wit_errors",
        &["tools/check_wit_errors.py"],
    ),
    Step::py(
        Lane::Par,
        "check_wit_reference",
        &["tools/check_wit_reference.py"],
    ),
    Step::py(Lane::Par, "check_wit_since", &["tools/check_wit_since.py"]),
    Step::py(Lane::Par, "check_wit_style", &["tools/check_wit_style.py"]),
    Step::py(
        Lane::Par,
        "check_wit_vendoring",
        &["tools/check_wit_vendoring.py"],
    ),
    Step::py(Lane::Par, "check_xrefs", &["tools/check_xrefs.py"]),
    Step::py(
        Lane::Par,
        "gen_backlog",
        &["tools/gen_backlog.py", "--check"],
    ),
    Step::py(
        Lane::Par,
        "gen_capability_catalogue",
        &["tools/gen_capability_catalogue.py", "--check"],
    ),
    Step::py(
        Lane::Par,
        "gen_llms_txt",
        &["tools/gen_llms_txt.py", "--check"],
    ),
    Step::py(
        Lane::Par,
        "gen_schemas",
        &["tools/gen_schemas.py", "--check"],
    ),
    Step::py(
        Lane::Par,
        "milestone_dashboard",
        &["tools/milestone_dashboard.py", "--check"],
    ),
    Step::py(
        Lane::Par,
        "normalize_eol",
        &["tools/normalize_eol.py", "--check"],
    ),
    Step::py(Lane::Par, "sync_docs", &["tools/sync_docs.py", "--check"]),
    Step::py(Lane::Seq, "audit_unsafe", &["tools/audit_unsafe.py"]),
    Step::py(
        Lane::Seq,
        "audit_unsafe",
        &["tools/audit_unsafe.py", "--check-doc"],
    ),
    Step::py(
        Lane::Seq,
        "audit_unsafe",
        &["tools/audit_unsafe.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_admission",
        &["tools/check_admission.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_advisories",
        &["tools/check_advisories.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_agent_bench",
        &["tools/check_agent_bench.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_agent_cookbook",
        &["tools/check_agent_cookbook.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_api_examples",
        &["tools/check_api_examples.py", "--allow", "1928"],
    ),
    Step::py(
        Lane::Seq,
        "check_api_examples",
        &["tools/check_api_examples.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_bench_contract",
        &["tools/check_bench_contract.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_checklist_citations",
        &["tools/check_checklist_citations.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_checklist_counts",
        &["tools/check_checklist_counts.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_ci_examples",
        &["tools/check_ci_examples.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_coderabbit_config",
        &["tools/check_coderabbit_config.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_conformance",
        &["tools/check_conformance.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_corpus_at_rest",
        &["tools/check_corpus_at_rest.py"],
    ),
    Step::py(
        Lane::Seq,
        "check_corpus_repair",
        &["tools/check_corpus_repair.py"],
    ),
    Step::py(
        Lane::Seq,
        "check_corpus_repair",
        &["tools/check_corpus_repair.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_doc_claims",
        &["tools/check_doc_claims.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_done_lines",
        &["tools/check_done_lines.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_error_all",
        &["tools/check_error_all.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_error_catalogue",
        &["tools/check_error_catalogue.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_error_standard",
        &["tools/check_error_standard.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_gate_parity",
        &["tools/check_gate_parity.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_glossary",
        &["tools/check_glossary.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_glossary_usage",
        &["tools/check_glossary_usage.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_handoff",
        &["tools/check_handoff.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_include_str",
        &["tools/check_include_str.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_language_parity",
        &["tools/check_language_parity.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_license_boundary",
        &["tools/check_license_boundary.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_lifecycle_counts",
        &["tools/check_lifecycle_counts.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_live_dev",
        &["tools/check_live_dev.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_metric_cardinality",
        &["tools/check_metric_cardinality.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_milestones",
        &["tools/check_milestones.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_no_panic_in_host_impls",
        &["tools/check_no_panic_in_host_impls.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_no_poison_expect",
        &["tools/check_no_poison_expect.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_ordered_maps",
        &["tools/check_ordered_maps.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_panic_strategy",
        &["tools/check_panic_strategy.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_public_reachability",
        &["tools/check_public_reachability.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_reconciliation",
        &["tools/check_reconciliation.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_sbom",
        &["tools/check_sbom.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_schema_conformance",
        &["tools/check_schema_conformance.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_scope_table",
        &["tools/check_scope_table.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_security_scope",
        &["tools/check_security_scope.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_source_claims",
        &["tools/check_source_claims.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_spdx",
        &["tools/check_spdx.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_subprocess_encoding",
        &["tools/check_subprocess_encoding.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_threat_model",
        &["tools/check_threat_model.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_tiers",
        &["tools/check_tiers.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_tombstones",
        &["tools/check_tombstones.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_toolchain",
        &["tools/check_toolchain.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_unicode_escapes",
        &["tools/check_unicode_escapes.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_verified_facts",
        &["tools/check_verified_facts.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_wit",
        &["tools/check_wit.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_wit_bindings",
        &["tools/check_wit_bindings.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_wit_reference",
        &["tools/check_wit_reference.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_wit_style",
        &["tools/check_wit_style.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_wit_vendoring",
        &["tools/check_wit_vendoring.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "check_xrefs",
        &["tools/check_xrefs.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "det009_trials",
        &["tools/det009_trials.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "fault_inject_live_components",
        &["tools/fault_inject_live_components.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "gen_backlog",
        &["tools/gen_backlog.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "gen_capability_catalogue",
        &["tools/gen_capability_catalogue.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "gen_llms_txt",
        &["tools/gen_llms_txt.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "milestone_dashboard",
        &["tools/milestone_dashboard.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "normalize_eol",
        &["tools/normalize_eol.py", "--self-test"],
    ),
    Step::py(Lane::Seq, "run_conformance", &["tools/run_conformance.py"]),
    Step::py(
        Lane::Seq,
        "run_conformance",
        &["tools/run_conformance.py", "--list"],
    ),
    Step::py(
        Lane::Seq,
        "run_conformance",
        &["tools/run_conformance.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "run_language_probes",
        &["tools/run_language_probes.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "run_perf_regression",
        &["tools/run_perf_regression.py", "--self-test"],
    ),
    Step::py(
        Lane::Seq,
        "self_test_schemas",
        &["tools/self_test_schemas.py"],
    ),
    Step::py(Lane::Seq, "self_test_xrefs", &["tools/self_test_xrefs.py"]),
    Step::py(
        Lane::Seq,
        "self_test_xrefs",
        &["tools/self_test_xrefs.py", "--check-clean"],
    ),
];

/// One step's outcome for the summary.
struct Outcome {
    name: String,
    ok: bool,
    secs: u64,
}

/// The log/summary label for a step: the human name plus the exact argv, so
/// two forms sharing one name (`check_conformance` bare/`--matrix`,
/// `audit_unsafe` x3, ...) are told apart in `run`, `ok`/`FAIL` and
/// `GATE RED` lines. Keyed summaries on the bare name cannot say which form
/// failed (M1); the label matches `cmd_list`'s `args.join(" ")` spelling so
/// the summary greps against the coverage manifest.
fn step_label(step: &Step) -> String {
    match &step.kind {
        StepKind::Py { args } => format!("{} [{}]", step.name, args.join(" ")),
        StepKind::Cmd { program, args, dir } => {
            // M5: the working directory is part of the identity — two steps
            // could share name/program/argv in different dirs, and the
            // summary must still name the failed one.
            let where_ = dir.unwrap_or(".");
            format!("{} [{program} {} (in {where_})]", step.name, args.join(" "))
        }
        StepKind::UnsafeScan | StepKind::HelpBrevity => step.name.to_owned(),
    }
}

/// A lane thread died: report *which* step it was carrying. The summary
/// keys on names, so `<panicked step>` twice would reintroduce exactly the
/// ambiguity M1 removed (r2-M1).
fn panicked_outcome(label: String) -> Outcome {
    Outcome {
        name: label,
        ok: false,
        secs: 0,
    }
}

/// The parsed subcommand.
#[derive(Debug, PartialEq, Eq)]
enum Args {
    Ci,
    Hygiene,
    List,
    FaultInjectList,
    FaultInject(String),
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    match argv.first().map(String::as_str) {
        Some("ci") if argv.len() == 1 => Ok(Args::Ci),
        Some("hygiene") if argv.len() == 1 => Ok(Args::Hygiene),
        Some("list") if argv.len() == 1 => Ok(Args::List),
        Some("fault-inject") if argv.len() == 2 && argv.get(1).is_some_and(|a| a == "--list") => {
            Ok(Args::FaultInjectList)
        }
        Some("fault-inject") if argv.len() == 2 => {
            Ok(Args::FaultInject(argv.get(1).cloned().unwrap_or_default()))
        }
        _ => Err("usage: cargo xtask <ci|hygiene|list|fault-inject [--list|NAME]>".to_owned()),
    }
}

/// Aggregate outcomes: the names that failed, if any.
fn failed(outcomes: &[Outcome]) -> Vec<&str> {
    outcomes
        .iter()
        .filter(|o| !o.ok)
        .map(|o| o.name.as_str())
        .collect()
}

/// Discover a Python interpreter: `python3`, then `python`, then `py -3`
/// (Windows). The first whose `--version` exits 0 wins.
fn discover_python() -> Result<Vec<String>, String> {
    const CANDIDATES: &[&[&str]] = &[&["python3"], &["python"], &["py", "-3"]];
    pick_program(CANDIDATES, &["--version"], &|prog, args, probe| {
        Command::new(prog)
            .args(args)
            .args(probe)
            .output()
            .is_ok_and(|o| o.status.success())
    })
    .map(|c| c.iter().map(|s| (*s).to_owned()).collect())
    .ok_or_else(|| "no Python interpreter found (tried python3, python, py -3)".to_owned())
}

/// The probe a candidate interpreter must pass (`--version`, exit 0).
type Probe = dyn Fn(&str, &[&str], &[&str]) -> bool;

/// Pure core of interpreter discovery, so tests can drive it without processes.
fn pick_program<'a>(
    candidates: &[&'a [&'a str]],
    probe_args: &[&str],
    run: &Probe,
) -> Option<&'a [&'a str]> {
    candidates.iter().copied().find(|c| {
        c.split_first()
            .is_some_and(|(head, tail)| run(head, tail, probe_args))
    })
}

/// Scrub the `cargo run` inheritance from a child command's environment.
///
/// Measured (I-08): `cargo machete` spawned under `cargo xtask` analyses a
/// directory literally named `machete` and fails, while the same binary
/// spawned from a shell analyses `.` and passes. Bisecting the inherited
/// environment names the culprit: `CARGO_PKG_NAME` (set to `xtask` by the
/// parent `cargo run`). The child is a different crate in a different role;
/// package-identity variables that describe *xtask* misdescribe *it*.
/// Toolchain selection (`RUSTUP_TOOLCHAIN`, `CARGO_HOME`), network config
/// (`CARGO_NET_*`), output (`CARGO_TERM_COLOR`) and the cargo path itself
/// (`CARGO`) are kept: removing those would change *which* toolchain runs,
/// which is a different and worse divergence from a clean shell.
fn scrub_cargo_run_env(cmd: &mut Command) {
    const EXACT: &[&str] = &[
        "CARGO_MANIFEST_DIR",
        "CARGO_MANIFEST_PATH",
        "CARGO_MANIFEST_LINKS",
        "CARGO_PRIMARY_PACKAGE",
    ];
    const PREFIXES: &[&str] = &["CARGO_PKG_", "CARGO_BIN_", "CARGO_CRATE_"];
    for key in EXACT {
        cmd.env_remove(key);
    }
    // Keys inherited from this process, plus keys set explicitly on the
    // command: either channel carries the leak.
    let mut doomed: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| PREFIXES.iter().any(|p| k.starts_with(p)))
        .collect();
    doomed.extend(
        cmd.get_envs()
            .filter(|(k, v)| {
                v.is_some() && PREFIXES.iter().any(|p| k.to_string_lossy().starts_with(p))
            })
            .map(|(k, _)| k.to_string_lossy().into_owned()),
    );
    for key in doomed {
        cmd.env_remove(key);
    }
}

fn run_cmd(
    program: &str,
    args: &[String],
    dir: Option<&Path>,
    workspace: &Path,
) -> Result<(bool, String), String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.current_dir(dir.map_or_else(|| workspace.to_path_buf(), |d| workspace.join(d)));
    scrub_cargo_run_env(&mut cmd);
    match cmd.output() {
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            Ok((o.status.success(), text))
        }
        // M3: a spawn failure is an infrastructure error, never a verdict —
        // returning it as `Err` keeps the caller's `contains(expect)` match
        // from certifying a checker that never ran (false DETECTED).
        Err(e) => Err(format!("failed to spawn {program}: {e}")),
    }
}

fn run_step(step: &Step, workspace: &Path, python: &[String]) -> Outcome {
    let start = Instant::now();
    let label = step_label(step);
    if step.lane == Lane::Seq {
        // Name the step up front: a hung step never reaches its completion
        // line, so without this the log goes silent instead of identifying
        // the in-flight step. Parallel steps stay completion-only -- their
        // start lines would interleave across threads and name nothing
        // reliably. (`println!` line-flushes, so this is visible pre-hang
        // even when stdout is piped.)
        println!("run  {label}");
    }
    let (ok, output) = match &step.kind {
        StepKind::Cmd { program, args, dir } => {
            let argv: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
            let dir = dir.map(Path::new);
            // A spawn failure shows as a failed step with the reason, not a
            // silent pass: `Err` unwraps to `(false, reason)` for display.
            run_cmd(program, &argv, dir, workspace).unwrap_or_else(|e| (false, e))
        }
        StepKind::Py { args } => {
            let mut argv: Vec<String> = python.to_vec();
            argv.extend(args.iter().map(|s| (*s).to_owned()));
            match argv.split_first() {
                Some((head, tail)) => {
                    run_cmd(head, tail, None, workspace).unwrap_or_else(|e| (false, e))
                }
                None => (false, "empty argv for a python step".to_owned()),
            }
        }
        StepKind::UnsafeScan => run_unsafe_scan(workspace),
        StepKind::HelpBrevity => run_help_brevity(workspace),
    };
    let outcome = Outcome {
        name: label,
        ok,
        secs: start.elapsed().as_secs(),
    };
    if ok {
        println!("ok   {:<64} ({}s)", outcome.name, outcome.secs);
    } else {
        println!("FAIL {:<64} ({}s)", outcome.name, outcome.secs);
        println!("{output}");
    }
    outcome
}

// ---------------------------------------------------------------------------
// Ported checks (no portable shell): same rule, same output contract.
// ---------------------------------------------------------------------------

/// A line violates iff `unsafe` opens a code position outside the exception
/// crate. Faithful port of the CI grep:
/// `\bunsafe[[:space:]]*(\{|fn\b|impl\b|extern\b|trait\b)`, minus only the
/// `crates/qqq-sys/` directory (skipped by the caller). The crate-level
/// forbid attribute is exempted by `unsafe_line_exempt`, narrowly: a
/// `cfg_attr` mention elsewhere on the line never exempts (M2).
fn unsafe_line_is_violation(line: &str) -> bool {
    // String literals are skipped: a real `unsafe` block can never hide in
    // string data, so matching there is pure false-positive surface. (The CI
    // grep this ports cannot tell strings from code; this is intentionally
    // more precise.) Comments still match — conservatively, and because a
    // commented-out block is one uncomment away from live — but comment
    // regions never toggle string/char/raw state: a quote that lives inside
    // a comment (`/* " */`, `// "`) must not open string mode and hide a
    // real opener further down the line (H2), the dangerous direction.
    // Char literals are tracked so a `'"'` (or `b'"'`) does not open string
    // mode and hide the rest of the line — that would be a missed violation,
    // the dangerous direction. A `'` opens a char literal only when a closing
    // quote sits nearby (lifetimes never close); same heuristic as
    // `tools/audit_unsafe.py`, which the self-test pins.
    // Raw strings (`r"..."`, `br##"..."##`) are tracked single-line: a
    // quote inside raw content toggles nothing (no escapes), and only a
    // quote with the matching hash count closes. A raw string left open at
    // end of line hides the rest of the line -- the multiline residual,
    // fail-unsafe in theory; in practice the audit tool threads raw state
    // across lines, and this scan's regression tests pin the single-line
    // shapes. Newlines inside the input reset plain strings, chars and line
    // comments (none of them can legally span lines) but thread raw strings
    // and block comments (both can): the caller feeds adjacent line pairs
    // joined by `\n`, so a dangling `unsafe` at end of line still finds its
    // opener on the next one (H-r3-H1). Precision here must never
    // be mistaken for completeness.
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut st = ScanState::default();
    while bytes.get(i).is_some() {
        if step_literal_text(bytes, &mut i, &mut st) {
            continue;
        }
        if st.in_line_comment || st.comment_depth > 0 {
            if step_comment_text(
                line,
                bytes,
                &mut i,
                &mut st.in_line_comment,
                &mut st.comment_depth,
            ) {
                return true;
            }
            continue;
        }
        if step_code_text(line, bytes, &mut i, &mut st) {
            return true;
        }
    }
    false
}

/// Track literal state (raw strings, plain strings, chars) plus the
/// newline resets at `*i`. Returns true when the position was literal
/// content or a newline (caller `continue`s); advances `*i` past escapes
/// and closers. Raw strings and block comments thread through `\n` (both
/// can span lines); plain strings, chars and line comments reset (none
/// can) — carrying an unclosed quote would hide the next line (miss).
fn step_literal_text(bytes: &[u8], i: &mut usize, st: &mut ScanState) -> bool {
    let Some(&b) = bytes.get(*i) else {
        return false;
    };
    if let Some(n) = st.in_raw {
        // Inside a raw string: no escapes, exact-count close only.
        if b == b'"' {
            let mut k = 0;
            while bytes.get(*i + 1 + k) == Some(&b'#') {
                k += 1;
            }
            if k == n {
                st.in_raw = None;
                *i += 1 + k;
                return true;
            }
        }
        *i += 1;
        return true;
    }
    if st.in_string {
        if b == b'\n' {
            st.in_string = false;
            *i += 1;
            return true;
        }
        if b == b'\\' {
            *i += 2;
            return true;
        }
        if b == b'"' {
            st.in_string = false;
        }
        *i += 1;
        return true;
    }
    if st.in_char {
        if b == b'\n' {
            st.in_char = false;
            *i += 1;
            return true;
        }
        if b == b'\\' {
            *i += 2;
            return true;
        }
        if b == b'\'' {
            st.in_char = false;
        }
        *i += 1;
        return true;
    }
    if b == b'\n' {
        // Newlines end line comments (block comments and raw strings
        // thread through, handled in their own branches).
        st.in_line_comment = false;
        *i += 1;
        return true;
    }
    false
}

/// Lexer state for one scan unit (a line, or a `\n`-joined pair): literal
/// tracking plus comment tracking. One struct so the step helpers below
/// take a single state argument instead of five.
#[derive(Default)]
struct ScanState {
    in_string: bool,
    in_char: bool,
    in_raw: Option<usize>,
    in_line_comment: bool,
    comment_depth: u32,
}

/// One step outside strings/chars/comments: comment openers, literal
/// openers, and the `unsafe`-opener check. Returns true on a violation;
/// otherwise advances `*i` past what it consumed.
fn step_code_text(line: &str, bytes: &[u8], i: &mut usize, st: &mut ScanState) -> bool {
    let Some(&b) = bytes.get(*i) else {
        return false;
    };
    if b == b'/' && bytes.get(*i + 1) == Some(&b'/') {
        st.in_line_comment = true;
        *i += 2;
        return false;
    }
    if b == b'/' && bytes.get(*i + 1) == Some(&b'*') {
        st.comment_depth += 1;
        *i += 2;
        return false;
    }
    if b == b'"' {
        if let Some(n) = raw_opener(line, *i) {
            st.in_raw = Some(n);
        } else {
            st.in_string = true;
        }
        *i += 1;
        return false;
    }
    if b == b'\'' {
        let rest = line.get(*i + 1..).unwrap_or("");
        if rest.chars().take(3).collect::<String>().contains('\'') {
            st.in_char = true;
        }
        *i += 1;
        return false;
    }
    if is_unsafe_opener(line, bytes, *i, false) {
        return true;
    }
    *i += 1;
    false
}

/// One step while inside comment text (`in_line_comment || depth > 0`).
/// Comment-held quotes never toggle string state (H2); the `unsafe` check
/// still runs, per the comments-match policy. Returns true on a violation
/// at this position; otherwise advances `*i` past what it consumed.
fn step_comment_text(
    line: &str,
    bytes: &[u8],
    i: &mut usize,
    in_line_comment: &mut bool,
    comment_depth: &mut u32,
) -> bool {
    let Some(&b) = bytes.get(*i) else {
        return false;
    };
    if b == b'\n' {
        // Newlines end line comments (block comments thread through, via
        // the depth branch below). Without this reset a `//`-commented
        // keyword would govern a real block on the next line — precisely
        // backwards: the commented keyword governs nothing.
        *in_line_comment = false;
        *i += 1;
        return false;
    }
    if *comment_depth > 0 {
        if b == b'*' && bytes.get(*i + 1) == Some(&b'/') {
            *comment_depth = comment_depth.saturating_sub(1);
            *i += 2;
            return false;
        }
        if b == b'/' && bytes.get(*i + 1) == Some(&b'*') {
            *comment_depth += 1;
            *i += 2;
            return false;
        }
    }
    if is_unsafe_opener(line, bytes, *i, *in_line_comment) {
        return true;
    }
    *i += 1;
    false
}

/// The `unsafe`-opener test at byte `i`: the word `unsafe` on a non-identifier
/// boundary followed by an opener — `{`, `fn`, `impl`, `extern`, `trait` —
/// with only whitespace (newlines included), and block comments between
/// them (H3: a comment sitting between the keyword and the brace used to
/// hide the opener; H-r3-H1: `unsafe` may dangle at end of line with the
/// opener on the next — the caller feeds adjacent line pairs, and the gap
/// skips the joining newline; nesting resolves, so text inside the comment
/// never decides).
///
/// `same_line_only` stops the gap at `\n`: inside a `//` comment the
/// keyword governs nothing on the next line (`// unsafe` plus a real block
/// is precisely not a violation), while block comments and code see across.
fn is_unsafe_opener(line: &str, bytes: &[u8], i: usize, same_line_only: bool) -> bool {
    if bytes.get(i) != Some(&b'u')
        || !line.get(i..).is_some_and(|t| t.starts_with("unsafe"))
        // LOW r3: the boundary is Unicode-aware like `starts_word` below —
        // a byte check reads `é` as two non-ident bytes and flagging
        // `éunsafe{` as a violation (it is one identifier, not the keyword).
        || !(i == 0
            || line
                .get(..i)
                .is_none_or(|pre| !pre.ends_with(|c: char| c.is_alphanumeric() || c == '_')))
    {
        return false;
    }
    let mut j = i + "unsafe".len();
    loop {
        while let Some(&x) = bytes.get(j) {
            if x == b' ' || x == b'\t' {
                j += 1;
            } else if x == b'\n' {
                if same_line_only {
                    return false;
                }
                j += 1;
            } else {
                break;
            }
        }
        if bytes.get(j) == Some(&b'/') && bytes.get(j + 1) == Some(&b'*') {
            j += 2;
            let mut depth: u32 = 1;
            let mut closed = false;
            while let Some(&c) = bytes.get(j) {
                if c == b'\n' && same_line_only {
                    return false;
                } else if c == b'/' && bytes.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if c == b'*' && bytes.get(j + 1) == Some(&b'/') {
                    depth = depth.saturating_sub(1);
                    j += 2;
                    if depth == 0 {
                        closed = true;
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            if !closed {
                // The comment runs past end of line: no opener is visible on
                // this line (the multiline residual, documented above).
                return false;
            }
            continue;
        }
        break;
    }
    let rest = line.get(j..).unwrap_or("");
    rest.starts_with('{')
        || starts_word(rest, "fn")
        || starts_word(rest, "impl")
        || starts_word(rest, "extern")
        || starts_word(rest, "trait")
}

/// A `"` at byte `i` opens a raw string iff walking back over `#`s lands on
/// `r`, `br` or `cr` with a non-identifier char (or the line start) before
/// it — the lexer's own rule, so `bar"` stays an identifier plus a string.
/// Returns the opening hash count. `b"..."` is a plain byte string, not raw,
/// and `rb` is no language's prefix (accepting it misread `\r`+`b` escapes
/// as raw openers).
fn raw_opener(line: &str, i: usize) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut j = i;
    while j > 0 && bytes.get(j - 1) == Some(&b'#') {
        j -= 1;
    }
    let hashes = i - j;
    let pre = line.get(..j).unwrap_or("");
    let prefix_len = if pre.ends_with("br") || pre.ends_with("cr") {
        2
    } else if pre.ends_with('r') {
        1
    } else {
        return None;
    };
    let start = j - prefix_len;
    // Same Unicode-aware boundary as the opener test: a non-ASCII
    // identifier char before the `r` makes it an identifier, not a prefix.
    if start > 0
        && line
            .get(..start)
            .is_some_and(|pre| pre.ends_with(|c: char| c.is_alphanumeric() || c == '_'))
    {
        return None;
    }
    Some(hashes)
}

/// A line carries the crate-level attribute iff `#![forbid(unsafe_code)]`
/// opens the line's code: leading whitespace allowed, but the `#` must be
/// the first character outside any string, char, line comment or block
/// comment. A commented-out attribute is one uncomment away from *absent*,
/// so here — unlike the unsafe-block matcher, which deliberately still
/// matches comments — comments exclude.
///
/// Block nesting depth threads across lines through `depth` (Rust block
/// comments nest: `/* /* */ code */` is still comment after the inner
/// close, and a boolean would certify the rest); strings and chars are
/// single-line (the documented residual, same as the block matcher).
/// Raw strings are the other residual: a quote inside raw content desyncs
/// the scan, and the regression tests below pin the cases that must hold
/// rather than the ones that cannot.
fn line_has_forbid_attr(line: &str, depth: &mut u32) -> bool {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    let mut in_char = false;
    while let Some(&b) = bytes.get(i) {
        if *depth > 0 {
            if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
                *depth += 1;
                i += 2;
                continue;
            }
            if b == b'*' && bytes.get(i + 1) == Some(&b'/') {
                *depth = depth.saturating_sub(1);
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if in_string {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if in_char {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'\'' {
                in_char = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            // A string opens: the attribute cannot lead this line.
            return false;
        }
        if b == b'\'' {
            let rest = line.get(i + 1..).unwrap_or("");
            if rest.chars().take(3).collect::<String>().contains('\'') {
                in_char = true;
            }
            i += 1;
            continue;
        }
        if b == b'/' {
            if bytes.get(i + 1) == Some(&b'/') {
                // Line comment: no code follows.
                return false;
            }
            if bytes.get(i + 1) == Some(&b'*') {
                *depth += 1;
                i += 2;
                continue;
            }
        }
        if b == b' ' || b == b'\t' {
            i += 1;
            continue;
        }
        // First code character: it must open the attribute. The lint list
        // may carry siblings in any order (`#![forbid(warnings,
        // unsafe_code)]` is the alphabetical habit), with generous spacing
        // — so the `forbid(...)` list is parsed, not prefix-matched (M2:
        // the old boundary match missed second position and failed a
        // compliant tree as missing). The match is an exact lint equality:
        // `unsafe_codex` is a different lint and still does not count.
        // Multiline attributes remain a documented residual (single-line
        // scan, same as the block matcher): an unclosed `forbid(` on this
        // line is not a proof.
        let rest = line.get(i..).unwrap_or("");
        let Some(rest) = rest.strip_prefix("#![") else {
            return false;
        };
        let rest = rest.trim_start_matches([' ', '\t']);
        // Space between the lint path and its list is legal Rust
        // (`#![forbid (unsafe_code)]`), so it cannot count as absent.
        let Some(rest) = rest.strip_prefix("forbid") else {
            return false;
        };
        let rest = rest.trim_start_matches([' ', '\t']);
        let Some(rest) = rest.strip_prefix('(') else {
            return false;
        };
        let Some(end) = rest.find(')') else {
            return false;
        };
        let Some(list) = rest.get(..end) else {
            return false;
        };
        return list
            .split(',')
            .any(|lint| lint.trim_matches([' ', '\t', '\r']) == "unsafe_code");
    }
    false
}

/// Lines exempt from the unsafe scan: the crate-level forbid attribute
/// itself, and nothing else. The old whole-line skip (`contains` on
/// `forbid(unsafe_code)` or `cfg_attr`) let a real code-shaped opener hide
/// behind a trailing mention of `cfg_attr`, evading the scan (M2) — the
/// dangerous direction. Pure attribute lines carry no code-shaped `unsafe`
/// anyway (`unsafe_code` fails the word boundary), so narrowing the
/// exemption to attribute-position lines loses no legitimate skip.
///
/// H1: the exemption additionally requires *no violation on the line* — an
/// opener after the attribute (`#![forbid(unsafe_code)]` plus a real block
/// on the same line, legal as a block-inner attribute) must still flag.
/// Checking the violation first keeps the dangerous direction loud.
fn unsafe_line_exempt(line: &str) -> bool {
    line_has_forbid_attr(line, &mut 0) && !unsafe_line_is_violation(line)
}

fn starts_word(s: &str, word: &str) -> bool {
    s.starts_with(word)
        && s[word.len()..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric() && c != '_')
}

/// Scan one crate's `.rs` files for `unsafe` code positions, recording
/// violations. Split out of `run_unsafe_scan` so each lane stays readable.
fn scan_crate_rs_files(
    workspace: &Path,
    dir: &Path,
    violations: &mut Vec<String>,
    files_scanned: &mut usize,
) {
    let mut files = Vec::new();
    let mut dir_problems = Vec::new();
    collect_rs_into(dir, &mut files, &mut dir_problems);
    // M4: an unreadable directory fails the scan like an unreadable
    // file — certifying the rest GREEN would vouch for code never seen.
    violations.extend(dir_problems);
    files.sort();
    for f in &files {
        let rel = f
            .strip_prefix(workspace)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(text) = std::fs::read_to_string(f) else {
            // An unreadable file is a scan failure, not a skip: skipping
            // it would certify a tree the scanner never saw.
            violations.push(format!("{rel}: unreadable, scan incomplete"));
            continue;
        };
        *files_scanned += 1;
        if rel.starts_with("crates/qqq-sys/") {
            continue;
        }
        scan_rs_text(&rel, &text, violations);
    }
}

/// Scan one file's text: every line alone, then every adjacent pair.
/// The pair re-test closes the cross-line shape (H-r3-H1: `unsafe` dangling
/// at end of line with the opener on the next); pairs whose lines already
/// flagged are skipped to avoid double-reporting the same finding.
fn scan_rs_text(rel: &str, text: &str, violations: &mut Vec<String>) {
    let lines: Vec<&str> = text.lines().collect();
    let mut flagged: Vec<bool> = Vec::with_capacity(lines.len());
    for (n, line) in lines.iter().enumerate() {
        if unsafe_line_exempt(line) {
            flagged.push(false);
            continue;
        }
        if unsafe_line_is_violation(line) {
            violations.push(format!("{rel}:{}:{line}", n + 1));
            flagged.push(true);
        } else {
            flagged.push(false);
        }
    }
    for (n, w) in lines.windows(2).enumerate() {
        let [a, b] = w else { continue };
        if flagged.get(n) == Some(&true) || flagged.get(n + 1) == Some(&true) {
            continue;
        }
        let mut pair = String::with_capacity(a.len() + b.len() + 1);
        pair.push_str(a);
        pair.push('\n');
        pair.push_str(b);
        if unsafe_line_exempt(&pair) {
            continue;
        }
        if unsafe_line_is_violation(&pair) {
            violations.push(format!(
                "{rel}:{}:cross-line `unsafe` opener (the keyword dangles at the end of line {})",
                n + 2,
                n + 1
            ));
        }
    }
}

fn run_unsafe_scan(workspace: &Path) -> (bool, String) {
    let mut violations = Vec::new();
    let mut missing = Vec::new();
    let mut crates: Vec<PathBuf> = Vec::new();
    let Ok(rd) = std::fs::read_dir(workspace.join("crates")) else {
        return (
            false,
            "cannot read crates/; the scan certifies nothing".to_owned(),
        );
    };
    for e in rd {
        // H-r3-H2: `flatten()` would silently drop an `Err` entry (I/O
        // mid-listing) and certify the surviving files GREEN — the same
        // fail-open shape M4 closed for unreadable directories.
        let e = match e {
            Ok(e) => e,
            Err(e) => {
                violations.push(format!(
                    "{}: directory entry unreadable mid-listing, scan incomplete: {e}",
                    workspace.join("crates").display()
                ));
                continue;
            }
        };
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            crates.push(e.path());
        }
    }
    crates.sort();
    if crates.is_empty() {
        return (
            false,
            "no crates found; the scan certifies nothing".to_owned(),
        );
    }
    let mut files_scanned = 0_usize;
    for dir in &crates {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned();
        if name == "xtask" {
            // The scanner itself is scanned like every other crate: no
            // exception, and it must carry the forbid attribute to prove it.
        }
        scan_crate_rs_files(workspace, dir, &mut violations, &mut files_scanned);
        if name != "qqq-sys" {
            // The attribute must be real code, not a comment mentioning it:
            // a commented-out forbid is one uncomment away from absent, so a
            // text `contains` here would certify a root on hearsay — the same
            // shape `tools/audit_unsafe.py` guards with its prose filing.
            let lib = dir.join("src").join("lib.rs");
            let mut depth = 0;
            let has = std::fs::read_to_string(&lib)
                .is_ok_and(|t| t.lines().any(|l| line_has_forbid_attr(l, &mut depth)));
            if !has {
                let main = dir.join("src").join("main.rs");
                let mut depth = 0;
                let has_main = std::fs::read_to_string(&main)
                    .is_ok_and(|t| t.lines().any(|l| line_has_forbid_attr(l, &mut depth)));
                if !has_main {
                    missing.push(name.clone());
                }
            }
        }
    }
    if files_scanned == 0 {
        return (
            false,
            "no .rs files scanned; the scan certifies nothing".to_owned(),
        );
    }
    if !violations.is_empty() || !missing.is_empty() {
        use std::fmt::Write as _;
        let mut out = String::from("unsafe code found outside crates/qqq-sys:\n");
        for v in &violations {
            let _ = writeln!(out, "{v}");
        }
        for m in &missing {
            let _ = writeln!(out, "missing forbid(unsafe_code): {m}");
        }
        return (false, out);
    }
    (
        true,
        format!(
            "OK: no unsafe code outside the audited exception crate ({} crates, {files_scanned} files)",
            crates.len()
        ),
    )
}

/// Collect every `.rs` file under `dir`. An unreadable directory is a scan
/// failure, not a skip (M4): `run_unsafe_scan` fails loudly on `problems`
/// instead of certifying a tree it never saw. (Unreadable *files* already
/// fail the same way at the read site below.)
fn collect_rs_into(dir: &Path, out: &mut Vec<PathBuf>, problems: &mut Vec<String>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            problems.push(format!(
                "{}: unreadable directory, scan incomplete: {e}",
                dir.display()
            ));
            return;
        }
    };
    for e in rd {
        // Same fail-loud contract as the caller (H-r3-H2): a dropped `Err`
        // entry would certify a partial listing GREEN.
        let e = match e {
            Ok(e) => e,
            Err(e) => {
                problems.push(format!(
                    "{}: directory entry unreadable mid-listing, scan incomplete: {e}",
                    dir.display()
                ));
                continue;
            }
        };
        let p = e.path();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            collect_rs_into(&p, out, problems);
        } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

/// The sixteen commands `DX-013` requires in `--help`, in CI order.
const HELP_COMMANDS: &[&str] = &[
    "new", "build", "run", "dev", "serve", "test", "inspect", "audit", "verify", "caps", "why",
    "trace", "doctor", "mcp", "schema", "migrate",
];

/// Locate the debug output directory: `CARGO_TARGET_DIR` first (the bridge
/// builds there), then cargo's own answer, then the default. The CI step
/// this ports assumed `workspace/target`, which is wrong everywhere the
/// target directory is configured — including the bridge this gate runs in.
///
/// A relative `CARGO_TARGET_DIR` resolves against the caller's working
/// directory, not the workspace: `resolve_target_debug_dir` pins it under
/// the workspace so invoking xtask from a subdir probes the right tree
/// (L4). There is deliberately no per-step timeout on top (L3): a hung
/// checker blocks its lane until the CI job's own 60-minute backstop kills
/// it. The sequential lane still prints its `run` line up front, so the
/// in-flight step is named in the log instead of going silent.
fn target_debug_dir(workspace: &Path) -> PathBuf {
    let via_env = std::env::var("CARGO_TARGET_DIR")
        .ok()
        .filter(|d| !d.is_empty());
    // M-r3-MED: a failed `cargo metadata` (toolchain broken mid-gate)
    // must not silently fall back to `workspace/target` and then fail as
    // "missing; run the build step first" — check `success()` like the
    // `git` and interpreter-discovery paths do.
    let via_metadata = Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .current_dir(workspace)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| parse_target_dir(&o.stdout));
    resolve_target_debug_dir(workspace, via_env.as_deref(), via_metadata)
}

/// Pure core of `target_debug_dir`, so the relative-var pinning is unit
/// tested without mutating the process environment (cargo tests share it).
fn resolve_target_debug_dir(
    workspace: &Path,
    cargo_target_dir: Option<&str>,
    metadata_dir: Option<PathBuf>,
) -> PathBuf {
    if let Some(dir) = cargo_target_dir
        && !dir.is_empty()
    {
        let base = PathBuf::from(dir);
        let base = if base.is_relative() {
            workspace.join(base)
        } else {
            base
        };
        return base.join("debug");
    }
    if let Some(d) = metadata_dir {
        // L1: same pinning as the env var — a relative metadata directory
        // resolves against the caller's working directory otherwise.
        // (Cargo always emits absolute paths; this is the defensive arm.)
        let base = if d.is_relative() {
            workspace.join(d)
        } else {
            d
        };
        return base.join("debug");
    }
    workspace.join("target").join("debug")
}

/// The `target_directory` value from `cargo metadata` JSON, without serde
/// (this crate has no dependencies by design): scan for the key and decode
/// the quoted string, escapes included. Whitespace around the colon is
/// skipped and `\uXXXX` escapes decoded, so a spaced or non-ASCII metadata
/// answer still resolves instead of silently falling back to the default
/// directory (L5: a false "missing; run the build step first"). Every key
/// occurrence is tried in turn — the first hit may sit inside a string
/// value (M-r3-MED) — and surrogate pairs combine; anything malformed
/// yields `None` and the caller falls back.
fn parse_target_dir(json: &[u8]) -> Option<PathBuf> {
    const KEY: &[u8] = b"\"target_directory\"";
    let mut search = json;
    while let Some(pos) = search.windows(KEY.len()).position(|w| w == KEY) {
        let Some(after) = search.get(pos + KEY.len()..) else {
            break;
        };
        if let Some(dir) = parse_target_dir_at(after) {
            return Some(dir);
        }
        let Some(next) = search.get(pos + 1..) else {
            break;
        };
        search = next;
    }
    None
}

/// Decode one key occurrence: colon, opening quote, then the escaped string.
/// Surrogate pairs (`\uD83D\uDE00`) combine into the astral character; a
/// lone surrogate is malformed and refuses this occurrence (M-r3-MED).
fn parse_target_dir_at(json: &[u8]) -> Option<PathBuf> {
    let mut it = json.iter();
    for b in it.by_ref() {
        if *b == b' ' || *b == b'\t' || *b == b'\n' || *b == b'\r' {
            continue;
        }
        if *b == b':' {
            break;
        }
        return None;
    }
    for b in it.by_ref() {
        if *b == b' ' || *b == b'\t' || *b == b'\n' || *b == b'\r' {
            continue;
        }
        if *b == b'"' {
            break;
        }
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    loop {
        let b = *it.next()?;
        if b == b'"' {
            break;
        }
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match it.next()? {
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'r' => out.push(b'\r'),
            b'\\' => out.push(b'\\'),
            b'"' => out.push(b'"'),
            b'/' => out.push(b'/'),
            b'u' => {
                let cp = parse_hex4(&mut it)?;
                let cp = if (0xD800..0xDC00).contains(&cp) {
                    // High surrogate: the low half must follow immediately.
                    if *it.next()? != b'\\' || *it.next()? != b'u' {
                        return None;
                    }
                    let lo = parse_hex4(&mut it)?;
                    if !(0xDC00..0xE000).contains(&lo) {
                        return None;
                    }
                    0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                } else if (0xDC00..0xE000).contains(&cp) {
                    // Lone low surrogate: malformed.
                    return None;
                } else {
                    cp
                };
                let ch = char::from_u32(cp)?;
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            _ => return None,
        }
    }
    if out.is_empty() {
        return None;
    }
    std::str::from_utf8(&out).ok().map(PathBuf::from)
}

/// Four hex digits after `\u` as a code point number.
fn parse_hex4(it: &mut std::slice::Iter<'_, u8>) -> Option<u32> {
    let mut quad = [0u8; 4];
    for q in &mut quad {
        *q = *it.next()?;
    }
    let hex = std::str::from_utf8(&quad).ok()?;
    u32::from_str_radix(hex, 16).ok()
}

/// The `--help` brevity standard (`DX-013`): at most 40 lines, all 16
/// commands present as indented entries, and the loop proven to run.
/// Counts from the process output like the CI pipe does — never held in a
/// shell variable, which is the vacuity the CI comments warn about.
/// Presence keys on the command as the first token of an *indented* line
/// (LOW r3): pinning clap's exact four spaces would read a layout change
/// as 16 missing commands, while an unindented prose match ("run the
/// doctor …") must never count.
fn help_check(output: &str) -> Result<(usize, usize), String> {
    let text = output.replace("\r\n", "\n");
    if text.is_empty() {
        return Err(
            "the help output is empty; the budget check would have been vacuous".to_owned(),
        );
    }
    let lines = text.lines().count();
    let mut present = 0;
    for cmd in HELP_COMMANDS {
        if text
            .lines()
            .any(|l| l.starts_with([' ', '\t']) && l.split_whitespace().next() == Some(*cmd))
        {
            present += 1;
        } else {
            return Err(format!("the help omits the {cmd} command"));
        }
    }
    if present != HELP_COMMANDS.len() {
        return Err(format!(
            "expected to check {} commands, checked {present}",
            HELP_COMMANDS.len()
        ));
    }
    if lines > 40 {
        return Err(format!(
            "qqqai --help prints {lines} lines, over the 40-line budget"
        ));
    }
    Ok((lines, present))
}

fn run_help_brevity(workspace: &Path) -> (bool, String) {
    let exe = if cfg!(windows) { "qqqai.exe" } else { "qqqai" };
    let bin = target_debug_dir(workspace).join(exe);
    if !bin.is_file() {
        return (
            false,
            format!("{} is missing; run the build step first", bin.display()),
        );
    }
    let out = Command::new(&bin).arg("--help").output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout).into_owned();
            match help_check(&text) {
                Ok((lines, present)) => (
                    true,
                    format!("help is within budget at {lines} lines; {present} commands listed"),
                ),
                Err(e) => (false, e),
            }
        }
        Ok(o) => (false, format!("qqqai --help exited {}", o.status)),
        Err(e) => (false, format!("failed to run {}: {e}", bin.display())),
    }
}

// ---------------------------------------------------------------------------
// Fault injection on worktree copies, never the real tree (phase 1 proof).
// ---------------------------------------------------------------------------

/// One named injection: what to change, where, and what must be detected.
/// `expect` is a substring of a `FAIL`-prefixed report line the checker
/// prints on detection (see `injection_verdict`) — never of a crash dump.
struct Injection {
    name: &'static str,
    file: &'static str,
    needle: &'static str,
    replacement: &'static str,
    expect: &'static str,
    checker: &'static [&'static str],
}

/// Mirrors `tools/fault_inject_no_ambient.py` injection 1 (read from that
/// file, not composed from memory): an ambient read in a host crate, which
/// `check_no_ambient.py` must report.
const INJECTIONS: &[Injection] = &[Injection {
    name: "no-ambient-1",
    file: "crates/qqq-host/src/ambient.rs",
    needle: "use std::sync::atomic::{AtomicU64, Ordering};",
    replacement: "/// INJECTED: an ambient configuration read.\n#[must_use]\n pub fn injected_ambient() -> bool {\n    std::env::var(\"QQQ_INJECTED\").is_ok()\n}\n\nuse std::sync::atomic::{AtomicU64, Ordering};",
    expect: "std::env::var",
    checker: &["tools/check_no_ambient.py"],
}];

/// Strip repo-location overrides from a `git` child environment.
///
/// `GIT_DIR`, `GIT_WORK_TREE` and `GIT_INDEX_FILE` redirect every repository
/// operation the child performs: inherited from a parent shell (an IDE with
/// `GIT_DIR` set, a nested invocation), this helper's `init`/`add`/`commit`
/// in a scratch or worktree directory would run against the wrong
/// repository — the same chimera class as `scrub_cargo_run_env`'s
/// `CARGO_PKG_NAME` (`§O-614`), proven live by failing the worktree test
/// under a bogus inherited `GIT_DIR`.
fn scrub_git_env(cmd: &mut Command) {
    cmd.env_remove("GIT_DIR");
    cmd.env_remove("GIT_WORK_TREE");
    cmd.env_remove("GIT_INDEX_FILE");
}

/// The checker's verdict for one injection: detected (checker failed and
/// its output carries the expected marker) or missed. The spawn `Result`
/// travels intact to here (M3): a checker that never ran is an
/// infrastructure error, never a pass — matching the needle against a crash
/// dump that happens to contain it would certify a broken harness as
/// DETECTED.
///
/// M-r3-MED: the marker must ride a `FAIL`-prefixed report line — the
/// checkers' report contract (`  FAIL  {path}: {construct} — {reason}`).
/// A traceback that echoes the injected source still fails the checker, but
/// it is a crash, not a detection. `Injection.expect` must therefore be a
/// substring of such a report line, not of arbitrary output.
fn injection_verdict(run: Result<(bool, String), String>, expect: &str) -> Result<bool, String> {
    let (ok, output) = run.map_err(|e| format!("checker did not run: {e}"))?;
    if ok {
        return Ok(false);
    }
    let detected = output
        .lines()
        .any(|l| l.contains(expect) && l.trim_start().starts_with("FAIL"));
    Ok(detected)
}

/// Run `git` in `dir`, returning trimmed stdout on success.
fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new("git");
    cmd.args(args);
    cmd.current_dir(dir);
    scrub_git_env(&mut cmd);
    let o = cmd
        .output()
        .map_err(|e| format!("failed to spawn git: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&o.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_owned())
}

/// The worktree root for an injection: under the system temp dir, never the
/// real tree. A worktree is a linked checkout, not a copy, so even a large
/// tree is cheap — and deleting it removes every trace of the injection.
fn worktree_dir(name: &str) -> PathBuf {
    let pid = std::process::id();
    std::env::temp_dir().join(format!("qqq-fault-{name}-{pid}"))
}

fn worktree_contains(list: &str, dir: &Path) -> bool {
    // `git worktree list --porcelain` prints `worktree <path>` records (plus
    // blank lines and `bare`/`detached` markers); compare the record paths
    // canonically. Git prints the *resolved* path (symlinked temp dirs on
    // macOS, separators and case on Windows) while the caller usually holds
    // the unresolved one -- a string compare fails exactly there, proven by
    // CI failing this assert on macOS+Windows while Linux stayed green.
    // The direct compare remains as the fallback when either side cannot
    // be resolved. On Windows it is case-insensitive (L2): after
    // `remove --force` the admin record is gone, both `canonicalize` calls
    // fail, and `E:\` vs `e:\` must still agree the worktree is gone.
    let canon = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    list.lines().any(|l| {
        l.strip_prefix("worktree ").is_some_and(|p| {
            std::fs::canonicalize(p.trim()).is_ok_and(|c| c == canon)
                || paths_equal_for_platform(Path::new(p.trim()), dir)
        })
    })
}

/// Platform-aware path equality for the unresolvable fallback above: exact
/// on case-sensitive filesystems, ASCII case-insensitive on Windows.
fn paths_equal_for_platform(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    #[cfg(windows)]
    {
        a.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Apply one injection on a detached worktree of HEAD, run its checker
/// there, and remove the worktree on every path out. Returns the
/// checker's verdict: detected (pass) or missed (fail).
///
/// The worktree pins HEAD, not the working tree (L9): with uncommitted
/// changes the injection certifies a different tree than the one under
/// development. That is accepted — the gate runs on clean CI checkouts —
/// so a dirty tree warns rather than refuses. The before/after byte
/// comparison below covers only the injected file (L6): the checker runs
/// with the worktree as its working directory, but nothing stops a checker
/// from reaching absolute paths, so a hostile or buggy checker could touch
/// the real tree elsewhere unobserved. Single-file is the phase-1 proof
/// scope (one `INJECTIONS` entry mirroring `fault_inject_no_ambient.py`
/// injection 1, L10); widening the proof means more injections first, then
/// a tree-wide comparison.
fn fault_inject(workspace: &Path, python: &[String], name: &str) -> Result<bool, String> {
    let inj = INJECTIONS.iter().find(|i| i.name == name).ok_or_else(|| {
        format!("unknown injection {name:?}; see `cargo xtask fault-inject --list`")
    })?;
    if let Ok(status) = git(workspace, &["status", "--porcelain"])
        && !status.is_empty()
    {
        eprintln!(
            "warning: working tree is dirty; the worktree pins HEAD, so this injection certifies HEAD, not the uncommitted changes"
        );
    }
    let dir = worktree_dir(name);
    if dir.exists() {
        return Err(format!(
            "stale worktree dir {} exists; remove it first (`git worktree remove --force {}`, then `git worktree prune` if the admin entry survives a manual `rm -rf`)",
            dir.display(),
            dir.display()
        ));
    }
    let target = workspace.join(inj.file);
    let before =
        std::fs::read(&target).map_err(|e| format!("cannot read {}: {e}", target.display()))?;
    let cleanup = |ws: &Path, d: &Path| {
        let _ = git(
            ws,
            &[
                "worktree",
                "remove",
                "--force",
                d.to_string_lossy().as_ref(),
            ],
        );
    };
    // L3: `?` here used to early-return past `cleanup`, leaving a
    // half-created dir behind — the *next* run then died on the stale
    // error above instead of the real `add` failure. Remove the
    // residue so the failure stays diagnosable and retryable.
    if let Err(e) = git(
        workspace,
        &[
            "worktree",
            "add",
            "--detach",
            dir.to_string_lossy().as_ref(),
            "HEAD",
        ],
    ) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(e);
    }
    let detected = (|| -> Result<bool, String> {
        let wt_file = dir.join(inj.file);
        let text = std::fs::read_to_string(&wt_file)
            .map_err(|e| format!("cannot read worktree file {}: {e}", wt_file.display()))?;
        let patched = text.replacen(inj.needle, inj.replacement, 1);
        if patched == text {
            return Err(format!("needle not found in worktree copy of {}", inj.file));
        }
        std::fs::write(&wt_file, patched)
            .map_err(|e| format!("cannot write worktree file: {e}"))?;
        let mut argv: Vec<String> = python.to_vec();
        argv.extend(inj.checker.iter().map(|s| (*s).to_owned()));
        let run = match argv.split_first() {
            Some((head, tail)) => run_cmd(head, tail, None, &dir),
            None => Err("empty argv for the checker".to_owned()),
        };
        injection_verdict(run, inj.expect)
    })();
    cleanup(workspace, &dir);
    let after =
        std::fs::read(&target).map_err(|e| format!("cannot re-read {}: {e}", target.display()))?;
    if before != after {
        return Err(format!(
            "the real tree's {} changed during injection",
            inj.file
        ));
    }
    match git(workspace, &["worktree", "list", "--porcelain"]) {
        Ok(list) if worktree_contains(&list, &dir) => Err(format!(
            "worktree {} still listed after removal",
            dir.display()
        )),
        // LOW r3: `remove --force` unregisters the worktree but can leave
        // the directory behind (locked file on Windows) — the admin list
        // alone would call that clean, and the next run would die on the
        // stale-dir error instead. Check the disk too.
        Ok(_) => {
            if dir.exists() {
                return Err(format!(
                    "worktree {} still on disk after removal (locked file?); delete it and run `git worktree prune`",
                    dir.display()
                ));
            }
            detected
        }
        Err(e) => Err(format!("cannot verify worktree removal: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Subcommands.
// ---------------------------------------------------------------------------

fn cmd_list() -> ExitCode {
    // Machine-readable coverage manifest for `check_gate_parity.py`: the
    // python invocations this gate runs, one normalized `tools/...` line
    // each, exactly as the parity checker normalises both gates. Python
    // rows only, by design (L12): parity rule 5 covers `tools/check_*.py`,
    // and the non-check scripts this gate runs (portable-shell ports,
    // `normalize_eol --check`, fault-injection proofs) are compared
    // gate-to-gate by rules 1-4 instead. A helper that neither gate runs is
    // visible there as agreement-on-nothing only if it was never in either
    // gate — extending rule 5's glob is a tools-section decision, because
    // most `tools/*.py` are libraries, not gate checks.
    for step in PY_STEPS {
        if let StepKind::Py { args } = &step.kind {
            println!("{}", args.join(" "));
        }
    }
    ExitCode::SUCCESS
}

fn cmd_ci(workspace: &Path, python: &[String]) -> ExitCode {
    let steps = all_steps();
    let par: Vec<&Step> = steps.iter().filter(|s| s.lane == Lane::Par).collect();
    let seq: Vec<&Step> = steps.iter().filter(|s| s.lane == Lane::Seq).collect();
    let par_outcomes: Vec<Outcome> = std::thread::scope(|s| {
        let handles: Vec<_> = par
            .iter()
            .map(|step| {
                // M1: the label is captured before `spawn` so a panicking
                // lane thread still reports which step died.
                let label = step_label(step);
                (label, s.spawn(|| run_step(step, workspace, python)))
            })
            .collect();
        handles
            .into_iter()
            .map(|(label, h)| h.join().unwrap_or_else(|_| panicked_outcome(label)))
            .collect()
    });
    let mut outcomes = par_outcomes;
    for step in seq {
        outcomes.push(run_step(step, workspace, python));
    }
    println!("---- summary ----");
    for o in &outcomes {
        println!(
            "{:<64} {} ({}s)",
            o.name,
            if o.ok { "ok" } else { "FAILED" },
            o.secs
        );
    }
    let bad = failed(&outcomes);
    if bad.is_empty() {
        println!("GATE GREEN: {} steps", outcomes.len());
        ExitCode::SUCCESS
    } else {
        println!("GATE RED: {}", bad.join(", "));
        ExitCode::FAILURE
    }
}

/// The fast static subset: format, unused-dependency, line endings, doc claims.
const HYGIENE_STEPS: &[Step] = &[
    Step::cmd(
        Lane::Seq,
        "fmt",
        "cargo",
        &["fmt", "--all", "--", "--check"],
        None,
    ),
    Step::cmd(Lane::Seq, "machete", "cargo", &["machete"], None),
    Step::py(
        Lane::Seq,
        "normalize",
        &["tools/normalize_eol.py", "--check"],
    ),
    Step::py(Lane::Seq, "doc-claims", &["tools/check_doc_claims.py"]),
];

fn cmd_hygiene(workspace: &Path, python: &[String]) -> ExitCode {
    let mut outcomes = Vec::new();
    for step in HYGIENE_STEPS {
        outcomes.push(run_step(step, workspace, python));
    }
    let bad = failed(&outcomes);
    if bad.is_empty() {
        ExitCode::SUCCESS
    } else {
        println!("HYGIENE RED: {}", bad.join(", "));
        ExitCode::FAILURE
    }
}

fn all_steps() -> Vec<Step> {
    // Assembled in execution order: the sequential lane runs in this order
    // (cargo steps serialise on the target dir), the parallel lane ignores it.
    let mut v: Vec<Step> = Vec::new();
    v.extend_from_slice(CARGO_STEPS);
    v.extend_from_slice(IGNORED_TESTS);
    v.extend_from_slice(ORDERS_API_STEPS);
    // The release probe and the two ported shell checks need built binaries.
    v.push(Step::cmd(
        Lane::Seq,
        "f01-probe",
        "cargo",
        &[
            "run",
            "--release",
            "-p",
            "qqq-host",
            "--example",
            "panic_probe",
            "--features",
            "release-panic-probe",
        ],
        None,
    ));
    v.push(Step {
        name: "unsafe-scan",
        lane: Lane::Seq,
        kind: StepKind::UnsafeScan,
    });
    v.push(Step {
        name: "help-brevity",
        lane: Lane::Seq,
        kind: StepKind::HelpBrevity,
    });
    for s in PY_STEPS {
        v.push(*s);
    }
    v
}

fn workspace_root() -> Result<PathBuf, String> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot locate the workspace root".to_owned())
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    if cmd == Args::List {
        return cmd_list();
    }
    if cmd == Args::FaultInjectList {
        for i in INJECTIONS {
            println!("{}: {} (checker: {})", i.name, i.file, i.checker.join(" "));
        }
        return ExitCode::SUCCESS;
    }
    let workspace = match workspace_root() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    // Forbid running against a tree the invocation cannot see: xtask resolves
    // the workspace from its own manifest location, never from the shell's
    // working directory, so `cargo xtask ci` means the same everywhere.
    let python = match discover_python() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    match cmd {
        Args::Ci => cmd_ci(&workspace, &python),
        Args::Hygiene => cmd_hygiene(&workspace, &python),
        Args::FaultInject(name) => match fault_inject(&workspace, &python, &name) {
            Ok(true) => {
                println!("INJECTION DETECTED: {name}");
                ExitCode::SUCCESS
            }
            Ok(false) => {
                println!("INJECTION MISSED: {name}");
                ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("fault injection failed: {e}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("unreachable args");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_every_subcommand() {
        assert_eq!(parse_args(&args(&["ci"])), Ok(Args::Ci));
        assert_eq!(parse_args(&args(&["hygiene"])), Ok(Args::Hygiene));
        assert_eq!(parse_args(&args(&["list"])), Ok(Args::List));
        assert_eq!(
            parse_args(&args(&["fault-inject", "--list"])),
            Ok(Args::FaultInjectList)
        );
        assert_eq!(
            parse_args(&args(&["fault-inject", "no-ambient-1"])),
            Ok(Args::FaultInject("no-ambient-1".to_owned()))
        );
    }

    #[test]
    fn rejects_empty_and_unknown() {
        assert!(parse_args(&args(&[])).is_err());
        assert!(parse_args(&args(&["ci", "extra"])).is_err());
        assert!(parse_args(&args(&["frobnicate"])).is_err());
        assert!(parse_args(&args(&["fault-inject"])).is_err());
        assert!(parse_args(&args(&["fault-inject", "a", "b"])).is_err());
    }

    #[test]
    fn scrub_removes_package_identity_but_keeps_toolchain() {
        // `cargo test` itself sets `CARGO_PKG_NAME` for this binary's
        // environment, which is exactly the leak under test: without the
        // scrub, a child would inherit xtask's identity.
        let mut cmd = Command::new("cargo");
        cmd.env("CARGO_PKG_XTASK_PROBE", "1");
        cmd.env("CARGO_BIN_XTASK_PROBE", "1");
        scrub_cargo_run_env(&mut cmd);
        let removed: Vec<String> = cmd
            .get_envs()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        for key in [
            "CARGO_MANIFEST_DIR",
            "CARGO_MANIFEST_PATH",
            "CARGO_PRIMARY_PACKAGE",
            "CARGO_PKG_NAME",
            "CARGO_PKG_VERSION",
            "CARGO_PKG_XTASK_PROBE",
            "CARGO_BIN_NAME",
            "CARGO_BIN_XTASK_PROBE",
            "CARGO_CRATE_NAME",
        ] {
            // Removed, or absent from this process entirely (nothing to
            // inherit means nothing to scrub): either way the child cannot
            // see xtask's identity through this key.
            let gone = removed.iter().any(|k| k == key) || std::env::var(key).is_err();
            assert!(gone, "{key} not scrubbed");
        }
        // Toolchain selection survives: scrubbing it would change *which*
        // toolchain runs, a worse divergence than the one being fixed.
        let kept_nones: Vec<String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                let k = k.to_string_lossy().into_owned();
                (v.is_none() && (k == "RUSTUP_TOOLCHAIN" || k == "CARGO_HOME")).then_some(k)
            })
            .collect();
        assert!(
            kept_nones.is_empty(),
            "toolchain env scrubbed: {kept_nones:?}"
        );
    }

    #[test]
    fn git_scrub_removes_repo_location_overrides() {
        // An inherited `GIT_DIR` redirects `init`/`add`/`commit` at a scratch
        // directory to the wrong repository — proven live by failing the
        // worktree test under a bogus `GIT_DIR`. The scrub runs on every
        // `git()` child; this pins the three keys it must remove.
        let mut cmd = Command::new("git");
        cmd.env("GIT_DIR", "bogus");
        cmd.env("GIT_WORK_TREE", "bogus");
        cmd.env("GIT_INDEX_FILE", "bogus");
        scrub_git_env(&mut cmd);
        let removed: Vec<String> = cmd
            .get_envs()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        for key in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
            assert!(removed.iter().any(|k| k == key), "{key} not scrubbed");
        }
    }

    #[test]
    fn worktree_contains_resolves_noncanonical_paths() {
        // `git worktree list` prints resolved paths; the caller holds what
        // it passed in. A trailing `.` is the portable stand-in for every
        // platform's resolution difference (macOS temp symlinks, Windows
        // separators and case): string comparison fails it, canonical
        // comparison does not.
        let dir = std::env::temp_dir().join(format!("qqq-xtask-canon-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        let dotted = dir.join(".");
        let list = format!("worktree {}\nHEAD abc\n\n", dotted.display());
        assert!(
            worktree_contains(&list, &dir),
            "resolved record did not match the unresolved dir"
        );
        assert!(
            !worktree_contains("worktree /elsewhere\nHEAD abc\n", &dir),
            "an unrelated record matched"
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn worktree_contains_ignores_case_on_windows() {
        // L2: the canonical-compare fallback is byte-exact, but Windows
        // paths are case-insensitive — after `remove --force` the admin
        // record is gone, `canonicalize` fails on both sides, and `E:\`
        // vs `e:\` must still agree that the worktree is gone.
        let dir = PathBuf::from("E:\\TMP\\qqq-fault-case-1");
        assert!(worktree_contains(
            "worktree e:\\tmp\\qqq-fault-case-1\nHEAD abc\n",
            &dir
        ));
    }

    #[test]
    fn discovery_prefers_first_working_candidate() {
        const CANDS: &[&[&str]] = &[&["python3"], &["python"], &["py", "-3"]];
        let none = |_: &str, _: &[&str], _: &[&str]| false;
        assert_eq!(pick_program(CANDS, &["--version"], &none), None);
        let second = |p: &str, _: &[&str], _: &[&str]| p == "python";
        assert_eq!(
            pick_program(CANDS, &["--version"], &second),
            Some(&["python"][..])
        );
    }

    #[test]
    fn aggregation_fails_on_any_failure() {
        let ok = |n: &str| Outcome {
            name: n.to_owned(),
            ok: true,
            secs: 1,
        };
        let bad = |n: &str| Outcome {
            name: n.to_owned(),
            ok: false,
            secs: 2,
        };
        assert!(failed(&[ok("a"), ok("b")]).is_empty());
        assert_eq!(failed(&[ok("a"), bad("b")]), vec!["b"]);
        assert_eq!(failed(&[bad("a"), bad("b")]).len(), 2);
    }

    #[test]
    fn cargo_build_steps_run_sequentially() {
        // `cargo` steps serialise on the target directory; the table must
        // say so. `fmt` is exempt (no build), as are non-cargo programs.
        for s in all_steps() {
            if let StepKind::Cmd { program, args, .. } = s.kind
                && program == "cargo"
                && let Some(first) = args.first()
                && ["clippy", "build", "test", "run"].contains(first)
            {
                assert_eq!(
                    s.lane,
                    Lane::Seq,
                    "{} runs cargo {first} outside the sequential lane",
                    s.name
                );
            }
        }
    }

    #[test]
    fn binary_needing_checkers_run_sequentially() {
        // Checkers that shell a prebuilt `target/debug/qqqai` must not run
        // in the parallel wave ahead of `build`: on a cold runner there is
        // no binary yet, and CI failed `check_error_standard` on all three
        // platforms with exactly that message. The sequential lane runs
        // after `build` by table order, so the lane is the fix.
        const NEEDS_BINARY: &[&str] = &["tools/check_error_standard.py"];
        for s in all_steps() {
            if let StepKind::Py { args } = s.kind
                && let Some(script) = args.first()
                && NEEDS_BINARY.contains(script)
                && !args.contains(&"--self-test")
            {
                assert_eq!(
                    s.lane,
                    Lane::Seq,
                    "{} needs a built binary outside the sequential lane",
                    s.name
                );
            }
        }
    }

    #[test]
    fn cargo_shelling_checkers_run_sequentially() {
        // Checkers that shell `cargo xtask list` on the live path compile
        // the xtask binary into the shared target dir as a side effect. Two
        // of them in the parallel wave race: one deletes
        // `target/debug/xtask` mid-rebuild while the other is about to exec
        // it, and CI failed `check_gate_parity` on macOS with `could not
        // execute process ... (never executed)`. The `--self-test` forms
        // inject coverage and never shell cargo, so only the live forms
        // need the sequential lane, where steps run one at a time.
        const SHELLS_CARGO: &[&str] = &["tools/check_conformance.py", "tools/check_gate_parity.py"];
        for s in all_steps() {
            if let StepKind::Py { args } = s.kind
                && let Some(script) = args.first()
                && SHELLS_CARGO.contains(script)
                && !args.contains(&"--self-test")
            {
                assert_eq!(
                    s.lane,
                    Lane::Seq,
                    "{} shells cargo outside the sequential lane",
                    s.name
                );
            }
        }
    }

    #[test]
    fn unsafe_scan_matches_code_positions_only() {
        // Fixtures are assembled with `concat!` so no single source line
        // matches the pattern under test: the scanner reads its own file,
        // and a literal code-shaped opener in a test would be a self-flag —
        // the same reason the CI grep step would fail on this file.
        assert!(unsafe_line_is_violation(concat!(
            "    unsafe ",
            "{ foo(); }"
        )));
        assert!(unsafe_line_is_violation(concat!("unsafe ", "fn f() {}")));
        assert!(unsafe_line_is_violation(concat!(
            "pub unsafe ",
            "impl T {}"
        )));
        assert!(!unsafe_line_is_violation(
            "// which is the unsafe direction"
        ));
        assert!(!unsafe_line_is_violation("#![forbid(unsafe_code)]"));
        assert!(!unsafe_line_is_violation("let unsafe_code = 1;"));
        // String data is never code: the same shape inside quotes is not a
        // violation (the old grep could not tell, and flagged it).
        assert!(!unsafe_line_is_violation("let s = \"unsafe { }\";"));
        // Faithful to the CI grep (which it ports): a comment containing a
        // code-shaped unsafe block matches, because grep cannot tell comments
        // from code either. The tree carries no such line — the gate proves
        // it — so the parity holds in practice, not just in the pattern.
        assert!(unsafe_line_is_violation(concat!(
            "    // unsafe ",
            "{ in a comment"
        )));
        // The word boundary is Unicode-aware (LOW r3): `éunsafe` is one
        // identifier, not the keyword plus a brace.
        assert!(!unsafe_line_is_violation("éunsafe { x(); }"));
    }

    #[test]
    fn unsafe_scan_survives_char_literals() {
        // A char literal holding a double quote (`'"'`, `b'"'`) must not
        // open string mode: the quote belongs to the literal, and treating
        // it as a string opener hides the rest of the line — a missed
        // violation, the dangerous direction. Fixtures use `concat!` like
        // the code-position test above so no source line carries a
        // code-shaped opener outside a string.
        assert!(unsafe_line_is_violation(concat!(
            "let q = '\"'; ",
            "unsafe { f() }"
        )));
        assert!(unsafe_line_is_violation(concat!(
            "let q = b'\"'; ",
            "unsafe { f() }"
        )));
        // Control: a lifetime's lonely quote opens nothing.
        assert!(!unsafe_line_is_violation("fn f(x: &'a str) {}"));
    }

    #[test]
    fn unsafe_scan_tracks_raw_strings() {
        // A raw string's inner quotes toggle nothing: backslashes are
        // literal inside, and only a quote with the matching hash count
        // closes. Fixtures use `concat!` like the code-position test so no
        // source line carries a code-shaped opener outside a string.
        assert!(unsafe_line_is_violation(concat!(
            "let s = r#\"a \" b\"#; ",
            "unsafe { f() }"
        )));
        assert!(unsafe_line_is_violation(concat!(
            "let b = br##\"x \" y\"##; ",
            "unsafe { f() }"
        )));
        // `bar"` is an identifier plus a string, not a raw opener: the
        // prefix needs a non-identifier boundary.
        assert!(!unsafe_line_is_violation("let bar = 1; foo(bar\"baz\");"));
        // `cr` takes the same path; `rb` is no prefix, so the escape's
        // closing quote stays a plain close and the code after it is code.
        assert!(unsafe_line_is_violation(concat!(
            "let c = cr#\"a \" b\"#; ",
            "unsafe { f() }"
        )));
        assert!(unsafe_line_is_violation(
            "let s = \"a\\rb\"; unsafe { f() }"
        ));
    }

    #[test]
    fn forbid_check_needs_code_position_attribute() {
        // A commented-out attribute is one uncomment away from absent, so
        // only an attribute that opens the line's code counts. String-held
        // fixtures are safe here: the check returns false at the opening
        // quote, so no source line of this test flags the scan of its own
        // file.
        let mut b = 0;
        assert!(line_has_forbid_attr("#![forbid(unsafe_code)]", &mut b));
        assert_eq!(b, 0);
        let mut b = 0;
        assert!(line_has_forbid_attr(
            "  #![forbid(unsafe_code)]  // trailing",
            &mut b
        ));
        let mut b = 0;
        assert!(!line_has_forbid_attr("// #![forbid(unsafe_code)]", &mut b));
        let mut b = 0;
        assert!(!line_has_forbid_attr(
            "let s = \"#![forbid(unsafe_code)]\";",
            &mut b
        ));
        let mut b = 0;
        assert!(!line_has_forbid_attr(
            "/* #![forbid(unsafe_code)] */",
            &mut b
        ));
        // Multiline block: the attribute line sits inside the opener above.
        let mut b = 0;
        assert!(!line_has_forbid_attr("/* still open", &mut b));
        assert_eq!(b, 1);
        assert!(!line_has_forbid_attr("#![forbid(unsafe_code)]", &mut b));
        assert_eq!(b, 1);
        assert!(!line_has_forbid_attr("*/", &mut b));
        assert_eq!(b, 0);
        // Nesting: one closer of two openers still leaves comment, so the
        // attribute between them is not code.
        let mut b = 0;
        assert!(!line_has_forbid_attr("/* outer /* inner */", &mut b));
        assert_eq!(b, 1);
        assert!(!line_has_forbid_attr("#![forbid(unsafe_code)]", &mut b));
        assert!(!line_has_forbid_attr("still comment */", &mut b));
        assert_eq!(b, 0);
        // Item-level is not crate-level.
        let mut b = 0;
        assert!(!line_has_forbid_attr("#[forbid(unsafe_code)]", &mut b));
        // An attribute after a same-line block comment is real code.
        let mut b = 0;
        assert!(line_has_forbid_attr(
            "/* note */ #![forbid(unsafe_code)]",
            &mut b
        ));
    }

    #[test]
    fn target_dir_parses_metadata_json() {
        let win =
            br#"{"packages":[],"target_directory":"E:\\QQQ\\target","workspace_root":"E:\\QQQ"}"#;
        assert_eq!(
            parse_target_dir(win),
            Some(PathBuf::from("E:\\QQQ\\target"))
        );
        let nix = br#"{"target_directory":"/home/qqq/app/target"}"#;
        assert_eq!(
            parse_target_dir(nix),
            Some(PathBuf::from("/home/qqq/app/target"))
        );
        assert_eq!(parse_target_dir(b"{}"), None);
        assert_eq!(parse_target_dir(b"{\"target_directory\":\"\"}"), None);
        assert_eq!(parse_target_dir(b"not json"), None);
    }

    #[test]
    fn target_dir_tolerates_spacing_and_unicode_escapes() {
        // `cargo metadata` is compact today, but the key lookup must not
        // depend on zero whitespace after the colon: a spaced variant must
        // still resolve instead of silently falling back to
        // `workspace/target` (L5: false "missing; run build first").
        let spaced = br#"{"target_directory" : "/tmp/qqq-target"}"#;
        assert_eq!(
            parse_target_dir(spaced),
            Some(PathBuf::from("/tmp/qqq-target"))
        );
        // `\u` escapes must decode, not reject: otherwise a non-ASCII path
        // yields `None` and the same silent fallback.
        let uni = br#"{"target_directory":"/tmp/\u0041bc"}"#;
        assert_eq!(parse_target_dir(uni), Some(PathBuf::from("/tmp/Abc")));
        // Surrogate pairs combine (M-r3-MED): a lone high surrogate is
        // malformed and falls back, a pair decodes.
        let pair = br#"{"target_directory":"/tmp/\uD83D\uDE00"}"#;
        assert_eq!(
            parse_target_dir(pair),
            Some(PathBuf::from("/tmp/\u{1F600}"))
        );
        // The first key hit may sit inside a string value (M-r3-MED) — keep
        // searching instead of refusing on its non-colon follower.
        let inner = br#"{"a":"\"target_directory\"","target_directory":"/real"}"#;
        assert_eq!(parse_target_dir(inner), Some(PathBuf::from("/real")));
    }

    #[test]
    fn target_debug_dir_keeps_relative_vars_under_workspace() {
        // A relative `CARGO_TARGET_DIR` joins the process working directory
        // under `PathBuf::from(dir)`, not the workspace: invoking xtask from
        // a subdir then probes the wrong tree (L4). The helper pins the
        // relative form under the workspace.
        let ws = Path::new("/ws");
        assert_eq!(
            resolve_target_debug_dir(ws, Some("target-custom"), None),
            PathBuf::from("/ws/target-custom/debug")
        );
        assert_eq!(
            resolve_target_debug_dir(ws, Some("/abs/t"), None),
            PathBuf::from("/abs/t/debug")
        );
        assert_eq!(
            resolve_target_debug_dir(ws, None, Some(PathBuf::from("/m/t"))),
            PathBuf::from("/m/t/debug")
        );
        // L1: a metadata-relative directory pins under the workspace too —
        // cargo always emits absolute paths, but the fallback must not
        // depend on the caller's working directory if that ever changes.
        assert_eq!(
            resolve_target_debug_dir(ws, None, Some(PathBuf::from("rel/t"))),
            PathBuf::from("/ws/rel/t/debug")
        );
        assert_eq!(
            resolve_target_debug_dir(ws, None, None),
            PathBuf::from("/ws/target/debug")
        );
    }

    #[test]
    fn step_labels_distinguish_duplicate_names() {
        // PY_STEPS reuses one name per form (3x `check_conformance`, 3x
        // `audit_unsafe`, ...): a summary keyed by name alone cannot say
        // which argv failed (M1). Labels must differ per duplicate.
        let mut seen = std::collections::HashSet::new();
        for s in all_steps() {
            let label = step_label(&s);
            assert!(
                seen.insert(label.clone()),
                "duplicate step label {label:?}; the summary stays ambiguous"
            );
        }
        let bare = Step::py(
            Lane::Par,
            "check_conformance",
            &["tools/check_conformance.py"],
        );
        let matrix = Step::py(
            Lane::Par,
            "check_conformance",
            &["tools/check_conformance.py", "--matrix"],
        );
        assert_ne!(step_label(&bare), step_label(&matrix));
        // M5: the working directory is part of the identity — same
        // name/program/argv in different dirs must not share a label.
        let here = Step::cmd(Lane::Seq, "probe", "cargo", &["test"], None);
        let there = Step::cmd(Lane::Seq, "probe", "cargo", &["test"], Some("orders-app"));
        assert_ne!(step_label(&here), step_label(&there));
    }

    #[test]
    fn unsafe_scan_flags_trailing_cfg_attr_mention() {
        // The old whole-line `cfg_attr` skip let a real opener through
        // whenever the line mentioned `cfg_attr` (M2). The violation is tested first now; a pure
        // attribute line still carries no code-shaped `unsafe` and stays
        // clean. `concat!` keeps the fixtures off the scanner's own file.
        assert!(unsafe_line_is_violation(concat!(
            "    unsafe ",
            "{ f(); } // cfg_attr gated?"
        )));
        assert!(!unsafe_line_is_violation(
            "#![cfg_attr(not(feature = \"x\"), forbid(unsafe_code))]"
        ));
    }

    #[test]
    fn forbid_check_accepts_multi_lint_attributes() {
        // `#![forbid(unsafe_code, warnings)]` proves the forbid: the old
        // exact-match read it as missing and failed the gate on a compliant
        // tree (L13 residual, fail-noisy).
        let mut b = 0;
        assert!(line_has_forbid_attr(
            "#![forbid(unsafe_code, warnings)]",
            &mut b
        ));
        let mut b = 0;
        assert!(line_has_forbid_attr("#![ forbid(unsafe_code) ]", &mut b));
        let mut b = 0;
        assert!(!line_has_forbid_attr("#![forbid(unsafe_codex)]", &mut b));
    }

    #[test]
    fn injection_verdict_takes_the_spawn_result() {
        // M3: the verdict takes `run_cmd`'s `Result`, not English prose —
        // a spawn failure is an infrastructure error even when its message
        // happens to contain the needle (old shape: false DETECTED).
        // M-r3-MED: the marker must ride a `FAIL`-prefixed report line (the
        // checkers' report contract) — a traceback echoing the injected
        // source is a crash, not a detection.
        assert!(
            injection_verdict(Err("failed to spawn python: gone".to_owned()), "std::env").is_err()
        );
        assert!(
            injection_verdict(
                Err("failed to spawn std::env::var checker".to_owned()),
                "std::env"
            )
            .is_err()
        );
        assert!(
            injection_verdict(Err("empty argv for the checker".to_owned()), "std::env").is_err()
        );
        assert_eq!(
            injection_verdict(
                Ok((
                    false,
                    "  FAIL  crates/x/src.rs:3: `std::env::var` — ambient".to_owned()
                )),
                "std::env"
            ),
            Ok(true)
        );
        assert_eq!(
            injection_verdict(
                Ok((
                    false,
                    "Traceback (most recent call last):\n  File \"chk\", line 1\nstd::env::var(\"Q\")\nValueError: boom".to_owned()
                )),
                "std::env"
            ),
            Ok(false)
        );
        assert_eq!(
            injection_verdict(
                Ok((
                    true,
                    "  FAIL  crates/x/src.rs:3: `std::env::var`".to_owned()
                )),
                "std::env"
            ),
            Ok(false)
        );
        assert_eq!(
            injection_verdict(Ok((false, "all clean".to_owned())), "std::env"),
            Ok(false)
        );
    }

    #[test]
    fn panicked_step_keeps_its_label() {
        // M1: a panicking step's lane thread must still report *which* step
        // died — `<panicked step>` twice is the same ambiguity M1 removed
        // from the summary.
        let o = panicked_outcome("check_x [tools/check_x.py --matrix]".to_owned());
        assert!(!o.ok);
        assert_eq!(o.name, "check_x [tools/check_x.py --matrix]");
    }

    #[test]
    fn unreadable_scan_dirs_fail_loudly() {
        // M4: `collect_rs` must not silently skip a directory it cannot
        // read — a partial scan that reports GREEN certifies nothing. A
        // missing path drives the same `Err` branch deterministically
        // (permission removal is unreliable under elevated accounts).
        let mut out = Vec::new();
        let mut problems = Vec::new();
        collect_rs_into(
            &std::env::temp_dir().join("qqq-xtask-probe-no-such-dir"),
            &mut out,
            &mut problems,
        );
        assert!(out.is_empty());
        assert_eq!(problems.len(), 1);
    }

    #[test]
    fn unsafe_scan_certifies_the_real_tree() {
        // End-to-end wiring tripwire: the matcher unit tests pin shapes,
        // but only a run over the real tree catches a self-flag — a prose
        // comment shaped like a violation (the M2 fix once flagged two of
        // its own new comments, caught by the gate, not by any unit test).
        // This scans `crates/` in seconds; the full gate remains the
        // authority, this is the fast feedback.
        let workspace = workspace_root().expect("workspace root");
        let (ok, output) = run_unsafe_scan(&workspace);
        assert!(ok, "unsafe scan flags the real tree:\n{output}");
    }

    #[test]
    fn exempt_never_covers_trailing_code() {
        // H1: the exemption is the attribute position, not the line — an
        // opener after the attribute (`#![forbid(unsafe_code)]` plus a real
        // block on the same line) must still flag. `concat!` keeps the
        // fixture off the scanner's own file.
        let line = concat!("#![forbid(", "unsafe_code)] ", "unsafe { evil(); }");
        assert!(unsafe_line_is_violation(line));
        assert!(
            !unsafe_line_exempt(line),
            "exemption covered a line that carries a violation"
        );
    }

    #[test]
    fn unsafe_scan_survives_quotes_inside_comments() {
        // H2: a quote that lives inside a comment must not open string mode
        // (`/* " */` then a real opener evaded the scan). Comment text
        // still matches — only the string toggling is disabled there.
        assert!(unsafe_line_is_violation(concat!(
            "/* ",
            "\" */ ",
            "unsafe {x}"
        )));
        assert!(unsafe_line_is_violation(concat!("// ", "\" ", "unsafe{}")));
        // Regression pin: `//` inside a string is not a comment.
        assert!(!unsafe_line_is_violation(
            "let url = \"http://example.com/x\";"
        ));
    }

    #[test]
    fn unsafe_scan_skips_block_comments_before_the_opener() {
        // H3: a block comment between the keyword and the brace is a real
        // block the old gap loop missed (spaces/tabs only). Nesting must
        // resolve too: only the opener after the *outer* close counts —
        // a brace that sits inside a still-open comment is not code.
        assert!(unsafe_line_is_violation(concat!(
            "unsafe ",
            "/*c*/ { x(); }"
        )));
        assert!(unsafe_line_is_violation(concat!(
            "unsafe ",
            "/* a /* b */ */ { x(); }"
        )));
        assert!(!unsafe_line_is_violation(concat!(
            "unsafe ",
            "/* a /* b */ { x(); }"
        )));
    }

    #[test]
    fn unsafe_scan_sees_across_the_line_break() {
        // H-r3-H1: `unsafe` dangling at end of line with the opener on the
        // next is valid Rust the single-line machine cannot see. The pair
        // re-test closes it; a commented-out keyword plus a real block is
        // precisely not a violation (the keyword governs nothing).
        assert!(unsafe_line_is_violation("unsafe\n{ x(); }"));
        assert!(unsafe_line_is_violation("unsafe /* trailing */\n{ x(); }"));
        assert!(!unsafe_line_is_violation("// unsafe\n{ x(); }"));
    }

    #[test]
    fn unsafe_scan_flags_cross_line_openers_in_tree() {
        // H-r3-H1 run level: the pair re-test lives in `run_unsafe_scan`,
        // so pin it there on a synthetic crate — forbid present (a missing
        // attribute would fail the scan for the wrong reason), the only
        // violation the dangling keyword plus next-line brace.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xline-{}", std::process::id()));
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(src.join("lib.rs"), "#![forbid(unsafe_code)]\n").expect("lib");
        std::fs::write(
            src.join("main.rs"),
            "#![forbid(unsafe_code)]\nfn main() {\n    let x = unsafe\n    { 1 };\n    let _ = x;\n}\n",
        )
        .expect("main");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "cross-line opener passed the scan:\n{out}");
        assert!(out.contains("cross-line"), "wrong failure shape:\n{out}");
    }

    #[test]
    fn forbid_check_reads_the_whole_lint_list() {
        // M2: the forbid may sit second (`warnings, unsafe_code` is the
        // alphabetical order) with generous spacing — a prefix-only match
        // reads a compliant tree as missing (fail-noisy gate red).
        let mut b = 0;
        assert!(line_has_forbid_attr(
            "#![forbid(warnings, unsafe_code)]",
            &mut b
        ));
        let mut b = 0;
        assert!(line_has_forbid_attr(
            "#![ forbid( warnings , unsafe_code ) ]",
            &mut b
        ));
        let mut b = 0;
        assert!(!line_has_forbid_attr("#![forbid(warnings)]", &mut b));
        // Space between the lint path and its list is legal Rust.
        let mut b = 0;
        assert!(line_has_forbid_attr("#![forbid (unsafe_code)]", &mut b));
    }

    #[test]
    fn help_check_enforces_budget_and_presence() {
        use std::fmt::Write as _;
        let mut help = String::from("Usage: qqqai [COMMAND]\nCommands:\n");
        for c in [
            "new", "build", "run", "dev", "serve", "test", "inspect", "audit", "verify", "caps",
            "why", "trace", "doctor", "mcp", "schema", "migrate",
        ] {
            let _ = writeln!(help, "    {c}  do {c}");
        }
        let (lines, present) = help_check(&help).expect("fixture must pass");
        assert_eq!(present, 16);
        assert!(lines < 40);
        assert!(help_check("").is_err());
        assert!(help_check(&help.replace("    migrate ", "    gone ")).is_err());
        let long = help.repeat(4);
        assert!(help_check(&long).is_err());
        // LOW r3: the presence check keys on the command as the first
        // whitespace-separated token under *some* indent — a clap layout
        // change (2 spaces instead of 4) must not read as 16 missing
        // commands. Prose still cannot match: the line must be indented.
        let narrow = help.replace("    ", "  ");
        let (_, present) = help_check(&narrow).expect("indent-tolerant fixture must pass");
        assert_eq!(present, 16);
        assert!(help_check("run the doctor when sick\n").is_err());
    }

    #[test]
    fn worktree_lifecycle_adds_and_removes() {
        let dir = std::env::temp_dir().join(format!("qqq-xtask-test-{}", std::process::id()));
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("clear stale test dir");
        }
        std::fs::create_dir_all(&dir).expect("test dir");
        git(&dir, &["init", "-q"]).expect("init");
        git(&dir, &["config", "user.email", "t@t"]).expect("config");
        git(&dir, &["config", "user.name", "t"]).expect("config");
        std::fs::write(dir.join("f.txt"), "x").expect("write");
        git(&dir, &["add", "."]).expect("add");
        // `-c commit.gpgsign=false`: a dev machine with `commit.gpgsign=true`
        // would otherwise block this commit on a pinentry prompt — or fail it
        // — so the test pins the one bit of user config it cannot tolerate.
        git(&dir, &["-c", "commit.gpgsign=false", "commit", "-qm", "t"]).expect("commit");
        let wt = dir.join("wt");
        git(
            &dir,
            &[
                "worktree",
                "add",
                "--detach",
                wt.to_string_lossy().as_ref(),
                "HEAD",
            ],
        )
        .expect("add");
        assert!(wt.join("f.txt").is_file());
        let list = git(&dir, &["worktree", "list", "--porcelain"]).expect("list");
        assert!(worktree_contains(&list, &wt));
        git(
            &dir,
            &[
                "worktree",
                "remove",
                "--force",
                wt.to_string_lossy().as_ref(),
            ],
        )
        .expect("remove");
        let list = git(&dir, &["worktree", "list", "--porcelain"]).expect("list");
        assert!(!worktree_contains(&list, &wt));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
