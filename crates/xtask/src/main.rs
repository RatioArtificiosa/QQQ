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
/// Fresh-state entry point used by the unit tests: production scans go
/// through `_in` with threaded entry state. `cfg(test)` because the gate
/// runs `clippy -D warnings` and an unused-in-prod wrapper would fail it.
#[cfg(test)]
fn unsafe_line_is_violation(line: &str) -> bool {
    unsafe_line_is_violation_in(line, None, 0)
}

/// The violation test with an entry raw state: `Some(hash)` means the line
/// starts inside a multiline raw string opened earlier, so leading content
/// is prose — but the string may close mid-line with real code after it
/// (C1 r5), which this threads to instead of skipping or misreading.
fn unsafe_line_is_violation_in(line: &str, initial_raw: Option<usize>, initial_depth: u32) -> bool {
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
    let mut st = ScanState {
        in_raw: initial_raw,
        comment_depth: initial_depth,
        ..ScanState::default()
    };
    while bytes.get(i).is_some() {
        if step_literal_text(bytes, &mut i, &mut st) {
            continue;
        }
        if st.in_line_comment || st.comment_depth > 0 {
            if step_comment_text(line, bytes, &mut i, &mut st) {
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
        // Inside a raw string: no escapes; the string closes at a `"`
        // followed by *at least* `n` hashes (L-1 r13: `r"a"#` closes at
        // the `"`, the trailing `#` is a separate token — only
        // uncompilable code shapes this, so either reading is fail-noisy,
        // and matching real lexing is strictly more faithful).
        if b == b'"' {
            let mut k = 0;
            while bytes.get(*i + 1 + k) == Some(&b'#') {
                k += 1;
            }
            if k >= n {
                st.in_raw = None;
                *i += 1 + n;
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
        // Advance past the keyword even though this caller returns: the
        // prefix pass (`raw_entry_states`) ignores the verdict and keeps
        // threading, and re-reading the same keyword would loop forever.
        *i += "unsafe".len();
        return true;
    }
    *i += 1;
    false
}

/// One step while inside comment text. Comment-held quotes never toggle
/// string state (H2); the `unsafe` check still runs, per the comments-match
/// policy. Returns true on a violation at this position; otherwise advances
/// `*i` past what it consumed.
fn step_comment_text(line: &str, bytes: &[u8], i: &mut usize, st: &mut ScanState) -> bool {
    let Some(&b) = bytes.get(*i) else {
        return false;
    };
    // No `\n` arm here (LOW r4: dead defense): every newline reaches
    // `step_literal_text` first, which consumes it and resets the line
    // comment — this function provably never observes one. Deleting the
    // unreachable branch rather than documenting around it.
    if st.comment_depth > 0 {
        if b == b'*' && bytes.get(*i + 1) == Some(&b'/') {
            st.comment_depth = st.comment_depth.saturating_sub(1);
            *i += 2;
            return false;
        }
        if b == b'/' && bytes.get(*i + 1) == Some(&b'*') {
            st.comment_depth += 1;
            *i += 2;
            return false;
        }
    }
    if is_unsafe_opener(line, bytes, *i, st.in_line_comment) {
        // Same advance-past-the-keyword contract as the code step above.
        *i += "unsafe".len();
        return true;
    }
    *i += 1;
    false
}

/// Whether `c` can sit inside a Rust identifier. ASCII follows the lexer
/// exactly; non-ASCII accepts alphabetic characters and `_` (M7 r4: pure
/// `is_alphanumeric` admits `²`, which no Rust ident holds, so the keyword
/// after such a mark still matches — fail-noisy on code that cannot
/// compile — while pure-ASCII would split `é` and false-positive on a real
/// identifier). Barring the `unicode-ident` crate this errs fail-noisy:
/// exotic Nd identifiers (Arabic-Indic digits) read as boundaries, and
/// the scan then flags rather than certifies).
fn is_ident_char(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphanumeric() || c == '_'
    } else {
        c.is_alphabetic() || c == '_'
    }
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
        || !(i == 0
            || line
                .get(..i)
                .is_none_or(|pre| !pre.ends_with(is_ident_char)))
    {
        return false;
    }
    let mut j = i + "unsafe".len();
    loop {
        // H-r4-H1 + C1 r7: every Rust line separator breaks nothing — ASCII
        // space/tab/newline/CR/FF, plus the rest of `char::is_whitespace`
        // (VT, NBSP, …). rustc skips all of them and the CI grep's
        // `[[:space:]]` matches VT too, so stopping at one would miss what
        // the port claims parity with. `line.get(j..)` needs a char
        // boundary: ASCII bytes advance one step, anything else decodes.
        while let Some(&x) = bytes.get(j) {
            if x == b' ' || x == b'\t' || x == b'\r' || x == b'\x0C' {
                j += 1;
            } else if x == b'\n' {
                if same_line_only {
                    return false;
                }
                j += 1;
            } else if let Some(r) = line.get(j..).and_then(|r| r.chars().next()).filter(|c| {
                // `\n` handled above (it alone ends a `//` line); every
                // other Unicode whitespace gap-skips.
                *c != '\n' && c.is_whitespace()
            }) {
                j += r.len_utf8();
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
        // H-r4-H2: a `//` tail comment does not end the search when the
        // opener may legally sit on the next line (`unsafe // SAFETY: …`
        // with the block below is valid Rust). Line-comment context itself
        // stays strict via `same_line_only` above.
        if !same_line_only && bytes.get(j) == Some(&b'/') && bytes.get(j + 1) == Some(&b'/') {
            j += 2;
            while bytes.get(j).is_some_and(|&c| c != b'\n') {
                j += 1;
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
            .is_some_and(|pre| pre.ends_with(is_ident_char))
    {
        return None;
    }
    Some(hashes)
}

/// Skip whitespace (the full Unicode alphabet, L-5 r7) and `/*…*/` block
/// comments (nesting) at the start of `rest`, returning what follows.
/// Single-purpose helper for token-stream spacing, not text: the
/// forbid-attribute parser and the `#[path]`/`include!` follower share it
/// so `forbid\x0B/*c*/(…)` and `include /*c*/ !(…)` both resolve.
fn skip_inline_block_comments(mut rest: &str) -> &str {
    loop {
        rest = rest.trim_start_matches(char::is_whitespace);
        if !(rest.starts_with("/*")) {
            return rest;
        }
        let mut depth: u32 = 0;
        let mut j = 0;
        let bytes = rest.as_bytes();
        let mut closed = None;
        while let Some(&c) = bytes.get(j) {
            if c == b'/' && bytes.get(j + 1) == Some(&b'*') {
                depth += 1;
                j += 2;
            } else if c == b'*' && bytes.get(j + 1) == Some(&b'/') {
                depth = depth.saturating_sub(1);
                j += 2;
                if depth == 0 {
                    closed = Some(j);
                    break;
                }
            } else {
                j += 1;
            }
        }
        match closed.and_then(|k| rest.get(k..)) {
            Some(after) => rest = after,
            None => return rest,
        }
    }
}

/// Remove every `/*…*/` comment (nesting) from `s`. An unclosed trailing
/// comment truncates (fail-noisy: the remaining list is then incomplete).
/// The output is always valid UTF-8: comment markers are ASCII, so
/// removals never split a multi-byte char.
fn strip_block_comments(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        if c == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let mut depth: u32 = 1;
            i += 2;
            while let Some(&c2) = bytes.get(i) {
                if c2 == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if c2 == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    depth = depth.saturating_sub(1);
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// If `line` (which starts inside a raw string of `hash` hashes) closes it,
/// return what follows the closer. Byte-level but boundary-safe: only
/// ASCII `"`/`#` are examined, so indices never split a multi-byte char.
/// Closes at *at least* `hash` hashes (L-1 r13): a trailing `#` after the
/// closer is a separate token, and only uncompilable code shapes this.
fn raw_tail_after_close(line: &str, hash: usize) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        if c == b'"' {
            let mut k = 0;
            while bytes.get(i + 1 + k) == Some(&b'#') {
                k += 1;
            }
            if k >= hash {
                return line.get(i + 1 + hash..);
            }
        }
        i += 1;
    }
    None
}

/// Whether trimmed `t` is only separators: blank, a `//` line comment, or
/// balanced `/*…*/` block comments possibly followed by a `//` tail
/// (M-1 r6: a comment-only line between the keyword and the opener must not
/// break the pair). Anything else — code, strings, an unclosed `/*` —
/// stays significant: pairs thread block depth through unclosed openers,
/// and a stray `*/` is code-ish (L-3 r6), never a pure comment.
fn is_comment_only_separator(t: &str) -> bool {
    let mut rest = t;
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            return true;
        }
        if rest.starts_with("//") {
            return true;
        }
        if rest.starts_with("/*") {
            let bytes = rest.as_bytes();
            let mut depth: u32 = 0;
            let mut k = 0;
            let mut closed = None;
            while let Some(&c) = bytes.get(k) {
                if c == b'/' && bytes.get(k + 1) == Some(&b'*') {
                    depth += 1;
                    k += 2;
                } else if c == b'*' && bytes.get(k + 1) == Some(&b'/') {
                    depth = depth.saturating_sub(1);
                    k += 2;
                    if depth == 0 {
                        closed = Some(k);
                        break;
                    }
                } else {
                    k += 1;
                }
            }
            match closed.and_then(|k| rest.get(k..)) {
                Some(after) => rest = after,
                None => return false,
            }
        } else {
            return false;
        }
    }
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
            // L1 r5: a char literal opens the same verdict — an inner
            // attribute must lead the line, and a leading literal (string
            // or char) means it does not. Lifetimes never enter here:
            // without a closing quote nearby the `'` is skipped above.
            let rest = line.get(i + 1..).unwrap_or("");
            if rest.chars().take(3).collect::<String>().contains('\'') {
                return false;
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
        // L-5 r7: leading whitespace is every Unicode whitespace, not just
        // space/tab — a VT-indented attribute is still the attribute.
        // Advance by the whole char: stepping one byte into a multi-byte
        // space would strand the scan mid-char (miss, not just slow).
        if let Some(r) = line.get(i..).and_then(|r| r.chars().next())
            && r.is_whitespace()
            && r != '\n'
        {
            i += r.len_utf8();
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
        // L-5 r7: every Unicode whitespace — VT, NBSP, … — separates tokens
        // exactly like spaces here. `char::is_whitespace` is the single
        // alphabet shared with the gap and list trims below.
        let rest = rest.trim_start_matches(char::is_whitespace);
        // Space between the lint path and its list is legal Rust
        // (`#![forbid (unsafe_code)]`), so it cannot count as absent.
        let Some(rest) = rest.strip_prefix("forbid") else {
            return false;
        };
        return forbid_list_has_unsafe_code(rest);
    }
    false
}

/// Byte index just past the raw/byte/C string literal opening at `k`
/// (which points at the `r`, `b`, or `c` prefix), or `None` when no such
/// literal opens there. Used by the forbid-list paren scan so a paren
/// inside one cannot truncate the list (M-4 r23: plain and char quotes
/// are skipped inline; raw forms need their `#` count). Byte-safe and
/// OOB-safe; unclosed spans run to EOF (fail-noisy, rustc owns validity).
fn raw_lit_end(bytes: &[u8], k: usize) -> Option<usize> {
    let mut p = k;
    match bytes.get(p) {
        // `br`/`cr` need the `r`; a bare `b`/`c` faces a quote directly
        // (handled by the plain-quote arm — a bare letter otherwise is
        // just an identifier character, not a literal).
        Some(b'b' | b'c') => {
            p += 1;
            if bytes.get(p) != Some(&b'r') {
                return None;
            }
            p += 1;
        }
        Some(b'r') => {
            p += 1;
        }
        _ => return None,
    }
    let mut hashes = 0;
    while bytes.get(p) == Some(&b'#') {
        hashes += 1;
        p += 1;
    }
    if bytes.get(p) != Some(&b'"') {
        return None;
    }
    // Closer is `"` followed by exactly `hashes` hashes.
    let mut q = p + 1;
    while let Some(&c) = bytes.get(q) {
        if c == b'"' {
            let mut h = 0;
            while h < hashes && bytes.get(q + 1 + h) == Some(&b'#') {
                h += 1;
            }
            if h == hashes {
                return Some(q + 1 + hashes);
            }
        }
        q += 1;
    }
    None
}

/// Whether the lint list after `forbid` names `unsafe_code`: `forbid`,
/// optional spaces/comments, `(`, then the comma-separated list up to the
/// matching `)` — comments stripped before splitting, so neither a paren
/// nor a comma inside one can truncate or split the list (L2 r5). Extracted
/// from `line_has_forbid_attr` for the line budget.
fn forbid_list_has_unsafe_code(after_forbid: &str) -> bool {
    // A block comment between path and list is one token stream (LOW r4).
    let rest = skip_inline_block_comments(after_forbid);
    let rest = rest.trim_start_matches(char::is_whitespace);
    let Some(rest) = rest.strip_prefix('(') else {
        return false;
    };
    // The closing paren is the MATCHING one.
    let bytes = rest.as_bytes();
    let mut k = 0;
    let mut end = None;
    while let Some(&c) = bytes.get(k) {
        // M-4 r23 follow-up: raw/byte/C strings open with prefixes, not a
        // bare quote — skip their spans whole too, counting `#`s for the
        // closer (`r#"…")"#` content may hold a bare `"`).
        if let Some(past) = raw_lit_end(bytes, k) {
            k = past;
            continue;
        }
        if c == b'"' || c == b'\'' {
            // M-4 r23: a `)` inside a string/char span cannot close the
            // list — skip quoted spans whole so a quoted paren never
            // truncates the match and hides a real lint. Only reachable
            // in invalid Rust (valid lint lists hold no strings), which
            // rustc owns; the dangerous direction would be a miss.
            // Byte stepping is safe: no UTF-8 continuation byte collides
            // with quote/backslash bytes.
            let q = c;
            k += 1;
            while let Some(&c2) = bytes.get(k) {
                if c2 == b'\\' {
                    k += 2;
                } else {
                    k += 1;
                    if c2 == q {
                        break;
                    }
                }
            }
            continue;
        }
        if c == b'/' && bytes.get(k + 1) == Some(&b'*') {
            let mut depth: u32 = 1;
            k += 2;
            while let Some(&c2) = bytes.get(k) {
                if c2 == b'/' && bytes.get(k + 1) == Some(&b'*') {
                    depth += 1;
                    k += 2;
                } else if c2 == b'*' && bytes.get(k + 1) == Some(&b'/') {
                    depth = depth.saturating_sub(1);
                    k += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    k += 1;
                }
            }
        } else if c == b')' {
            end = Some(k);
            break;
        } else {
            k += 1;
        }
    }
    let Some(end) = end else {
        return false;
    };
    let Some(span) = rest.get(..end) else {
        return false;
    };
    let stripped = strip_block_comments(span);
    stripped
        .split(',')
        .any(|lint| lint.trim_matches(char::is_whitespace) == "unsafe_code")
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
///
/// C1: both checks accept the entry raw state. A line that starts inside a
/// multiline raw string is content, not code — but the string may close
/// mid-line with a real block after the closer, which a fresh state would
/// read as a string plus code and a skip would hide entirely.
/// Seeding threads the string to its closer and checks the tail.
/// Fresh-state entry point used by the unit tests (same `cfg(test)`
/// rationale as `unsafe_line_is_violation` above).
#[cfg(test)]
fn unsafe_line_exempt(line: &str) -> bool {
    unsafe_line_exempt_in(line, None, 0)
}

fn unsafe_line_exempt_in(line: &str, initial_raw: Option<usize>, initial_depth: u32) -> bool {
    // The forbid check seeds the entry block depth too — a line starting
    // inside a block comment holds no attribute, and the seeded violation
    // check below decides the line on the same state.
    let mut depth = initial_depth;
    line_has_forbid_attr(line, &mut depth)
        && !unsafe_line_is_violation_in(line, initial_raw, initial_depth)
}

fn starts_word(s: &str, word: &str) -> bool {
    s.starts_with(word)
        && s[word.len()..]
            .chars()
            .next()
            .is_none_or(|c| !is_ident_char(c))
}

/// Whether `f` is exempt as audited `crates/qqq-sys/` content: the REAL
/// file must live under the REAL qqq-sys dir (H-2 r12). A lexical check
/// is fooled by a symlinked parent smuggling outside content under the
/// exception name — resolve both sides with `canonicalize` first. Failure
/// to resolve means we cannot prove exemption, so do NOT exempt
/// (fail-noisy: the file gets scanned).
fn is_qqq_sys_content(qsys_canon: &Path, f: &Path) -> bool {
    match std::fs::canonicalize(f) {
        Ok(canon) => canon.strip_prefix(qsys_canon).is_ok(),
        Err(_) => false,
    }
}

/// Scan one crate's `.rs` files for `unsafe` code positions, recording
/// violations. Split out of `run_unsafe_scan` so each lane stays readable.
fn scan_crate_rs_files(
    workspace: &Path,
    dir: &Path,
    roots: &ManifestRoots,
    violations: &mut Vec<String>,
    files_scanned: &mut usize,
) {
    let mut files = Vec::new();
    let mut dir_problems = Vec::new();
    collect_rs_into(dir, &mut files, &mut dir_problems);
    // M4: an unreadable directory fails the scan like an unreadable
    // file — certifying the rest GREEN would vouch for code never seen.
    violations.extend(dir_problems);
    // H-2 r18: manifest custom roots join `files` BEFORE the redirection
    // follower runs — a custom root's own `#[path]`/`include!` targets
    // compile as Rust too, and appending roots after the follow left that
    // whole chain unscanned (a non-`.rs` root redirecting to a hidden
    // `unsafe` file sailed through GREEN).
    // H-1 r14: manifest custom roots compile as crate roots regardless
    // of location or extension — a `path = "custom/lib.txt"` with
    // `unsafe` would otherwise sail through GREEN. The parse below is
    // shared with the roots check (L-3 r17); aux roots join the body
    // scan only (see `ManifestRoots::aux`).
    {
        // L-3 r17: one parse per crate — `manifest_roots` is read once
        // here and shared with the roots check, so one unreadable
        // manifest yields one problem entry, not one per consumer.
        let ws_canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
        // L-4 r15: a present-but-unreadable manifest fails loudly — the
        // roots it names are unknown, so the scan cannot certify them.
        if let Some(problem) = &roots.problem {
            violations.push(format!(
                "{}: manifest problem, scan incomplete ({})",
                sanitize_for_log(
                    &dir.strip_prefix(workspace)
                        .unwrap_or(dir)
                        .to_string_lossy()
                        .replace('\\', "/")
                ),
                sanitize_for_log(problem),
            ));
        }
        // H-1 r14 + M-1 r17: manifest custom roots compile as crate roots
        // regardless of location or extension — a `path = "custom/lib.txt"`
        // with `unsafe` would otherwise sail through GREEN. Gate like a
        // redirect (inside the workspace only) and skip files the normal
        // walk already found. Aux (test/example/bench) roots join the body
        // scan but never the forbid check (see `ManifestRoots::aux`).
        for root in roots.lib_bin.iter().chain(&roots.aux) {
            // M-2 r15: fold before the lexical fallback — an escaping
            // `..` is invisible to a raw `strip_prefix` (it matches the
            // joined prefix lexically) and would be silently dropped
            // instead of flagged outside. Roots arrive folded from the
            // parser; folding again is idempotent belt-and-braces.
            let inside = std::fs::canonicalize(root).map_or_else(
                |_| fold_dot_components(root).strip_prefix(workspace).is_ok(),
                |c| c.strip_prefix(&ws_canon).is_ok(),
            );
            if !inside {
                violations.push(format!(
                    "{}: references code outside the workspace ({}), scan incomplete",
                    sanitize_for_log(
                        &dir.strip_prefix(workspace)
                            .unwrap_or(dir)
                            .to_string_lossy()
                            .replace('\\', "/")
                    ),
                    sanitize_for_log(&root.to_string_lossy()),
                ));
                continue;
            }
            if root.is_file() && !files.contains(root) {
                files.push(root.clone());
            }
        }
    }
    // H-1 r23: drop the uncompiled conventional build.rs BEFORE the
    // follower runs, so a `#[path]`/`include!` that names it re-adds it
    // for the body scan (a custom `build = "build.rs"` self-ref, a
    // redirected include, or any other live use compiles it after all —
    // dropping it after the follow sailed that `unsafe` through GREEN).
    // A custom root that already names the file keeps it: `custom_covers`
    // skips the retain when the manifest claims the same path.
    if roots.skip_build_rs {
        let conventional = dir.join("build.rs");
        let custom_covers = roots
            .lib_bin
            .iter()
            .chain(&roots.aux)
            .any(|r| r == &conventional);
        if !custom_covers {
            files.retain(|f| f != &conventional);
        }
    }
    // H-3 r7: follow `#[path]`/`include!` redirections into non-`.rs`
    // files — they compile as Rust regardless of extension. Runs after
    // the manifest expansion above so chains rooted at custom roots are
    // followed transitively (H-2 r18), including a dynamic `include!`
    // hiding inside one (fail-closed, H-1 r8).
    let mut redir_problems = Vec::new();
    follow_code_redirections(workspace, &mut files, &mut redir_problems);
    violations.extend(redir_problems);
    files.sort();
    files.dedup();
    // Canonical exception root, hoisted out of the per-file loop (L-9).
    let qsys_canon = std::fs::canonicalize(workspace.join("crates").join("qqq-sys"))
        .unwrap_or_else(|_| workspace.join("crates").join("qqq-sys"));
    for f in &files {
        // M-7 r11: path-derived fragments are sanitized at format time —
        // a hostile filename must not split the violation report.
        let rel = sanitize_for_log(
            &f.strip_prefix(workspace)
                .unwrap_or(f)
                .to_string_lossy()
                .replace('\\', "/"),
        );
        let Ok(text) = std::fs::read_to_string(f) else {
            // An unreadable file is a scan failure, not a skip: skipping
            // it would certify a tree the scanner never saw.
            violations.push(format!("{rel}: unreadable, scan incomplete"));
            continue;
        };
        *files_scanned += 1;
        // H-2 r12: the exemption attaches to where the file REALLY lives,
        // not its lexical path — a symlinked parent dir would otherwise
        // smuggle outside content under the exception name. H-3 r11: a
        // symlink *file* itself is still scanned (`symlink_metadata` never
        // follows), since only audited content is exempt.
        let is_link = std::fs::symlink_metadata(f).is_ok_and(|m| m.file_type().is_symlink());
        if !is_link && is_qqq_sys_content(&qsys_canon, f) {
            continue;
        }
        scan_rs_text(&rel, &text, violations);
    }
}

/// The entry lexer state per line: the multiline raw string open at the
/// line's start (its opening hash count, or `None`), plus the block-comment
/// nesting depth (L-1 r6). One threading pass with the shared step helpers
/// — no drift by construction. Strings, chars and line comments reset at
/// every joining newline (same as the pair scan); only raw strings and
/// block comments thread through. Callers seed per-line scans with the
/// entry state so content stays prose but a closer with real code after it
/// still flags (C1 r5) — never skip the line, never scan it fresh.
fn raw_entry_states(lines: &[&str]) -> Vec<(Option<usize>, u32)> {
    let mut st = ScanState::default();
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        out.push((st.in_raw, st.comment_depth));
        let bytes = line.as_bytes();
        let mut i = 0;
        while bytes.get(i).is_some() {
            if step_literal_text(bytes, &mut i, &mut st) {
                continue;
            }
            if st.in_line_comment || st.comment_depth > 0 {
                if step_comment_text(line, bytes, &mut i, &mut st) {
                    // A hit changes nothing about the lexer state the next
                    // line inherits — keep threading to end of line.
                }
                continue;
            }
            if step_code_text(line, bytes, &mut i, &mut st) {
                // Same: the verdict is the caller's; state threads on.
            }
        }
        // The joining newline, exactly as the pair scan applies it.
        let mut k = 0;
        step_literal_text(b"\n", &mut k, &mut st);
    }
    out
}

/// Scan one file's text: every line alone, then every significant pair.
/// The pair re-test closes the cross-line shape (H-r3-H1: `unsafe` dangling
/// at end of line with the opener on the next); pairs whose lines already
/// flagged are skipped to avoid double-reporting the same finding.
/// Pairing skips blank and full-line-`//` separators (H-r4-H2): they carry
/// no tokens, so `unsafe`, a blank or comment line, then the opener still
/// resolves. Lines starting inside a multiline raw string are prose, not
/// code, for both passes. L14: a dangling keyword separated by intervening
/// *code*, or inside an unclosed block comment, stays invisible — the
/// whole-file grammar that would see it is the same work `audit_unsafe.py`
/// defers, and both scanners agree here.
fn scan_rs_text(rel: &str, text: &str, violations: &mut Vec<String>) {
    let lines: Vec<&str> = text.lines().collect();
    let raw_entry = raw_entry_states(&lines);
    let mut flagged: Vec<bool> = Vec::with_capacity(lines.len());
    for (n, line) in lines.iter().enumerate() {
        // C1: no line is skipped for starting inside a raw string — the
        // entry state seeds the scan, so content stays prose but a closer
        // with real code after it still flags.
        let (initial_raw, initial_depth) = raw_entry.get(n).copied().unwrap_or((None, 0));
        if unsafe_line_exempt_in(line, initial_raw, initial_depth) {
            flagged.push(false);
            continue;
        }
        if unsafe_line_is_violation_in(line, initial_raw, initial_depth) {
            // The echoed line is evidence, but lone CRs and ESC bytes in
            // it would rewrite the report terminal — redact those, keep
            // the rest verbatim for grep-ability.
            violations.push(format!("{rel}:{}:{}", n + 1, sanitize_for_log(line)));
            flagged.push(true);
        } else {
            flagged.push(false);
        }
    }
    let sig: Vec<(usize, &str)> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| {
            // Blank lines and comment-only separators carry no tokens
            // (H1 r5, M-1 r6): `//…`, complete `/*…*/`, and mixed
            // `/*…*/ //…` lines between the keyword and the opener must not
            // break the pair. Anything else stays — including an unclosed
            // `/*` (pairs thread block depth). A raw-string content line
            // that looks like a comment is harmless either way: the pair
            // scan below seeds line a's entry state, so content still
            // classifies as a string whether such a line is dropped or
            // kept — L-1 r8 documents this no-op rather than
            // special-casing the filter.
            let t = l.trim();
            !is_comment_only_separator(t)
        })
        .map(|(n, l)| (n, *l))
        .collect();
    for w in sig.windows(2) {
        let (Some(&(na, a)), Some(&(nb, b))) = (w.first(), w.get(1)) else {
            continue;
        };
        if flagged.get(na) == Some(&true) || flagged.get(nb) == Some(&true) {
            continue;
        }
        // H-1 r6: seed the pair with line a's entry state instead of
        // refusing pairs that start in raw. Content resolves as content
        // (raw threads through), a closer on line a exposes line b as
        // code, and a dangling keyword on a finds its opener on b.
        let (initial_raw, initial_depth) = raw_entry.get(na).copied().unwrap_or((None, 0));
        let mut pair = String::with_capacity(a.len() + b.len() + 1);
        pair.push_str(a);
        pair.push('\n');
        pair.push_str(b);
        if unsafe_line_exempt_in(&pair, initial_raw, initial_depth) {
            continue;
        }
        if unsafe_line_is_violation_in(&pair, initial_raw, initial_depth) {
            violations.push(format!(
                "{rel}:{}:cross-line `unsafe` opener (the keyword dangles at the end of line {})",
                nb + 1,
                na + 1
            ));
        }
    }
}

/// Check a crate's entry roots for the crate-level forbid attribute.
/// Split out of `run_unsafe_scan` for the line budget.
///
/// The attribute must be real code, not a comment mentioning it: a
/// commented-out forbid is one uncomment away from absent, so a text
/// `contains` here would certify a root on hearsay — the same shape
/// `tools/audit_unsafe.py` guards with its prose filing.
/// M1 r5: EVERY existing root carries it — a forbid in lib.rs no longer
/// excuses a missing one in main.rs (either-or was the dual-root hole).
/// M-3 r6: a `forbid` inside a multiline raw string is content, not code —
/// gate the hit on starting outside one, the same entry state the main
/// scan seeds with.
/// H-2 r7: the gate also consults the entry block depth instead of
/// threading a private one — a commented-out forbid must not certify, even
/// when the `/*` opener sits on a line whose own forbid parse fails first
/// (which used to freeze the private depth at zero).
/// M-4 r7: tri-state — a present-but-unreadable root is a scan failure
/// (`unreadable`), not a missing lint. The file scan already reports
/// unreadable files the same way; the root check must agree on the repair
/// (fix perms, not add a lint).
/// Enumerate binary roots: every `src/bin/<name>.rs` and every
/// `src/bin/<name>/main.rs` (cargo's second binary form). Extracted from
/// `check_crate_roots` for the line budget. Fail-loud on unreadable
/// entries and symlinked bins (H-4/M-6 r11): the collector never follows
/// them, so vouching for their targets would certify unseen code.
/// Symlink check-vs-read here shares the documented TOCTOU shape (L-5 r15
/// on `follow_code_redirections`): a concurrent tree mutation between the
/// `symlink_metadata` gate and the read could substitute content, but
/// there is no concurrent-writer threat model for a local gate run.
fn collect_bin_roots(
    dir: &Path,
    rel: &dyn Fn() -> String,
    violations: &mut Vec<String>,
) -> Vec<PathBuf> {
    let mut bins: Vec<PathBuf> = Vec::new();
    let bin_dir = dir.join("src").join("bin");
    // M-3 r16: a symlinked `src/bin` would re-root every bin entry outside
    // while `root_ok` reads them as crate roots (ungated arbitrary read,
    // same class as M-1 r15). Fail closed before collecting.
    if std::fs::symlink_metadata(&bin_dir).is_ok_and(|m| m.file_type().is_symlink()) {
        violations.push(format!(
            "{}: symlinked bin dir, scan incomplete",
            sanitize_for_log(&bin_dir.to_string_lossy())
        ));
        return bins;
    }
    let Ok(rd) = std::fs::read_dir(bin_dir) else {
        return bins;
    };
    for e in rd {
        // M-6 r11: a dropped `Err` here would hide an unforbidden bin
        // root — the same fail-loud contract as the crate listing.
        let e = match e {
            Ok(e) => e,
            Err(e) => {
                violations.push(format!(
                    "{}: bin entry unreadable mid-listing, scan incomplete: {}",
                    rel(),
                    fmt_io_err(&e)
                ));
                continue;
            }
        };
        let p = e.path();
        // H-4 r11: no-follow stat — a symlinked bin entry is never
        // recursed by the collector, so vouching for its target here
        // would certify unseen code. Fail closed instead.
        let ft = match e.file_type() {
            Ok(t) => t,
            Err(e) => {
                violations.push(format!(
                    "{}: cannot stat bin entry, scan incomplete: {}",
                    sanitize_for_log(&p.to_string_lossy()),
                    fmt_io_err(&e)
                ));
                continue;
            }
        };
        if ft.is_symlink() {
            violations.push(format!(
                "{}: symlinked bin entry, scan incomplete",
                sanitize_for_log(&p.to_string_lossy())
            ));
            continue;
        }
        if ft.is_dir() {
            // Second binary form: src/bin/<name>/main.rs. M-5 r23: the
            // `is_file` check follows symlinks — a symlinked main.rs
            // would be read as a crate root (ungated arbitrary file, same
            // class as the entry-level symlink arm above). Fail closed.
            let main = p.join("main.rs");
            if std::fs::symlink_metadata(&main).is_ok_and(|m| m.file_type().is_symlink()) {
                violations.push(format!(
                    "{}: symlinked bin entry, scan incomplete",
                    sanitize_for_log(&main.to_string_lossy())
                ));
                continue;
            }
            if main.is_file() {
                bins.push(main);
            }
        } else if p
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| x.eq_ignore_ascii_case("rs"))
        {
            bins.push(p);
        }
    }
    bins.sort();
    bins
}

/// Cut a manifest line at the first `#` outside quotes (comment strip).
/// Returns the byte index where code ends. `#` is legal inside quoted
/// filenames, and `\` escapes only inside `"…"` strings (M-4 r16) — TOML
/// `'...'` literals have no escapes. Split out for reuse on value
/// continuation lines (L-2 r20).
fn manifest_code_cut(raw_line: &str) -> usize {
    let mut cut = raw_line.len();
    let mut quote = None;
    let mut escaped = false;
    for (i, c) in raw_line.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' && q == '"' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
        } else if c == '#' {
            cut = i;
            break;
        }
    }
    cut
}

/// Validate a TOML table header strictly: exactly `[ name ]` or
/// `[[ name ]]` (TOML-legal inner spacing allowed), with no leftover
/// brackets — `[[[lib]]]` or `[lib] junk` are not headers. The old
/// trim-everything fold accepted those and misattributed the next `path`
/// (M-2 r22). Returns the unquoted section name, or `None`.
fn strict_header_name(t: &str) -> Option<&str> {
    let inner = t.strip_prefix('[')?.strip_suffix(']')?.trim();
    // Peel at most ONE more pair: `[[bin]]` is valid, `[[[lib]]]` is not.
    let inner = match inner.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        Some(r) => r.trim(),
        None => inner,
    };
    if inner.is_empty() || inner.chars().any(|c| c == '[' || c == ']') {
        return None;
    }
    Some(strip_one_quote_pair(inner))
}

/// Strip one matching ASCII quote pair around a TOML key or section name
/// (`"path"`, `'lib'`), returning the text unchanged when it is not
/// quoted. H-1 r15/r16: Cargo accepts quoted keys and quoted table
/// headers; an unquoted-only match would miss those roots entirely.
fn strip_one_quote_pair(s: &str) -> &str {
    let mut chars = s.chars();
    let q = match chars.next() {
        Some(q) if q == '"' || q == '\'' => q,
        _ => return s,
    };
    let rest = &s[q.len_utf8()..];
    let Some(end) = rest.find(q) else {
        return s;
    };
    if rest[end + q.len_utf8()..].trim().is_empty() {
        &rest[..end]
    } else {
        s
    }
}

/// Process one manifest `key = rest` value: resolve next-line values,
/// gate `[package] build` bools/non-strings, parse/decode the value, and
/// push the root or record a fail-closed problem. Split out of
/// `manifest_roots` for the line budget.
fn manifest_process_value(
    out: &mut ManifestRoots,
    section: &ManifestSection,
    norm: &str,
    rest: &str,
    raw_lines: &[&str],
    li: &mut usize,
    dir: &Path,
) {
    let mut rest = rest;
    // L-2 r20: `path =` with the value on the next line is valid TOML
    // (blanks and comments may surround `=`) — read it instead of
    // fail-closing a valid manifest. M-1 r21: only a quote-led line can
    // be the value — never consume a header or key line (that would hide
    // the next section), and never silently stop at EOF.
    if rest.is_empty() {
        let mut j = *li;
        let mut accepted: Option<&str> = None;
        while let Some(&next) = raw_lines.get(j) {
            j += 1;
            let code = next[..manifest_code_cut(next)].trim();
            if code.is_empty() {
                continue;
            }
            let is_value = code.starts_with(['"', '\''])
                || (section == &ManifestSection::Package
                    && norm == "build"
                    && (code == "false" || code == "true"));
            if !is_value {
                break;
            }
            accepted = Some(code);
            *li = j;
            break;
        }
        let Some(v) = accepted else {
            if out.problem.is_none() {
                out.problem = Some(format!("Cargo.toml {norm} value unclosed"));
            }
            return;
        };
        rest = v;
    }
    if section == &ManifestSection::Package && norm == "build" {
        if out.dup.build {
            // M-2 r21: duplicate `build` keys are invalid TOML — fail
            // closed with a problem and do not trust the skip flag.
            if out.problem.is_none() {
                out.problem = Some("Cargo.toml build key is duplicated".to_owned());
            }
            out.skip_build_rs = false;
            return;
        }
        out.dup.build = true;
        if rest == "false" || rest == "true" {
            // `build = false` disables the script: the conventional
            // build.rs is dead code (M-3 r20). `true` keeps it.
            if rest == "false" {
                out.skip_build_rs = true;
            }
            return;
        }
        if !(rest.starts_with('"') || rest.starts_with('\'')) {
            // M-1 r20: `build = 5` is invalid Cargo (not a string,
            // not a bool) — fail closed, unlike the silent bools.
            if out.problem.is_none() {
                out.problem = Some("Cargo.toml build value is not a string".to_owned());
            }
            return;
        }
    }
    match parse_manifest_value(rest, raw_lines, li) {
        ManifestValue::Value(value) => {
            if !value.is_empty() {
                // L-1 r15: fold `.`/`..` lexically so spellings like
                // `sub/../lib.rs` merge with the walked path instead of
                // double-scanning (and so the callers' lexical
                // outside-gate sees the real shape — M-2 r15).
                let root = fold_dot_components(&dir.join(&value));
                // C-1 r19: custom build scripts join lib_bin (scanned
                // + forbid-checked exactly like a conventional
                // build.rs); aux roots stay scan-only. L-1 r23: the skip
                // commits only here, on a successfully parsed value — a
                // string-shaped build that fails to parse (bad escape,
                // unclosed, trailing junk, empty) leaves the conventional
                // file checked rather than trusting a broken manifest.
                if section == &ManifestSection::Aux {
                    out.aux.push(root);
                } else {
                    if section == &ManifestSection::Package && norm == "build" {
                        out.skip_build_rs = true;
                    }
                    // M-1 r22: arm the duplicate-`path` tripwire only on a
                    // pushed root — a valueless `path =` must not disarm
                    // the real `path` that follows it.
                    if norm == "path" {
                        out.dup.path = true;
                    }
                    out.lib_bin.push(root);
                }
            } else if out.problem.is_none() {
                // M-2 r20: `path = ""` is invalid Cargo — an empty
                // root is unknown, so fail closed, never skip.
                out.problem = Some(format!("Cargo.toml {norm} value is empty"));
            }
        }
        ManifestValue::BadEscape => {
            if out.problem.is_none() {
                out.problem = Some(format!("Cargo.toml {norm} value has invalid escape"));
            }
        }
        // M-1 r19: a `path`/`build = …` line with no closer names an
        // unknown root (truncated line, unclosed string) — fail closed
        // with a problem, never silently skip. Non-string values in
        // `[lib]` sections are invalid Cargo, so they land here
        // correctly; `[package] build = false` never reaches the
        // parser (guarded above: bools are valid and mean "no custom
        // script").
        ManifestValue::Unclosed => {
            if out.problem.is_none() {
                out.problem = Some(format!("Cargo.toml {norm} value unclosed"));
            }
        }
        ManifestValue::TrailingJunk => {
            if out.problem.is_none() {
                out.problem = Some(format!("Cargo.toml {norm} value has trailing characters"));
            }
        }
    }
}

/// Duplicate/invalid-input tracking for one manifest parse (M-1 r22,
/// M-2 r21, M-2 r23): transient per-table state, kept out of
/// `ManifestRoots` so the result struct stays a plain accumulator.
#[derive(Default)]
struct ManifestDup {
    /// A `path` key already produced a root in this table: duplicate
    /// `path` keys are invalid TOML and fail closed with first-wins.
    /// Re-armed by every valid header ([[bin]] repeats legitimately).
    /// Arms only on a pushed root — a valueless `path =` must not
    /// disarm the real one that follows it.
    path: bool,
    /// A `[package] build` key was seen (any value shape): duplicate
    /// `build` keys are invalid TOML and fail closed.
    build: bool,
    /// A duplicate singleton section is being skipped: after `[lib]` or
    /// `[package]` repeats (invalid TOML), its keys are dropped with a
    /// problem instead of silently merging. Non-singleton sections
    /// re-arm normally.
    skip_section: bool,
}

/// Custom root paths from a crate manifest, classified by target kind and
/// parsed once per crate (L-3 r17: the scan loop and the roots check share
/// one parse, so one unreadable manifest yields one problem entry, not
/// one per consumer).
#[derive(Default)]
struct ManifestRoots {
    /// `[lib]`/`[[bin]]` roots: compiled code whose missing forbid fails
    /// the gate (M-1 r12).
    lib_bin: Vec<PathBuf>,
    /// `[[test]]`/`[[example]]`/`[[bench]]` roots (M-1 r17): compiled code
    /// whose bodies are scanned like every other root — but never
    /// forbid-checked here. The compiler owns test-target lints via the
    /// manifest `[lints]` table (every crate sets it), which source
    /// text cannot see; forbid-checking them would false-flag
    /// `[lints]`-covered trees.
    aux: Vec<PathBuf>,
    /// Present-but-unreadable manifest (L-4 r15): the named roots are
    /// unknown, so callers fail loudly instead of certifying them.
    problem: Option<String>,
    /// `[package] build = "custom/…"` (successfully parsed) or `build =
    /// false`: a custom script or disabled script means the conventional
    /// `build.rs` is NOT compiled — skip its forbid check and body scan
    /// (it would be dead code). Defaults to false: no key, `build = true`,
    /// or an unparseable build value (fail-closed: an unreadable value
    /// must not silence the conventional file).
    skip_build_rs: bool,
    /// Per-table duplicate tracking (see above).
    dup: ManifestDup,
}

/// Escape-aware search for a TOML value closer: returns the byte index
/// where `mark` starts, or `None` when the line holds no closer. A `\`
/// escapes the next char inside `"…"` strings only (M-4 r16) — TOML
/// `'...'` literals have no escapes, so a `\` there must not swallow the
/// real closer.
fn find_value_close(chunk: &str, mark: &str, backslash_escapes: bool) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in chunk.char_indices() {
        if escaped {
            escaped = false;
        } else if backslash_escapes && c == '\\' {
            escaped = true;
        } else if chunk[i..].starts_with(mark) {
            return Some(i);
        }
    }
    None
}

/// Hex run inside a TOML `\u`/`\U` escape: `n` hex digits to a char.
/// Exactly `n` hex digits — TOML has no `_` separators (cargo rejects
/// `\u12_4b` as "too few digits"), so anything else is `None`. `None`
/// also on short input, non-hex digits, or a non-scalar value.
fn toml_hex(chars: &mut std::str::Chars<'_>, n: usize) -> Option<char> {
    let mut v: u32 = 0;
    for _ in 0..n {
        v = v * 16 + chars.next()?.to_digit(16)?;
    }
    char::from_u32(v)
}

/// Decode TOML basic-string escapes (`\\ \" \/ \b \f \n \r \t \uXXXX`
/// `\UXXXXXXXX`, plus the line-ending-backslash continuation in
/// multiline strings) in a manifest value. `None` on invalid escape —
/// the manifest is then not valid TOML (Cargo rejects it), so the caller
/// treats the root as unknown (fail-closed problem, same as L-4 r15).
fn decode_basic_escapes(s: &str) -> Option<String> {
    if !s.contains('\\') {
        return Some(s.to_owned());
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        // TOML line-ending backslash (M-3 r18): a `\` with only trailing
        // blanks before the newline trims the break plus all whitespace
        // around it (cargo resolves `"""l\` + newline + `  .rs"""`
        // to `l.rs`). A single-line value never holds `\n`, so this arm
        // cannot fire there — and anything else after the blanks stays an
        // invalid escape (fail closed below).
        let rest = chars.as_str();
        let blanks = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        if rest[blanks..].starts_with('\n') {
            for _ in 0..blanks {
                chars.next();
            }
            chars.next();
            let after = chars.as_str();
            let ws = after.len() - after.trim_start_matches([' ', '\t', '\n']).len();
            for _ in 0..ws {
                chars.next();
            }
            continue;
        }
        match chars.next()? {
            '\\' => out.push('\\'),
            '"' => out.push('"'),
            '/' => out.push('/'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{C}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => out.push(toml_hex(&mut chars, 4)?),
            'U' => out.push(toml_hex(&mut chars, 8)?),
            _ => return None,
        }
    }
    Some(out)
}

/// Target section of a manifest `path = …` line: compiled lib/bin roots,
/// test/example/bench roots (see `ManifestRoots::aux`), and the
/// `[package]` table (only its `build` key names a compilable root).
#[derive(PartialEq)]
enum ManifestSection {
    LibBin,
    Aux,
    Package,
    Other,
}

/// How a manifest key resolves: a normalized root key, or nothing.
enum KeyUse<'a> {
    Key(&'a str),
    Ignore,
}

/// Classify one manifest key in its section (H-1 r20, H-2/H-3 r21).
/// Dotted keys NEVER name target roots (verified against cargo across
/// placements: top-level dotted becomes a dependency spec, in-section
/// dotted is silently ignored) — dependencies and dotted shapes are not
/// crate roots, so skip silently. Quote handling: `"path"` unquotes to
/// `path`; `"lib.path"` keeps its dot and is ignored like the bare form.
fn classify_manifest_key<'a>(section: &ManifestSection, key: &'a str) -> KeyUse<'a> {
    if key.contains('.') {
        return KeyUse::Ignore;
    }
    match (section, key) {
        (ManifestSection::LibBin | ManifestSection::Aux, "path") => KeyUse::Key("path"),
        (ManifestSection::Package, "build") => KeyUse::Key("build"),
        _ => KeyUse::Ignore,
    }
}

/// Outcome of parsing one manifest `path = value` right-hand side.
enum ManifestValue {
    /// Decoded value (TOML basic escapes applied for `"…"` strings).
    Value(String),
    /// No closer on this line (single-quoted) or through EOF (triple).
    Unclosed,
    /// Invalid escape in a `"…"` value: invalid TOML, fail closed.
    BadEscape,
    /// Trailing characters after the closer (`path = "a" "b"`): invalid
    /// TOML, fail closed instead of certifying a guess (L-4 r20).
    TrailingJunk,
}

/// Parse the value of a manifest `path = …` line whose right-hand side
/// (trimmed) is `rest`: detect the quote mark (triple or single),
/// accumulate continuation lines for triple-quoted values spanning lines
/// (M-2 r17), and TOML-decode basic-string escapes (M-2 r17). Advances
/// `li` past consumed continuation lines. Split out of `manifest_roots`
/// for the line budget.
fn parse_manifest_value(rest: &str, lines: &[&str], li: &mut usize) -> ManifestValue {
    let (mark, mlen): (&str, usize) = if rest.starts_with("\"\"\"") {
        ("\"\"\"", 3)
    } else if rest.starts_with("'''") {
        ("'''", 3)
    } else if rest.starts_with('"') {
        ("\"", 1)
    } else if rest.starts_with('\'') {
        ("'", 1)
    } else {
        return ManifestValue::Unclosed;
    };
    // L-3 r15: the value closer is escape-aware — `\"` is content, not
    // the end of the value. Escapes apply inside `"…"` strings only
    // (M-4 r16): TOML `'...'` literals have none, so a `\` there must
    // not swallow the real closer.
    let backslash_escapes = mark.starts_with('"');
    let mut chunk = rest[mlen..].to_string();
    let mut end = find_value_close(&chunk, mark, backslash_escapes);
    while end.is_none() && mark.len() == 3 {
        let Some(&next) = lines.get(*li) else {
            break;
        };
        *li += 1;
        chunk.push('\n');
        chunk.push_str(next);
        end = find_value_close(&chunk, mark, backslash_escapes);
    }
    let Some(end) = end else {
        return ManifestValue::Unclosed;
    };
    let Some(raw) = chunk.get(..end) else {
        return ManifestValue::Unclosed;
    };
    // L-4 r20: anything but blanks after the closer is invalid TOML —
    // a trailing comment belongs to the line, not the value (M-3 r21:
    // strip it before judging the remainder — the single-line path was
    // already comment-cut, the multiline path was not).
    let after = &chunk[end + mark.len()..];
    if !after[..manifest_code_cut(after)].trim().is_empty() {
        return ManifestValue::TrailingJunk;
    }
    if !backslash_escapes {
        return ManifestValue::Value(raw.to_owned());
    }
    // M-2 r17: the compiled path is the TOML-decoded value — `\"` is `"`,
    // `\\` is `\`. Without decoding, lexical and compiled paths disagree
    // and `root_ok` vacuous-passes the nonexistent lexical path. Invalid
    // escapes mean invalid TOML (Cargo rejects it): fail closed with a
    // problem, never skip silently.
    if let Some(v) = decode_basic_escapes(raw) {
        ManifestValue::Value(v)
    } else {
        ManifestValue::BadEscape
    }
}
/// Custom root paths from a crate manifest (`[lib] path = …`,
/// `[[bin]] path = …`): without this, a root living outside `src/`
/// compiles but is never forbid-checked (M-1 r12). Line-oriented on
/// purpose — this crate takes no dependencies: section headers plus
/// `path = "…"` lines with `#` comments stripped cover every real
/// manifest shape. Anything fancier falls back to the conventional roots
/// (collected separately); rustc fails an unresolvable manifest loudly.
/// Returns the discovered roots plus a problem description when the
/// manifest is present but unreadable (L-4 r15) — callers fail the scan
/// loudly instead of certifying roots they never saw.
/// Test-only view of the lib/bin subset (the forbid-checked roots):
/// production code uses `manifest_roots` directly.
#[cfg(test)]
fn manifest_custom_roots(dir: &Path) -> (Vec<PathBuf>, Option<String>) {
    let roots = manifest_roots(dir);
    (roots.lib_bin, roots.problem)
}

fn manifest_roots(dir: &Path) -> ManifestRoots {
    let manifest = dir.join("Cargo.toml");
    let text = match std::fs::read_to_string(&manifest) {
        Ok(t) => t,
        // M-1 r16: `exists()` follows links — a dangling `Cargo.toml`
        // symlink reports absent and would silently yield no roots.
        // Presence is the link itself; readability is the read above.
        Err(e) if std::fs::symlink_metadata(&manifest).is_ok() => {
            return ManifestRoots {
                problem: Some(format!("Cargo.toml unreadable: {e}")),
                ..ManifestRoots::default()
            };
        }
        Err(_) => return ManifestRoots::default(),
    };
    let mut out = ManifestRoots::default();
    let mut section = ManifestSection::Other;
    // Duplicate singleton sections are invalid TOML ([[bin]] repeats
    // legitimately; [lib] and [package] never do).
    let mut seen_lib = false;
    let mut seen_package = false;
    // H-2 r16: leading UTF-8 BOMs prefix the first line — a section header
    // there must still match (editors add BOMs silently). L-2 r17: strip
    // all of them, not just one.
    let body: &str = text.trim_start_matches('\u{FEFF}');
    // Index loop (not `for`): a triple-quoted value may span lines (M-2
    // r17) — continuation lines are consumed as part of the value.
    let raw_lines: Vec<&str> = body.lines().collect();
    let mut li = 0;
    while let Some(&raw_line) = raw_lines.get(li) {
        li += 1;
        let t = raw_line[..manifest_code_cut(raw_line)].trim();
        // Strict headers only (`[ lib ]`, `[ [bin]]`): extra brackets or
        // trailing junk are not headers (M-2 r22).
        if let Some(name) = strict_header_name(t) {
            // H-1 r16: quoted headers (`["lib"]`) name the same section.
            // M-1 r17: `[[test]]`/`[[example]]`/`[[bench]]` custom paths
            // compile as Rust too — their bodies join the scan (as aux
            // roots, never forbid-checked: the compiler owns those
            // lints, see `ManifestRoots::aux`).
            // M-2 r23: `[lib]` and `[package]` are singleton tables —
            // a repeat is invalid TOML (Cargo rejects duplicates), so
            // fail closed with a problem and skip the repeated section
            // instead of silently merging. `[[bin]]`-style array tables
            // repeat legitimately and are exempt.
            if (name == "lib" && seen_lib) || (name == "package" && seen_package) {
                if out.problem.is_none() {
                    out.problem = Some(format!("Cargo.toml [{name}] table is duplicated"));
                }
                out.dup.skip_section = true;
            } else {
                out.dup.skip_section = false;
            }
            if name == "lib" {
                seen_lib = true;
            } else if name == "package" {
                seen_package = true;
            }
            section = match name {
                "lib" | "bin" => ManifestSection::LibBin,
                "test" | "example" | "bench" => ManifestSection::Aux,
                "package" => ManifestSection::Package,
                _ => ManifestSection::Other,
            };
            // M-1 r22: `path`/`build` keys live in one table each —
            // a new header re-arms duplicate detection.
            out.dup.path = false;
            continue;
        } else if t.starts_with('[') {
            // L-3 r20 + H-3 r22 + M-1 r23: a `[`-led line that is not a
            // valid header is invalid TOML (no valid manifest has one:
            // value continuations are consumed by the value parser and
            // comments are stripped first) — reset the section and fail
            // closed with a problem instead of silently misattributing
            // or skipping the next `path`.
            if out.problem.is_none() {
                out.problem = Some("Cargo.toml section header is malformed".to_owned());
            }
            section = ManifestSection::Other;
            continue;
        }
        if section == ManifestSection::Other {
            continue;
        }
        // Duplicate singleton sections are skipped wholesale (M-2 r23).
        if out.dup.skip_section {
            continue;
        }
        // H-1 r15: TOML keys may be quoted (`"path" = …`, `'path' = …`)
        // — Cargo accepts them, so an unquoted-only match would miss the
        // root entirely. Split at the first `=` (keys never contain a
        // bare one), strip one matching quote pair, and compare. In
        // `[package]` only `build` names a root (C-1 r19: a custom build
        // script compiles as Rust); `build = false`/`true` are valid
        // bools meaning "no custom script" and stay silent.
        let Some(eq) = t.find('=') else {
            continue;
        };
        let key = strip_one_quote_pair(t[..eq].trim());
        let norm = match classify_manifest_key(&section, key) {
            KeyUse::Key(k) => k,
            KeyUse::Ignore => continue,
        };
        // M-1 r22: duplicate `path` keys in one table are invalid TOML —
        // first wins, the second is dropped with a problem (same contract
        // as duplicate `build`). The flag arms only when a root is
        // actually pushed (in `manifest_process_value`): a valueless
        // `path =` followed by a real `path` is one root plus an
        // Unclosed problem, not a duplicate.
        if norm == "path" && out.dup.path {
            if out.problem.is_none() {
                out.problem = Some("Cargo.toml path key is duplicated".to_owned());
            }
            continue;
        }
        manifest_process_value(
            &mut out,
            &section,
            norm,
            t[eq + 1..].trim_start(),
            &raw_lines,
            &mut li,
            dir,
        );
    }
    out.lib_bin.sort();
    out.lib_bin.dedup();
    out.aux.sort();
    out.aux.dedup();
    out
}

fn check_crate_roots(
    workspace: &Path,
    dir: &Path,
    name: &str,
    roots: &ManifestRoots,
    violations: &mut Vec<String>,
    missing: &mut Vec<String>,
) {
    let root_ok = |path: &Path| -> Option<bool> {
        if path.is_dir() {
            return None;
        }
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            // A missing root is not a violation (conventional roots are
            // optional); an unreadable one is. `exists()` follows links,
            // so a dangling symlink reports absent and would be
            // vacuous-passed as "found" — check the link itself instead
            // (L-1 r24): no link means absent, a link means unreadable.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && std::fs::symlink_metadata(path).is_err() =>
            {
                return Some(true);
            }
            Err(_) => return None,
        };
        let lines: Vec<&str> = text.lines().collect();
        let raw_entry = raw_entry_states(&lines);
        let found = lines.iter().enumerate().any(|(n, l)| {
            // Raw content never counts as a forbid — but a closer with a
            // real forbid after it on the same line does (L-7 r8: skipping
            // entry-raw lines wholesale would miss `#![forbid]` after
            // `"#`, a false missing on a compliant tree). Block-comment
            // state threads in (a closer followed by a real forbid still
            // counts — skipping on entry depth alone would miss it).
            let (raw, depth) = raw_entry.get(n).copied().unwrap_or((None, 0));
            if let Some(hash) = raw {
                return match raw_tail_after_close(l, hash) {
                    Some(tail) => {
                        let mut depth = depth;
                        line_has_forbid_attr(tail, &mut depth)
                    }
                    None => false,
                };
            }
            let mut depth = depth;
            line_has_forbid_attr(l, &mut depth)
        });
        Some(found)
    };
    let rel = || {
        sanitize_for_log(
            &dir.strip_prefix(workspace)
                .unwrap_or(dir)
                .to_string_lossy()
                .replace('\\', "/"),
        )
    };
    // M-1 r9 + r10 + r12: every compilable root carries the attribute —
    // lib.rs, main.rs, each src/bin/<name>.rs, each src/bin/<name>/main.rs
    // (cargo's second binary form), [lib]/[[bin]] custom `path = …`
    // redirections, and the crate-level build.rs.
    // The file scan already covers their bodies for `unsafe`; the missing
    // check must cover their roots for the lint, or a bin target could
    // drop its forbid silently. Manifest parsing is line-oriented on
    // purpose (this crate takes no dependencies): section headers plus
    // `path = "…"` lines cover every real manifest shape; anything fancier
    // falls back to the conventional roots, and rustc owns the rest.
    // `lib_bin` arrives pre-parsed from the shared per-crate parse (L-3
    // r17); aux (test/example/bench) roots are never forbid-checked here
    // (see `ManifestRoots::aux`).
    let mut all_roots = vec![
        dir.join("src").join("lib.rs"),
        dir.join("src").join("main.rs"),
    ];
    // M-3 r20: no `build = …` key (or `build = true`) means the
    // conventional build.rs compiles — check it. A custom string build
    // or `build = false` uncompiles it (dead code is not a root).
    if !roots.skip_build_rs {
        all_roots.push(dir.join("build.rs"));
    }
    // M-1 r15: manifest roots get the same outside-gate as the scan loop
    // before they are read — `root_ok` must never open an arbitrary file
    // (an absolute `path = "/etc/x"` or an escaping relative one). Roots
    // arriving folded are gated canonically when they resolve, lexically
    // otherwise; outside roots are skipped here because the scan loop
    // already emits the outside-workspace violation for them.
    let ws_canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    for root in &roots.lib_bin {
        let inside = std::fs::canonicalize(root).map_or_else(
            |_| fold_dot_components(root).strip_prefix(workspace).is_ok(),
            |c| c.strip_prefix(&ws_canon).is_ok(),
        );
        if inside {
            all_roots.push(root.clone());
        }
    }
    all_roots.extend(collect_bin_roots(dir, &rel, violations));
    let mut unreadable = false;
    let mut missing_root = false;
    for root in &all_roots {
        match root_ok(root) {
            Some(true) => {}
            None => unreadable = true,
            Some(false) => missing_root = true,
        }
    }
    if unreadable {
        violations.push(format!("{}: crate root unreadable, scan incomplete", rel()));
    } else if missing_root {
        missing.push(name.to_owned());
    }
}

/// Report accumulated fail-closed evidence when the scan found nothing it
/// can certify. The bare "nothing found" message must never discard the
/// violations that caused the emptiness (CI red r13: a lone symlinked
/// crate dir produced violations, then `crates.is_empty()` returned "no
/// crates found" and dropped the evidence). Missing-forbid names ride
/// along sanitized, exactly as in the main report.
fn incomplete_report(prefix: &str, violations: &[String], missing: &[String]) -> (bool, String) {
    if violations.is_empty() && missing.is_empty() {
        return (false, prefix.to_owned());
    }
    let mut out = String::from(prefix);
    out.push('\n');
    for v in violations {
        out.push_str(v);
        out.push('\n');
    }
    for m in missing {
        out.push_str("missing forbid(unsafe_code): ");
        out.push_str(&sanitize_for_log(m));
        out.push('\n');
    }
    (false, out)
}

/// Render an I/O error for a violation line: OS error text echoes the
/// offending path, which may carry line breaks or terminal escapes in a
/// hostile filename, so it passes through the same redaction as paths
/// (L-1 r17) instead of reaching the report raw.
fn fmt_io_err(e: &std::io::Error) -> String {
    sanitize_for_log(&e.to_string())
}

/// Scan one crate dir: the shared manifest parse feeds the body scan,
/// and (except qqq-sys) the forbid-roots check. Split out of
/// `run_unsafe_scan` for the line budget (L r17).
fn scan_one_crate(
    workspace: &Path,
    dir: &Path,
    name: &str,
    violations: &mut Vec<String>,
    missing: &mut Vec<String>,
    files_scanned: &mut usize,
) {
    // L-3 r17: one manifest parse per crate, shared by the body scan
    // and the roots check (duplicate parses also duplicated the
    // unreadable-manifest problem entry).
    let roots = manifest_roots(dir);
    scan_crate_rs_files(workspace, dir, &roots, violations, files_scanned);
    if name != "qqq-sys" {
        check_crate_roots(workspace, dir, name, &roots, violations, missing);
    }
}

fn run_unsafe_scan(workspace: &Path) -> (bool, String) {
    let mut violations = Vec::new();
    let mut missing = Vec::new();
    let mut crates: Vec<PathBuf> = Vec::new();
    let crates_dir = workspace.join("crates");
    // H-3 r16: a symlinked `crates/` dir would silently re-root the whole
    // scan — entries resolve outside while rel paths claim the workspace.
    // Fail closed before listing, like symlinked crate dirs (H-1 r13).
    if std::fs::symlink_metadata(&crates_dir).is_ok_and(|m| m.file_type().is_symlink()) {
        violations.push(format!(
            "{}: symlinked crates dir, scan incomplete",
            sanitize_for_log(&crates_dir.to_string_lossy())
        ));
        return incomplete_report(
            "no crates found; the scan certifies nothing",
            &violations,
            &missing,
        );
    }
    let Ok(rd) = std::fs::read_dir(&crates_dir) else {
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
                    "{}: directory entry unreadable mid-listing, scan incomplete: {}",
                    sanitize_for_log(&workspace.join("crates").display().to_string()),
                    fmt_io_err(&e)
                ));
                continue;
            }
        };
        // H-r4-H3: a failed `file_type` (dangling target, denied stat) is a
        // hole the same size as a failed listing — neither dir nor file may
        // silently vanish. `file_type` never follows symlinks, so linked
        // trees stay unrecursed by design (L11: same as the CI grep's `-r`).
        // H-1 r13: a symlinked *directory* is fail-closed, not skipped —
        // the collector would never recurse into it, so silence would
        // certify unseen code. (Symlinked *files* are still collected:
        // the scan reads through them, so their content is verified.)
        match e.file_type() {
            Ok(t) if t.is_symlink() && std::fs::metadata(e.path()).is_ok_and(|m| m.is_dir()) => {
                violations.push(format!(
                    "{}: symlinked crate dir, scan incomplete",
                    sanitize_for_log(&e.path().to_string_lossy())
                ));
            }
            Ok(t) if t.is_dir() => crates.push(e.path()),
            Ok(_) => {}
            Err(e) => violations.push(format!(
                "{}: cannot stat entry, scan incomplete: {}",
                sanitize_for_log(&workspace.join("crates").display().to_string()),
                fmt_io_err(&e)
            )),
        }
    }
    crates.sort();
    if crates.is_empty() {
        return incomplete_report(
            "no crates found; the scan certifies nothing",
            &violations,
            &missing,
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
        // L-3 r17: one manifest parse per crate, shared by the body scan
        // and the roots check — see `scan_one_crate`.
        scan_one_crate(
            workspace,
            dir,
            &name,
            &mut violations,
            &mut missing,
            &mut files_scanned,
        );
    }
    if files_scanned == 0 {
        return incomplete_report(
            "no .rs files scanned; the scan certifies nothing",
            &violations,
            &missing,
        );
    }
    if !violations.is_empty() || !missing.is_empty() {
        use std::fmt::Write as _;
        let mut out = String::from("unsafe code found outside crates/qqq-sys:\n");
        for v in &violations {
            let _ = writeln!(out, "{v}");
        }
        for m in &missing {
            // Crate names come from directory names: sanitize like paths.
            let _ = writeln!(out, "missing forbid(unsafe_code): {}", sanitize_for_log(m));
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

/// Sanitize untrusted text for violation output. Paths may legally span
/// lines (raw-string `#[path]`, hostile filenames), and echoed source may
/// carry a lone CR or an escape character — any of which would split the
/// report or restyle a terminal reading the log (M-2 r9, M-7 r11). `?`
/// marks the redaction visibly; everything else passes through untouched
/// so findings stay greppable. The alphabet covers C0/C1 controls, DEL,
/// bidi overrides and zero-widths (L-2 r15) — anything that could restyle
/// a terminal reading the log.
fn sanitize_for_log(s: &str) -> String {
    s.replace(
        |c: char| {
            c.is_control()
                || matches!(
                    c,
                    '\u{202A}'..='\u{206F}'
                        | '\u{200B}'..='\u{200F}'
                        | '\u{FEFF}'
                        // L-1 r16: line/paragraph separators, Arabic letter
                        // mark, soft hyphen, Mongolian vowel separator.
                        | '\u{2028}'
                        | '\u{2029}'
                        | '\u{061C}'
                        | '\u{00AD}'
                        | '\u{180E}'
                )
        },
        "?",
    )
}

/// Fold `.`/`..` components lexically, without touching the filesystem
/// (M-2 r10, L-1/M-2 r15). `..` folds without following links, so the
/// result keeps working for gating and reporting when the target does not
/// exist; when it does exist, callers canonicalize for the real decision.
/// A `..` that `pop()` cannot fold (leading `..` of a relative path) is
/// content, not nothing (L-1 r19): dropping it would re-root `../../b`
/// as `b` — inside instead of outside. Absolute callers are unaffected
/// (their prefix is never empty).
fn fold_dot_components(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                // Pop a real segment; a `..` with nothing (or only `..`)
                // left is content (L-1 r19). Above a root/prefix there is
                // nothing to pop — drop it (the historical absolute fold).
                match out.components().next_back() {
                    Some(Component::Normal(_)) => {
                        out.pop();
                    }
                    None | Some(Component::ParentDir) => {
                        out.push("..");
                    }
                    _ => {}
                }
            }
            Component::CurDir => {}
            _ => out.push(c.as_os_str()),
        }
    }
    out
}

/// Decide whether a redirection `target` (joined onto its file's `base`
/// dir) stays inside the workspace. Canonicalizes first so symlinks are
/// resolved before gating (M-2 r10): a lexical `..` fold would attest the
/// wrong file when a link sits in the middle. Falls back to the lexical
/// path when the target does not exist (rustc fails those loudly); the
/// pushed path is always the lexical one so `rel` reporting and the
/// qqq-sys exemption keep working on tree-shaped paths. Returns the path
/// to push and whether it is inside.
fn gate_redirect(
    workspace_canon: &Path,
    workspace: &Path,
    base: &Path,
    target: &str,
) -> (PathBuf, bool) {
    // Lexical normalization first (no fs touch): `..` folds without
    // following links, so the fallback path below keeps working when the
    // target does not exist.
    let joined = fold_dot_components(&base.join(target));
    if let Ok(canon) = std::fs::canonicalize(&joined) {
        return (joined, canon.strip_prefix(workspace_canon).is_ok());
    }
    // Unresolvable: gate lexically. A `..` that escapes lexically is
    // outside; anything else is presumed inside and left for rustc (a
    // missing file fails the build loudly, and the scan loop reports
    // unreadable files it cannot read).
    let inside = joined.strip_prefix(workspace).is_ok();
    (joined, inside)
}

/// Extra compilable files pulled in by `#[path = "…"]` and
/// `include!("…")`. Both compile arbitrary files as Rust regardless of
/// extension (H-3 r7): one `#[path = "evil.txt"]` line hides arbitrary
/// `unsafe` from an unsuffixed scan. `include_str!`/`include_bytes!` are
/// data, not code — following them would flag their prose as code, against
/// the scan's own string policy.
/// Paths that resolve outside the workspace are refused, not followed
/// (M r8): following them would read arbitrary files into the scan output.
///
/// A dynamic `include!` (non-literal argument, e.g. `concat!(env!(…))`)
/// is a fail-closed violation, not a skip: generated code is real code the
/// static scan cannot see (H-1 r8). (A dynamic `#[path]` cannot compile —
/// attributes take literals only — so it stays silent and lets rustc
/// report it.)
/// Cycle-safe via the visited set; unresolvable targets are ignored
/// (rustc fails the build elsewhere, loudly).
/// Accepted residual (L-2 r12): the gate canonicalizes but the scan reads
/// by the lexical path, so a concurrent tree mutation between the two
/// could substitute content. No concurrent-writer threat model exists for
/// a local gate run — an adversary with write access in that window has
/// simpler attacks — so this stays documented, not plumbed. The qqq-sys
/// exemption (`canonicalize` then read) and the manifest-root gating share
/// this shape (L-5 r15): gate decision and read are never one atomic step,
/// and the same no-concurrent-writer rationale covers all three.
fn follow_code_redirections(
    workspace: &Path,
    files: &mut Vec<PathBuf>,
    problems: &mut Vec<String>,
) {
    use std::collections::HashSet;
    let rel_of = |p: &Path| {
        sanitize_for_log(
            &p.strip_prefix(workspace)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/"),
        )
    };
    let mut seen: HashSet<PathBuf> = files.iter().cloned().collect();
    let mut queue: Vec<PathBuf> = files.clone();
    // Hoisted out of the per-target loop (L-9 r11): canonicalizing the
    // workspace root once instead of per redirection.
    let ws_canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    while let Some(f) = queue.pop() {
        // Unreadable files are skipped here: the scan loop reports them
        // as `unreadable` when it reaches them below.
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        let base = f.parent().map(Path::to_path_buf).unwrap_or_default();
        let (targets, dynamic) = code_redirections(&text);
        if dynamic {
            problems.push(format!(
                "{}: dynamic include! path, generated code is outside the static scan",
                rel_of(&f)
            ));
        }
        for target in targets {
            let (p, inside) = gate_redirect(&ws_canon, workspace, &base, &target);
            if !inside {
                problems.push(format!(
                    "{}: references code outside the workspace ({}), scan incomplete",
                    rel_of(&f),
                    sanitize_for_log(&target)
                ));
                continue;
            }
            if seen.insert(p.clone()) && p.is_file() {
                files.push(p.clone());
                queue.push(p);
            }
        }
    }
}

/// One hex digit's value, for `\x41` / `\u{…}` escapes in `#[path]` /
/// `include!` literals.
fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode one escape after `\` at `pos` (`pos` points at the backslash).
/// Returns the decoded bytes and the total consumed length.
/// A `\` + line break is a continuation, not an escape (H-2 r9): it
/// contributes no bytes and skips following whitespace, exactly as rustc
/// lexes it — rejecting it would miss a legal literal.
fn decode_escape(buf: &[u8], pos: usize, text: &str) -> Option<(Vec<u8>, usize)> {
    let esc = *buf.get(pos + 1)?;
    if esc == b'\n' || (esc == b'\r' && buf.get(pos + 2) == Some(&b'\n')) {
        let mut end = if esc == b'\n' { pos + 2 } else { pos + 3 };
        while let Some(r) = text.get(end..).and_then(|r| r.chars().next()) {
            if r.is_whitespace() {
                end += r.len_utf8();
            } else {
                break;
            }
        }
        return Some((Vec::new(), end - pos));
    }
    match esc {
        b'n' => Some((vec![b'\n'], 2)),
        b't' => Some((vec![b'\t'], 2)),
        b'r' => Some((vec![b'\r'], 2)),
        b'\\' => Some((vec![b'\\'], 2)),
        b'"' => Some((vec![b'"'], 2)),
        b'\'' => Some((vec![b'\''], 2)),
        b'0' => Some((vec![0], 2)),
        b'x' => {
            let hi = hex_val(*buf.get(pos + 2)?)?;
            let lo = hex_val(*buf.get(pos + 3)?)?;
            Some((vec![hi << 4 | lo], 4))
        }
        b'u' => {
            if buf.get(pos + 2) != Some(&b'{') {
                return None;
            }
            let mut idx = pos + 3;
            let mut cp: u32 = 0;
            let mut digits = 0;
            loop {
                let cur = *buf.get(idx)?;
                if cur == b'}' {
                    idx += 1;
                    break;
                }
                if cur == b'_' && digits > 0 {
                    idx += 1;
                    continue;
                }
                cp = cp * 16 + u32::from(hex_val(cur)?);
                digits += 1;
                if digits > 6 {
                    return None;
                }
                idx += 1;
            }
            if digits == 0 {
                return None;
            }
            let ch = char::from_u32(cp)?;
            let mut tmp = [0u8; 4];
            Some((ch.encode_utf8(&mut tmp).as_bytes().to_vec(), idx - pos))
        }
        _ => None,
    }
}

/// A `"…"` literal at `pos` (which points at the opening quote), with
/// escapes; returns the value and the index past the closing quote.
/// A bare `\n` ends it unclosed (`None`); a lone `\r` is likewise refused
/// (L-1 r9: rustc rejects bare CR in strings, verified live).
fn quoted_lit(text: &str, buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    pos += 1;
    let mut out: Vec<u8> = Vec::new();
    loop {
        let cur = *buf.get(pos)?;
        if cur == b'\\' {
            let (mut decoded, used) = decode_escape(buf, pos, text)?;
            out.append(&mut decoded);
            pos += used;
        } else if cur == b'"' {
            pos += 1;
            break;
        } else if cur == b'\n' || cur == b'\r' {
            return None;
        } else {
            out.push(cur);
            pos += 1;
        }
    }
    Some((String::from_utf8(out).ok()?, pos))
}

/// A raw-string literal at `pos` (`r"…"`, `r#"…"#`, …): no escapes.
/// Closes at *at least* the opening hash count, consuming exactly that
/// many (L-1 r13): a trailing `#` after the closer is a separate token —
/// only uncompilable code shapes this, and real lexing never swallows it.
fn raw_quoted_lit(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    pos += 1;
    let mut hashes = 0;
    while buf.get(pos) == Some(&b'#') {
        hashes += 1;
        pos += 1;
    }
    if buf.get(pos) != Some(&b'"') {
        return None;
    }
    pos += 1;
    let mut out: Vec<u8> = Vec::new();
    loop {
        let cur = *buf.get(pos)?;
        if cur == b'"' {
            let mut closing = 0;
            while buf.get(pos + 1 + closing) == Some(&b'#') {
                closing += 1;
            }
            if closing >= hashes {
                pos += 1 + hashes;
                break;
            }
            out.push(cur);
            pos += 1;
        } else {
            out.push(cur);
            pos += 1;
        }
    }
    Some((String::from_utf8(out).ok()?, pos))
}

/// Whitespace (Unicode, like the scanner gap), `/*…*/` block comments,
/// and `//…` line comments between tokens: `include /*c*/ !(…)`,
/// `#[ path = …]`, `include // why
/// !(…)` are all valid Rust (H-1 r9: the line comment runs to `\n`, then
/// scanning continues). Unclosed block comments stop the skip (the caller
/// decides; content after an unclosed opener is a residual, not a gap).
fn skip_gap_tokens(text: &str, buf: &[u8], pos: &mut usize) {
    loop {
        while let Some(r) = text.get(*pos..).and_then(|r| r.chars().next()) {
            if r.is_whitespace() {
                *pos += r.len_utf8();
            } else {
                break;
            }
        }
        if buf.get(*pos) == Some(&b'/') && buf.get(*pos + 1) == Some(&b'/') {
            // Line comment to end of line — then keep skipping (the opener
            // may sit on the next line, same as the unsafe gap).
            *pos += 2;
            while buf.get(*pos).is_some_and(|&c| c != b'\n') {
                *pos += 1;
            }
        } else if buf.get(*pos) == Some(&b'/') && buf.get(*pos + 1) == Some(&b'*') {
            let mut depth: u32 = 1;
            *pos += 2;
            let mut closed = false;
            while let Some(&cur) = buf.get(*pos) {
                if cur == b'/' && buf.get(*pos + 1) == Some(&b'*') {
                    depth += 1;
                    *pos += 2;
                } else if cur == b'*' && buf.get(*pos + 1) == Some(&b'/') {
                    depth = depth.saturating_sub(1);
                    *pos += 2;
                    if depth == 0 {
                        closed = true;
                        break;
                    }
                } else {
                    *pos += 1;
                }
            }
            if !closed {
                return;
            }
        } else {
            return;
        }
    }
}

/// Whether `word` at `pos` ends on a word boundary: the next char must not
/// continue an identifier (`pathname`, `includes!` are not the macros).
fn word_ends_clean(text: &str, pos: usize, word: &str) -> bool {
    text.get(pos + word.len()..)
        .and_then(|r| r.chars().next())
        .is_none_or(|c| !is_ident_char(c))
}

/// A string or raw-string literal value at `pos`; `None` if neither.
/// (The caller decides: invalid for `#[path]`, dynamic for `include!`.)
fn literal_string(text: &str, buf: &[u8], pos: usize) -> Option<(String, usize)> {
    if buf.get(pos) == Some(&b'"') {
        quoted_lit(text, buf, pos)
    } else if buf.get(pos) == Some(&b'r') && matches!(buf.get(pos + 1), Some(b'"' | b'#')) {
        raw_quoted_lit(buf, pos)
    } else {
        None
    }
}

/// Try `#[ path = lit ]` with gaps at `i` (which points at `#`).
/// Returns the target and the index past the match, or `None`.
///
/// `#[cfg_attr(pred, path = lit)]` expands to the plain path attribute
/// when the cfg holds (H-1 r17: `#[cfg_attr(all(), path = "evil.txt")]`
/// compiles `evil.txt` as Rust — verified against rustc), so the
/// follower sees through it. The match is condition-blind (conservative
/// for true cfgs; a false cfg over-follows noisily, same as the scan's
/// existing `#[cfg]` blindness). Strings in the predicate are skipped
/// (`target_os = "…"`) and the match anchors at the top-level comma.
/// `cfg_attr` layers nest (`cfg_attr(a, cfg_attr(b, path = …))` compiles
/// — verified against rustc), so wrappers peel in a loop (H-1 r18).
fn match_path_attr(text: &str, buf: &[u8], idx: usize) -> Option<(String, usize)> {
    let mut pos = idx + 1;
    skip_gap_tokens(text, buf, &mut pos);
    if buf.get(pos) != Some(&b'[') {
        return None;
    }
    pos += 1;
    skip_gap_tokens(text, buf, &mut pos);
    // Peel `cfg_attr(pred, …)` wrappers outermost-first: each layer
    // expands when its cfg holds, so a nested `cfg_attr(a, cfg_attr(b,
    // path = …))` still yields the path (H-1 r18). Every iteration
    // consumes at least `cfg_attr(` past the current position, so the
    // loop terminates; a wrapper without `(` or without a top-level
    // comma is not a path attribute at all.
    loop {
        let is_wrapper = text.get(pos..).is_some_and(|r| r.starts_with("cfg_attr"))
            && word_ends_clean(text, pos, "cfg_attr");
        if !is_wrapper {
            break;
        }
        pos += "cfg_attr".len();
        skip_gap_tokens(text, buf, &mut pos);
        if buf.get(pos) != Some(&b'(') {
            return None;
        }
        pos += 1;
        // Balanced skip of the cfg predicate to the top-level comma:
        // parens nest, strings may hide both (skipped whole).
        let mut depth: u32 = 1;
        loop {
            skip_gap_tokens(text, buf, &mut pos);
            if let Some((_, end)) = literal_string(text, buf, pos) {
                pos = end;
                continue;
            }
            match buf.get(pos) {
                Some(b'(') => {
                    depth += 1;
                    pos += 1;
                }
                Some(b')') => {
                    if depth == 1 {
                        return None;
                    }
                    depth -= 1;
                    pos += 1;
                }
                Some(b',') if depth == 1 => {
                    pos += 1;
                    break;
                }
                Some(_) => {
                    pos += 1;
                }
                None => return None,
            }
        }
        skip_gap_tokens(text, buf, &mut pos);
    }
    if !(text.get(pos..).is_some_and(|r| r.starts_with("path"))
        && word_ends_clean(text, pos, "path"))
    {
        return None;
    }
    pos += "path".len();
    skip_gap_tokens(text, buf, &mut pos);
    if buf.get(pos) != Some(&b'=') {
        return None;
    }
    pos += 1;
    skip_gap_tokens(text, buf, &mut pos);
    let (target, end) = literal_string(text, buf, pos)?;
    Some((target, end))
}

/// The outcome of matching `include` at `i`: a static target, a dynamic
/// (non-literal-argument) invocation, or no invocation at all.
enum IncludeMatch {
    Static(String, usize),
    Dynamic,
    NoMatch,
}

/// Try `include !( lit )` with gaps at `i` (which points at the `i`).
/// A non-literal argument is dynamic — fail-closed downstream (H-1 r8).
fn match_include(text: &str, buf: &[u8], idx: usize) -> IncludeMatch {
    if !(text.get(idx..).is_some_and(|r| r.starts_with("include"))
        && word_ends_clean(text, idx, "include"))
    {
        return IncludeMatch::NoMatch;
    }
    let mut pos = idx + "include".len();
    skip_gap_tokens(text, buf, &mut pos);
    if buf.get(pos) != Some(&b'!') {
        return IncludeMatch::NoMatch;
    }
    pos += 1;
    skip_gap_tokens(text, buf, &mut pos);
    if buf.get(pos) != Some(&b'(') {
        return IncludeMatch::NoMatch;
    }
    pos += 1;
    skip_gap_tokens(text, buf, &mut pos);
    match literal_string(text, buf, pos) {
        Some((target, end)) => IncludeMatch::Static(target, end),
        // M-3 r23: `c"…"`/`b"…"` (and raw forms) are not string literals
        // — `include!` rejects them at compile time ("argument must be a
        // string literal", verified against rustc), so they are silently
        // ignored like unresolvable paths, not flagged dynamic. A char or
        // byte-char literal (`'…'`, `b'…'`) is equally invalid there.
        // Anything else non-literal (concat!, env!, variables) really can
        // smuggle in generated code and stays fail-closed.
        None if is_byte_or_c_string(text, buf, pos) => IncludeMatch::NoMatch,
        None if matches!(buf.get(pos).copied(), Some(b'\'')) => IncludeMatch::NoMatch,
        None => IncludeMatch::Dynamic,
    }
}

/// Whether `buf` holds a `c"..."` / `b"..."` (or raw `cr#"..."#` form)
/// literal at `pos`: rejected by `include!`, which takes plain string
/// literals only. Only the lead-in is checked; validity beyond that is
/// rustc's. (A bare `'...'`/`b'…'` char at `pos` is handled by the caller
/// — also invalid for `include!`, same `NoMatch`.)
fn is_byte_or_c_string(text: &str, buf: &[u8], pos: usize) -> bool {
    let Some(&lead) = buf.get(pos) else {
        return false;
    };
    if lead != b'c' && lead != b'b' {
        return false;
    }
    let after = pos + 1;
    if buf.get(after) == Some(&b'"') {
        return true;
    }
    // Raw forms: `br#"…"#`, `cr#"…"#`.
    if (lead == b'b' || lead == b'c') && buf.get(after) == Some(&b'r') {
        return matches!(text.get(after + 1..), Some(r) if r.starts_with(['"', '#']));
    }
    false
}

/// Static `#[path = "…"]` / `include!("…")` targets in `text`, plus whether
/// an `include!` with a non-literal argument was seen (dynamic code path —
/// fail-closed by the caller, H-1 r8). String/comment-aware: matches only
/// fire at code positions, via the shared step-machine state.
fn code_redirections(text: &str) -> (Vec<String>, bool) {
    let buf = text.as_bytes();
    let mut out = Vec::new();
    let mut dynamic = false;
    let mut i = 0;
    let mut st = ScanState::default();
    while buf.get(i).is_some() {
        let in_code = !st.in_string
            && !st.in_char
            && st.in_raw.is_none()
            && !st.in_line_comment
            && st.comment_depth == 0;
        let mut advanced = false;
        if in_code
            && buf.get(i) == Some(&b'#')
            && let Some((target, end)) = match_path_attr(text, buf, i)
        {
            out.push(target);
            i = end;
            advanced = true;
        }
        if !advanced
            && in_code
            && text.get(i..).is_some_and(|r| r.starts_with("include"))
            && word_ends_clean(text, i, "include")
        {
            match match_include(text, buf, i) {
                IncludeMatch::Static(target, end) => {
                    out.push(target);
                    i = end;
                    advanced = true;
                }
                IncludeMatch::Dynamic => {
                    dynamic = true;
                }
                IncludeMatch::NoMatch => {}
            }
        }
        if advanced {
            continue;
        }
        // One lexer step to keep the state machine honest.
        if step_literal_text(buf, &mut i, &mut st) {
            continue;
        }
        if st.in_line_comment || st.comment_depth > 0 {
            step_comment_text(text, buf, &mut i, &mut st);
            continue;
        }
        step_code_text(text, buf, &mut i, &mut st);
    }
    (out, dynamic)
}

/// Collect every `.rs` file under `dir`. An unreadable directory is a scan
/// failure, not a skip (M4): `run_unsafe_scan` fails loudly on `problems`
/// instead of certifying a tree it never saw. (Unreadable *files* already
/// fail the same way at the read site below.)
/// Symlinked directories are not recursed (L11): `file_type` never follows
/// links, so a linked tree is silently unrecursed rather than loop-chased.
/// That matches the CI grep's default `-r` (which likewise does not follow
/// symlinks) — following them would need a visited-set against cycles,
/// and the parity target defines the contract here.
fn collect_rs_into(dir: &Path, out: &mut Vec<PathBuf>, problems: &mut Vec<String>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            problems.push(format!(
                "{}: unreadable directory, scan incomplete: {}",
                sanitize_for_log(&dir.display().to_string()),
                fmt_io_err(&e)
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
                    "{}: directory entry unreadable mid-listing, scan incomplete: {}",
                    sanitize_for_log(&dir.display().to_string()),
                    fmt_io_err(&e)
                ));
                continue;
            }
        };
        let p = e.path();
        // H2 r5: a failed `file_type` (dangling target, denied stat) is a
        // hole the same size as a failed listing — neither dir nor file may
        // silently vanish. (Symlink *targets* are not followed, L11 above;
        // this arm is about the stat itself failing.)
        match e.file_type() {
            // H-1 r13: a symlinked directory is fail-closed, not silently
            // skipped — the collector below would never recurse into it.
            // (Symlinked *files* are still collected and read through, so
            // their content is verified rather than vouched for.)
            Ok(t) if t.is_symlink() && std::fs::metadata(e.path()).is_ok_and(|m| m.is_dir()) => {
                problems.push(format!(
                    "{}: symlinked dir, scan incomplete",
                    sanitize_for_log(&e.path().to_string_lossy())
                ));
            }
            Ok(t) if t.is_dir() => collect_rs_into(&p, out, problems),
            Ok(_) => {
                // L-2 r6: case-insensitive — `FOO.RS` compiles via an
                // explicit `#[path]` on a case-insensitive FS, and skipping
                // it would certify a tree with unseen code.
                if p.extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x.eq_ignore_ascii_case("rs"))
                {
                    out.push(p);
                }
            }
            Err(e) => problems.push(format!(
                "{}: cannot stat entry, scan incomplete: {}",
                sanitize_for_log(&p.display().to_string()),
                fmt_io_err(&e)
            )),
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
///
/// M6 r4: a failed `cargo metadata` (toolchain broken mid-gate) is an
/// `Err` with the real cause — falling back to `workspace/target` would
/// blame a missing build for a broken toolchain, the wrong repair.
fn target_debug_dir(workspace: &Path) -> Result<PathBuf, String> {
    let via_env = std::env::var("CARGO_TARGET_DIR")
        .ok()
        .filter(|d| !d.is_empty());
    // M-r3-MED: a failed `cargo metadata` (toolchain broken mid-gate)
    // must not silently fall back to `workspace/target` and then fail as
    // "missing; run the build step first" — check `success()` like the
    // `git` and interpreter-discovery paths do.
    let via_metadata = match Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .current_dir(workspace)
        .output()
    {
        Err(e) => return Err(format!("cannot run `cargo metadata`: {e}")),
        Ok(o) if !o.status.success() => {
            return Err(format!(
                "`cargo metadata` exited {}: the toolchain is broken, not the target dir",
                o.status
            ));
        }
        // M-2 r6: a *successful* metadata run with no parsable directory
        // (alien output, future format) must not silently become the
        // default and then blame a missing build — that wrong repair is
        // exactly what the success() gate above was added to prevent. Real
        // cargo always emits `target_directory`, so `None` is impossible
        // without something already being wrong.
        Ok(o) => {
            let Some(d) = parse_target_dir(&o.stdout) else {
                let snippet: String = String::from_utf8_lossy(&o.stdout)
                    .chars()
                    .take(120)
                    .collect();
                return Err(format!(
                    "`cargo metadata` succeeded but emitted no target_directory (output: {snippet:?}); refusing to guess"
                ));
            };
            Some(d)
        }
    };
    Ok(resolve_target_debug_dir(
        workspace,
        via_env.as_deref(),
        via_metadata,
    ))
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
            b'b' => out.push(0x08),
            b'f' => out.push(0x0C),
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
/// followed by a column separator (LOW r3: pinning clap's exact four spaces
/// would read a layout change as 16 missing commands; LOW r4: bare
/// first-token matching would count indented prose starting with a command
/// word, and a suffixed token like `doctor,` must not stand in for the
/// entry — clap pads entries with two or more spaces).
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
        if text.lines().any(|l| {
            let t = l.trim_start_matches([' ', '\t']);
            // Indented (so prose at column zero never counts) with the
            // command as the first token and a column gap after it.
            l.len() != t.len()
                && t.split_whitespace().next() == Some(*cmd)
                && t.get(cmd.len()..).is_some_and(|r| {
                    r.starts_with("  ") || r.starts_with('\t') || r.trim().is_empty()
                })
        }) {
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
    // M6 r4: a broken toolchain reports itself here, not as a missing
    // binary that sends the reader to re-run the build.
    let bin = match target_debug_dir(workspace) {
        Ok(dir) => dir.join(exe),
        Err(e) => return (false, e),
    };
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
    let detected = output.lines().any(|l| {
        // `FAIL ` with a column separator — not a bare `FAIL` prefix, which
        // `FAILED…` crash lines also carry (M4 r4).
        l.trim_start()
            .strip_prefix("FAIL")
            .is_some_and(|r| r.starts_with([' ', '\t', ':']))
            && l.contains(expect)
    });
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
        // identifier, not the keyword plus a brace — while `²unsafe` is not
        // one identifier at all (² is alphanumeric but not alphabetic, and
        // no Rust ident holds it), so the keyword still matches there:
        // fail-noisy on code that cannot compile beats silent (M7 r4).
        // (`unsafe²` cuts the other way: `²` is not gap whitespace, so no
        // opener is visible — the machine reports what it sees.)
        assert!(!unsafe_line_is_violation("éunsafe { x(); }"));
        assert!(unsafe_line_is_violation("²unsafe { x(); }"));
        assert!(!unsafe_line_is_violation("unsafe² { x(); }"));
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
        // L1 r5: a leading char literal means the attribute does not lead
        // the line — same as a leading string. (Lifetimes never enter the
        // char branch: no closing quote nearby.)
        let mut b = 0;
        assert!(!line_has_forbid_attr("'a' #![forbid(unsafe_code)]", &mut b));
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
        // The full JSON escape set decodes (M5 r4): `\b` and `\f` are not
        // exotic, just rare in paths — refusing them falls back silently.
        let bf = br#"{"target_directory":"/tmp/a\bb\fc"}"#;
        assert_eq!(
            parse_target_dir(bf),
            Some(PathBuf::from("/tmp/a\u{8}b\u{c}c"))
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
        // M4 r4: the prefix is `FAIL `, not `FAIL` — a crash line starting
        // `FAILED…` that echoes the needle must not count as a detection.
        assert_eq!(
            injection_verdict(
                Ok((false, "  FAILED to parse std::env::var report".to_owned())),
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
        // H-r4: the gap is every Rust line separator — lone CR too — and a
        // `//` tail comment does not end the search when the opener may
        // legally sit on the next line (same_line_only stays strict).
        assert!(unsafe_line_is_violation("unsafe\r{ x(); }"));
        assert!(unsafe_line_is_violation("unsafe // SAFETY: why\n{ x(); }"));
        // C1 r7: VT and NBSP are whitespace to rustc and to the CI grep's
        // `[[:space:]]` — stopping at them would miss what the port claims
        // parity with (executed proof from the review).
        assert!(unsafe_line_is_violation("pub unsafe\x0B{ x(); }"));
        assert!(unsafe_line_is_violation("pub unsafe\u{a0}{ x(); }"));
    }

    #[test]
    fn unsafe_scan_flags_cross_line_openers_in_tree() {
        // H-r3-H1 run level: the pair re-test lives in `run_unsafe_scan`,
        // so pin it there on a synthetic crate — forbid present (a missing
        // attribute would fail the scan for the wrong reason), the only
        // violation the dangling keyword plus next-line brace.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xline-{}", std::process::id()));
        // M8: clear a previous crashed run's residue first — create alone
        // would reuse it, and the assertion below must judge this run.
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(src.join("lib.rs"), "#![forbid(unsafe_code)]\n").expect("lib");
        std::fs::write(
            src.join("main.rs"),
            "#![forbid(unsafe_code)]\nfn main() {\n    let x = unsafe\n\n    // SAFETY: separated\n    /* also */ // trailing\n    { 1 };\n    let _ = x;\n}\n",
        )
        .expect("main");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "cross-line opener passed the scan:\n{out}");
        assert!(out.contains("cross-line"), "wrong failure shape:\n{out}");
    }

    #[test]
    fn raw_entry_states_thread_across_lines() {
        // Prefix-pass contract: lines inside a multiline raw string are
        // marked as content, and keyword-heavy prose or comments do not
        // disturb the threading. (The verdict-ignoring loop once re-read
        // the same keyword forever here — caught only by the real-tree
        // tripwire hanging, never by an assertion. This test pins the
        // termination directly: it hangs pre-fix.)
        let lines = vec![
            "let s = r#\"",
            "    foo unsafe",
            "    { x }",
            "\"#;",
            "// a comment holding unsafe { shapes",
            "let y = unsafe",
            "{ y };",
        ];
        let entry = raw_entry_states(&lines);
        assert_eq!(
            entry,
            vec![
                (None, 0),
                (Some(1), 0),
                (Some(1), 0),
                (Some(1), 0),
                (None, 0),
                (None, 0),
                (None, 0)
            ]
        );
        // L-6 r7: block-comment state threads too — the entry depth marks
        // lines starting inside an unclosed `/*` (the closer on the line
        // itself does not rewrite the entry).
        let commented = vec!["/* open", "still comment", "*/ code"];
        assert_eq!(
            raw_entry_states(&commented),
            vec![(None, 0), (None, 1), (None, 1)]
        );
    }

    #[test]
    fn unsafe_scan_ignores_multiline_raw_content() {
        // Entry-raw run level: mimic shapes inside a multiline raw string
        // are prose — the pair scan must not resolve them as code. The
        // `// looks-like-a-comment` content line pins L-1 r8: dropping it
        // as a separator changes nothing because the pair is seeded.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xraw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(src.join("lib.rs"), "#![forbid(unsafe_code)]\n").expect("lib");
        std::fs::write(
            src.join("main.rs"),
            "#![forbid(unsafe_code)]\nfn main() {\n    let s = r#\"\n    foo unsafe\n    // looks-like-a-comment\n    { x }\n    \"#;\n    let _ = s;\n}\n",
        )
        .expect("main");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(ok, "multiline raw content flagged as code:\n{out}");
    }

    #[test]
    fn unsafe_scan_flags_code_after_a_raw_closer() {
        // C1 r5: a line that starts inside a raw string may close it
        // mid-line with a real block after the closer — seeding threads
        // to the closer and flags the tail, instead of skipping
        // the line or misreading the content as code.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xtail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(src.join("lib.rs"), "#![forbid(unsafe_code)]\n").expect("lib");
        std::fs::write(
            src.join("main.rs"),
            "#![forbid(unsafe_code)]\nfn main() {\n    let s = r#\"\nfoo\n\"#; unsafe { 1 };\n    let _ = s;\n}\n",
        )
        .expect("main");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "code after a raw closer passed the scan:\n{out}");
        // The hit must come from the seeded single-line scan (which shows
        // the line), not the pair scan: the pair path misreads this shape
        // as string-plus-code and must stay out of it.
        assert!(
            !out.contains("cross-line"),
            "wrong mechanism (pair instead of seeded line):\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_requires_every_crate_root() {
        // M1 r5: a forbid in lib.rs must not excuse a missing one in
        // main.rs — every existing root carries the attribute.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xroot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(src.join("lib.rs"), "#![forbid(unsafe_code)]\n").expect("lib");
        std::fs::write(src.join("main.rs"), "fn main() {}\n").expect("main");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "unforbidden bin root passed the scan:\n{out}");
        assert!(
            out.contains("missing forbid"),
            "wrong failure shape:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_rejects_raw_spoofed_forbid() {
        // M-3 r6: a forbid inside a multiline raw string is content, not
        // code — both roots spoofed must still read as missing.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xspoof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(
            src.join("lib.rs"),
            "let s = r#\"\n#![forbid(unsafe_code)]\n\"#;\npub fn f() {}\n",
        )
        .expect("lib");
        std::fs::write(
            src.join("main.rs"),
            "let t = r#\"\n#![forbid(unsafe_code)]\n\"#;\nfn main() {}\n",
        )
        .expect("main");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "raw-spoofed forbid passed the scan:\n{out}");
        assert!(
            out.contains("missing forbid"),
            "wrong failure shape:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_rejects_comment_spoofed_forbid() {
        // H-2 r7: a commented-out forbid must not certify — even when the
        // `/*` opener sits on a line whose own forbid parse fails first
        // (which used to freeze the private depth at zero and let the next
        // line's commented forbid through).
        let root = std::env::temp_dir().join(format!("qqq-xtask-xcspoof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(
            src.join("lib.rs"),
            "#![forbid(unsafe_codex)] /*\n#![forbid(unsafe_code)]\n",
        )
        .expect("lib");
        std::fs::write(
            src.join("main.rs"),
            "#![forbid(unsafe_code)]\nfn main() {}\n",
        )
        .expect("main");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "comment-spoofed forbid passed the scan:\n{out}");
        assert!(
            out.contains("missing forbid"),
            "wrong failure shape:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_reports_unreadable_roots_loudly() {
        // M-4 r7: a present-but-unreadable root is a scan failure, not a
        // missing lint — the repair is fixing perms, not adding an
        // attribute. A directory in place of the root reads as
        // unreadable on every platform (open-for-read fails).
        let root = std::env::temp_dir().join(format!("qqq-xtask-xunread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(src.join("lib.rs")).expect("unreadable stand-in");
        std::fs::write(
            src.join("main.rs"),
            "#![forbid(unsafe_code)]\nfn main() {}\n",
        )
        .expect("main");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "unreadable root passed the scan:\n{out}");
        assert!(
            out.contains("unreadable"),
            "wrong failure shape (should not say missing):\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_sees_forbid_after_raw_closer() {
        // L-7 r8: a closer with a real forbid after it on the same line
        // counts — entry-raw lines are seeded, not skipped, in the root
        // check too. (The forbid must still open the tail's code: a `;`
        // before it disqualifies exactly as on a whole line.)
        let root = std::env::temp_dir().join(format!("qqq-xtask-xtailroot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(
            src.join("lib.rs"),
            "let s = r#\"\nfoo\n\"# #![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        std::fs::write(
            src.join("main.rs"),
            "#![forbid(unsafe_code)]\nfn main() {}\n",
        )
        .expect("main");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(ok, "tail forbid misread as missing:\n{out}");
    }

    #[test]
    fn unsafe_scan_collects_uppercase_rs() {
        // L-2 r6: `EXTRA.RS` compiles via `#[path]` on a case-insensitive
        // FS — the scan must not skip it for its casing.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xrs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(
            src.join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        std::fs::write(src.join("EXTRA.RS"), "pub unsafe fn evil() {}\n").expect("upper");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "uppercase .RS violation passed the scan:\n{out}");
        assert!(out.contains("EXTRA.RS"), "wrong file flagged:\n{out}");
    }

    #[test]
    fn comment_only_separator_rejects_stray_close() {
        // L-3 r6: `/* */ */` is a complete comment plus a stray closer —
        // the trailing `*/` is code-ish, so the line stays significant.
        // M-1 r7: balanced blocks and //-tails drop out; unclosed stays.
        assert!(is_comment_only_separator(""));
        assert!(is_comment_only_separator("   "));
        assert!(is_comment_only_separator("// only"));
        assert!(is_comment_only_separator("/* c */"));
        assert!(is_comment_only_separator("/* a /* b */ */"));
        assert!(is_comment_only_separator("/* c */ // trailing"));
        assert!(!is_comment_only_separator("/* unclosed"));
        assert!(!is_comment_only_separator("/* */ */"));
        assert!(!is_comment_only_separator("let x = 1; // c"));
        assert!(!is_comment_only_separator("\"/*\""));
        assert!(!is_comment_only_separator("*/ code"));
    }

    #[test]
    fn code_redirections_finds_path_and_include() {
        // H-3 r7 unit: `#[path]` and `include!` targets extract;
        // `include_str!`/`include_bytes!` (data) never do.
        assert_eq!(
            code_redirections("#[path = \"a.rs\"]\ninclude!(\"b.rs\")\ninclude_str!(\"c.txt\")\n"),
            (vec!["a.rs".to_owned(), "b.rs".to_owned()], false)
        );
        // H-3 r8: token spacing is irrelevant — `#[ path`, `include !(`
        // and `/*…*/` between tokens are all valid Rust.
        assert_eq!(
            code_redirections("#[ path = \"a.rs\"]\ninclude /*c*/ ! (\"b.rs\")\n"),
            (vec!["a.rs".to_owned(), "b.rs".to_owned()], false)
        );
        // Raw-string paths decode without escapes (M r8).
        assert_eq!(
            code_redirections("#[path = r#\"a.rs\"#]\n"),
            (vec!["a.rs".to_owned()], false)
        );
        // Escaped paths decode (L r8): `\x41` is `A`, `\u{63}` is `c`.
        assert_eq!(
            code_redirections("#[path = \"\\x41.rs\"]\ninclude!(\"\\u{63}.rs\")\n"),
            (vec!["A.rs".to_owned(), "c.rs".to_owned()], false)
        );
        // Unicode separators (M r8): NBSP between tokens is legal Rust.
        assert_eq!(
            code_redirections("#[path\u{a0}=\u{a0}\"a.rs\"]\n"),
            (vec!["a.rs".to_owned()], false)
        );
        // A dynamic `#[path]` cannot compile (attributes take literals),
        // so it stays silent and lets rustc report it.
        assert_eq!(
            code_redirections("#[path = concat!(env!(\"X\"), \"/a.rs\")]"),
            (Vec::<String>::new(), false)
        );
        // A dynamic `include!` compiles generated code the static scan
        // cannot see — fail closed (H-1 r8).
        assert_eq!(
            code_redirections("include!(concat!(env!(\"OUT_DIR\"), \"/g.rs\"));"),
            (Vec::<String>::new(), true)
        );
        // A mention inside a real string literal cannot match: source
        // files escape inner quotes (`\"`), and only a bare `"` opens the
        // value here.
        assert_eq!(
            code_redirections("let s = \"#[path = \\\"no.rs\\\"]\";"),
            (Vec::<String>::new(), false)
        );
        // H-1 r9: `//` line comments separate tokens — `include // why`
        // on one line and `!(…)` on the next is valid Rust.
        assert_eq!(
            code_redirections("include // why\n!(\"e.txt\")\n"),
            (vec!["e.txt".to_owned()], false)
        );
        assert_eq!(
            code_redirections("#[path // why\n= \"f.rs\"]\n"),
            (vec!["f.rs".to_owned()], false)
        );
        // H-2 r9: a backslash-newline inside the literal is a line
        // continuation, not the end — the path still resolves. (Built
        // with concat! so the test source itself stays single-line: the
        // assembled value carries a real backslash + newline.)
        assert_eq!(
            code_redirections(concat!("#[path = \"g\\", "\n  h.rs\"]\n")),
            (vec!["gh.rs".to_owned()], false)
        );
        // L-1 r9: a bare CR is not a legal string character (rustc
        // rejects it), so it ends the literal unclosed — no match.
        assert_eq!(
            code_redirections("#[path = \"i\rr.rs\"]\n"),
            (Vec::<String>::new(), false)
        );
        // H-1 r17: `#[cfg_attr(pred, path = "…")]` expands to the path
        // when the cfg holds — the follower must see through it, with
        // strings in the predicate skipped (`target_os = "…"`) and the
        // match at the top-level comma.
        assert_eq!(
            code_redirections("#[cfg_attr(all(), path = \"j.rs\")]\n"),
            (vec!["j.rs".to_owned()], false)
        );
        assert_eq!(
            code_redirections("#[cfg_attr(target_os = \"linux\", path = \"k.rs\")]\n"),
            (vec!["k.rs".to_owned()], false)
        );
        // No path after the predicate comma: nothing to follow.
        assert_eq!(
            code_redirections("#[cfg_attr(all(), warn(dead_code))]\n"),
            (Vec::<String>::new(), false)
        );
        // H-1 r18: `cfg_attr` layers nest (`cfg_attr(a, cfg_attr(b,
        // path = "…"))` compiles — verified against rustc), so wrappers
        // peel outermost-first, with strings skipped at every layer.
        assert_eq!(
            code_redirections("#[cfg_attr(all(), cfg_attr(all(), path = \"n.rs\"))]\n"),
            (vec!["n.rs".to_owned()], false)
        );
        assert_eq!(
            code_redirections(
                "#[cfg_attr(target_os = \"linux\", cfg_attr(all(), path = \"o.rs\"))]\n"
            ),
            (vec!["o.rs".to_owned()], false)
        );
        // A wrapper without a top-level comma is not a path attribute.
        assert_eq!(
            code_redirections("#[cfg_attr(all())]\n"),
            (Vec::<String>::new(), false)
        );
    }

    #[test]
    fn io_errors_are_sanitized_for_log() {
        // L-1 r17: OS error text echoes the offending path — hostile
        // filenames (newlines, escapes) must not reach the report raw.
        let e = std::io::Error::other("bad\nname\x08");
        assert_eq!(fmt_io_err(&e), "bad?name?");
    }

    #[test]
    fn sanitize_for_log_masks_line_breaks() {
        // M-2 r9: raw paths may legally span lines; echoing the newline
        // would split the violation report.
        assert_eq!(sanitize_for_log("a\nb\rc"), "a?b?c");
        assert_eq!(sanitize_for_log("plain.rs"), "plain.rs");
    }

    #[test]
    fn incomplete_report_keeps_evidence() {
        // CI-red root cause (r13 batch, all three platforms): a lone
        // symlinked crate dir filled `violations` but `crates` stayed
        // empty, and the bare "no crates found" return dropped the
        // evidence. The report must carry violations and missing names;
        // the bare message survives only when there is nothing to carry.
        let (ok, out) = incomplete_report(
            "no crates found; the scan certifies nothing",
            &["c/link: symlinked crate dir, scan incomplete".to_owned()],
            &["probe".to_owned()],
        );
        assert!(!ok);
        assert!(
            out.contains("symlinked crate dir"),
            "evidence dropped:\n{out}"
        );
        assert!(
            out.contains("missing forbid(unsafe_code): probe"),
            "missing dropped:\n{out}"
        );
        let (ok, out) = incomplete_report("no crates found; the scan certifies nothing", &[], &[]);
        assert!(!ok);
        assert_eq!(out, "no crates found; the scan certifies nothing");
    }

    #[test]
    fn sanitize_for_log_redacts_controls_and_bidi() {
        // L-2 r15: terminal-spoofing controls beyond \n \r ESC (backspace,
        // DEL, bidi overrides, zero-widths, BOM) must not reach the report.
        // L-1 r16: plus line/paragraph separators, Arabic mark, soft hyphen,
        // Mongolian vowel separator.
        assert_eq!(
            sanitize_for_log("a\x08b\u{202A}c\u{200B}d\u{FEFF}e\x7Ff"),
            "a?b?c?d?e?f"
        );
        assert_eq!(
            sanitize_for_log("g\u{2028}h\u{2029}i\u{061C}j\u{00AD}k\u{180E}l"),
            "g?h?i?j?k?l"
        );
        assert_eq!(sanitize_for_log("plain.rs"), "plain.rs");
    }

    #[test]
    fn gate_redirect_stays_inside_without_symlinks() {
        // L-10 r11: the containment gate, pinned without symlinks so it
        // runs everywhere (the live symlink test covers the link half and
        // skips where the OS forbids creating them).
        let ws = PathBuf::from(if cfg!(windows) { "C:\\ws" } else { "/ws" });
        let ws_canon = ws.clone();
        let base = ws.join("crates").join("probe").join("src");
        // Inside, plain and dotted. (Unresolvable targets gate lexically
        // and deterministically — nothing here exists on disk.)
        assert!(gate_redirect(&ws_canon, &ws, &base, "hidden.txt").1);
        assert!(gate_redirect(&ws_canon, &ws, &base, "sub/../hidden.txt").1);
        // Outside: escaping past the root (four levels up from src/) and
        // absolute paths.
        assert!(!gate_redirect(&ws_canon, &ws, &base, "/etc/passwd").1);
        assert!(!gate_redirect(&ws_canon, &ws, &base, "../../../../outside.txt").1);
    }

    #[test]
    fn unsafe_scan_follows_path_redirections() {
        // H-3 r7 run level: a `#[path = "hidden.txt"]` module compiles as
        // Rust regardless of extension — the scan must see its `unsafe`.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xredir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(src.join("lib.rs"), "#![forbid(unsafe_code)]\n").expect("lib");
        std::fs::write(
            src.join("main.rs"),
            "#![forbid(unsafe_code)]\nfn main() {}\n",
        )
        .expect("main");
        std::fs::write(
            src.join("redir.rs"),
            "#![forbid(unsafe_code)]\n#[path = \"hidden.txt\"]\nmod hidden;\n",
        )
        .expect("redir");
        std::fs::write(src.join("hidden.txt"), "pub unsafe fn evil() {}\n").expect("hidden");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "redirected unsafe passed the scan:\n{out}");
        assert!(out.contains("hidden.txt"), "wrong file flagged:\n{out}");
    }

    #[test]
    fn unsafe_scan_follows_cfg_attr_path_redirection() {
        // H-1 r17 run level: `#[cfg_attr(all(), path = "hidden2.txt")]`
        // compiles the target as Rust when the cfg holds — the scan is
        // condition-blind (conservative for true cfgs) and must see it.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xcfgredir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(src.join("lib.rs"), "#![forbid(unsafe_code)]\n").expect("lib");
        std::fs::write(
            src.join("redir.rs"),
            "#![forbid(unsafe_code)]\n#[cfg_attr(all(), path = \"hidden2.txt\")]\nmod hidden2;\n",
        )
        .expect("redir");
        std::fs::write(src.join("hidden2.txt"), "pub unsafe fn evil() {}\n").expect("hidden");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "cfg_attr-redirected unsafe passed the scan:\n{out}");
        assert!(out.contains("hidden2.txt"), "wrong file flagged:\n{out}");
    }

    #[test]
    fn unsafe_scan_follows_nested_cfg_attr_path_redirection() {
        // H-1 r18 run level: `#[cfg_attr(a, cfg_attr(b, path = "…"))]`
        // compiles the target when the cfgs hold (verified against
        // rustc) — the follower peels wrappers outermost-first.
        let root =
            std::env::temp_dir().join(format!("qqq-xtask-xcfgredir2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(src.join("lib.rs"), "#![forbid(unsafe_code)]\n").expect("lib");
        std::fs::write(
            src.join("redir.rs"),
            "#![forbid(unsafe_code)]\n#[cfg_attr(all(), cfg_attr(all(), path = \"hidden3.txt\"))]\nmod hidden3;\n",
        )
        .expect("redir");
        std::fs::write(src.join("hidden3.txt"), "pub unsafe fn evil() {}\n").expect("hidden");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            !ok,
            "nested cfg_attr-redirected unsafe passed the scan:\n{out}"
        );
        assert!(out.contains("hidden3.txt"), "wrong file flagged:\n{out}");
    }

    #[test]
    fn unsafe_scan_follows_redirections_inside_manifest_roots() {
        // H-2 r18 run level: a custom manifest root's own `#[path]`
        // targets compile as Rust too — the follower runs after the
        // manifest expansion, so chains rooted at custom roots resolve
        // transitively (previously the expansion ran after the follow
        // and this `unsafe` sailed through GREEN).
        let root =
            std::env::temp_dir().join(format!("qqq-xtask-xrootredir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("src")).expect("temp crate");
        std::fs::create_dir_all(dir.join("custom")).expect("custom dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"custom/a.txt\"\n",
        )
        .expect("manifest");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        std::fs::write(
            dir.join("custom").join("a.txt"),
            "#![forbid(unsafe_code)]\n#[path = \"b.txt\"]\nmod b;\n",
        )
        .expect("custom root");
        std::fs::write(
            dir.join("custom").join("b.txt"),
            "pub unsafe fn evil() {}\n",
        )
        .expect("hidden");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            !ok,
            "redirection inside manifest root passed the scan:\n{out}"
        );
        assert!(out.contains("b.txt"), "wrong file flagged:\n{out}");
    }

    #[test]
    fn unsafe_scan_scans_custom_test_target_body() {
        // M-1 r17 run level: a custom `[[test]] path` outside `tests/`
        // (here with a non-`.rs` extension the walk never takes) compiles
        // as Rust — its body must be scanned. Forbid roots stay with
        // lib/bin (the compiler owns test-target lints via manifest
        // `[lints]`), so no "missing forbid" may appear for it.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xtestroot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("src")).expect("temp crate");
        std::fs::create_dir_all(dir.join("custom")).expect("custom dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[[test]]\nname = \"weird\"\npath = \"custom/t.txt\"\n",
        )
        .expect("manifest");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        std::fs::write(
            dir.join("custom").join("t.txt"),
            "#![forbid(unsafe_code)]\npub unsafe fn evil() {}\n",
        )
        .expect("test root");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "custom test target unsafe passed the scan:\n{out}");
        assert!(out.contains("t.txt"), "wrong failure shape:\n{out}");
        assert!(
            !out.contains("missing forbid"),
            "test target wrongly forbid-checked:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_scans_custom_build_script_body() {
        // C-1 r19 run level: `[package] build = "custom/b.txt"` compiles
        // as the build script — its body is scanned and its forbid is
        // checked exactly like a conventional `build.rs`.
        let root =
            std::env::temp_dir().join(format!("qqq-xtask-xbuildroot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("src")).expect("temp crate");
        std::fs::create_dir_all(dir.join("custom")).expect("custom dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nbuild = \"custom/b.txt\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .expect("manifest");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        std::fs::write(
            dir.join("custom").join("b.txt"),
            "#![forbid(unsafe_code)]\npub unsafe fn evil() {}\n",
        )
        .expect("build script");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "custom build script unsafe passed the scan:\n{out}");
        assert!(out.contains("b.txt"), "wrong failure shape:\n{out}");
    }

    #[test]
    fn unsafe_scan_requires_custom_build_script_forbid() {
        // C-1 r19 run level: a custom build script without the attribute
        // fails loudly like a conventional `build.rs`.
        let root =
            std::env::temp_dir().join(format!("qqq-xtask-xbuildforbid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("src")).expect("temp crate");
        std::fs::create_dir_all(dir.join("custom")).expect("custom dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nbuild = \"custom/b.rs\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .expect("manifest");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        std::fs::write(dir.join("custom").join("b.rs"), "pub fn f() {}\n").expect("build");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            !ok,
            "unforbidden custom build script passed the scan:\n{out}"
        );
        assert!(
            out.contains("missing forbid"),
            "wrong failure shape:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_ignores_disabled_build_script() {
        // M-3 r20 run level: `build = false` uncompiles the conventional
        // `build.rs` — neither its body nor its missing forbid may fail
        // the scan (its `unsafe` is dead code, not shipped code).
        let root = std::env::temp_dir().join(format!("qqq-xtask-xnobuild-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("src")).expect("temp crate");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nbuild = false\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .expect("manifest");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        std::fs::write(dir.join("build.rs"), "pub unsafe fn evil() {}\n").expect("stray build");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(ok, "disabled build.rs failed the scan:\n{out}");
    }

    #[test]
    fn unsafe_scan_skips_outside_build_script_without_reading() {
        // C-1 r19 run level: an outside-workspace custom build script is
        // refused like any other outside root — and never read (its
        // content must not leak into evidence as "missing forbid").
        let pid = std::process::id();
        let root = std::env::temp_dir().join(format!("qqq-xtask-xbuildout-{pid}"));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("src")).expect("temp crate");
        let outside = std::env::temp_dir().join(format!("qqq-xtask-xbuildoutside-{pid}.rs"));
        let _ = std::fs::remove_file(&outside);
        std::fs::write(&outside, "pub unsafe fn evil() {}\n").expect("outside file");
        std::fs::write(
            dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"probe\"\nbuild = \"../../../qqq-xtask-xbuildoutside-{pid}.rs\"\n\n[lib]\npath = \"src/lib.rs\"\n"
            ),
        )
        .expect("manifest");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&outside);
        assert!(!ok, "outside build script passed the scan:\n{out}");
        assert!(
            out.contains("outside the workspace"),
            "wrong failure shape:\n{out}"
        );
        assert!(
            !out.contains("missing forbid"),
            "ungated read of outside build leaked into evidence:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_scans_self_referential_build_script() {
        // H-1 r21 run level: `[package] build = "build.rs"` names the
        // conventional file explicitly — the skip for the conventional
        // path must not drop a root that is also the custom target, or
        // its `unsafe` sails through GREEN while forbid still passes.
        let root =
            std::env::temp_dir().join(format!("qqq-xtask-xbuildself-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("src")).expect("temp crate");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nbuild = \"build.rs\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .expect("manifest");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        std::fs::write(
            dir.join("build.rs"),
            "#![forbid(unsafe_code)]\npub unsafe fn evil() {}\n",
        )
        .expect("build script");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            !ok,
            "self-referential build script unsafe passed the scan:\n{out}"
        );
        assert!(out.contains("build.rs"), "wrong failure shape:\n{out}");
    }

    #[test]
    fn unsafe_scan_follows_redirection_into_disabled_build_script() {
        // H-1 r23: `build = false` uncompiles the conventional build.rs —
        // but a `#[path]` that names it compiles it as a module anyway.
        // The skip must run before the follower so the redirect re-adds
        // it; dropping it after the follow sailed its `unsafe` GREEN.
        let root =
            std::env::temp_dir().join(format!("qqq-xtask-xredirbuild-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("src")).expect("temp crate");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nbuild = false\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .expect("manifest");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\n#[path = \"../build.rs\"]\nmod b;\n",
        )
        .expect("lib");
        std::fs::write(
            dir.join("build.rs"),
            "#![forbid(unsafe_code)]\npub unsafe fn evil() {}\n",
        )
        .expect("build script");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            !ok,
            "redirected disabled build script passed the scan:\n{out}"
        );
        assert!(out.contains("build.rs"), "wrong failure shape:\n{out}");
    }

    #[test]
    fn unsafe_scan_dangling_symlink_root_is_unreadable() {
        // L-1 r24: a custom root that is a dangling symlink is
        // present-but-unreadable (`exists()` follows links, so the old
        // check vacuous-passed it as "found"). Fail loud instead of
        // certifying a root the scan never read. The `.txt` extension
        // keeps the body walk from flagging it first, isolating the
        // roots check. Skipped where the platform denies symlink
        // creation (fires on CI).
        let pid = std::process::id();
        let root = std::env::temp_dir().join(format!("qqq-xtask-xdanglink-{pid}"));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("src")).expect("temp crate");
        std::fs::create_dir_all(dir.join("custom")).expect("custom dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"custom/dangle.txt\"\n",
        )
        .expect("manifest");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        let missing = std::env::temp_dir().join(format!("qqq-xtask-xdangling-target-{pid}.txt"));
        let _ = std::fs::remove_file(&missing);
        #[cfg(unix)]
        let link_ok =
            std::os::unix::fs::symlink(&missing, dir.join("custom").join("dangle.txt")).is_ok();
        #[cfg(windows)]
        let link_ok =
            std::os::windows::fs::symlink_file(&missing, dir.join("custom").join("dangle.txt"))
                .is_ok();
        #[cfg(not(any(unix, windows)))]
        let link_ok = false;
        if !link_ok {
            let _ = std::fs::remove_dir_all(&root);
            eprintln!("SKIP: cannot create symlinks here");
            return;
        }
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "dangling symlinked root passed the scan:\n{out}");
        assert!(out.contains("unreadable"), "wrong failure shape:\n{out}");
    }

    #[test]
    fn unsafe_scan_reports_unreadable_manifest_once() {
        // L-3 r17 run level: one unreadable manifest must yield one
        // problem entry, not one per consumer (scan loop +
        // roots check). A directory in place of the file fails every
        // read on all platforms.
        let root =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-dupmsg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("Cargo.toml")).expect("temp crate");
        std::fs::create_dir_all(dir.join("src")).expect("src dir");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "unreadable manifest passed the scan:\n{out}");
        let hits = out
            .lines()
            .filter(|l| l.contains("manifest problem"))
            .count();
        assert_eq!(hits, 1, "manifest problem reported twice:\n{out}");
    }

    #[test]
    fn unsafe_scan_flags_dynamic_include() {
        // H-1 r8: `include!(concat!(…))` compiles generated code the
        // static scan cannot see — fail closed, do not certify.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xdyn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(src.join("lib.rs"), "#![forbid(unsafe_code)]\n").expect("lib");
        std::fs::write(
            src.join("main.rs"),
            "#![forbid(unsafe_code)]\ninclude!(concat!(env!(\"OUT_DIR\"), \"/g.rs\"));\nfn main() {}\n",
        )
        .expect("main");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "dynamic include passed the scan:\n{out}");
        assert!(
            out.contains("dynamic include"),
            "wrong failure shape:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_refuses_outside_workspace() {
        // M r8: a redirection that resolves outside the workspace is
        // refused, not followed — the scan must not read arbitrary files
        // into its output.
        let outside =
            std::env::temp_dir().join(format!("qqq-xtask-xoutside-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).expect("outside dir");
        std::fs::write(outside.join("evil.txt"), "pub unsafe fn evil() {}\n").expect("evil");
        let root = std::env::temp_dir().join(format!("qqq-xtask-xredirout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(src.join("lib.rs"), "#![forbid(unsafe_code)]\n").expect("lib");
        std::fs::write(
            src.join("main.rs"),
            format!(
                "#![forbid(unsafe_code)]\n#[path = \"../../../../{}/evil.txt\"]\nmod evil;\nfn main() {{}}\n",
                outside.file_name().unwrap().to_string_lossy()
            ),
        )
        .expect("main");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        assert!(!ok, "outside-workspace redirect passed the scan:\n{out}");
        assert!(
            out.contains("outside the workspace"),
            "wrong failure shape:\n{out}"
        );
        assert!(
            !out.contains("pub unsafe"),
            "outside file content echoed:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_requires_bin_root_forbid() {
        // M-1 r9: every compilable root carries the attribute — a
        // src/bin/<name>.rs without one fails loudly, like lib.rs/main.rs.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xbin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(src.join("bin")).expect("temp crate");
        std::fs::write(
            src.join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        std::fs::write(src.join("bin").join("tool.rs"), "fn main() {}\n").expect("bin");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "unforbidden bin root passed the scan:\n{out}");
        assert!(
            out.contains("missing forbid"),
            "wrong failure shape:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_requires_nested_bin_root_forbid() {
        // M-1 r10: cargo's second binary form (src/bin/<name>/main.rs) is
        // a compilable root too — it must carry the forbid like the rest.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xbin2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(src.join("bin").join("tool")).expect("temp crate");
        std::fs::write(
            src.join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        std::fs::write(
            src.join("bin").join("tool").join("main.rs"),
            "fn main() {}\n",
        )
        .expect("bin main");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "unforbidden nested bin root passed the scan:\n{out}");
        assert!(
            out.contains("missing forbid"),
            "wrong failure shape:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_refuses_symlink_escape() {
        // M-2 r10: a redirection through a symlink that resolves outside
        // the workspace is refused, not followed. Skipped where the
        // platform denies symlink creation (no privilege to test with).
        let target_dir =
            std::env::temp_dir().join(format!("qqq-xtask-xlinkout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&target_dir);
        std::fs::create_dir_all(&target_dir).expect("outside dir");
        std::fs::write(target_dir.join("evil.txt"), "pub unsafe fn evil() {}\n").expect("evil");
        let root = std::env::temp_dir().join(format!("qqq-xtask-xlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        #[cfg(unix)]
        let link_ok = std::os::unix::fs::symlink(&target_dir, src.join("link")).is_ok();
        #[cfg(windows)]
        let link_ok = std::os::windows::fs::symlink_dir(&target_dir, src.join("link")).is_ok();
        #[cfg(not(any(unix, windows)))]
        let link_ok = false;
        if !link_ok {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&target_dir);
            eprintln!("SKIP: cannot create symlinks here");
            return;
        }
        std::fs::write(
            src.join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        std::fs::write(
            src.join("main.rs"),
            "#![forbid(unsafe_code)]\n#[path = \"link/evil.txt\"]\nmod evil;\nfn main() {}\n",
        )
        .expect("main");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&target_dir);
        assert!(!ok, "symlink escape passed the scan:\n{out}");
        assert!(
            out.contains("outside the workspace"),
            "wrong failure shape:\n{out}"
        );
        assert!(
            !out.contains("pub unsafe"),
            "escaped content echoed:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_symlinked_crate_dir_is_loud() {
        // H-1 r13: a symlinked crate dir is fail-closed, not silently
        // skipped — the collector never recurses into it, so silence
        // would vouch for unseen code. Skipped where the platform denies
        // symlink creation.
        let outside =
            std::env::temp_dir().join(format!("qqq-xtask-xcrateout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(outside.join("src")).expect("outside dir");
        std::fs::write(
            outside.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("outside lib");
        let root =
            std::env::temp_dir().join(format!("qqq-xtask-xcratelink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("crates")).expect("crates dir");
        #[cfg(unix)]
        let link_ok =
            std::os::unix::fs::symlink(&outside, root.join("crates").join("linkcrate")).is_ok();
        #[cfg(windows)]
        let link_ok =
            std::os::windows::fs::symlink_dir(&outside, root.join("crates").join("linkcrate"))
                .is_ok();
        #[cfg(not(any(unix, windows)))]
        let link_ok = false;
        if !link_ok {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            eprintln!("SKIP: cannot create symlinks here");
            return;
        }
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        assert!(!ok, "symlinked crate dir passed the scan:\n{out}");
        assert!(out.contains("symlinked"), "wrong failure shape:\n{out}");
    }

    #[test]
    fn unsafe_scan_symlinked_bin_dir_is_loud() {
        // H-4 r12: a symlinked src/bin/<name> dir is fail-closed — the
        // collector never recurses into it, so vouching for its target
        // would certify unseen code. Skipped where the platform denies
        // symlink creation.
        let target = std::env::temp_dir().join(format!("qqq-xtask-xbinout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&target);
        std::fs::create_dir_all(&target).expect("outside dir");
        std::fs::write(target.join("main.rs"), "fn main() {}\n").expect("bin main");
        let root = std::env::temp_dir().join(format!("qqq-xtask-xbinlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(src.join("bin")).expect("temp crate");
        std::fs::write(
            src.join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        #[cfg(unix)]
        let link_ok = std::os::unix::fs::symlink(&target, src.join("bin").join("tool")).is_ok();
        #[cfg(windows)]
        let link_ok =
            std::os::windows::fs::symlink_dir(&target, src.join("bin").join("tool")).is_ok();
        #[cfg(not(any(unix, windows)))]
        let link_ok = false;
        if !link_ok {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&target);
            eprintln!("SKIP: cannot create symlinks here");
            return;
        }
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&target);
        assert!(!ok, "symlinked bin dir passed the scan:\n{out}");
        assert!(out.contains("symlinked"), "wrong failure shape:\n{out}");
    }

    #[test]
    fn unsafe_scan_symlinked_nested_bin_main_is_loud() {
        // M-5 r23: a symlinked `src/bin/<name>/main.rs` is read through by
        // `is_file` — the no-follow check the entry arm applies must
        // apply here too, or an outside file is read as a crate root.
        // Skipped where the platform denies symlink creation (fires on CI).
        let target =
            std::env::temp_dir().join(format!("qqq-xtask-xbinmainout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&target);
        std::fs::create_dir_all(&target).expect("outside dir");
        std::fs::write(target.join("evil.rs"), "pub unsafe fn evil() {}\n").expect("outside file");
        let root =
            std::env::temp_dir().join(format!("qqq-xtask-xbinmainlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(src.join("bin").join("tool")).expect("temp crate");
        std::fs::write(
            src.join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        #[cfg(unix)]
        let link_ok = std::os::unix::fs::symlink(
            target.join("evil.rs"),
            src.join("bin").join("tool").join("main.rs"),
        )
        .is_ok();
        #[cfg(windows)]
        let link_ok = std::os::windows::fs::symlink_file(
            target.join("evil.rs"),
            src.join("bin").join("tool").join("main.rs"),
        )
        .is_ok();
        #[cfg(not(any(unix, windows)))]
        let link_ok = false;
        if !link_ok {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&target);
            eprintln!("SKIP: cannot create symlinks here");
            return;
        }
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&target);
        assert!(!ok, "symlinked nested bin main passed the scan:\n{out}");
        assert!(out.contains("symlinked"), "wrong failure shape:\n{out}");
        assert!(
            !out.contains("missing forbid"),
            "ungated read of outside bin leaked into evidence:\n{out}"
        );
    }

    #[test]
    fn manifest_custom_roots_parses_lib_and_bin_paths() {
        // M-1 r13: custom [lib]/[[bin]] path= redirections are discovered
        // for the missing-forbid backstop.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-parse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"custom/lib2.rs\"\n\n[[bin]]\nname = \"tool\"\npath = 'custom-bin/main.rs' # comment\n\n[dependencies]\n",
        )
        .expect("manifest");
        let (mut roots, problem) = manifest_custom_roots(&dir);
        roots.sort();
        assert_eq!(problem, None);
        assert_eq!(
            roots,
            vec![dir.join("custom/lib2.rs"), dir.join("custom-bin/main.rs")]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_tolerates_spacing_and_hash_paths() {
        // M-1/M-3 r14: TOML-legal `[ lib ]` spacing, and `#` inside a
        // quoted path (must not truncate as a comment).
        let dir = std::env::temp_dir().join(format!("qqq-xtask-xmanifest2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[ lib ]\npath = \"a#b/lib.rs\"\n",
        )
        .expect("manifest");
        assert_eq!(manifest_custom_roots(&dir).0, vec![dir.join("a#b/lib.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_accepts_quoted_keys() {
        // H-1 r15: TOML keys may be quoted (`"path" = …`) — Cargo accepts
        // them, so the discovery must too or the root goes unscanned.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-qkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\n\"path\" = \"custom/q.rs\"\n\n[[bin]]\nname = \"tool\"\n'path' = 'custom-bin/main.rs'\n",
        )
        .expect("manifest");
        let (mut roots, problem) = manifest_custom_roots(&dir);
        roots.sort();
        assert_eq!(problem, None);
        assert_eq!(
            roots,
            vec![dir.join("custom/q.rs"), dir.join("custom-bin/main.rs")]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_keeps_escaped_quotes() {
        // L-3 r15: `\"` inside a quoted value is content, not the closer —
        // and a `#` after an escaped quote is content, not a comment.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-qesc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"a\\\"#b.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        // M-2 r17: basic-string escapes decode — the compiled path is
        // `a"#b.rs`, not the raw `a\"#b.rs`.
        assert_eq!(roots, vec![dir.join("a\"#b.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_rejects_invalid_escapes() {
        // M-2 r17: `\q` is not a TOML escape — the manifest is invalid
        // (Cargo rejects it), so the root is unknown: fail closed with a
        // problem, never silently skip or join the raw text.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-badesc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"a\\qb.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(roots.is_empty());
        assert!(problem.is_some(), "invalid escape surfaced no problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_reads_spanning_triple_values() {
        // M-2 r17: a `"""…"""` value may span lines — accumulate until
        // the triple closer instead of dropping the root. (TOML trims one
        // leading newline; other newlines are content.)
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-span-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"\"\"custom/sp\nan.rs\"\"\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("custom/sp\nan.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_parses_package_build() {
        // C-1 r19: `[package] build = "custom/b.txt"` compiles as the
        // crate's build script — a custom path there must be discovered
        // like any other root, or its `unsafe` sails through GREEN.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-build-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nbuild = \"custom/b.txt\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(
            roots,
            vec![dir.join("custom/b.txt"), dir.join("src/lib.rs")]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_ignores_bool_build() {
        // `build = false` disables the build script — no string, no root,
        // and crucially no problem entry (it is valid TOML, unlike an
        // unclosed string).
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-nobuild-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nbuild = false\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("src/lib.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_ignores_dotted_lib_path() {
        // H-2 r21: dotted `lib.path` never compiles as the lib target
        // (verified against cargo: top-level becomes a dependency spec,
        // in-section is ignored) — dependencies are not crate roots, so
        // skip silently. (An earlier revision parsed in-`[package]`
        // dotted forms as roots; the probes proved those files never
        // compile, so parsing them risked false-flagging dead code.)
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-dotted-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nlib.path = \"custom/d.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert!(roots.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_ignores_dead_dotted_root() {
        // H-2 r21 run-level pin: a dotted-named NON-`.rs` file is dead
        // code — the walk never collects it, and dotted keys never name
        // roots (verified against cargo), so flagging it would be a
        // false positive on a building tree. (An in-tree `.rs` file is
        // still scanned by the walk, dotted key or not — that is the
        // walk-everything policy, not manifest discovery.)
        let root = std::env::temp_dir().join(format!("qqq-xtask-xdotdead-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("src")).expect("temp crate");
        std::fs::create_dir_all(dir.join("custom")).expect("custom dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nlib.path = \"custom/d.txt\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .expect("manifest");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        std::fs::write(
            dir.join("custom").join("d.txt"),
            "pub unsafe fn evil() {}\n",
        )
        .expect("dead file");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(ok, "dead dotted file failed the scan:\n{out}");
    }

    #[test]
    fn manifest_custom_roots_ignores_inline_lib_table() {
        // H-1 r21: `lib = { path = "e.rs" }` never compiles as the lib
        // target (verified against cargo: silently ignored). Skip
        // silently — failing here would false-positive on building trees.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-inline-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nlib = { path = \"e.rs\" }\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(roots.is_empty());
        assert_eq!(problem, None, "ignored inline table surfaced a problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_ignores_non_target_dotted_keys() {
        // H-1 r20 pin: dotted keys outside target tables (workspace
        // inheritance like `version.workspace`) are not roots and not
        // problems — dependencies are not crate roots.
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-dotother-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nversion.workspace = true\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("src/lib.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_rejects_duplicate_section() {
        // M-2 r23: duplicate `[lib]` tables are invalid TOML (Cargo
        // rejects them) — fail closed with a problem instead of silently
        // merging their `path` keys. (`[[bin]]` repeats legitimately and
        // is exempt.)
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-dupsec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n[lib]\npath = \"a.rs\"\n[lib]\npath = \"b.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(roots, vec![dir.join("a.rs")]);
        assert!(problem.is_some(), "duplicate section surfaced no problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_rejects_duplicate_build() {
        // M-2 r21: duplicate `build` keys are invalid TOML — fail closed
        // with a problem; first occurrence wins, the second adds nothing.
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-dupbuild-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nbuild = false\nbuild = \"custom/b.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(roots.is_empty());
        assert!(problem.is_some(), "duplicate build surfaced no problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_ignores_comment_after_triple_closer() {
        // M-3 r21: a `#` comment after the triple closer on a
        // continuation line is a real comment — the single-line path
        // strips it, the multiline path must too instead of TrailingJunk.
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-tricomment-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"\"\"custom/a\nb.rs\"\"\" # the root\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("custom/a\nb.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_rejects_eof_after_equals() {
        // L-1 r21: `path =` with no value through EOF names an unknown
        // root — fail closed, never silently return to conventional roots.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-eofeq-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath =",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(roots.is_empty());
        assert!(problem.is_some(), "EOF after `=` surfaced no problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_does_not_swallow_header_as_value() {
        // M-1 r21: `path =` followed by a header line must not consume
        // the header as its value — a `[`-led line is never a value, so
        // report unclosed without advancing past it (the next `path`
        // still resolves in its own section: aux, not lib_bin).
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-noswallow-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath =\n[[test]]\nname = \"t\"\npath = \"custom/t.rs\"\n",
        )
        .expect("manifest");
        let roots = manifest_roots(&dir);
        assert!(
            roots.problem.is_some(),
            "swallowed header surfaced no problem"
        );
        assert!(roots.lib_bin.is_empty(), "header swallowed into lib");
        assert_eq!(roots.aux, vec![dir.join("custom/t.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_rejects_int_build() {
        // M-1 r20: `build = 5` is invalid Cargo (not a string, not a
        // bool) — fail closed, unlike the silent `false`.
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-intbuild-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nbuild = 5\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(roots, vec![dir.join("src/lib.rs")]);
        assert!(problem.is_some(), "non-string build surfaced no problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_rejects_empty_path() {
        // M-2 r20: `path = ""` is invalid Cargo — an empty root is
        // unknown, so fail closed instead of skipping silently.
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-emptypath-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(roots.is_empty());
        assert!(problem.is_some(), "empty path surfaced no problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_rejects_trailing_junk() {
        // L-4 r20: `path = "a.rs" "b"` is invalid TOML — taking the first
        // value and ignoring the rest would certify a guess.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-junk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"a.rs\" \"b\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(roots.is_empty());
        assert!(problem.is_some(), "trailing junk surfaced no problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_resets_on_malformed_header() {
        // L-3 r20 + M-2 r23: `[lib] garbage` is not a header — invalid TOML,
        // so the section resets (the next `path` is not misattributed) AND
        // a junk bracket line fails closed with a problem.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-badhdr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n[lib]\npath = \"a.rs\"\n[lib] garbage\npath = \"q.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(problem.is_some(), "malformed header surfaced no problem");
        assert_eq!(
            roots,
            vec![dir.join("a.rs")],
            "malformed header leaked section: {roots:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_ignores_junk_line_before_value() {
        // M-1 r23 gate: a non-quote line after `path =` is not the value —
        // report unclosed without consuming it, so the following lines
        // still parse in their own section. (A `[`-led line is the
        // header-swallowing case; here a stray key line must behave the
        // same: no consumption, still fail closed.)
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-junkline-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath =\nname = \"oops\"\npath = \"q.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(problem.is_some(), "junk line swallowed silently");
        assert_eq!(roots, vec![dir.join("q.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_accepts_spaced_bracket_headers() {
        // L-3 r23 pins: valid spacing/bracket shapes keep working under
        // strict validation — `[ [bin]]`, `[[ "lib" ]]`, and an empty
        // quoted name (unknown section, skipped silently).
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-spaced-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n[ [bin]]\nname = \"tool\"\npath = \"custom/t.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("custom/t.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n[[ \"lib\" ]]\npath = \"custom/u.rs\"\n",
        )
        .expect("manifest");
        let (mut roots, problem) = manifest_custom_roots(&dir);
        roots.sort();
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("custom/u.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n[\"\"]\npath = \"custom/v.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert!(roots.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_reads_next_line_value() {
        // L-2 r20: `path =` with the value on the next line is valid TOML
        // (blank/comment lines allowed around `=`) — read it instead of
        // fail-closing a valid manifest.
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-nextline-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath =\n# a comment line\n\"nl.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("nl.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_parses_quoted_single_triple_build() {
        // L-5 r20 gap pins: quoted keys, literals, triples and escapes
        // work for `build` exactly like `path`.
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-buildforms-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\"build\" = 'custom/sq.rs'\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("custom/sq.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nbuild = \"\"\"custom/tq.rs\"\"\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("custom/tq.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nbuild = \"a\\\"b.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("a\"b.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nbuild = \"a\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(roots.is_empty());
        assert!(problem.is_some(), "unclosed build surfaced no problem");
        assert!(
            problem.is_some_and(|p| p.contains("build")),
            "problem names the wrong key"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_rejects_header_with_junk_and_key() {
        // H-3 r22: `[lib] path = "q.rs"` is invalid TOML shaped like a
        // root — fail closed with a problem instead of inheriting or
        // dropping the section silently.
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-hdrjunk-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n[lib] path = \"q.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(roots.is_empty());
        assert!(problem.is_some(), "junk header surfaced no problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_rejects_duplicate_path() {
        // M-1 r22: duplicate `path` keys are invalid TOML — first wins,
        // the second is dropped, and a problem is recorded (same
        // contract as duplicate `build`).
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-duppath-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"a.rs\"\npath = \"b.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(roots, vec![dir.join("a.rs")]);
        assert!(problem.is_some(), "duplicate path surfaced no problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_rejects_bracket_mismatch_header() {
        // `[[[lib]]]` is not a header — strict validation rejects the
        // extra brackets (M-2 r22) and any `[`-led junk line fails closed
        // (M-1 r23: no valid manifest has one).
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-badbracket-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n[[[lib]]]\npath = \"q.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(roots.is_empty());
        assert!(problem.is_some(), "mismatched brackets surfaced no problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_rejects_unclosed_value() {
        // M-1 r19: `path = "a.rs` (truncated, no closer) names an unknown
        // root — fail closed with a problem, never silently skip (same
        // contract as invalid escapes).
        let dir = std::env::temp_dir().join(format!(
            "qqq-xtask-xmanifest-unclosed-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"a.rs\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(roots.is_empty());
        assert!(problem.is_some(), "unclosed value surfaced no problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fold_dot_components_keeps_leading_parent_dirs() {
        // L-1 r19: a leading `..` that `pop()` cannot fold is content, not
        // nothing — dropping it re-roots the path inside (`../../b` is
        // outside, `b` is not). Absolute callers are unaffected (their
        // prefix is never empty).
        assert_eq!(
            fold_dot_components(std::path::Path::new("../../b")),
            std::path::PathBuf::from("../../b")
        );
        assert_eq!(
            fold_dot_components(std::path::Path::new("sub/../lib.rs")),
            std::path::PathBuf::from("lib.rs")
        );
    }

    #[test]
    fn manifest_custom_roots_trims_continuation_backslash() {
        // M-3 r18: a TOML line-ending backslash trims the break plus all
        // whitespace around it (cargo resolves `"""l\` + newline +
        // `  .rs"""` to `l.rs`) — decoding must agree instead of
        // fail-closing a valid manifest.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-cont-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"\"\"custom/l\\\n  .rs\"\"\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("custom/l.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_rejects_underscore_escapes() {
        // M-3 r18: `\u` takes exactly four hex digits — TOML has no `_`
        // separators (cargo rejects `\u12_4b` as "too few digits"), so it
        // fails closed like every other invalid escape.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-uesc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"a\\u12_4b.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(roots.is_empty());
        assert!(problem.is_some(), "underscore escape surfaced no problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_normalizes_dot_spellings() {
        // L-1 r15: `path = "sub/../lib.rs"` names the same file the walk
        // finds as `lib.rs` — normalize so it dedups instead of
        // double-scanning. (`./` spellings already compare equal through
        // component equality; `..` ones do not.)
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-dot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"sub/../lib.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("lib.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_reports_unreadable_manifest() {
        // L-4 r15: a present-but-unreadable manifest must surface as a
        // problem, not silently yield no roots. A directory in place of
        // the file fails every read on all platforms.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-unread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Cargo.toml")).expect("temp dir");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert!(roots.is_empty());
        assert!(problem.is_some(), "unreadable manifest surfaced no problem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_accepts_quoted_headers() {
        // H-1 r16: TOML table headers may quote the name (`["lib"]`) —
        // Cargo accepts them, so the section match must unquote too.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-qhdr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[\"lib\"]\npath = \"custom/q.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("custom/q.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_ignores_bom() {
        // H-2 r16: a UTF-8 BOM prefixes the first line — a section header
        // there must still match (editors add BOMs silently).
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-bom-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "\u{FEFF}\u{FEFF}[lib]\npath = \"custom/q.rs\"\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("custom/q.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_backslash_is_content_in_literals() {
        // M-4 r16: TOML `'...'` literals have no escapes — a `\` before
        // the quote is content, and the quote still closes the value.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-lit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = 'weird\\'\n",
        )
        .expect("manifest");
        let (roots, problem) = manifest_custom_roots(&dir);
        assert_eq!(problem, None);
        assert_eq!(roots, vec![dir.join("weird\\")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_custom_roots_accepts_triple_quoted_values() {
        // L-2 r16: TOML multiline strings (`"""…"""`, `'''…'''`) are valid
        // values — the closer is the triple mark, not the first quote.
        let dir =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifest-tri-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"\"\"custom/t.rs\"\"\"\n\n[[bin]]\nname = \"tool\"\npath = '''custom-bin/u.rs'''\n",
        )
        .expect("manifest");
        let (mut roots, problem) = manifest_custom_roots(&dir);
        roots.sort();
        assert_eq!(problem, None);
        assert_eq!(
            roots,
            vec![dir.join("custom/t.rs"), dir.join("custom-bin/u.rs")]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsafe_scan_requires_custom_manifest_root_forbid() {
        // M-1 r13 run level: a custom [lib] path without the attribute
        // fails loudly like a conventional root.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xmanifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("custom")).expect("temp crate");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"custom/lib2.rs\"\n",
        )
        .expect("manifest");
        std::fs::write(dir.join("custom").join("lib2.rs"), "pub fn f() {}\n").expect("lib");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "unforbidden custom root passed the scan:\n{out}");
        assert!(
            out.contains("missing forbid"),
            "wrong failure shape:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_scans_manifest_custom_root_body() {
        // H-1 r14: a custom `path = "custom/lib.txt"` compiles regardless
        // of location or extension — its body must be scanned, not just
        // its forbid checked.
        let root =
            std::env::temp_dir().join(format!("qqq-xtask-xmanifestb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("custom")).expect("temp crate");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"custom/lib.txt\"\n",
        )
        .expect("manifest");
        std::fs::write(
            dir.join("custom").join("lib.txt"),
            "#![forbid(unsafe_code)]\npub unsafe fn evil() {}\n",
        )
        .expect("lib");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "unsafe custom manifest root passed the scan:\n{out}");
        assert!(out.contains("lib.txt"), "wrong failure shape:\n{out}");
    }

    #[test]
    fn unsafe_scan_skips_outside_manifest_root_without_reading() {
        // M-1 r15: a manifest root outside the workspace is refused by the
        // scan loop — the roots check must skip it too instead of reading
        // an arbitrary file (its content would add misleading evidence
        // next to the real outside-workspace violation).
        let pid = std::process::id();
        let root = std::env::temp_dir().join(format!("qqq-xtask-xmanifest-out-{pid}"));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(&dir).expect("temp crate");
        let outside = std::env::temp_dir().join(format!("qqq-xtask-xmanifest-outside-{pid}.rs"));
        let _ = std::fs::remove_file(&outside);
        std::fs::write(&outside, "pub unsafe fn evil() {}\n").expect("outside file");
        std::fs::write(
            dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"probe\"\n\n[lib]\npath = \"../../../qqq-xtask-xmanifest-outside-{pid}.rs\"\n"
            ),
        )
        .expect("manifest");
        std::fs::create_dir_all(dir.join("src")).expect("src dir");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&outside);
        assert!(!ok, "outside manifest root passed the scan:\n{out}");
        assert!(
            out.contains("outside the workspace"),
            "wrong failure shape:\n{out}"
        );
        assert!(
            !out.contains("missing forbid"),
            "ungated read of outside root leaked into evidence:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_flags_escaping_nonexistent_manifest_root() {
        // M-2 r15: an escaping manifest path that names no file must be
        // flagged outside, not silently dropped by an unnormalized
        // lexical gate.
        let pid = std::process::id();
        let root = std::env::temp_dir().join(format!("qqq-xtask-xmanifest-esc-{pid}"));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("src")).expect("temp crate");
        std::fs::write(
            dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"probe\"\n\n[lib]\npath = \"../../../../xmanifest-esc-{pid}.rs\"\n"
            ),
        )
        .expect("manifest");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "escaping manifest root passed the scan:\n{out}");
        assert!(
            out.contains("outside the workspace"),
            "wrong failure shape:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_no_double_scan_on_dotdot_spelling() {
        // L-1 r15 run level: a `sub/../lib.rs` manifest spelling names
        // the walked `lib.rs` — it must merge, not report twice.
        let pid = std::process::id();
        let root = std::env::temp_dir().join(format!("qqq-xtask-xmanifest-dup-{pid}"));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("sub")).expect("temp crate");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lib]\npath = \"sub/../lib.rs\"\n",
        )
        .expect("manifest");
        std::fs::write(
            dir.join("lib.rs"),
            "#![forbid(unsafe_code)]\npub unsafe fn evil() {}\n",
        )
        .expect("lib");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "unsafe lib passed the scan:\n{out}");
        let hits = out.lines().filter(|l| l.contains("lib.rs")).count();
        assert_eq!(hits, 1, "same file reported twice:\n{out}");
    }

    #[test]
    fn unsafe_scan_symlinked_crates_dir_is_loud() {
        // H-3 r16: a symlinked `crates/` dir would silently re-root the
        // whole scan — entries resolve outside while rel paths claim the
        // workspace. Fail closed. Skipped where the platform denies
        // symlink creation (fires on CI).
        let outside =
            std::env::temp_dir().join(format!("qqq-xtask-xcratesout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(outside.join("probe").join("src")).expect("outside dir");
        std::fs::write(
            outside.join("probe").join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("outside lib");
        let root =
            std::env::temp_dir().join(format!("qqq-xtask-xcrateslink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        #[cfg(unix)]
        let link_ok = std::os::unix::fs::symlink(&outside, root.join("crates")).is_ok();
        #[cfg(windows)]
        let link_ok = std::os::windows::fs::symlink_dir(&outside, root.join("crates")).is_ok();
        #[cfg(not(any(unix, windows)))]
        let link_ok = false;
        if !link_ok {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            eprintln!("SKIP: cannot create symlinks here");
            return;
        }
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        assert!(!ok, "symlinked crates dir passed the scan:\n{out}");
        assert!(
            out.contains("symlinked crates dir"),
            "wrong failure shape:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_dangling_manifest_link_is_loud() {
        // M-1 r16: a dangling `Cargo.toml` symlink is present-but-unreadable
        // (`exists()` follows links, so it reports absent). The manifest
        // roots are unknown — fail loudly. Skipped where the platform
        // denies symlink creation (fires on CI).
        let pid = std::process::id();
        let root = std::env::temp_dir().join(format!("qqq-xtask-xmanifest-dangle-{pid}"));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("crates").join("probe");
        std::fs::create_dir_all(dir.join("src")).expect("temp crate");
        std::fs::write(
            dir.join("src").join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        let missing = std::env::temp_dir().join(format!("qqq-xtask-xmanifest-notthere-{pid}.toml"));
        let _ = std::fs::remove_file(&missing);
        #[cfg(unix)]
        let link_ok = std::os::unix::fs::symlink(&missing, dir.join("Cargo.toml")).is_ok();
        #[cfg(windows)]
        let link_ok = std::os::windows::fs::symlink_file(&missing, dir.join("Cargo.toml")).is_ok();
        #[cfg(not(any(unix, windows)))]
        let link_ok = false;
        if !link_ok {
            let _ = std::fs::remove_dir_all(&root);
            eprintln!("SKIP: cannot create symlinks here");
            return;
        }
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "dangling manifest passed the scan:\n{out}");
        assert!(
            out.contains("manifest problem"),
            "wrong failure shape:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_symlinked_src_bin_dir_is_loud() {
        // M-3 r16: a symlinked `src/bin` would re-root every bin entry
        // outside while `root_ok` reads them as crate roots. Fail closed
        // before collecting. Skipped where the platform denies symlink
        // creation (fires on CI).
        let pid = std::process::id();
        let target = std::env::temp_dir().join(format!("qqq-xtask-xsrcbinout-{pid}"));
        let _ = std::fs::remove_dir_all(&target);
        std::fs::create_dir_all(&target).expect("outside dir");
        std::fs::write(target.join("tool.rs"), "fn main() {}\n").expect("outside bin");
        let root = std::env::temp_dir().join(format!("qqq-xtask-xsrcbinlink-{pid}"));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates").join("probe").join("src");
        std::fs::create_dir_all(&src).expect("temp crate");
        std::fs::write(
            src.join("lib.rs"),
            "#![forbid(unsafe_code)]\npub fn f() {}\n",
        )
        .expect("lib");
        #[cfg(unix)]
        let link_ok = std::os::unix::fs::symlink(&target, src.join("bin")).is_ok();
        #[cfg(windows)]
        let link_ok = std::os::windows::fs::symlink_dir(&target, src.join("bin")).is_ok();
        #[cfg(not(any(unix, windows)))]
        let link_ok = false;
        if !link_ok {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&target);
            eprintln!("SKIP: cannot create symlinks here");
            return;
        }
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&target);
        assert!(!ok, "symlinked src/bin passed the scan:\n{out}");
        assert!(
            out.contains("symlinked bin dir"),
            "wrong failure shape:\n{out}"
        );
        assert!(
            !out.contains("missing forbid"),
            "outside content read as a root:\n{out}"
        );
    }

    #[test]
    fn unsafe_scan_symlink_inside_qqq_sys_is_scanned() {
        // H-2 r12: a symlinked path inside qqq-sys does not inherit the
        // exception — the target lives outside the audited crate (here in
        // a sibling crate dir inside the workspace, so the outside-workspace
        // gate does not interfere), so its content must be scanned, not
        // skipped. The target is a non-.rs file so only the `#[path]`
        // redirection — not the normal walk — can discover it.
        let root = std::env::temp_dir().join(format!("qqq-xtask-xqlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let victim = root.join("crates").join("victim");
        std::fs::create_dir_all(&victim).expect("victim dir");
        std::fs::write(victim.join("evil.txt"), "pub unsafe fn evil() {}\n").expect("evil");
        let qsys = root.join("crates").join("qqq-sys").join("src");
        std::fs::create_dir_all(&qsys).expect("temp crate");
        #[cfg(unix)]
        let link_ok = std::os::unix::fs::symlink(&victim, qsys.join("link")).is_ok();
        #[cfg(windows)]
        let link_ok = std::os::windows::fs::symlink_dir(&victim, qsys.join("link")).is_ok();
        #[cfg(not(any(unix, windows)))]
        let link_ok = false;
        if !link_ok {
            let _ = std::fs::remove_dir_all(&root);
            eprintln!("SKIP: cannot create symlinks here");
            return;
        }
        std::fs::write(
            qsys.join("lib.rs"),
            "#![forbid(unsafe_code)]\n#[path = \"link/evil.txt\"]\nmod evil;\n",
        )
        .expect("lib");
        let (ok, out) = run_unsafe_scan(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!ok, "symlinked qqq-sys content passed the scan:\n{out}");
        assert!(
            out.contains("evil"),
            "wrong failure shape (expected the outside file flagged):\n{out}"
        );
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
        // So is a block comment there (LOW r4): token stream, not text.
        let mut b = 0;
        assert!(line_has_forbid_attr("#![forbid/*c*/(unsafe_code)]", &mut b));
        // L-5 r7: every Unicode whitespace separates — VT indent, NBSP in
        // the list, VT before a block comment — exactly like spaces do.
        let mut b = 0;
        assert!(line_has_forbid_attr("#![forbid\x0B(unsafe_code)]", &mut b));
        let mut b = 0;
        assert!(line_has_forbid_attr(
            "#![forbid(\u{a0}unsafe_code)]",
            &mut b
        ));
        let mut b = 0;
        assert!(line_has_forbid_attr(
            "#![forbid\x0B/*c*/(unsafe_code)]",
            &mut b
        ));
        // L2 r5: comments inside the list do not hide the lint — nor does
        // a paren inside a comment end the list early.
        let mut b = 0;
        assert!(line_has_forbid_attr("#![forbid(/*c*/unsafe_code)]", &mut b));
        let mut b = 0;
        assert!(line_has_forbid_attr(
            "#![forbid(/* ) */, unsafe_code)]",
            &mut b
        ));
        // M-4 r23: a `)` inside a string or char cannot close the list —
        // strings never occur in a valid lint list, but the scan must not
        // let one truncate the match (invalid Rust either way, and the
        // dangerous direction is a miss).
        let mut b = 0;
        assert!(line_has_forbid_attr(
            "#![forbid(note = \")\", unsafe_code)]",
            &mut b
        ));
        let mut b = 0;
        assert!(line_has_forbid_attr("#![forbid(')', unsafe_code)]", &mut b));
        // Raw strings need their `#` count for the closer: content may
        // hold a bare `"`, which must not end the match early.
        let mut b = 0;
        assert!(line_has_forbid_attr(
            "#![forbid(r#\")\"#, unsafe_code)]",
            &mut b
        ));
        let mut b = 0;
        assert!(line_has_forbid_attr(
            "#![forbid(br#\")\"#, unsafe_code)]",
            &mut b
        ));
    }

    #[test]
    fn code_redirections_ignores_non_string_literal_includes() {
        // M-3 r23: `include!(c"…")` / `include!(b"…")` (and raw forms)
        // are compile errors ("argument must be a string literal",
        // verified against rustc) — rustc owns them, so they stay
        // silent instead of tripping the dynamic-include fail-closed.
        // Genuinely dynamic arguments (concat!, env!, idents) still do.
        assert_eq!(
            code_redirections("include!(c\"e.rs\");\n"),
            (Vec::<String>::new(), false)
        );
        assert_eq!(
            code_redirections("include!(b\"e.rs\");\n"),
            (Vec::<String>::new(), false)
        );
        assert_eq!(
            code_redirections("include!(br#\"e.rs\"#);\n"),
            (Vec::<String>::new(), false)
        );
        assert_eq!(
            code_redirections("include!('e');\n"),
            (Vec::<String>::new(), false)
        );
        assert_eq!(
            code_redirections("include!(concat!(env!(\"OUT_DIR\"), \"/g.rs\"));\n"),
            (Vec::<String>::new(), true)
        );
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
        // LOW r4: indented prose starting with a command word must not
        // count either — the token needs a column separator after it (two
        // spaces, as clap pads entries), not prose spacing. Drop the real
        // entry so only the prose could satisfy it.
        let no_doctor = help.replace("    doctor  do doctor\n", "");
        assert!(help_check(&(no_doctor + "    doctor is great\n")).is_err());
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
