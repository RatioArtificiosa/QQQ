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
//! `--report` form, which only read. Everything that can write goes
//! sequentially in listed order: every `--self-test` (temporary fixtures,
//! fault injections, builds), every cargo invocation, the orders-api
//! workspace, the release probe, and the two ported shell checks. A
//! parallelised fault-injection self-test could interleave with another
//! check's restore and flake; the sequential lane keeps today's exact
//! behaviour for exactly those steps.
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
        "check_coderabbit_config",
        &["tools/check_coderabbit_config.py"],
    ),
    Step::py(
        Lane::Par,
        "check_conformance",
        &["tools/check_conformance.py"],
    ),
    Step::py(
        Lane::Par,
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
        Lane::Par,
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
        "check_no_poison_expect",
        &["tools/check_no_poison_expect.py"],
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
        &["tools/check_api_examples.py", "--allow", "2115"],
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
        "check_no_poison_expect",
        &["tools/check_no_poison_expect.py", "--self-test"],
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

fn run_cmd(program: &str, args: &[String], dir: Option<&Path>, workspace: &Path) -> (bool, String) {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.current_dir(dir.map_or_else(|| workspace.to_path_buf(), |d| workspace.join(d)));
    scrub_cargo_run_env(&mut cmd);
    match cmd.output() {
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), text)
        }
        Err(e) => (false, format!("failed to spawn {program}: {e}")),
    }
}

fn run_step(step: &Step, workspace: &Path, python: &[String]) -> Outcome {
    let start = Instant::now();
    if step.lane == Lane::Seq {
        // Name the step up front: a hung step never reaches its completion
        // line, so without this the log goes silent instead of identifying
        // the in-flight step. Parallel steps stay completion-only -- their
        // start lines would interleave across threads and name nothing
        // reliably. (`println!` line-flushes, so this is visible pre-hang
        // even when stdout is piped.)
        println!("run  {}", step.name);
    }
    let (ok, output) = match &step.kind {
        StepKind::Cmd { program, args, dir } => {
            let argv: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
            let dir = dir.map(Path::new);
            run_cmd(program, &argv, dir, workspace)
        }
        StepKind::Py { args } => {
            let mut argv: Vec<String> = python.to_vec();
            argv.extend(args.iter().map(|s| (*s).to_owned()));
            match argv.split_first() {
                Some((head, tail)) => run_cmd(head, tail, None, workspace),
                None => (false, "empty argv for a python step".to_owned()),
            }
        }
        StepKind::UnsafeScan => run_unsafe_scan(workspace),
        StepKind::HelpBrevity => run_help_brevity(workspace),
    };
    let outcome = Outcome {
        name: step.name.to_owned(),
        ok,
        secs: start.elapsed().as_secs(),
    };
    if ok {
        println!("ok   {:<22} ({}s)", outcome.name, outcome.secs);
    } else {
        println!("FAIL {:<22} ({}s)", outcome.name, outcome.secs);
        println!("{output}");
    }
    outcome
}

// ---------------------------------------------------------------------------
// Ported checks (no portable shell): same rule, same output contract.
// ---------------------------------------------------------------------------

/// A line violates iff `unsafe` opens a code position outside the exception
/// crate and the recognised allowances. Faithful port of the CI grep:
/// `\bunsafe[[:space:]]*(\{|fn\b|impl\b|extern\b|trait\b)` minus the
/// `crates/qqq-sys/`, `forbid(unsafe_code)` and `cfg_attr` exclusions.
fn unsafe_line_is_violation(line: &str) -> bool {
    // String literals are skipped: a real `unsafe` block can never hide in
    // string data, so matching there is pure false-positive surface. (The CI
    // grep this ports cannot tell strings from code; this is intentionally
    // more precise.) Comments still match — conservatively, and because a
    // commented-out block is one uncomment away from live.
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
    // shapes. Precision here must never be mistaken for completeness.
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    let mut in_char = false;
    let mut in_raw: Option<usize> = None;
    while let Some(&b) = bytes.get(i) {
        if let Some(n) = in_raw {
            // Inside a raw string: no escapes, exact-count close only.
            if b == b'"' {
                let mut k = 0;
                while bytes.get(i + 1 + k) == Some(&b'#') {
                    k += 1;
                }
                if k == n {
                    in_raw = None;
                    i += 1 + k;
                    continue;
                }
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
            if let Some(n) = raw_opener(line, i) {
                in_raw = Some(n);
            } else {
                in_string = true;
            }
            i += 1;
            continue;
        }
        if b == b'\'' {
            let rest = line.get(i + 1..).unwrap_or("");
            if rest.chars().take(3).collect::<String>().contains('\'') {
                in_char = true;
            }
            i += 1;
            continue;
        }
        if b == b'u'
            && line.get(i..).is_some_and(|t| t.starts_with("unsafe"))
            && (i == 0 || bytes.get(i - 1).is_none_or(|p| !is_ident(*p)))
        {
            let mut j = i + "unsafe".len();
            while bytes.get(j).is_some_and(|x| *x == b' ' || *x == b'\t') {
                j += 1;
            }
            let rest = line.get(j..).unwrap_or("");
            let hit = rest.starts_with('{')
                || starts_word(rest, "fn")
                || starts_word(rest, "impl")
                || starts_word(rest, "extern")
                || starts_word(rest, "trait");
            if hit {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
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
    if start > 0 && bytes.get(start - 1).is_some_and(|b| is_ident(*b)) {
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
        // First code character: it must open the attribute.
        return line.get(i..).is_some_and(|t| {
            t.starts_with("#![forbid(unsafe_code)]") || t.starts_with("#![ forbid(unsafe_code)]")
        });
    }
    false
}

fn starts_word(s: &str, word: &str) -> bool {
    s.starts_with(word)
        && s[word.len()..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric() && c != '_')
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
    for e in rd.flatten() {
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
        let mut files = Vec::new();
        collect_rs(dir, &mut files);
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
            files_scanned += 1;
            if rel.starts_with("crates/qqq-sys/") {
                continue;
            }
            for (n, line) in text.lines().enumerate() {
                if line.contains("forbid(unsafe_code)") || line.contains("cfg_attr") {
                    continue;
                }
                if unsafe_line_is_violation(line) {
                    violations.push(format!("{rel}:{}:{line}", n + 1));
                }
            }
        }
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

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                collect_rs(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                out.push(p);
            }
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
fn target_debug_dir(workspace: &Path) -> PathBuf {
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir).join("debug");
    }
    if let Ok(o) = Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .current_dir(workspace)
        .output()
        && let Some(d) = parse_target_dir(&o.stdout)
    {
        return d.join("debug");
    }
    workspace.join("target").join("debug")
}

/// The `target_directory` value from `cargo metadata` JSON, without serde
/// (this crate has no dependencies by design): scan for the key and decode
/// the quoted string, escapes included. Anything malformed yields `None`
/// and the caller falls back to the default directory.
fn parse_target_dir(json: &[u8]) -> Option<PathBuf> {
    const KEY: &[u8] = b"\"target_directory\":\"";
    let start = json.windows(KEY.len()).position(|w| w == KEY)? + KEY.len();
    let mut out: Vec<u8> = Vec::new();
    let mut bytes = json.get(start..)?.iter();
    loop {
        let b = *bytes.next()?;
        if b == b'"' {
            break;
        }
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match bytes.next()? {
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'r' => out.push(b'\r'),
            b'\\' => out.push(b'\\'),
            b'"' => out.push(b'"'),
            b'/' => out.push(b'/'),
            _ => return None,
        }
    }
    if out.is_empty() {
        return None;
    }
    std::str::from_utf8(&out).ok().map(PathBuf::from)
}

/// The `--help` brevity standard (`DX-013`): at most 40 lines, all 16
/// commands present with their leading spaces, and the loop proven to run.
/// Counts from the process output like the CI pipe does — never held in a
/// shell variable, which is the vacuity the CI comments warn about.
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
        let needle = format!("    {cmd} ");
        if text.lines().any(|l| l.starts_with(&needle)) {
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
    // be resolved.
    let canon = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    list.lines().any(|l| {
        l.strip_prefix("worktree ").is_some_and(|p| {
            std::fs::canonicalize(p.trim()).is_ok_and(|c| c == canon) || Path::new(p.trim()) == dir
        })
    })
}

/// Apply one injection on a detached worktree of HEAD, run its checker
/// there, and remove the worktree on every path out. Returns the
/// checker's verdict: detected (pass) or missed (fail).
fn fault_inject(workspace: &Path, python: &[String], name: &str) -> Result<bool, String> {
    let inj = INJECTIONS.iter().find(|i| i.name == name).ok_or_else(|| {
        format!("unknown injection {name:?}; see `cargo xtask fault-inject --list`")
    })?;
    let dir = worktree_dir(name);
    if dir.exists() {
        return Err(format!(
            "stale worktree dir {} exists; remove it first",
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
    git(
        workspace,
        &[
            "worktree",
            "add",
            "--detach",
            dir.to_string_lossy().as_ref(),
            "HEAD",
        ],
    )?;
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
        let (ok, output) = match argv.split_first() {
            Some((head, tail)) => run_cmd(head, tail, None, &dir),
            None => (false, "empty argv for the checker".to_owned()),
        };
        Ok(!ok && output.contains(inj.expect))
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
        Ok(_) => detected,
        Err(e) => Err(format!("cannot verify worktree removal: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Subcommands.
// ---------------------------------------------------------------------------

fn cmd_list() -> ExitCode {
    // Machine-readable coverage manifest for `check_gate_parity.py`: the
    // python invocations this gate runs, one normalized `tools/...` line
    // each, exactly as the parity checker normalises both gates.
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
            .map(|step| s.spawn(|| run_step(step, workspace, python)))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or_else(|_| Outcome {
                    name: "<panicked step>".to_owned(),
                    ok: false,
                    secs: 0,
                })
            })
            .collect()
    });
    let mut outcomes = par_outcomes;
    for step in seq {
        outcomes.push(run_step(step, workspace, python));
    }
    println!("---- summary ----");
    for o in &outcomes {
        println!(
            "{:<24} {} ({}s)",
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
