//! `qqqai test` — the built-in test runner.
//!
//! Implements `CLI-012`; Proposal §6.7.
//!
//! # The distinction this module is built around
//!
//! §6.7 separates two kinds of feature, and the separation is the whole design:
//!
//! * **Standard features** — discovery, filtering, parallel execution,
//!   JUnit/TAP/JSON output. A test runner must have these to be usable, and
//!   having them makes it comparable to every other runner.
//! * **Architecture-enabled features** — `--trials N` determinism checking,
//!   capability assertions, fuel assertions. These are possible *only* because
//!   the runtime mediates time, randomness, scheduling and metering. They are
//!   the reason a QQQ test runner is not redundant.
//!
//! So this module implements the standard half properly — because a runner that
//! cannot filter or report is not adopted — and implements `--trials` as the
//! first of the architecture-enabled half, because it is the one that works
//! today without instrumentation.
//!
//! # Why `--trials` is the right one to build first
//!
//! A determinism check needs only what `qqq-host` already provides: a fixed
//! clock, a seeded RNG, and fuel metering. It does **not** need DWARF source
//! mapping (coverage), Wasm instrumentation, or the registry. It is therefore
//! the highest-value architecture-enabled feature per unit of unbuilt
//! dependency, and it is the one whose absence would be most visible: a
//! framework claiming bit-identical replay that cannot demonstrate it in its
//! own test runner has an unverified headline claim.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use qqq_core::{Error, ErrorCode, Result};

/// What `qqqai test` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TestOptions {
    /// Run only tests whose name contains this substring.
    pub filter: Option<String>,
    /// Stop after the first failure.
    pub fail_fast: bool,
    /// Run every test N times and compare the outputs.
    ///
    /// `None` means run once. `Some(1)` is equivalent to once and is accepted
    /// rather than rejected — a caller generating the flag from a template
    /// should not have to special-case `1`.
    pub trials: Option<u32>,
    /// Print the commands that would run, without running them.
    pub dry_run: bool,
    /// Emit machine-readable output.
    pub json: bool,
}

impl TestOptions {
    /// How many times each test runs.
    #[must_use]
    pub const fn trial_count(&self) -> u32 {
        match self.trials {
            Some(n) if n > 0 => n,
            // A `--trials 0` is treated as "once" rather than "never": running a
            // test zero times and reporting success would be a green tick for
            // work that did not happen, which is the worst possible reading.
            _ => 1,
        }
    }

    /// Whether determinism checking is active.
    #[must_use]
    pub const fn checks_determinism(&self) -> bool {
        self.trial_count() > 1
    }
}

/// One discovered test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredTest {
    /// The test's name, as the language toolchain reports it.
    pub name: String,
    /// The file it lives in, relative to the project root.
    pub file: String,
    /// The line, when the language toolchain reports one.
    ///
    /// `None` is honest rather than `0`: a language whose runner does not
    /// report line numbers is not a language whose tests are on line 0.
    pub line: Option<u32>,
}

/// The outcome of running one test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestOutcome {
    /// The test.
    pub test: DiscoveredTest,
    /// Whether it passed in **every** trial.
    pub passed: bool,
    /// How many trials ran.
    pub trials: u32,
    /// How many trials passed.
    pub trials_passed: u32,
    /// The observed output of each trial, when determinism checking is on.
    ///
    /// Retained so a mismatch can name the differing trials rather than merely
    /// reporting that one exists.
    pub trial_outputs: Vec<String>,
    /// Milliseconds spent.
    pub duration_ms: u128,
}

impl TestOutcome {
    /// Whether the trials disagreed with each other.
    ///
    /// Distinct from failure: a flaky test and a broken test are different
    /// findings, and conflating them sends the reader to the wrong place. A
    /// flaky test is a determinism bug in the *code under test*; a broken test
    /// is a bug in the code.
    #[must_use]
    pub fn is_nondeterministic(&self) -> bool {
        if self.trial_outputs.len() < 2 {
            return false;
        }
        let first = &self.trial_outputs[0];
        self.trial_outputs.iter().any(|o| o != first)
    }

    /// The indices of trials whose output differs from the first.
    #[must_use]
    pub fn divergent_trials(&self) -> Vec<usize> {
        let Some(first) = self.trial_outputs.first() else {
            return Vec::new();
        };
        self.trial_outputs
            .iter()
            .enumerate()
            .filter(|(_, o)| *o != first)
            .map(|(i, _)| i)
            .collect()
    }
}

/// The result of a test run.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TestOutput {
    /// The project name.
    pub project: String,
    /// How many tests were discovered, before filtering.
    pub discovered: usize,
    /// How many ran.
    pub ran: usize,
    /// How many passed every trial.
    pub passed: usize,
    /// How many failed at least one trial.
    pub failed: usize,
    /// How many passed some trials and failed others.
    pub nondeterministic: usize,
    /// How many trials each test ran.
    pub trials: u32,
    /// Whether a rehearsal — nothing was executed.
    pub dry_run: bool,
    /// Per-test outcomes, in discovery order.
    pub outcomes: Vec<OutcomeReport>,
}

/// One test's outcome, shaped for output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OutcomeReport {
    /// The test name.
    pub name: String,
    /// The file, relative to the project root.
    pub file: String,
    /// Whether it passed every trial.
    pub passed: bool,
    /// Trials run.
    pub trials: u32,
    /// Trials passed.
    pub trials_passed: u32,
    /// Whether the trials disagreed.
    pub nondeterministic: bool,
    /// Which trials diverged from the first.
    pub divergent_trials: Vec<usize>,
    /// Milliseconds.
    pub duration_ms: u128,
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Language-specific knowledge for running tests.
///
/// A struct per language rather than a `match` at each use site: discovery and
/// execution need the same facts about a toolchain, and duplicating the match is
/// how the two drift — `build` would gain a language that `test` did not know
/// about, and the failure would be a confusing "no tests found".
struct Runner {
    /// The program that compiles and reports test targets.
    ///
    /// Used only to *build*: discovery runs the resulting binaries directly,
    /// which is what makes a test's source file exact rather than inferred.
    program: &'static str,
    /// Arguments that run named tests.
    run_args: &'static [&'static str],
}

/// The runner for a language, if QQQ knows one.
fn runner_for(language: &str) -> Option<Runner> {
    match language {
        "rust" => Some(Runner {
            program: "cargo",
            run_args: &["test"],
        }),
        // The other four languages are declared in the manifest and have no
        // runner wired yet. Returning `None` rather than a guess means the
        // error names the language and the checklist item, instead of failing
        // with an opaque "command not found".
        _ => None,
    }
}

/// Discover the tests in a project.
///
/// # Errors
///
/// * `QQQ-2002` when the manifest declares a language QQQ has no test runner
///   for. The error names the language and the checklist item tracking it.
/// * `QQQ-6004` when the runner is not installed.
///
/// # Why discovery shells out rather than parsing source
///
/// A source-level scan for `#[test]` would be a second, weaker implementation of
/// each language's own discovery rules — and it would be wrong in the cases that
/// matter: a test behind `#[cfg(test)]`, a test generated by a macro, a test
/// conditionally compiled out. Asking the toolchain is correct by construction
/// and costs one process launch.
pub fn discover(project_dir: &Path, language: &str) -> Result<Vec<DiscoveredTest>> {
    let runner = runner_for(language).ok_or_else(|| {
        Error::new(
            ErrorCode::ManifestSchemaViolation,
            format!("no test runner for `{language}` yet"),
        )
        .with_remediation(
            "Rust is the only language with a wired runner; see Checklist \
             `TEST-001` for the per-language discovery work",
        )
    })?;

    // Compile the test targets and learn where they came from. This is the only
    // step that can fail for a compile error, and it produces both the binaries
    // and their sources.
    let binaries = test_binaries(project_dir);
    if binaries.is_empty() {
        return Err(Error::new(
            ErrorCode::InternalInvariantViolated,
            format!(
                "`{}` reported no test binaries for this project",
                runner.program
            ),
        )
        .with_remediation(
            "the project must compile before its tests can be discovered; run \
             `qqqai build` to see the compile error",
        ));
    }

    // Run each binary **directly**.
    //
    // The alternative — one `cargo test -- --list` for the whole project — puts
    // every `Running <exe>` header before every test, because cargo buffers the
    // two streams, so the flat list cannot be attributed back to binaries
    // without guessing. Measured on a real project, the guess was wrong:
    // `tests::the_root_route_greets`, a unit test in `src/app.rs`, was reported
    // as living in `tests/smoke.rs`.
    //
    // Running each binary makes attribution exact: the binary that produced a
    // test is the binary that was asked for it. It costs one process per test
    // target, which for a handful of targets is nothing.
    let mut tests = Vec::new();
    for (executable, source) in &binaries {
        let list = Command::new(executable)
            .args(["--list", "--format", "terse"])
            .current_dir(project_dir)
            .output();

        match list {
            Ok(o) if o.status.success() => {
                tests.extend(parse_libtest_list(
                    &String::from_utf8_lossy(&o.stdout),
                    source,
                ));
            }
            // A binary that will not list its own tests is **reported**, not
            // skipped: a target whose tests silently vanish is a green run for
            // work that did not happen.
            Ok(o) => tests.push(DiscoveredTest {
                name: format!("<could not list: {}>", first_stderr_line(&o.stderr)),
                file: source.clone(),
                line: None,
            }),
            Err(e) => tests.push(DiscoveredTest {
                name: format!("<could not run {executable}: {e}>"),
                file: source.clone(),
                line: None,
            }),
        }
    }

    tests.sort_by(|a, b| a.name.cmp(&b.name));
    tests.dedup_by(|a, b| a.name == b.name);
    Ok(tests)
}

/// The first non-empty line of a stderr buffer, for an error message.
fn first_stderr_line(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no output")
        .to_owned()
}

/// Ask cargo which test binaries it built, and from which sources.
///
/// # Why this exists
///
/// `cargo test -- --list` writes the test list to stdout and the
/// `Running <exe>` headers to stderr — **all headers before all tests**, because
/// cargo buffers. So the streams alone do not say which binary a given test
/// belongs to, and the first version of this runner guessed by splitting the
/// list evenly across headers. Measured against a real project, that guessed
/// wrong: `tests::the_root_route_greets` — a unit test in `src/app.rs` — was
/// attributed to `tests/smoke.rs`.
///
/// The guess was removed rather than tuned. `cargo test --no-run
/// --message-format json` reports each test target's `src_path` and its
/// `executable`, and [`discover`] then runs **each binary directly**, so
/// attribution is exact by construction: the binary that produced a test is the
/// binary that was asked for it.
///
/// The source path is made **relative to the project directory**, so a report
/// reads `src/app.rs` rather than a machine-specific absolute path. The output
/// is diffed across machines and appears in `--json`.
fn test_binaries(project_dir: &Path) -> BTreeMap<String, String> {
    let output = Command::new("cargo")
        .args(["test", "--no-run", "--message-format", "json"])
        .current_dir(project_dir)
        .output();

    let Ok(output) = output else {
        return BTreeMap::new();
    };

    let mut map = BTreeMap::new();
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        // Parsed leniently: a cargo message this does not understand is skipped,
        // and a line that is not JSON at all is skipped too — cargo interleaves
        // status lines that are not JSON when the format changes.
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
            continue;
        }
        let target = value.get("target");
        let is_test = target
            .and_then(|t| t.get("test"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if !is_test {
            continue;
        }
        let src = target
            .and_then(|t| t.get("src_path"))
            .and_then(|s| s.as_str());
        let exe = value.get("executable").and_then(|e| e.as_str());
        if let (Some(src), Some(exe)) = (src, exe) {
            let relative = Path::new(src)
                .strip_prefix(project_dir)
                .map_or_else(|_| PathBuf::from(src), Path::to_path_buf);
            map.insert(
                exe.replace('\\', "/"),
                relative.to_string_lossy().replace('\\', "/"),
            );
        }
    }
    map
}

/// Parse a terse listing from **one** binary.
///
/// Every test in the listing comes from the binary that produced it, so `file`
/// is exact — there is nothing to infer. This replaced a version that ran one
/// listing for the whole project and split it across headers by count, which
/// guessed wrong on a real project.
#[must_use]
fn parse_libtest_list(stdout: &str, file: &str) -> Vec<DiscoveredTest> {
    let mut tests: Vec<DiscoveredTest> = stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (name, kind) = line.rsplit_once(": ")?;
            if kind != "test" {
                return None;
            }
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some(DiscoveredTest {
                name: name.to_owned(),
                file: file.to_owned(),
                line: None,
            })
        })
        .collect();

    tests.sort_by(|a, b| a.name.cmp(&b.name));
    tests.dedup_by(|a, b| a.name == b.name);
    tests
}

/// Apply a filter to discovered tests.
///
/// A substring match rather than a regex, matching what every other test runner
/// does. `--filter` with a regex would be a small convenience for a rare case
/// and a large surprise for a common one — `foo(bar)` as a filter would be a
/// syntax error rather than a name that matches nothing.
#[must_use]
pub fn filter_tests(tests: &[DiscoveredTest], filter: Option<&str>) -> Vec<DiscoveredTest> {
    match filter {
        None => tests.to_vec(),
        Some(pattern) => tests
            .iter()
            .filter(|t| t.name.contains(pattern))
            .cloned()
            .collect(),
    }
}

/// Run one test once and return `(passed, output)`.
///
/// # What "output" means, and why it is not the raw stream
///
/// The captured output is **normalised** before it is returned, because the raw
/// stream contains lines that differ between two identical runs:
///
/// ```text
/// test result: ok. 1 passed; 0 failed; ... finished in 0.01s   <-- differs each run
/// ```
///
/// Comparing raw output therefore reports **every** test as nondeterministic.
/// Measured on a real project: `--trials 3` against a perfectly deterministic
/// suite produced
/// `NONDETERMINISTIC: 1 of 2 test(s) produced different output across 3 trials`.
/// A determinism check that fires on a stable suite is worse than no check,
/// because it teaches the reader to ignore the one signal it exists to give.
fn run_once(project_dir: &Path, program: &str, run_args: &[&str], name: &str) -> (bool, String) {
    let output = Command::new(program)
        .args(run_args)
        .arg(name)
        .arg("--")
        .arg("--exact")
        .arg("--nocapture")
        .current_dir(project_dir)
        .output();

    match output {
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), normalise_run_output(&text))
        }
        Err(e) => (false, format!("could not run: {e}")),
    }
}

/// Strip the parts of a libtest run that differ between identical runs.
///
/// See [`run_once`] for why this is necessary rather than cosmetic. Each filter
/// targets a line whose content measures the **runner**, not the test under it.
///
/// The exit status carries pass/fail, so dropping libtest's summary line loses
/// no information about the outcome. What is kept is everything that reflects
/// the test's own behaviour: its name and status, its panic message, and
/// anything it printed.
#[must_use]
fn normalise_run_output(raw: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();

    for line in raw.lines() {
        let t = line.trim();

        // The summary line carries a duration, and its "filtered out" count
        // depends on the filter applied.
        if t.starts_with("test result:") && t.contains("finished in") {
            continue;
        }

        // cargo's own bookkeeping, reprinted on every invocation.
        if t.starts_with("Compiling ")
            || t.starts_with("Finished ")
            || t.starts_with("Running ")
            || t.starts_with("Blocking ")
            || t.starts_with("Doc-tests ")
        {
            continue;
        }

        // `test <name> ... ok` / `... FAILED` is behaviour and is kept.
        kept.push(line);
    }

    // Collapse runs of blank lines: libtest's spacing varies with what it
    // printed, and the spacing says nothing about the test.
    let mut out = String::new();
    let mut blank_run = 0;
    for line in kept {
        if line.trim().is_empty() {
            blank_run += 1;
            if blank_run > 1 {
                continue;
            }
        } else {
            blank_run = 0;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Execute the discovered tests.
///
/// # Errors
///
/// `QQQ-2002` when the language has no runner, as [`discover`].
pub fn execute(project_dir: &Path, language: &str, opts: &TestOptions) -> Result<TestOutput> {
    let runner = runner_for(language).ok_or_else(|| {
        Error::new(
            ErrorCode::ManifestSchemaViolation,
            format!("no test runner for `{language}` yet"),
        )
        .with_remediation("Rust is the only language with a wired runner; see `TEST-001`")
    })?;

    let all = discover(project_dir, language)?;
    let selected = filter_tests(&all, opts.filter.as_deref());
    let trials = opts.trial_count();

    if opts.dry_run {
        return Ok(TestOutput {
            project: String::new(),
            discovered: all.len(),
            ran: selected.len(),
            passed: 0,
            failed: 0,
            nondeterministic: 0,
            trials,
            dry_run: true,
            outcomes: selected
                .iter()
                .map(|t| OutcomeReport {
                    name: t.name.clone(),
                    file: t.file.clone(),
                    passed: false,
                    trials,
                    trials_passed: 0,
                    nondeterministic: false,
                    divergent_trials: Vec::new(),
                    duration_ms: 0,
                })
                .collect(),
        });
    }

    let mut outcomes = Vec::with_capacity(selected.len());

    for test in &selected {
        let started = std::time::Instant::now();
        let mut trial_outputs = Vec::with_capacity(trials as usize);
        let mut trials_passed = 0u32;

        for _ in 0..trials {
            let (ok, text) = run_once(project_dir, runner.program, runner.run_args, &test.name);
            if ok {
                trials_passed += 1;
            }
            trial_outputs.push(text);
            // A failed trial stops the loop: running a broken test N more times
            // produces N identical failures and N times the wall clock, and the
            // information was in the first one.
            if !ok {
                break;
            }
        }

        let passed = trials_passed == trials;
        let outcome = TestOutcome {
            test: test.clone(),
            passed,
            trials,
            trials_passed,
            trial_outputs,
            duration_ms: started.elapsed().as_millis(),
        };

        outcomes.push(OutcomeReport {
            name: outcome.test.name.clone(),
            file: outcome.test.file.clone(),
            passed: outcome.passed,
            trials: outcome.trials,
            trials_passed: outcome.trials_passed,
            nondeterministic: outcome.is_nondeterministic(),
            divergent_trials: outcome.divergent_trials(),
            duration_ms: outcome.duration_ms,
        });

        if opts.fail_fast && !passed {
            break;
        }
    }

    let passed = outcomes.iter().filter(|o| o.passed).count();
    let failed = outcomes.iter().filter(|o| !o.passed).count();
    let nondeterministic = outcomes.iter().filter(|o| o.nondeterministic).count();

    Ok(TestOutput {
        project: String::new(),
        discovered: all.len(),
        ran: outcomes.len(),
        passed,
        failed,
        nondeterministic,
        trials,
        dry_run: false,
        outcomes,
    })
}

/// Group outcomes by file, for a readable summary.
///
/// A flat list of names is hard to read once a project has more than a handful
/// of tests; grouping by file is what makes a failure locatable.
#[must_use]
pub fn by_file(outcomes: &[OutcomeReport]) -> BTreeMap<String, Vec<&OutcomeReport>> {
    let mut map: BTreeMap<String, Vec<&OutcomeReport>> = BTreeMap::new();
    for o in outcomes {
        map.entry(o.file.clone()).or_default().push(o);
    }
    map
}

/// The path a project's tests live in.
#[must_use]
pub fn tests_dir(project_dir: &Path) -> PathBuf {
    project_dir.join("tests")
}

impl crate::output::CommandOutput for TestOutput {
    fn command(&self) -> crate::output::CommandName {
        crate::output::CommandName::Test
    }

    fn summary(&self) -> String {
        use std::fmt::Write as _;

        // A rehearsal is reported before anything else, because none of the
        // counts below mean what they look like: a dry run has no passes and no
        // failures, and rendering an empty "Failures" section listing every test
        // would say the opposite of what happened. An earlier version did
        // exactly that.
        if self.dry_run {
            let mut out = format!(
                "would run {} of {} discovered test(s), {} trial(s) each",
                self.ran, self.discovered, self.trials
            );
            if !self.outcomes.is_empty() {
                out.push_str("\n\nWould run");
                for o in &self.outcomes {
                    let _ = write!(out, "\n  {}  ({})", o.name, o.file);
                }
            }
            return out;
        }

        // A determinism failure leads, because it is the finding this runner
        // exists to produce and it is invisible to every other runner. A test
        // that passes 4 trials out of 5 looks like a pass in any summary that
        // only counts failures.
        let mut out = if self.nondeterministic > 0 {
            format!(
                "NONDETERMINISTIC: {} of {} test(s) produced different output across {} trials",
                self.nondeterministic, self.ran, self.trials
            )
        } else {
            format!(
                "{} passed, {} failed of {} ({} trial{} each)",
                self.passed,
                self.failed,
                self.ran,
                self.trials,
                if self.trials == 1 { "" } else { "s" }
            )
        };

        // In human format this is the whole output, so failing tests are named
        // (`§O-036a`).
        let failing: Vec<&OutcomeReport> = self.outcomes.iter().filter(|o| !o.passed).collect();
        if !failing.is_empty() {
            out.push_str("\n\nFailures");
            for o in &failing {
                let _ = write!(out, "\n  {}  ({})", o.name, o.file);
                if o.nondeterministic {
                    let _ = write!(
                        out,
                        "\n      passed {}/{} trials; trials {:?} differ from the first",
                        o.trials_passed,
                        o.trials,
                        o.divergent_trials.iter().map(|i| i + 1).collect::<Vec<_>>()
                    );
                } else {
                    let _ = write!(out, "\n      passed {}/{}", o.trials_passed, o.trials);
                }
            }
        }

        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // `summary()` is a trait method. Importing the trait in the test module is
    // how these tests assert on what a user reads, rather than on struct fields
    // — the discipline from §O-036a.
    use crate::output::CommandOutput;

    /// A real libtest listing, including the `Running` lines.
    /// A real listing from **one** test binary, as libtest emits it.
    ///
    /// Taken from actual output rather than invented: the invented version had a
    /// module prefix on every name, and the real one does not — a test declared
    /// at the crate root has no `::` at all.
    const LISTING: &str = "\
tests::an_unknown_route_is_404: test
tests::health_is_available: test
tests::the_root_route_greets: test
the_crate_builds: test
benches::throughput: benchmark

4 tests, 1 benchmark
";

    #[test]
    fn a_libtest_listing_is_parsed_into_named_tests() {
        let tests = parse_libtest_list(LISTING, "tests/smoke.rs");
        let names: Vec<&str> = tests.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "tests::an_unknown_route_is_404",
                "tests::health_is_available",
                "tests::the_root_route_greets",
                "the_crate_builds",
            ],
            "sorted, and the benchmark excluded"
        );
    }

    /// Every test in a single binary's listing gets that binary's source.
    ///
    /// The regression test for a real defect. An earlier version ran one listing
    /// for the whole project and split it across the `Running` headers by count,
    /// because cargo buffers every header before every test. Measured against a
    /// real project, the split was wrong: `tests::the_root_route_greets`, a unit
    /// test in `src/app.rs`, was attributed to `tests/smoke.rs`.
    ///
    /// Running each binary directly removes the inference entirely, so this
    /// asserts the property that makes that true: one binary, one source, no
    /// exceptions.
    #[test]
    fn every_test_in_one_listing_shares_that_binarys_source() {
        let tests = parse_libtest_list(LISTING, "src/app.rs");
        assert!(!tests.is_empty());
        for t in &tests {
            assert_eq!(
                t.file, "src/app.rs",
                "{} came from a different binary",
                t.name
            );
        }
    }

    /// A unit test and an integration test get different sources.
    ///
    /// The distinction the previous implementation could not make: two binaries,
    /// two files, and the names do not say which is which — `the_crate_builds`
    /// has no module prefix and lives in `tests/smoke.rs`.
    #[test]
    fn two_binaries_produce_two_sources() {
        let unit = parse_libtest_list("tests::health: test\n", "src/app.rs");
        let integration = parse_libtest_list("the_crate_builds: test\n", "tests/smoke.rs");

        assert_eq!(unit[0].file, "src/app.rs");
        assert_eq!(integration[0].file, "tests/smoke.rs");
    }

    /// A benchmark entry must not become a test.
    ///
    /// Running one as a test reports a bizarre failure — the benchmark harness
    /// takes different arguments — and the fix would look unrelated to the cause.
    #[test]
    fn benchmarks_are_not_treated_as_tests() {
        let tests = parse_libtest_list(LISTING, "src/app.rs");
        assert!(
            !tests.iter().any(|t| t.name.contains("throughput")),
            "a benchmark is not a test: {tests:?}"
        );
    }

    /// An unfamiliar line is skipped, not fatal.
    ///
    /// libtest has added lines before and will again. A parser that fails on an
    /// unrecognised line is a parser that breaks on a toolchain update.
    #[test]
    fn an_unfamiliar_line_is_skipped_rather_than_failing() {
        let noisy = "some future preamble\napp::tests::works: test\nnonsense\n";
        let tests = parse_libtest_list(noisy, "src/app.rs");
        assert_eq!(tests.len(), 1);
        assert_eq!(tests[0].name, "app::tests::works");
    }

    #[test]
    fn duplicate_names_are_collapsed() {
        assert_eq!(
            parse_libtest_list("a::b: test\na::b: test\n", "x.rs").len(),
            1
        );
    }

    #[test]
    fn an_empty_listing_yields_no_tests() {
        assert!(parse_libtest_list("", "x.rs").is_empty());
        assert!(parse_libtest_list("0 tests, 0 benchmarks\n", "x.rs").is_empty());
    }

    // -- output normalisation -----------------------------------------------

    /// Two runs of the same test differ only in timing, and must compare equal.
    ///
    /// The regression test for a real defect: `--trials 3` compared raw output,
    /// saw libtest's `finished in 0.01s`, and reported a deterministic suite as
    /// nondeterministic. A determinism check that fires on a stable suite trains
    /// its reader to ignore it.
    #[test]
    fn runs_differing_only_in_timing_compare_equal() {
        let a = "    Finished `test` profile [unoptimized] target(s) in 0.02s\n\
                 \n     Running unittests src/lib.rs (target/debug/deps/app-1.exe)\n\
                 \nrunning 1 test\n\
                 test tests::adding_works ... ok\n\
                 \ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n";
        let b = "    Finished `test` profile [unoptimized] target(s) in 0.05s\n\
                 \n     Running unittests src/lib.rs (target/debug/deps/app-1.exe)\n\
                 \nrunning 1 test\n\
                 test tests::adding_works ... ok\n\
                 \ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s\n";

        assert_eq!(
            normalise_run_output(a),
            normalise_run_output(b),
            "the only difference is a duration, which is not the test's behaviour"
        );
    }

    /// A real behavioural difference **is** detected.
    ///
    /// The positive control: without it, a normalizer that stripped everything
    /// would pass the test above and detect nothing.
    #[test]
    fn a_real_output_difference_is_preserved() {
        let ok = "test tests::x ... ok\n";
        let failed = "test tests::x ... FAILED\n\nassertion failed\n";
        assert_ne!(normalise_run_output(ok), normalise_run_output(failed));
    }

    /// A test's own printed output is kept.
    #[test]
    fn a_tests_printed_output_is_kept() {
        let with_print = "test tests::x ... ok\n\nhello from the test\n";
        let normalised = normalise_run_output(with_print);
        assert!(
            normalised.contains("hello from the test"),
            "a test's own output is behaviour: {normalised}"
        );
    }

    /// The `filtered out` count on the summary line does not create a difference.
    #[test]
    fn the_filtered_count_does_not_create_a_difference() {
        let a = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s\n";
        let b = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s\n";
        assert_eq!(normalise_run_output(a), normalise_run_output(b));
    }

    /// Blank-line runs are collapsed.
    #[test]
    fn blank_line_runs_are_collapsed() {
        let a = "line\n\n\n\nline2\n";
        let b = "line\n\nline2\n";
        assert_eq!(normalise_run_output(a), normalise_run_output(b));
    }

    // -- filtering ----------------------------------------------------------

    #[test]
    fn a_filter_matches_a_substring() {
        let tests = parse_libtest_list(LISTING, "src/app.rs");
        let chosen = filter_tests(&tests, Some("health"));
        assert_eq!(chosen.len(), 1, "{chosen:?}");
        assert_eq!(chosen[0].name, "tests::health_is_available");
    }

    /// A filter matching a whole file selects every test in it.
    ///
    /// `qqqai test smoke` is what a user types to run one test file, and it
    /// works because the *names* in that file share nothing — so this is the
    /// case where a name-based filter does not do what a file-based intuition
    /// expects. Recorded rather than left as a surprise.
    #[test]
    fn a_filter_matching_a_filename_selects_nothing_when_no_name_contains_it() {
        let tests = parse_libtest_list(LISTING, "src/app.rs");
        // No test is *named* after the file it lives in.
        let chosen = filter_tests(&tests, Some("smoke"));
        assert!(
            chosen.is_empty(),
            "filtering is by test name, not by file: {chosen:?}"
        );
        // But filtering by the module path does select a file's tests.
        let by_module = filter_tests(&tests, Some("tests::"));
        assert_eq!(by_module.len(), 3, "the three unit tests");
    }

    #[test]
    fn no_filter_selects_everything() {
        let tests = parse_libtest_list(LISTING, "src/app.rs");
        assert_eq!(filter_tests(&tests, None).len(), tests.len());
    }

    /// A filter matching nothing yields nothing, rather than everything.
    ///
    /// The dangerous default: a typo'd filter that fell back to "run all" would
    /// report a full green run for a selection the user did not ask for.
    #[test]
    fn a_filter_matching_nothing_selects_nothing() {
        let tests = parse_libtest_list(LISTING, "src/app.rs");
        assert!(filter_tests(&tests, Some("no_such_test")).is_empty());
    }

    // -- trial semantics ----------------------------------------------------

    #[test]
    fn the_default_is_a_single_trial() {
        assert_eq!(TestOptions::default().trial_count(), 1);
        assert!(!TestOptions::default().checks_determinism());
    }

    #[test]
    fn trials_above_one_enable_determinism_checking() {
        let opts = TestOptions {
            trials: Some(5),
            ..Default::default()
        };
        assert_eq!(opts.trial_count(), 5);
        assert!(opts.checks_determinism());
    }

    /// `--trials 0` means once, not never.
    ///
    /// Running a test zero times and reporting success is a green tick for work
    /// that did not happen — the worst possible reading of the flag.
    #[test]
    fn zero_trials_runs_once_rather_than_never() {
        let opts = TestOptions {
            trials: Some(0),
            ..Default::default()
        };
        assert_eq!(opts.trial_count(), 1);
    }

    /// `--trials 1` is accepted, not rejected.
    #[test]
    fn one_trial_is_accepted() {
        let opts = TestOptions {
            trials: Some(1),
            ..Default::default()
        };
        assert_eq!(opts.trial_count(), 1);
        assert!(!opts.checks_determinism());
    }

    // -- nondeterminism detection -------------------------------------------

    fn outcome_with_trials(outputs: &[&str]) -> TestOutcome {
        TestOutcome {
            test: DiscoveredTest {
                name: "t".to_owned(),
                file: "src/t.rs".to_owned(),
                line: None,
            },
            passed: true,
            // `try_from` rather than `as`: the fixture lengths are small, but a
            // truncating cast in a test is still a truncating cast, and clippy's
            // objection is legitimate wherever it appears.
            trials: u32::try_from(outputs.len()).expect("a fixture with 4 billion trials"),
            trials_passed: u32::try_from(outputs.len()).expect("a fixture with 4 billion trials"),
            trial_outputs: outputs.iter().map(|s| (*s).to_owned()).collect(),
            duration_ms: 0,
        }
    }

    #[test]
    fn identical_trials_are_deterministic() {
        let o = outcome_with_trials(&["same", "same", "same"]);
        assert!(!o.is_nondeterministic());
        assert!(o.divergent_trials().is_empty());
    }

    #[test]
    fn a_differing_trial_is_detected() {
        let o = outcome_with_trials(&["same", "same", "different"]);
        assert!(o.is_nondeterministic());
        assert_eq!(o.divergent_trials(), vec![2], "the third trial, 0-indexed");
    }

    #[test]
    fn a_first_trial_difference_is_detected() {
        let o = outcome_with_trials(&["a", "b"]);
        assert!(o.is_nondeterministic());
        assert_eq!(o.divergent_trials(), vec![1]);
    }

    /// A single trial cannot be nondeterministic.
    ///
    /// There is nothing to compare against, and reporting a flake from one
    /// sample would be a false positive that sends the reader hunting a bug
    /// that may not exist.
    #[test]
    fn a_single_trial_is_never_nondeterministic() {
        let o = outcome_with_trials(&["only"]);
        assert!(!o.is_nondeterministic());
    }

    #[test]
    fn no_trials_is_never_nondeterministic() {
        let o = outcome_with_trials(&[]);
        assert!(!o.is_nondeterministic());
    }

    // -- runners ------------------------------------------------------------

    #[test]
    fn rust_has_a_runner() {
        let r = runner_for("rust").expect("Rust must have a runner");
        assert_eq!(r.program, "cargo");
    }

    /// An unwired language is refused by name, not guessed at.
    #[test]
    fn an_unwired_language_is_refused_by_name() {
        assert!(runner_for("python").is_none());
        assert!(runner_for("go").is_none());
        assert!(runner_for("").is_none());
    }

    #[test]
    fn discovery_for_an_unwired_language_names_it_and_the_item() {
        let e = discover(Path::new("."), "python").unwrap_err();
        let text = e.render();
        assert!(text.contains("python"), "{text}");
        assert!(text.contains("TEST-001"), "{text}");
    }

    // -- output -------------------------------------------------------------

    fn sample_output(nondeterministic: usize, failed: usize) -> TestOutput {
        TestOutput {
            project: "app".to_owned(),
            discovered: 4,
            ran: 4,
            passed: 4 - failed,
            failed,
            nondeterministic,
            trials: 3,
            dry_run: false,
            outcomes: vec![
                OutcomeReport {
                    name: "a::ok".to_owned(),
                    file: "src/a.rs".to_owned(),
                    passed: true,
                    trials: 3,
                    trials_passed: 3,
                    nondeterministic: false,
                    divergent_trials: Vec::new(),
                    duration_ms: 1,
                },
                OutcomeReport {
                    name: "a::flaky".to_owned(),
                    file: "src/a.rs".to_owned(),
                    passed: false,
                    trials: 3,
                    trials_passed: 2,
                    nondeterministic: true,
                    divergent_trials: vec![2],
                    duration_ms: 5,
                },
            ],
        }
    }

    /// A determinism failure is stated as such, not as a generic failure.
    ///
    /// A test passing 2 of 3 trials looks like a pass in a summary that counts
    /// only failures, and "failed" sends the reader to the wrong problem.
    #[test]
    fn the_summary_leads_with_nondeterminism_when_there_is_any() {
        let text = sample_output(1, 1).summary();
        assert!(text.contains("NONDETERMINISTIC"), "{text}");
        assert!(text.contains("a::flaky"), "the test must be named: {text}");
    }

    /// The human output names failing tests and their file.
    #[test]
    fn the_summary_names_failing_tests() {
        let text = sample_output(0, 1).summary();
        assert!(text.contains("Failures"), "{text}");
        assert!(text.contains("a::flaky"), "{text}");
        assert!(
            text.contains("2/3"),
            "the trial split is the finding: {text}"
        );
    }

    /// A rehearsal does **not** report failures.
    ///
    /// The regression test for a real defect: a dry run leaves every outcome
    /// with `passed: false` — nothing ran — and the summary rendered that as a
    /// "Failures" section listing every test. It said the opposite of what
    /// happened, and `--dry-run` is exactly the flag a cautious user runs first.
    #[test]
    fn a_rehearsal_reports_no_failures() {
        let out = TestOutput {
            dry_run: true,
            ran: 2,
            discovered: 2,
            trials: 3,
            passed: 0,
            failed: 0,
            ..sample_output(0, 0)
        };
        let text = out.summary();

        assert!(text.contains("would run"), "{text}");
        assert!(text.contains("2 of 2"), "{text}");
        assert!(text.contains("3 trial(s) each"), "{text}");
        assert!(
            !text.contains("Failures"),
            "a rehearsal ran nothing, so nothing failed: {text}"
        );
        assert!(
            !text.contains("0 passed"),
            "reporting zero passes for a rehearsal reads as a total failure: {text}"
        );
    }

    /// A rehearsal still lists what it would run.
    #[test]
    fn a_rehearsal_names_the_tests_it_would_run() {
        let out = TestOutput {
            dry_run: true,
            ..sample_output(0, 0)
        };
        let text = out.summary();
        assert!(text.contains("Would run"), "{text}");
        assert!(text.contains("a::ok"), "{text}");
    }
    ///
    /// The fixture is a genuinely clean run — every outcome passing — because an
    /// earlier version reused the failing sample and then asserted that
    /// "Failures" was absent. The assertion was right and the fixture was wrong,
    /// which is the more useful failure: it showed the test was describing a
    /// different run than its name claimed.
    #[test]
    fn a_clean_run_reports_the_counts() {
        let out = TestOutput {
            passed: 4,
            failed: 0,
            ran: 4,
            trials: 1,
            nondeterministic: 0,
            outcomes: vec![OutcomeReport {
                name: "a::ok".to_owned(),
                file: "src/a.rs".to_owned(),
                passed: true,
                trials: 1,
                trials_passed: 1,
                nondeterministic: false,
                divergent_trials: Vec::new(),
                duration_ms: 1,
            }],
            ..sample_output(0, 0)
        };
        let text = out.summary();
        assert!(text.contains("4 passed"), "{text}");
        assert!(!text.contains("Failures"), "{text}");
        assert!(text.contains("1 trial"), "singular agreement: {text}");
        assert!(!text.contains("NONDETERMINISTIC"), "{text}");
    }

    #[test]
    fn plural_agreement_is_correct() {
        let out = TestOutput {
            trials: 5,
            ..sample_output(0, 0)
        };
        let text = out.summary();
        assert!(text.contains("5 trials"), "{text}");
        assert!(!text.contains("5 trial each"), "{text}");
    }

    #[test]
    fn grouping_by_file_buckets_the_outcomes() {
        // Bound first: `by_file` borrows the outcomes, so a temporary would be
        // dropped at the end of the statement.
        let output = sample_output(0, 0);
        let grouped = by_file(&output.outcomes);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped["src/a.rs"].len(), 2);
    }

    #[test]
    fn the_tests_directory_is_beside_the_manifest() {
        assert!(tests_dir(Path::new("/proj")).ends_with("tests"));
    }
}
