// SPDX-License-Identifier: Apache-2.0

//! The flaky-test detector — a test that has both passed and failed across runs.
//!
//! # Why this is not [`crate::test::TestOutcome::is_nondeterministic`]
//!
//! They are two different questions, and `§O-430` is the observation that recorded the difference after a
//! previous round conflated them:
//!
//! * `is_nondeterministic()` asks **"did this test vary within one `--trials N` run?"** Its subject is
//!   `trial_outputs`, which are the `N` trials of a *single* invocation. That is `TEST-005`, and it is
//!   finished.
//! * A flaky-test detector asks **"has this test passed on some runs and failed on others?"** Its subject
//!   is a **history** that outlives one process, and nothing in this tree kept one:
//!
//!   ```text
//!   $ rg -n -e 'flaky|flake' crates/ tools/ .github/
//!     twelve hits. Every one is a comment about a past flake or a comment explaining why an assertion was
//!     written to avoid one. No history. No detector.
//!   ```
//!
//! # What its absence cost, measured
//!
//! `§O-425` records a macOS-only failure in `serve_policy` that took **three separate measurements** to
//! attribute. `§O-430` predicted the remedy: a detector that said
//!
//! > *"this test has failed 1 of the last N runs on this platform"*
//!
//! *"would have turned three into one."*
//!
//! **And the prediction was then paid for again**, which is why this module exists rather than an
//! acknowledgement: `serve_policy::an_origin_outside_the_manifest_list_is_not_granted` **passed** on
//! `dd40706` and **failed** on `eb1bba9`, in runs eight minutes apart. Attributing it took the CI log, a
//! step-timing measurement to rule out the 30-minute timeout, the observation that the panic message was
//! empty after its colon, the file's own record of **three earlier patches to the same race**, and finally
//! running the binary. **The same file tells the same story a second time**, in
//! `crates/qqq-run/tests/common/mod.rs`:
//!
//! > *"**Six test files carried their own copy of the same helper**, and … the flake … each fix had been
//! > aimed at whichever file happened to fail."*
//!
//! # What a history is, and why it is a file rather than a field
//!
//! A history has to outlive the process that produced it, so it is a **JSON Lines** file: one record per
//! line, append-only, and readable by anything. JSONL rather than JSON because appending one line is a
//! single write and never rewrites what is there — **a detector whose record can be corrupted by the act
//! of recording is a detector that reports its own damage as a flake.**
//!
//! # Why the platform is part of the key
//!
//! Because the failures this exists for are platform-shaped. `§O-425`'s was macOS-only; the readiness race
//! fixed in `a6dca8a` failed on Ubuntu and passed on the other two. **A detector that pooled platforms
//! would report every one of them as flaky everywhere**, which is the same as reporting nothing.

use std::collections::BTreeMap;
use std::path::Path;

use qqq_core::{Error, ErrorCode, Result};

/// One test's outcome, in one run, on one platform.
///
/// # Why `commit` and `run` are carried rather than a timestamp
///
/// Because a bare timestamp is not comparable across machines, and the question a reader asks of a flake
/// is *"when did it start"* — which is a commit, not a clock. **`run` is the CI run identifier when there
/// is one and `None` locally**, so a record written on a developer's machine is not mistaken for evidence
/// about CI.
/// # Example
///
/// ```
/// use qqq_run::flaky::TestRecord;
///
/// let record = TestRecord {
///     test: "serve_policy::a_route".to_owned(),
///     platform: "linux".to_owned(),
///     passed: false,
///     commit: "eb1bba9".to_owned(),
///     run: Some("36640019865".to_owned()),
/// };
///
/// // It is JSON Lines on disk, so the record itself is writable by hand if it has to be.
/// let line = serde_json::to_string(&record).expect("serialises");
/// let back: TestRecord = serde_json::from_str(&line).expect("round trips");
/// assert_eq!(back, record);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TestRecord {
    /// The test's name, as the runner reports it.
    pub test: String,
    /// `std::env::consts::OS` at the time — `linux`, `macos` or `windows`.
    pub platform: String,
    /// Whether the test passed.
    pub passed: bool,
    /// The commit the run was made at, abbreviated. Free-form: a history is read by people.
    pub commit: String,
    /// The CI run identifier, when the record came from CI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
}

/// One `(test, platform)` that has both passed and failed.
/// # Example
///
/// ```
/// use qqq_run::flaky::Flake;
///
/// let flake = Flake {
///     test: "serve_policy::an_origin".to_owned(),
///     platform: "linux".to_owned(),
///     runs: 40,
///     failures: 1,
///     first_failure: "eb1bba9".to_owned(),
///     last_failure: "eb1bba9".to_owned(),
/// };
///
/// // One failure in forty, and the commit says which one -- the count alone cannot.
/// assert!(flake.summary().contains("failed 1 of the last 40"));
/// assert!(flake.summary().contains("eb1bba9"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Flake {
    /// The test's name.
    pub test: String,
    /// The platform it is flaky on. **One platform, not all of them** — see this module's own docs.
    pub platform: String,
    /// How many records were considered, after the window.
    pub runs: usize,
    /// How many of them failed.
    pub failures: usize,
    /// The commits of the first and last failure, in the order the history holds them.
    ///
    /// # Why these are the useful part of the report
    ///
    /// Because *"failed 1 of 40"* says a test is unreliable and *"first failed at `eb1bba9`, last at
    /// `eb1bba9`"* says where to look. **A defect that appears once and never again is a different thing
    /// from one that appears every third run**, and the count alone cannot tell them apart.
    pub first_failure: String,
    /// The commit of the last failure in the window.
    pub last_failure: String,
}

impl Flake {
    /// `failed 1 of 40 runs on linux`, the sentence `§O-430` asked for.
    ///
    /// # Example
    ///
    /// ```
    /// use qqq_run::flaky::{detect, TestRecord};
    ///
    /// let history = vec![
    ///     TestRecord { test: "t".to_owned(), platform: "macos".to_owned(), passed: true,
    ///                  commit: "dd40706".to_owned(), run: None },
    ///     TestRecord { test: "t".to_owned(), platform: "macos".to_owned(), passed: false,
    ///                  commit: "eb1bba9".to_owned(), run: None },
    /// ];
    ///
    /// let found = detect(&history, 20);
    /// assert_eq!(found.len(), 1);
    /// assert_eq!(found[0].summary(), "t failed 1 of the last 2 run(s) on macos (eb1bba9 .. eb1bba9)");
    /// ```
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} failed {} of the last {} run(s) on {} ({} .. {})",
            self.test,
            self.failures,
            self.runs,
            self.platform,
            self.first_failure,
            self.last_failure
        )
    }
}

/// Read a JSON Lines history. A missing file is an empty history, not an error.
///
/// # Why a missing file is not an error
///
/// Because the ordinary first use of this is `qqqai test --history <path>` on a path that does not exist
/// yet, and **an error there would make the first run fail while recording the thing that makes the second
/// run useful.** A malformed line *is* an error, for the opposite reason: it is a record somebody wrote and
/// this cannot read, and skipping it silently would under-report a failure — which is the direction that
/// hides a flake.
/// # Example
///
/// ```
/// use qqq_run::flaky::read_history;
///
/// // **A missing file is an empty history, not an error.** The ordinary first use of this is a path
/// // that does not exist yet, and an error there would make the first run fail while recording the
/// // thing that makes the second run useful.
/// let missing = std::env::temp_dir().join("qqq-flaky-doc-never-written.jsonl");
/// let _ = std::fs::remove_file(&missing);
/// assert!(read_history(&missing).expect("a missing history is empty").is_empty());
/// ```
///
/// # Errors
///
/// **One refusal, and it is deliberate.** A line that does not parse is an error naming its line number
/// rather than a record that is skipped: a skipped record under-reports a failure, and the failures are
/// the whole point of the file. A missing file is **not** an error -- see the example above.
pub fn read_history(path: &Path) -> Result<Vec<TestRecord>> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: TestRecord = serde_json::from_str(line).map_err(|e| {
            Error::new(
                ErrorCode::ManifestSchemaViolation,
                format!("{} line {} is not a history record: {e}", path.display(), i + 1),
            )
            .with_remediation(
                "a history is JSON Lines: one object per line, appended by `qqqai test --history`. \
                 A line that does not parse is the tail of a run that was killed while writing, or a \
                 hand edit -- neither is silently skipped, because a skipped record under-reports a \
                 failure and the failures are the whole point of the file",
            )
        })?;
        out.push(record);
    }
    Ok(out)
}

/// Append records to a JSON Lines history, creating it if it is absent.
///
/// # Why this is append-only
///
/// Because a history is evidence. **A recorder that rewrites the file can lose the run that produced the
/// failure, and the failure is the only thing anybody wants from it.** The one write here is one line per
/// record, so a process killed mid-run leaves a truncated final line and never a corrupted prefix — and a
/// truncated line is loud, because [`read_history`] refuses it by line number.
/// # Example
///
/// ```
/// use qqq_run::flaky::{append_history, detect, read_history, TestRecord};
///
/// let dir = std::env::temp_dir().join("qqq-flaky-doc-append");
/// let _ = std::fs::remove_dir_all(&dir);
/// let path = dir.join("history.jsonl");
/// let at = |passed, commit: &str| TestRecord {
///     test: "t".to_owned(), platform: "linux".to_owned(), passed,
///     commit: commit.to_owned(), run: None,
/// };
///
/// append_history(&path, &[at(true, "dd40706")]).expect("append");
/// append_history(&path, &[at(false, "eb1bba9")]).expect("append again");
///
/// // **Append-only, so nothing was rewritten** -- and the two lines together are the flake.
/// assert_eq!(read_history(&path).expect("read").len(), 2);
/// assert_eq!(detect(&read_history(&path).expect("read"), 20).len(), 1);
/// let _ = std::fs::remove_dir_all(&dir);
/// ```
///
/// # Errors
///
/// **Creating the parent directory, opening the file, or writing a line.** All three are reported with
/// the path, because the alternative -- a recorder that swallows a write failure -- produces a history
/// with holes in it, and a detector reading a history with holes reports the *absence* of a failure as
/// evidence that there was none.
///
/// A record that does not serialise cannot happen and is reported as an internal invariant rather than
/// as input this refuses.
pub fn append_history(path: &Path, records: &[TestRecord]) -> Result<()> {
    use std::io::Write as _;

    if records.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::new(
                    ErrorCode::ManifestSchemaViolation,
                    format!("create {}: {e}", parent.display()),
                )
            })?;
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| {
            Error::new(
                ErrorCode::ManifestSchemaViolation,
                format!("open {}: {e}", path.display()),
            )
        })?;
    for record in records {
        let line = serde_json::to_string(record).map_err(|e| {
            Error::new(
                ErrorCode::InternalInvariantViolated,
                format!("a record this module built did not serialise: {e}"),
            )
        })?;
        writeln!(file, "{line}").map_err(|e| {
            Error::new(
                ErrorCode::ManifestSchemaViolation,
                format!("write {}: {e}", path.display()),
            )
        })?;
    }
    Ok(())
}

/// Every `(test, platform)` in the last `window` records that both **passed** and **failed**.
///
/// # Why both, and not merely "failed"
///
/// Because a test that fails on every run is **broken**, not flaky, and it needs a different response: the
/// first is a flake to be diagnosed and the second is a build to be fixed. `§O-430`'s sentence is *"failed
/// **1** of the last N"*, and the `1` is load-bearing — it is what distinguishes the two.
///
/// # Why the window is per-key and not global
///
/// Because a global window answers a different question. If a platform runs four times as often, a global
/// *last 100 records* would hold eighty of its runs and twenty of the others', so **a test that fails half
/// the time on the quiet platform would be invisible.** The window is applied to each
/// `(test, platform)`'s own sequence, in the order the history holds them.
///
/// # Why the order is the file's and not a parsed date
///
/// Because the file is append-only and its order **is** the chronological order, and a date would make the
/// detector depend on every writer's clock agreeing. **A history whose meaning depends on clocks is a
/// history that reports flakes whenever a machine's clock is wrong.**
/// # Example
///
/// The case this exists for: a test that **passed on one commit and failed on another**, which is the
/// question `is_nondeterministic` cannot answer because its subject is one run's trials.
///
/// ```
/// use qqq_run::flaky::{detect, TestRecord};
///
/// let at = |platform: &str, passed, commit: &str| TestRecord {
///     test: "serve_policy".to_owned(), platform: platform.to_owned(), passed,
///     commit: commit.to_owned(), run: None,
/// };
///
/// let history = vec![
///     at("linux", true, "dd40706"),
///     at("linux", false, "eb1bba9"),
///     at("macos", true, "dd40706"),
/// ];
///
/// let found = detect(&history, 20);
/// // **One platform, not all of them.** Pooling them would name every platform a test ever ran on.
/// assert_eq!(found.len(), 1);
/// assert_eq!(found[0].platform, "linux");
/// ```
///
/// And a test that **never** passes is not reported, because it is broken rather than flaky:
///
/// ```
/// use qqq_run::flaky::{detect, TestRecord};
///
/// let history = vec![
///     TestRecord { test: "b".to_owned(), platform: "linux".to_owned(), passed: false,
///                  commit: "c1".to_owned(), run: None },
///     TestRecord { test: "b".to_owned(), platform: "linux".to_owned(), passed: false,
///                  commit: "c2".to_owned(), run: None },
/// ];
/// assert!(detect(&history, 20).is_empty());
/// ```
#[must_use]
pub fn detect(records: &[TestRecord], window: usize) -> Vec<Flake> {
    let mut by_key: BTreeMap<(&str, &str), Vec<&TestRecord>> = BTreeMap::new();
    for r in records {
        by_key
            .entry((r.test.as_str(), r.platform.as_str()))
            .or_default()
            .push(r);
    }

    let mut out = Vec::new();
    for ((test, platform), all) in by_key {
        let recent = if window == 0 || all.len() <= window {
            &all[..]
        } else {
            &all[all.len() - window..]
        };
        let failures = recent.iter().filter(|r| !r.passed).count();
        // **Both, so a test that never passes is reported as broken rather than as flaky.**
        if failures == 0 || failures == recent.len() {
            continue;
        }
        let failing: Vec<&&TestRecord> = recent.iter().filter(|r| !r.passed).collect();
        out.push(Flake {
            test: test.to_owned(),
            platform: platform.to_owned(),
            runs: recent.len(),
            failures,
            first_failure: failing
                .first()
                .map_or_else(String::new, |r| r.commit.clone()),
            last_failure: failing
                .last()
                .map_or_else(String::new, |r| r.commit.clone()),
        });
    }
    out
}

/// The platform string a record carries, from the binary's own build target.
///
/// One place decides, so a record written on one platform and read on another cannot disagree about what
/// the first one was.
/// # Example
///
/// ```
/// use qqq_run::flaky::platform;
///
/// // The same string `std::env::consts::OS` gives, so a record written here is comparable to one
/// // written anywhere else.
/// assert_eq!(platform(), std::env::consts::OS);
/// ```
#[must_use]
pub fn platform() -> String {
    std::env::consts::OS.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(test: &str, platform: &str, passed: bool, commit: &str) -> TestRecord {
        TestRecord {
            test: test.to_owned(),
            platform: platform.to_owned(),
            passed,
            commit: commit.to_owned(),
            run: None,
        }
    }

    /// The detector finds the case `§O-430` asked for, and says it in those words.
    #[test]
    fn a_test_that_passed_and_failed_is_reported_with_its_counts() {
        let history = vec![
            rec("a", "linux", true, "c1"),
            rec("a", "linux", true, "c2"),
            rec("a", "linux", false, "eb1bba9"),
            rec("a", "linux", true, "c4"),
        ];
        let found = detect(&history, 20);
        assert_eq!(found.len(), 1, "one flake");
        assert_eq!(found[0].failures, 1);
        assert_eq!(found[0].runs, 4);
        assert_eq!(found[0].platform, "linux");
        assert!(found[0]
            .summary()
            .contains("failed 1 of the last 4 run(s) on linux"));
        assert!(found[0].summary().contains("eb1bba9"));
    }

    /// **A test that fails every time is broken, and must not be called flaky.**
    ///
    /// The distinction is the reason `detect` requires a pass *and* a failure. If this case were reported,
    /// every genuinely broken test would arrive in the same list as the intermittent ones and the list
    /// would be useless for either.
    #[test]
    fn a_test_that_never_passes_is_not_flaky() {
        let history = vec![
            rec("broken", "linux", false, "c1"),
            rec("broken", "linux", false, "c2"),
        ];
        assert!(
            detect(&history, 20).is_empty(),
            "a broken test is not a flake"
        );
    }

    /// **And a test that never fails is not flaky either**, which is the case that matters for noise.
    #[test]
    fn a_test_that_never_fails_is_not_flaky() {
        let history = vec![
            rec("solid", "linux", true, "c1"),
            rec("solid", "linux", true, "c2"),
        ];
        assert!(detect(&history, 20).is_empty());
    }

    /// **The platform is part of the key**, so a failure on one is not reported as a failure on all.
    ///
    /// This is `§O-425`'s shape: its flake was macOS-only, and a detector that pooled platforms would have
    /// named all three. Measured here as: the same test, failing only on macOS, yields exactly one report.
    #[test]
    fn a_flake_on_one_platform_is_reported_for_that_platform_only() {
        let history = vec![
            rec("serve_policy", "linux", true, "dd40706"),
            rec("serve_policy", "macos", true, "dd40706"),
            rec("serve_policy", "macos", false, "c1"),
            rec("serve_policy", "windows", true, "dd40706"),
        ];
        let found = detect(&history, 20);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].platform, "macos");
    }

    /// **The window is per-key**, so a busy platform cannot crowd a quiet one out of the report.
    ///
    /// The quiet platform's two records are at the very start of a long history, so a *global* last-4
    /// window would exclude them entirely and the flake would be invisible. This is the case that makes
    /// the window per-key rather than global.
    #[test]
    fn a_quiet_platform_is_not_crowded_out_by_a_busy_one() {
        let mut history = vec![
            rec("t", "macos", true, "c1"),
            rec("t", "macos", false, "c2"),
        ];
        for i in 0..50 {
            history.push(rec("t", "linux", true, &format!("l{i}")));
        }
        let found = detect(&history, 4);
        assert_eq!(found.len(), 1, "the macos flake survives a per-key window");
        assert_eq!(found[0].platform, "macos");
        assert_eq!(found[0].runs, 2);
    }

    /// **A window of zero means the whole history**, which is the useful reading of "no limit".
    #[test]
    fn a_window_of_zero_means_no_limit() {
        let mut history = vec![rec("t", "linux", false, "c1")];
        for i in 0..30 {
            history.push(rec("t", "linux", true, &format!("c{i}")));
        }
        let found = detect(&history, 0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].runs, 31, "the whole history, not none of it");
    }

    /// A history round-trips through the file, and a missing file reads as empty rather than failing.
    #[test]
    fn a_history_round_trips_and_a_missing_file_is_empty() {
        let dir = std::env::temp_dir().join(format!("qqq-flaky-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("history.jsonl");

        assert!(read_history(&path)
            .expect("a missing history is empty")
            .is_empty());

        let first = vec![rec("a", "linux", true, "c1")];
        append_history(&path, &first).expect("append");
        append_history(&path, &[rec("a", "linux", false, "c2")]).expect("append again");

        let back = read_history(&path).expect("read");
        assert_eq!(back.len(), 2, "append-only, so nothing was rewritten");
        assert_eq!(
            detect(&back, 20).len(),
            1,
            "and the two together are a flake"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A malformed line is an error naming its line number**, not a record silently skipped.
    ///
    /// Skipping it would under-report the failures, which is the direction that hides a flake — and a
    /// truncated final line is what a killed writer leaves, so this is the ordinary case rather than a
    /// contrived one.
    #[test]
    fn a_malformed_line_names_its_number_rather_than_being_skipped() {
        let dir = std::env::temp_dir().join(format!("qqq-flaky-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create");
        let path = dir.join("history.jsonl");
        std::fs::write(
            &path,
            "{\"test\":\"a\",\"platform\":\"linux\",\"passed\":true,\"commit\":\"c1\"}\nnot json at all\n",
        )
        .expect("write");

        let err = read_history(&path).expect_err("a malformed line must be an error");
        let text = err.to_string();
        assert!(
            text.contains("line 2"),
            "the message must name the line: {text}"
        );

        // **And a record that is valid JSON but missing a required field is refused at ITS line.**
        // The first version of this fixture wrote `{"test":"a"}` and this test failed while the
        // code was right: serde refused line 1 for the three absent fields, so line 2 was never
        // reached. That is the better behaviour and it is worth its own assertion -- a history whose
        // records could be partly defaulted would report a test as passing because nobody wrote down
        // that it failed.
        std::fs::write(&path, "{\"test\":\"a\"}\n").expect("write");
        let err = read_history(&path).expect_err("a partial record must be an error");
        assert!(
            err.to_string().contains("line 1"),
            "a record missing fields must be refused at its own line: {err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
